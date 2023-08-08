#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include "ngx_port.h"
#include "http_parser.h"

char* hmacsha1(char* key, char* data) {
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), hmac, &hmac_len);
    ngx_str_t input = {hmac_len, hmac};
    ngx_str_t output;
    ngx_encode_base64url(&output, &input);
    printf("%s\n", output.data);
    return output.data;
}

char* get_authorization(char* url, char* appID, char* appSalt) {
    CURLU* url_obj = curl_url();
    curl_url_set(url_obj, CURLUPART_URL, url, 0);
    char* path = NULL;
    curl_url_get(url_obj, CURLUPART_PATH, &path, 0);
    char* query = NULL;
    curl_url_get(url_obj, CURLUPART_QUERY, &query, 0);
    char* singing_str;
    if (query == NULL) {
        asprintf(&singing_str, "%s\n", path);
    } else {
        asprintf(&singing_str, "%s?%s\n", path, query);
    }
    char* encoded_sign = hmacsha1(appSalt, singing_str);
    for(int i = 0; i < strlen(encoded_sign); i++) {
        if(encoded_sign[i] == '+') {
            encoded_sign[i] = '-';
        }
        if(encoded_sign[i] == '/') {
            encoded_sign[i] = '_';
        }
    }
    char* authorization;
    asprintf(&authorization, "QApp %s:%s", appID, encoded_sign);
    free(path);
    free(query);
    free(singing_str);
    free(encoded_sign);
    curl_url_cleanup(url_obj);
    return authorization;
}

int parse_url(const char* url, char* schema, int* schemaSize, char* domain, int* domainSize, char* path, int* pathSize, char* query, int* querySize)
{
    if (NULL == url) {
        return -1;
    }

    struct http_parser_url http_url;
    http_parser_url_init(&http_url);
    http_parser_parse_url(url, strlen(url), 0, &http_url);
    char* data[] = {schema, domain, path, query};
    int* dataSize[] = {schemaSize, domainSize, pathSize, querySize};
    int lens[] = {0,0,0,0};
    int types[] = {UF_SCHEMA, UF_HOST, UF_PATH, UF_QUERY};
    for (int i = 0; i < (int)(sizeof(data)/sizeof(data[0])); i++) {
        if (NULL != dataSize[i]) {
            if (0 != (http_url.field_set & (1 << types[i]))) {
                lens[i] = http_url.field_data[types[i]].len;
                if (NULL != data[i] && *dataSize[i] > lens[i]) {
                    memcpy(data[i], (char*)&url[http_url.field_data[types[i]].off], lens[i]+1);
                    data[i][lens[i]] = 0;
                }
            }
            *dataSize[i] = lens[i];
        }
    }

    return 0;
}

int __getAuthorization(const char* url, const char* appID, const char* appSalt, char* buff, int len)
{
    char path[1024];
    char query[8192];
    char signStr[8192];
    int pathSize = sizeof(path);
    int querySize = sizeof(query);
    
    parse_url(url,NULL, NULL, NULL, NULL, path, &pathSize, query, &querySize);
    if (0 < querySize) {
        snprintf(signStr, sizeof(signStr), "%s?%s\n", path, query);
    } else {
        snprintf(signStr, sizeof(signStr), "%s\n", path);
    }
    printf("%s\n", signStr);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
 
    HMAC(EVP_sha1(), appSalt, strlen(appSalt), (unsigned char*)signStr, strlen(signStr), digest, &digest_len);
    digest[digest_len] = 0;
    ngx_port_encode_base64url(signStr, sizeof(signStr), (char*)digest);
    printf("%s \n", digest);
    int count = snprintf(buff, len, "Authorization: QApp %s:%s", appID, signStr);
    if (count < len - 1 && buff[count-1] != '=') {
        buff[count++] = '=';
        buff[count] = 0;
    }
    return count;
}

#define MAX_URL_LENGTH 256

struct MemoryStruct {
    char* memory;
    size_t size;
};

static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;

    mem->memory = (char*)realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void resolve(const char* domain, const char* appID, const char* appSalt) {
    const char* HTTP_DNS_API = "https://api.qiniudns.com/v1/resolve";
    const char* HEADER_AUTHORIZATION = "Authorization";
    const char* ERROR_NOT_SUPPORT_AREA = "error_not_support_area";
    const int DEFAULT_TTL = 3600;

    char url[MAX_URL_LENGTH];
    snprintf(url, MAX_URL_LENGTH, "%s?name=%s", HTTP_DNS_API, domain);

    CURL* curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = (char*)malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

        // char authHeader[512] = "Authorization: QApp 44zpao7x7vyw9ncu:k1niDDlDq6WP7H7-iw0upnbX5f0=";
        char authHeader[512];
        __getAuthorization(url, appID, appSalt, authHeader, sizeof(authHeader));
        printf("%s \n", authHeader);
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, authHeader);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        long connectStartTime = (long)time(NULL);
        res = curl_easy_perform(curl);
        long connectEndTime = (long)time(NULL);

        double t_conn = (connectEndTime - connectStartTime);

        if (res == CURLE_OK) {
            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
            if (responseCode == 200) {
                printf("%s\n",chunk.memory);
                free(chunk.memory);
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);  
                curl_global_cleanup();
                return;
            } else {
                printf("response code: %d \n", responseCode);
            }
        } else {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    curl_global_cleanup();
}

int main() {
    resolve("aqiniushare.tangdou.com", 
            "44zpao7x7vyw9ncu", 
            "916c9boaawdlnxlle6k7472asee6h7y8");
}
