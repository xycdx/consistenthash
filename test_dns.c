#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <curl/curl.h>

char* hmacsha1(char* key, char* data) {
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), hmac, &hmac_len);
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, hmac, hmac_len);
    BIO_flush(b64);
    char* bufferPtr = NULL;
    int output_len = BIO_get_mem_data(mem, &bufferPtr);
    char* output = (char*)malloc(output_len + 1);
    memcpy(output, bufferPtr, output_len);
    output[output_len] = '\0';
    BIO_free_all(mem);
    return output;
}

char* get_authorization(char* url, char* app_id, char* app_salt) {
    printf("%s\n", url);
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
    char* encoded_sign = hmacsha1(app_salt, singing_str);
    for(int i = 0; i < strlen(encoded_sign); i++) {
        if(encoded_sign[i] == '+') {
            encoded_sign[i] = '-';
        }
        if(encoded_sign[i] == '/') {
            encoded_sign[i] = '_';
        }
    }
    char* authorization;
    asprintf(&authorization, "QApp %s:%s", app_id, encoded_sign);
    free(path);
    free(query);
    free(singing_str);
    free(encoded_sign);
    curl_url_cleanup(url_obj);
    return authorization;
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
    printf("%s\n", domain);
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
        snprintf(authHeader, sizeof(authHeader), "%s: %s", HEADER_AUTHORIZATION, get_authorization(url, appID, appSalt));
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
            printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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
