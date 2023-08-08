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

char* getAuthorization(char* url, char* appID, char* appSalt) {
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
    char* authorization;
    asprintf(&authorization, "QApp %s:%s", appID, encoded_sign);
    free(path);
    free(query);
    free(singing_str);
    free(encoded_sign);
    curl_url_cleanup(url_obj);
    return authorization;
}

int main() {
    char* url = "https://api.qiniudns.com/v1/resolve?name=aqiniushare.tangdou.com";
    char* appID = "44zpao7x7vyw9ncu";
    char* appSalt = "916c9boaawdlnxlle6k7472asee6h7y8";
    char* authorization = getAuthorization(url, appID, appSalt);
    printf("%s\n", authorization);
    free(authorization);
    return 0;
}