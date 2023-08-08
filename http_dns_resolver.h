#ifndef __HTTP_DNS_RESOLVER_H__
#define __HTTP_DNS_RESOLVER_H__

#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "cJSON/cJSON.h"
#include "result_data.h"

#define N_MAX_URL_LEN 256

struct MemoryStruct {
    char* memory;
    size_t size;
};

result_data_t *get_result_data(char *json_str);

result_data_t *resolve(const char* domain, const char* appID, const char* appSalt);

void free_result_data(result_data_t *result_data);

void free_cache_key(cache_key_rule_t *cache_key);

void free_node_select(node_select_rule_t *node_select_rules, int n);

char* parse_domain(char* url);

char* getPath(const char* url);

char* getQuery(const char* url);

#endif