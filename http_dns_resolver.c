#include "http_dns_resolver.h"

static const char *TAG = "HttpDNSResolver";
static const char *HEADER_AUTHORIZATION = "Authorization";
static const char *HTTP_DNS_API = "https://api.qiniudns.com/v1/resolve";
static const int DEFAULT_TTL = 60 * 5;
static const char *ERROR_NOT_SUPPORT_AREA = "NotSupportedArea";

static void json_parse_groups(cJSON* json_obj, result_data_t *result_data);
static void json_parse_rules(cJSON* json_obj, result_data_t *result_data);
static void json_parse_cacheKey(cJSON* json_obj, cache_key_rule_t *rule);
static char* get_authorization(const char* url, const char* app_id, const char* app_salt);

char* parse_domain(char* url) {
    const char* start = strstr(url, "://");
    if (start) {
        start += 3;
        const char* end = strchr(start, '/');
        if (end) {
            size_t host_length = end - start;
            char* host = (char*)malloc(host_length + 1);
            if (host) {
                strncpy(host, start, host_length);
                host[host_length] = '\0';
                return host;
            }
        }
    }
    return NULL;
}

char* getPath(const char* url) {
    CURLU* url_obj = curl_url();
    curl_url_set(url_obj, CURLUPART_URL, url, 0);
    char* path = NULL;
    curl_url_get(url_obj, CURLUPART_PATH, &path, 0);
    curl_url_cleanup(url_obj);
    return path;
}

char* getQuery(const char* url) {
    CURLU* url_obj = curl_url();
    curl_url_set(url_obj, CURLUPART_URL, url, 0);
    char* query = NULL;
    curl_url_get(url_obj, CURLUPART_QUERY, &query, 0);
    curl_url_cleanup(url_obj);
    return query;
}

char* hmacsha1(const char* key, char* data) {
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

static char* get_authorization(const char* url, const char* app_id, const char* app_salt) {
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
    for (int i = 0; i < strlen(encoded_sign); i++) {
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

static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;

    mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

result_data_t *resolve(const char* domain, const char* appID, const char* appSalt) {
    // FILE *fp = fopen("dns.json", "r");
    // char *buffer = malloc(500000);
    // fread(buffer, 1, 500000, fp);
    // result_data_t *ret = get_result_data(buffer);
    // free(buffer);
    // fclose(fp);
    // return ret;

    char url[N_MAX_URL_LEN];
    snprintf(url, N_MAX_URL_LEN, "%s?name=%s", HTTP_DNS_API, domain);

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
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // char authHeader[512] = "Authorization: QApp 44zpao7x7vyw9ncu:k1niDDlDq6WP7H7-iw0upnbX5f0=";
        char authHeader[512];
        snprintf(authHeader, sizeof(authHeader), "%s: %s", HEADER_AUTHORIZATION, get_authorization(url, appID, appSalt));
        printf("%s\n", authHeader);
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
                free(chunk.memory);
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);  
                curl_global_cleanup();
                for (int i = 0;i < chunk.size; i++) {
                    printf("%c", chunk.memory[i]);
                }
                printf("\n");
                return get_result_data(chunk.memory);
            } else {
                printf("response code: %ld \n", responseCode);
            }
        } else {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    curl_global_cleanup();
    return NULL;
}
//192 81 122 98 225 85 0 0 144 42 115 98 225 85 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 15 251 118 109 45 49 51 100 48 102 50 98 97 100 48 53 55 54 102 51 55 97 10

static void json_parse_cacheKey(cJSON* json_obj, cache_key_rule_t *rule) {
    cJSON *json_cacheKey = cJSON_GetObjectItem(json_obj, "cacheKey");
    cJSON *json_query_config = cJSON_GetObjectItem(json_cacheKey, "queryString");
    char *type = cJSON_GetObjectItem(json_query_config, "type")->valuestring;
    if (strcmp(type, "none") == 0) {
        rule->query_config = QUERY_STRING_TYPE_NONE;
    } else if (strcmp(type, "all") == 0) {
        rule->query_config = QUERY_STRING_TYPE_ALL;
    } else if (strcmp(type, "include") == 0) {
        rule->query_config = QUERY_STRING_TYPE_INCLUDE;
    } else if( strcmp(type, "exclude") == 0) {
        rule->query_config = QUERY_STRING_TYPE_EXCLUDE;
    }

    cJSON *json_values = cJSON_GetObjectItem(json_query_config, "values");
    int values_size = cJSON_GetArraySize(json_values);
    rule->values = (char **)malloc(sizeof(char *) * values_size);
    rule->num_values = values_size;
    for (int i = 0; i < values_size; i++) {
        rule->values[i] = strdup(cJSON_GetArrayItem(json_values, i)->valuestring);
    }

    cJSON *json_rewrites = cJSON_GetObjectItem(json_cacheKey, "rewrites");
    int rewrites_size = cJSON_GetArraySize(json_rewrites);
    rule->rewrites = (rewrite_t *)malloc(sizeof(rewrite_t) * rewrites_size);
    rule->num_rewrites = rewrites_size;
    for (int i = 0; i < rewrites_size; i++) {
        cJSON *json_rewrite = cJSON_GetArrayItem(json_rewrites, i);
        rule->rewrites = (rewrite_t *)malloc(sizeof(rewrite_t));
        rule->rewrites[i].pattern = strdup(cJSON_GetObjectItem(json_rewrite, "pattern")->valuestring);
        rule->rewrites[i].repl = strdup(cJSON_GetObjectItem(json_rewrite, "repl")->valuestring);
    }
}

static void json_parse_rules(cJSON* json_obj, result_data_t *result_data) {
    cJSON *json_rules = cJSON_GetObjectItem(json_obj, "rules");
    int rules_size = cJSON_GetArraySize(json_rules);
    result_data->node_select_rules = (node_select_rule_t *)malloc(sizeof(node_select_rule_t) * rules_size);
    result_data->num_rules =rules_size;
    for (int i = 0; i < rules_size; i++) {
        cJSON *json_rule =cJSON_GetArrayItem(json_rules, i);
        
        result_data->node_select_rules[i].pattern = strdup(cJSON_GetObjectItem(json_rule, "pattern")->valuestring);
        result_data->node_select_rules[i].service_rate = cJSON_GetObjectItem(json_rule, "servicerate")->valuedouble;
        cJSON *json_groups = cJSON_GetObjectItem(json_rule, "groups");
        int group_size = cJSON_GetArraySize(json_groups);
        result_data->node_select_rules[i].group_select = (group_select_t *)malloc(sizeof(group_select_t) * group_size);
        result_data->node_select_rules[i].num_groups = group_size;
        for (int j = 0; j < group_size; j++) {
            cJSON *json_group = cJSON_GetArrayItem(json_groups, j);
            group_select_t group = {
                .groupIdx = cJSON_GetObjectItem(json_group, "groupIdx")->valueint,
                .splitn = cJSON_GetObjectItem(json_group, "splitn")->valueint,
                .weight = cJSON_GetObjectItem(json_group, "weight")->valueint
            };
            result_data->node_select_rules[i].group_select[j] = group;
        }
    }
}

static void json_parse_groups(cJSON* json_obj, result_data_t *result_data) {
    cJSON *json_groups = cJSON_GetObjectItem(json_obj, "groups");
    int groups_size = cJSON_GetArraySize(json_groups);
    result_data->num_groups = groups_size;
    result_data->groups = (group_t *)malloc(sizeof(group_t) * groups_size);
    //parse group
    for (int i = 0; i < groups_size; i++) {
        cJSON *json_group = cJSON_GetArrayItem(json_groups, i);
        group_t group;
        group.weight = cJSON_GetObjectItem(json_group, "weight")->valueint;
        //parse elt
        cJSON *json_elts = cJSON_GetObjectItem(json_group, "elts");
        int elts_size = cJSON_GetArraySize(json_elts);
        group.elts = (elt_t *)malloc(sizeof(elt_t) * elts_size);
        group.num_elts = elts_size;
        for (int j = 0; j < elts_size; j++) {
            cJSON *json_elt = cJSON_GetArrayItem(json_elts, j);
            elt_t elt;
            elt.id = strdup(cJSON_GetObjectItem(json_elt, "id")->valuestring);
            elt.fingerprint = strdup(cJSON_GetObjectItem(json_elt, "fingerprint")->valuestring);
            elt.replicas = cJSON_GetObjectItem(json_elt, "replicas")->valueint;
            //parse addr
            cJSON *json_addrs = cJSON_GetObjectItem(json_elt, "addrs");
            int addrs_size = cJSON_GetArraySize(json_addrs);
            elt.ips = (char **)malloc(sizeof(char *) * addrs_size);
            elt.num_ips = addrs_size;
            for (int k = 0; k < addrs_size; k++) {
                cJSON *json_addr = cJSON_GetArrayItem(json_addrs, k);
                char *ip = cJSON_GetObjectItem(json_addr, "ip")->valuestring;
                char http[10] = {0};
                sprintf(http, "%d", cJSON_GetObjectItem(json_addr, "http")->valueint);
                elt.ips[k] = (char *)malloc(strlen(ip) + strlen(http) + 2);
                memset(elt.ips[k], 0, sizeof(elt.ips[k]));
                strcat(elt.ips[k], ip);
                strcat(elt.ips[k], ":");
                strcat(elt.ips[k], http);
            }
            group.elts[j] = elt;
        }
        result_data->groups[i] = group;
    }
}

result_data_t *get_result_data(char *json_str) {
    cJSON *json_obj = NULL;
    result_data_t *result_data = (result_data_t *)malloc(sizeof(result_data_t));
    result_data->cache_key_rule = (cache_key_rule_t *)malloc(sizeof(cache_key_rule_t));
    json_obj = cJSON_Parse(json_str);

    // result_data->ttl = cJSON_GetObjectItem(json_obj, "ttl")->valueint;
    if (cJSON_GetObjectItem(json_obj, "groups") != NULL) {
        cJSON *json_bucket = cJSON_GetObjectItem(json_obj, "bucket");
        if(json_bucket != NULL) {
            result_data->bucket = strdup(json_bucket->valuestring);
        }
        json_parse_groups(json_obj, result_data);
        json_parse_rules(json_obj, result_data);
        json_parse_cacheKey(json_obj, result_data->cache_key_rule);
        result_data->threshold = cJSON_GetObjectItem(cJSON_GetObjectItem(json_obj, "mediaOptimization"), "threshold")->valuedouble;
    }
    cJSON_Delete(json_obj);
    return result_data;
}

void free_result_data(result_data_t *result_data) {
    if (result_data->groups) {
        for (int i = 0; i < result_data->num_groups; i++) {
            group_t *group = &result_data->groups[i];
            for (int j = 0; j < group->num_elts; j++) {
                elt_t *elt = &group->elts[j];
                if (elt->id) {
                    free(elt->id);
                }
                if (elt->fingerprint) {
                    free(elt->fingerprint);
                }
                if (elt->ips) {
                    for (int k = 0; k < elt->num_ips; k++) {
                        free(elt->ips[k]);
                    }
                    free(elt->ips);
                }
                
            }
            free(group->elts);
        }
        free(result_data->groups);
    }
    free_node_select(result_data->node_select_rules, result_data->node_select_rules);
    free_cache_key(result_data->cache_key_rule);
    free(result_data);
    result_data = NULL;
}

void free_cache_key(cache_key_rule_t *cache_key) {
    if (cache_key) {
        for (int i = 0; i < cache_key->num_rewrites; i++) {
            rewrite_t *rewrite = &cache_key->rewrites[i];
            if (rewrite->pattern) {
                free(rewrite->pattern);
            }
            if (rewrite->repl) {
                free(rewrite->repl);
            }
        }
        free(cache_key->rewrites);
        for (int i = 0; i < cache_key->num_values; i++) {
            free(cache_key->values[i]);
        }
        free(cache_key->values);
        cache_key->values = NULL;
        free(cache_key);
        cache_key = NULL;
    }
}

void free_node_select(node_select_rule_t *node_select_rules, int n) {
    if (node_select_rules) {
        for (int i = 0; i < n; i++) {
            node_select_rule_t *rule = &node_select_rules[i];

            if (rule->pattern) {
                free(rule->pattern);
                rule->pattern = NULL;
            }
            if (rule->group_select) {
                free(rule->group_select);
                rule->group_select = NULL;
            }
        }
        free(node_select_rules);
        node_select_rules = NULL;
    }
}