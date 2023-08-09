#include "dns.h"

const long DEFAULT_DURATION_MS = 1000;
long RESOLVE_TIMEOUT_MS = 2 * 1000;
const char *app_id = "44zpao7x7vyw9ncu";
const char *app_salt = "916c9boaawdlnxlle6k7472asee6h7y8";

static ip_group_t      *pick_random_by_replicas(ip_group_t *ip_groups, int num_ip_groups);
static group_select_t  *sort_random_by_weight(group_select_t *groups, int num_groups);
static void             do_resolve_by_ECDN(domain_cache_t *domain_cache, char *url, int attempts, ip_found_cb job);
static domain_cache_t  *resolve_domain(char *domain, _bool_t httpDNS);
static domain_cache_t  *updata_cache(char *domain, _bool_t httpDNS);
static char            *generate_cacheKey(char *url, char *bucket, cache_key_rule_t *cacheKeyRule);
static char            *applyRewrites(char *path, rewrite_t *rewrites, int num_rewrites);
static char            *applyQueryStringConfig(char *queryString, query_config_t query_config);
static domain_cache_t  *parse_domain_cache_by_ECDN(result_data_t *data, long retry_interval_MS);
static _bool_t          should_serve_with_rule(node_select_rule_t *nodeSelectRule);
static ip_group_t      *find_ip_group(node_group_t *node_group, char **eltIDs, int n);
static int              handle_http_request(char *ip, char *surl);

static int handle_http_request(char *ip, char *surl) {
    printf("%s %s \n", ip, surl);
    CURL *curl;
    CURLcode res;
    const char *referer = "Referer: http://www.tangdou.com/";
    const char *origin = "Origin: http://www.tangdou.com/";
    const char *range = "Range: bytes=0-1";
    const char *host = "Host: aqiniushare.tangdou.com";
    char url[512] = {0};
    sprintf(url, "http://%s/%s%s?%s", ip, parse_domain(surl), getPath(surl), getQuery(surl));
    int retryTimes = 0;
    int internalRequest = 1;

    FILE *fp;
    fp = fopen("example.mp4", "wb");

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    struct curl_slist *headers = NULL;
    // headers = curl_slist_append(headers, range);
    headers = curl_slist_append(headers, origin);
    headers = curl_slist_append(headers, referer);
    headers = curl_slist_append(headers, host);
    headers = curl_slist_append(headers, "X-Miku-Agent: miku-delivery-android/1.1.2");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    // curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    // curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    // curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &data);
    // curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);

    printf("start download\n");
    res = curl_easy_perform(curl);
    printf("finish download\n");
    if (res == CURLE_OK) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        char *response_message = NULL;
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &response_message);
        printf("code: %d, message: %s \n", response_code, response_message);
        // if (response_code >= 300 && response_code < 400) {
        //     char *location;
        //     curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &location);
        //     if (location) {
        //         printf("redirect to: %s \n", location);
        //         curl_slist_free_all(headers);
        //         headers = NULL;

        //         curl = curl_easy_init();
        //         curl_easy_setopt(curl, CURLOPT_URL, location);
        //         curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        //         curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        //         curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        //         curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
        //         curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        //         printf("start download\n");
        //         res = curl_easy_perform(curl);
        //         printf("finish download\n");

        //         if (res == CURLE_OK) {
        //             curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        //             curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &response_message);
        //             printf("code: %d, message: %s\n", response_code, response_message);

        //             fclose(fp);
        //             curl_easy_cleanup(curl);
        //             curl_slist_free_all(headers);
        //             curl_global_cleanup();
        //             return 1;
        //         } else {
        //             fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        //         }
        //     }
        // } else {
        //     fclose(fp);
        //     curl_easy_cleanup(curl);
        //     curl_slist_free_all(headers);
        //     curl_global_cleanup();
        //     return 1;
        // }
    } else {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    fclose(fp);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    return 1;
}

long current_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + (tv.tv_usec / 1000);
}

static domain_cache_t *parse_domain_cache_by_ECDN(result_data_t *data, long retry_interval_MS)
{
    domain_cache_t *domain_cache = (domain_cache_t *)malloc(sizeof(domain_cache_t));
    long expiry = current_time() + data->ttl * 1000;
    domain_cache->expiry = expiry;
    if (data->num_groups > 0) {
        domain_cache->node_groups = (node_group_t *)malloc(sizeof(node_group_t) * data->num_groups);
        domain_cache->num_groups = data->num_groups;
        for (int i = 0;i < data->num_groups; i++) {
            group_t *group = &data->groups[i];
            node_group_t node_group;
            node_group.consistenthash = consistenthash_create(43);
            node_group.num_ip_groups = group->num_elts;
            node_group.ip_groups = (ip_group_t *)malloc(sizeof(ip_group_t) * group->num_elts);
            node_group.wts = group->weight;
            
            for (int j = 0;j < group->num_elts; j++) {
                elt_t *elt = &group->elts[j];
                add(node_group.consistenthash, elt->id, elt->replicas);
                ip_group_t ip_group;
                ip_group.num_ips = elt->num_ips;
                ip_group.ips = (char **)malloc(sizeof(char *) * elt->num_ips);
                for (int k = 0; k < elt->num_ips; k++) {
                    // printf("%s\n", elt->ips[k]);
                    ip_group.ips[k] = strdup(elt->ips[k]);
                }
                ip_group.eltID = strdup(elt->id);
                ip_group.replicas = elt->replicas;
                ip_group.retryIntervalMs = retry_interval_MS;
                ip_group.after = 0;
                ip_group.index = -1;
                node_group.ip_groups[j] = ip_group;
            }
            domain_cache->node_groups[i] = node_group;
        }
        
        domain_cache->node_select_rules = data->node_select_rules;
        domain_cache->num_rules = data->num_rules;
        data->node_select_rules = NULL;
        domain_cache->cacheKeyRule = data->cache_key_rule;
        data->cache_key_rule = NULL;
        domain_cache->threshold = data->threshold;
    }
    free_result_data(data);
    return domain_cache;
}

static char *applyQueryStringConfig(char *queryString, query_config_t query_config) {
    return NULL;
}

static char *applyRewrites(char *path, rewrite_t *rewrites, int num_rewrites) {
    return NULL;
}

static char *generate_cacheKey(char *url, char *bucket, cache_key_rule_t *cacheKeyRule) {
    return url;
}

void execute(char *url, int attempts, _bool_t httpDNS, ip_found_cb job) {
    char *domain = parse_domain(url);
    domain_cache_t *domain_cache= resolve_domain(domain, httpDNS);
    if (!domain_cache->num_rules) {

    } else {
        do_resolve_by_ECDN(domain_cache, url, attempts, job);
    }
    free_domain_cache(domain_cache);
}

static domain_cache_t *updata_cache(char *domain, _bool_t httpDNS) {
    domain_cache_t *domain_cache = NULL;
    result_data_t *result_data = NULL;
    if (httpDNS) {
        result_data = resolve(domain, app_id, app_salt);
        if (result_data != NULL) {
            domain_cache = parse_domain_cache_by_ECDN(result_data, DEFAULT_DURATION_MS);
        }
    }
    return domain_cache;
}

static domain_cache_t *resolve_domain(char *domain, _bool_t httpDNS) {
    domain_cache_t *domain_cache = NULL;
    if (domain_cache == NULL) {
        domain_cache = updata_cache(domain, httpDNS);
    } else if (current_time() > domain_cache->expiry) {

    }
    return domain_cache;
}

char *get_cache_key(char *url) {

    return url;
}

static void do_resolve_by_ECDN(domain_cache_t *domain_cache, char *url, int attempts, ip_found_cb cb) {
    char *cacheKey = get_cache_key(url);
    node_select_rule_t *nodeSelectRule = &domain_cache->node_select_rules[0];
    // group_select_t *sorted_rule_groups = sort_random_by_weight(nodeSelectRule->group_select, nodeSelectRule->num_groups);
    int k = attempts < nodeSelectRule->num_groups ? attempts : nodeSelectRule->num_groups;
    for (int i = 0; i < k; i++) {
        group_select_t *group = &nodeSelectRule->group_select[i];
        node_group_t *node_group = &domain_cache->node_groups[group->groupIdx];
        int elm_num = group->splitn == 1 ? 2 : group->splitn;
        char **eltIDs = getN(node_group->consistenthash, cacheKey, &elm_num);
        ip_group_t *ip_groups = find_ip_group(node_group, eltIDs, elm_num);
        for (int j = 0; j < ip_groups->num_ips; j++) {
            if (cb(ip_groups->ips[j], url)) {
                return;
            }
        }
    }
}

static ip_group_t *pick_random_by_replicas(ip_group_t *ip_groups, int num_ip_groups)
{
    if (!num_ip_groups) {
        return NULL;
    }
    int sum = 0;
    for (int i = 0; i < num_ip_groups; i++) {
        sum += ip_groups[i].replicas;
    }
    srand(time(NULL));
    int rnd = rand() % sum;
    for (int i = 0; i < num_ip_groups; i++) {
        ip_group_t *ip_group = &ip_group[i];
        if (rnd < ip_group->replicas) {
            return ip_group;
        } else {
            rnd -= ip_group->replicas;
        }
    }
    return NULL;
}

static group_select_t *sort_random_by_weight(group_select_t *groups, int num_groups) {
    group_select_t *sorted_groups = (group_select_t *)malloc(sizeof(group_select_t) * num_groups);
    int *weights = (int *)malloc(sizeof(int) * num_groups);
    int sum = 0;
    list_head *p = NULL;
    for (int i = 0; i < num_groups; i++) {
        group_select_t *group = &groups[i];
        sum += group->weight;
        weights[i] = group->weight;
    }
    int j = 0;
    srand(time(NULL));
    while (sum != 0) {
        int rnd = rand() % sum;
        for (int i = 0; i < num_groups; i++) {
            if (rnd < weights[i]) {
                sum -= weights[i];
                weights[i] = 0;
                sorted_groups[j++] = groups[i];
                break;
            } else {
                rnd -= weights[i];
            }
        }
    }
    free(weights);
    return sorted_groups;
}

static _bool_t should_serve_with_rule(node_select_rule_t *nodeSelectRule) {
    srand(time(NULL));
    double rnd = 1.0 * rand() / RAND_MAX;
    return rnd < nodeSelectRule->service_rate;
}

static ip_group_t *find_ip_group(node_group_t *node_group, char **eltIDs, int n) {
    for (int i = 0; i < n; i++) {
        char *eltID = eltIDs[i];
        for (int j = 0; j < node_group->num_ip_groups; j++) {
            if (strcmp(eltID, node_group->ip_groups[j].eltID) == 0) {
                return &node_group->ip_groups[j];
            }
        }
    }
}

int main() {
    while (1) {
        execute("https://aqiniushare.tangdou.com/202304/20000004959887_H540P.mp4?sign=2b29ed1ecbbf9f341e31ff788d4ca4a2&t=64cd2724", 
                3, 1, (ip_found_cb)handle_http_request);
    }
    
}