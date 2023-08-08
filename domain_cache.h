#ifndef __DOMAIN_CACHE_H__
#define __DOMAIN_CACHE_H__

#include <sys/time.h>

#include "http_dns_resolver.h"
#include "consistenthash.h"
#include "result_data.h"

typedef struct domain_cache_t domain_cache_t;
typedef struct node_group_t node_group_t;
typedef struct ip_group_t ip_group_t;

struct domain_cache_t{
    node_group_t *node_groups;
    int num_groups;
    node_select_rule_t *node_select_rules;
    int num_rules;
    // ip_group_t *ip_groups;
    // int num_ip_groups;
    cache_key_rule_t *cacheKeyRule;
    long threshold;
    long expiry;
};

struct node_group_t {
    consistenthash_t *consistenthash;
    int wts;
    ip_group_t *ip_groups;
    int num_ip_groups;
};

struct ip_group_t {
    long after;
    int replicas;
    char *eltID;
    char **ips;
    int num_ips;
    long index;
    long retryIntervalMs;
};

domain_cache_t *create_as_ECDN();

domain_cache_t *create_as_CDN();

domain_cache_t *create_as_ban();

_bool_t is_empty(domain_cache_t *domain_cache);

void free_domain_cache(domain_cache_t *domain_cache);

#endif