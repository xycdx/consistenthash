#ifndef __RESULT_DATA_H__
#define __RESULT_DATA_H__

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "list.h"

#define N_MAX_ID_LEN 512

typedef struct group_t group_t;
typedef struct elt_t elt_t;
typedef struct ips_t ips_t;
typedef struct result_data_t result_data_t;
typedef struct cache_key_rule_t cache_key_rule_t;
typedef struct rewrite_t rewrite_t;
typedef struct value_t value_t;
typedef struct node_select_rule_t node_select_rule_t;
typedef struct group_select_t group_select_t;

typedef enum query_config_t query_config_t;

enum query_config_t {
    QUERY_STRING_TYPE_NONE = 1,
    QUERY_STRING_TYPE_ALL,
    QUERY_STRING_TYPE_INCLUDE,
    QUERY_STRING_TYPE_EXCLUDE
};

struct cache_key_rule_t {
    query_config_t query_config;
    char **values;
    int num_values;
    rewrite_t *rewrites;
    int num_rewrites;
};

struct rewrite_t {
    char *pattern;
    char *repl;
};

struct node_select_rule_t
{
    char *pattern;
    float service_rate;
    group_select_t *group_select;
    int num_groups;
};

struct group_select_t
{
    int groupIdx;
    int weight;
    int splitn;
};

struct result_data_t {
    char *bucket;
    group_t *groups;
    int num_groups;
    node_select_rule_t *node_select_rules;
    int num_rules;
    cache_key_rule_t *cache_key_rule;
    long threshold;
    int ttl;
};

struct group_t {
    elt_t *elts;
    int num_elts;
    int weight;
};

struct elt_t {
    char *id;
    char **ips;
    int num_ips;
    int replicas;
    char *fingerprint;
};

#endif
