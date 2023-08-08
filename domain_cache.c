#include "domain_cache.h"


void free_node_group(node_group_t *node_group) {
    consistenthash_fin(node_group->consistenthash);
    
    for (int i = 0; i < node_group->num_ip_groups; i++) {
        free(node_group->ip_groups[i].eltID);
        for (int j = 0; j < node_group->ip_groups[i].num_ips; j++) {
            free(node_group->ip_groups[i].ips[j]);
        }
        free(node_group->ip_groups[i].ips); 
    }
    free(node_group->ip_groups);
}

void free_domain_cache(domain_cache_t *domain_cache) {
    for (int i = 0; i < domain_cache->num_groups; i++) {
        free_node_group(&domain_cache->node_groups[i]);
    } 
    free(domain_cache->node_groups);
    free_cache_key(domain_cache->cacheKeyRule);
    free_node_select(domain_cache->node_select_rules, domain_cache->num_rules);
    free(domain_cache);
}