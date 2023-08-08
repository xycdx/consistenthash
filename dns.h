#ifndef __DNS_H__
#define __DNS_H__

typedef int (*ip_found_cb)(char *, char *);

#include "domain_cache.h"
#include "http_dns_resolver.h"

int ERROR_CODE_OK = 0;
int ERROR_CODE_IP_NO_FOUND = -1;

long current_time();

void execute(char *url, int attempts, _bool_t httpDNS, ip_found_cb job);

char *get_cache_key(char *url);

#endif