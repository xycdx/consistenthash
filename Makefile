CC = gcc

SOURCES = ngx_string.c ngx_port.c ngx_rbtree.c murmurhasher.c consistenthash.c cJSON/cJSON.c http_dns_resolver.c domain_cache.c dns.c
LIBRARIES = -lcurl -lcrypto -lm

my_program: $(SOURCES)
	$(CC) $(SOURCES) $(LIBRARIES) -g -o test_dns

clean:
	rm -f test_dns