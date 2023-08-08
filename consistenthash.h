#ifndef __CONSISTENTHASH_H__
#define __CONSISTENTHASH_H__

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "murmurhasher.h"
#include "ngx_rbtree.h"
#include "ngx_port.h"

#define TRUE 1
#define FALSE 0
#define N_MAX_ID_LEN 512

typedef signed char _bool_t;

typedef struct consistenthash_t consistenthash_t;

struct consistenthash_t {
    int default_number_of_replicas; //默认副本数
    long count; //加入的ID数
    ngx_rbtree_t sorted_hash; //存储所有哈希值的红黑树
    ngx_rbtree_node_t sentinel;
};

consistenthash_t *consistenthash_create(int default_number_of_replicas);

void consistenthash_fin(consistenthash_t *consistenthash);

void add(consistenthash_t *consistenthash, char *elem, int number_of_replicas);

char **getN(consistenthash_t *consistenthash, char *name, int *n);

char *get(consistenthash_t *consistenthash, char *name);

#endif