#include "consistenthash.h"

static char *getKey(char *elem, int idx);
static void insert_into_rbtree(ngx_rbtree_t *tree, long key, char *elem);
static void delete_from_rbtree(ngx_rbtree_t *tree, long key);
static ngx_rbtree_node_t *find_next_on_circle(ngx_rbtree_t *tree, ngx_rbtree_node_t *sentinel, long key);

consistenthash_t *consistenthash_create(int default_number_of_replicas) {
    consistenthash_t *consistenthash = (consistenthash_t *)malloc(sizeof(consistenthash_t));
    consistenthash->default_number_of_replicas = default_number_of_replicas; 
    consistenthash->count = 0;

    memset(&consistenthash->sorted_hash, 0, sizeof(ngx_rbtree_t)); //初始化红黑树
    memset(&consistenthash->sentinel, 0, sizeof(ngx_rbtree_node_t));
    ngx_port_rbtree_init(&consistenthash->sorted_hash, &consistenthash->sentinel);
    return consistenthash;
}

void add(consistenthash_t *consistenthash, char *elem, int number_of_replicas) { //插入number_of_replicas个elem
    if(!number_of_replicas) {
        number_of_replicas = consistenthash->default_number_of_replicas;
    }
    int i;
    for(i = 0;i < number_of_replicas; i++) {
        char *key = getKey(elem, i);
        long hash_val = hash(key); //对于number_of_replicas个elem，在字符串elem前面拼接一个数字来做区分，
                                              //然后再计算拼接得到的字符串的哈希值
        insert_into_rbtree(&consistenthash->sorted_hash, hash_val, elem); //更新红黑树
        free(key);
    }
    consistenthash->count++;
}

static char *getKey(char *elem, int idx) { //将idx转为字符串后拼接到elem前面
    char* result = (char *)malloc(N_MAX_ID_LEN);
    sprintf(result, "%d", idx);
    strcat(result, elem);
    return result;
}

void consistenthash_fin(consistenthash_t *consistenthash) {
    while(consistenthash->sorted_hash.root != &consistenthash->sentinel) {
        ngx_rbtree_node_t *root = consistenthash->sorted_hash.root;
        ngx_rbtree_delete(&consistenthash->sorted_hash, consistenthash->sorted_hash.root);
        free(root);
    }
    free(consistenthash);
}

char *get(consistenthash_t *consistenthash, char *name) { //传入cacheKey，在哈希环上顺时针方向找到最近的elem
    if(!consistenthash->count) { //判空
        return NULL;
    }
    return find_next_on_circle(&consistenthash->sorted_hash, &consistenthash->sentinel, hash(name))->data;
}

char **getN(consistenthash_t *consistenthash, char *name, int *n) {
    if(n <= 0) {
        return NULL;
    }
    if(consistenthash->count < *n) {
        *n = consistenthash->count;
    }
    char **res = (char **)malloc(sizeof(char *) * (*n));

    int cnt = 0;
    long key = hash(name);
    ngx_rbtree_node_t *next_node = find_next_on_circle(&consistenthash->sorted_hash, &consistenthash->sentinel, hash(name));
    long start = next_node->key;
    while(TRUE) {
        res[cnt++] = next_node->data;
        if(cnt == *n) {
            break;
        }
        next_node = find_next_on_circle(&consistenthash->sorted_hash, &consistenthash->sentinel, start);
        start = next_node->key;
    }
    return res;
}

static void insert_into_rbtree(ngx_rbtree_t *tree, long key, char *elem) {
    ngx_rbtree_node_t *node = (ngx_rbtree_node_t *)malloc(sizeof(ngx_rbtree_node_t));
    node->key = key;
    strcpy(node->data, elem);
    ngx_rbtree_insert(tree, node);
}

static void delete_from_rbtree(ngx_rbtree_t *tree, long key) {
    ngx_rbtree_node_t *node = (ngx_rbtree_node_t *)malloc(sizeof(ngx_rbtree_node_t));
    node->key = key;
    ngx_rbtree_delete(tree, node);
    free(node);
    node = NULL;
}

static ngx_rbtree_node_t *find_next_on_circle(ngx_rbtree_t *tree, ngx_rbtree_node_t *sentinel, long key) { //在哈希环上顺时针方向距离key找到最近的elem
    ngx_rbtree_node_t *tmp = ngx_rbtree_next(tree->root, sentinel, key); //先在红黑树里找一次
    if(tmp == NULL) {                                    //若tmp == NULL，说明key大于环上所有的哈希值，从头开始找
        tmp = ngx_rbtree_next(tree->root, sentinel, -1); //哈希值可能为0，所以找-1的后继，就是最小的哈希值
    }
    return tmp;
}

// int main() {
//     while(1) {
//         sleep(1);
//         consistenthash_t *consistenthash = consistenthash_create(100);
    
//         add(consistenthash, "abc", 100000);
//         add(consistenthash, "cde", 105000);
//         add(consistenthash, "def", 200000);

//         // print_tree(consistenthash.sorted_hash.root, &consistenthash.sentinel);
//         int cnt[6] = {0};
//         for(int i = 0; i < 20000; i++) {
//             char *key = "qaq";
//             char *res = get(consistenthash, key);
//             if(strcmp("abc", res) == 0) {
//                 cnt[0]++;
//             } else if(strcmp("cde", res) == 0) {
//                 cnt[1]++;
//             } else if(strcmp("def", res) == 0) {
//                 cnt[2]++;
//             } else if(strcmp("dqa", res) == 0) {
//                 cnt[3]++;
//             } else if(strcmp("sfv", res) == 0) {
//                 cnt[4]++;
//             } else if(strcmp("kmj", res) == 0) {
//                 cnt[5]++;
//             }
//         }
//         printf("%d %d %d %d %d %d\n", 
//                 cnt[0], cnt[1], cnt[2], cnt[3], cnt[4], cnt[5]);
//         consistenthash_fin(consistenthash);
//     }
// }