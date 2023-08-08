#ifndef __NGX_PORT_H__
#define __NGX_PORT_H__

#include "ngx_string.h"
#include "ngx_rbtree.h"

ngx_int_t ngx_port_encode_base64url(char *dst, int len, char *src);
ngx_int_t ngx_port_decode_base64url(char *dst, int len, char *src);

ngx_int_t ngx_port_encode_base64(char *dst, int dst_len, char *src, int src_len);
ngx_int_t ngx_port_decode_base64(char *dst, int dst_len, char *src, int src_len);

void ngx_port_escape_uri(char *dst, int len, char *src);

void ngx_port_rbtree_init(ngx_rbtree_t *tree, ngx_rbtree_node_t *sentinel);

#endif
