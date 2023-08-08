#include <string.h>
#include "ngx_port.h"

ngx_int_t ngx_port_encode_base64url(char *dst, int len, char *src)
{
    if (len < (int)ngx_base64_encoded_length(strlen(src))) {
        return NGX_ERROR;
    }

    ngx_str_t ngx_str_dst = {.len = len, .data = (u_char *)dst};
    ngx_str_t ngx_str_src = {.len = strlen(src), .data = (u_char *)src};


    memset(dst, 0, len);
    ngx_encode_base64url(&ngx_str_dst, &ngx_str_src);
    dst[len-1]='\0';
    return NGX_OK;
}

ngx_int_t ngx_port_decode_base64url(char *dst, int len, char *src)
{
    if (len < (int)ngx_base64_decoded_length(strlen(src))) {
        return NGX_ERROR;
    }

    ngx_str_t ngx_str_dst = {.len = len, .data = (u_char *)dst};
    ngx_str_t ngx_str_src = {.len = strlen(src), .data = (u_char *)src};

    memset(dst, 0, len);
    ngx_int_t nret = ngx_decode_base64url(&ngx_str_dst, &ngx_str_src);
    dst[len-1]='\0';
    return nret;
}

ngx_int_t ngx_port_encode_base64(char *dst, int dst_len, char *src, int src_len)
{
    if (dst_len < ngx_base64_encoded_length(src_len)) {
        return NGX_ERROR;
    }

    ngx_str_t ngx_str_dst = {.len = dst_len, .data = (u_char *)dst};
    ngx_str_t ngx_str_src = {.len = src_len, .data = (u_char *)src};

    memset(dst, 0, dst_len);
    ngx_encode_base64(&ngx_str_dst, &ngx_str_src);
    dst[dst_len-1]='\0';
    return NGX_OK;
}

ngx_int_t ngx_port_decode_base64(char *dst, int dst_len, char *src, int src_len)
{
    if (dst_len < ngx_base64_decoded_length(src_len)) {
        return NGX_ERROR;
    }

    ngx_str_t ngx_str_dst = {.len = dst_len, .data = (u_char *)dst};
    ngx_str_t ngx_str_src = {.len = src_len, .data = (u_char *)src};

    memset(dst, 0, dst_len);
    ngx_int_t nret = ngx_decode_base64(&ngx_str_dst, &ngx_str_src);
    dst[dst_len-1]='\0';
    return nret;
}

void ngx_port_escape_uri(char *dst, int len, char *src)
{
    memset(dst, 0, len);
    ngx_escape_uri((u_char *)(dst), (u_char *)src, (size_t)strlen(src), NGX_ESCAPE_URI_COMPONENT);
    dst[len-1]='\0';
}

void ngx_port_rbtree_init(ngx_rbtree_t *tree, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_init(tree, sentinel, ngx_rbtree_insert_value);
}
