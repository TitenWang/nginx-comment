
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * TODO: autoconfigure NGX_SOCKADDRLEN and NGX_SOCKADDR_STRLEN as
 *       sizeof(struct sockaddr_storage)
 *       sizeof(struct sockaddr_un)
 *       sizeof(struct sockaddr_in6)
 *       sizeof(struct sockaddr_in)
 */

#define NGX_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)
#define NGX_INET6_ADDRSTRLEN                                                 \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define NGX_UNIX_ADDRSTRLEN                                                  \
    (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#if (NGX_HAVE_UNIX_DOMAIN)
#define NGX_SOCKADDR_STRLEN   (sizeof("unix:") - 1 + NGX_UNIX_ADDRSTRLEN)
#else
#define NGX_SOCKADDR_STRLEN   (NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
#define NGX_SOCKADDRLEN       sizeof(struct sockaddr_un)
#else
#define NGX_SOCKADDRLEN       512
#endif


typedef struct {
    in_addr_t                 addr;  // ip地址
    in_addr_t                 mask;  // 掩码
} ngx_in_cidr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr           addr;
    struct in6_addr           mask;
} ngx_in6_cidr_t;

#endif


typedef struct {
    ngx_uint_t                family;  // 协议族，ipv4、ipv6 
    union {
        ngx_in_cidr_t         in;
#if (NGX_HAVE_INET6)
        ngx_in6_cidr_t        in6;
#endif
    } u;
} ngx_cidr_t;


typedef struct {
    struct sockaddr          *sockaddr;  // ip地址信息
    socklen_t                 socklen;
    ngx_str_t                 name;  // ip地址对应的主机名
} ngx_addr_t;


typedef struct {
    ngx_str_t                 url;  // url对应的字符串
    ngx_str_t                 host;  // url对应的主机名
    ngx_str_t                 port_text;  //字符串形式的port
    ngx_str_t                 uri;

    in_port_t                 port;  // port信息
    in_port_t                 default_port;  // 默认的port
    int                       family;  // ip协议类型

    unsigned                  listen:1;
    unsigned                  uri_part:1;
    unsigned                  no_resolve:1;  // 不进行域名解析的标志位
    unsigned                  one_addr:1;  /* compatibility */

    unsigned                  no_port:1;  // url中是否带有port信息标志位
    unsigned                  wildcard:1;  //地址通配符标志位

    socklen_t                 socklen;  // socket地址信息长度
    u_char                    sockaddr[NGX_SOCKADDRLEN];  // socket地址信息

    ngx_addr_t               *addrs;  // url对应的ip地址信息组成的数组
    ngx_uint_t                naddrs;  // url对应的ip地址信息的个数

    char                     *err;
} ngx_url_t;


in_addr_t ngx_inet_addr(u_char *text, size_t len);
#if (NGX_HAVE_INET6)
ngx_int_t ngx_inet6_addr(u_char *p, size_t len, u_char *addr);
size_t ngx_inet6_ntop(u_char *p, u_char *text, size_t len);
#endif
size_t ngx_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text,
    size_t len, ngx_uint_t port);
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);
ngx_int_t ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr);
ngx_int_t ngx_parse_addr(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text,
    size_t len);
ngx_int_t ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
    struct sockaddr *sa2, socklen_t slen2, ngx_uint_t cmp_port);


#endif /* _NGX_INET_H_INCLUDED_ */
