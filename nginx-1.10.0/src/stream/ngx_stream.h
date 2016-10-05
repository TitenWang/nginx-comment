
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_H_INCLUDED_
#define _NGX_STREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_STREAM_SSL)
#include <ngx_stream_ssl_module.h>
#endif


typedef struct ngx_stream_session_s  ngx_stream_session_t;


#include <ngx_stream_upstream.h>
#include <ngx_stream_upstream_round_robin.h>

/* stream{}块下存储所有stream模块的配置项结构体的上下文 */
typedef struct {
    void                  **main_conf;  // 存储所有stream模块生成的main级别配置项结构体指针数组
    void                  **srv_conf;  // 存储所有stream模块生成的srv级别配置项结构体的指针数组
} ngx_stream_conf_ctx_t;

/* 存储listen配置指令的参数 */
typedef struct {
    union {
        struct sockaddr     sockaddr;
        struct sockaddr_in  sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6 sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un  sockaddr_un;
#endif
        u_char              sockaddr_data[NGX_SOCKADDRLEN];
    } u;  // listen指令跟的socket地址信息

    socklen_t               socklen;

    /* server ctx */
    ngx_stream_conf_ctx_t  *ctx;  // 存储解析server块时生成的配置项上下文

    unsigned                bind:1;  // bind参数是否配置的标志位
    unsigned                wildcard:1;  // listen指令监听的ip:port是否存在通配符的标志位
#if (NGX_STREAM_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:1;
#endif
#if (NGX_HAVE_REUSEPORT)
    unsigned                reuseport:1;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
    int                     backlog;  // 监听套接口的队列长度
    int                     type;  // listen监听的socket类型
} ngx_stream_listen_t;


typedef struct {
    ngx_stream_conf_ctx_t  *ctx;  // 存储解析server块时生成的配置项上下文
    ngx_str_t               addr_text;
#if (NGX_STREAM_SSL)
    ngx_uint_t              ssl;    /* unsigned   ssl:1; */
#endif
} ngx_stream_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_stream_addr_conf_t  conf;  // 该地址信息对应的server块配置信息，用于后续寻找到server块
} ngx_stream_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    ngx_stream_addr_conf_t  conf;
} ngx_stream_in6_addr_t;

#endif

/* 该结构体在服务运行过程中使用 */
typedef struct {
    /* ngx_stream_in_addr_t or ngx_stream_in6_addr_t */
    void                   *addrs;  // 存放地址的指针数组
    ngx_uint_t              naddrs;  // 指针数组的长度
} ngx_stream_port_t;

/* 该结构体用于解析配置文件的时候使用 */
typedef struct {
    int                     family;  // 协议族
    int                     type;  // socket类型
    in_port_t               port;  // 端口号
    /* 存放监听该端口的所有地址信息 */
    ngx_array_t             addrs;       /* array of ngx_stream_conf_addr_t */
} ngx_stream_conf_port_t;


typedef struct {
    ngx_stream_listen_t     opt;  // ip地址对应的listen命令的信息
} ngx_stream_conf_addr_t;


typedef ngx_int_t (*ngx_stream_access_pt)(ngx_stream_session_t *s);

/* ngx_stream_core_module模块main级别的配置项结构体 */
typedef struct {
    /*
     * servers动态数组存放的是代表出现在stream块内的server块的配置项结构体，
     * 在ngx_stream_core_server函数中会将生成的ngx_stream_core_module模块的srv级别
     * 配置项结构体添加到这个动态数组中。
     */
    ngx_array_t             servers;     /* ngx_stream_core_srv_conf_t */

    /* 存放的是stream块内所有server块内出现的listen指令的参数，一个listen对应其中的一个元素 */
    ngx_array_t             listen;      /* ngx_stream_listen_t */
    ngx_stream_access_pt    limit_conn_handler;  // stream limit conn模块注册的处理函数
    ngx_stream_access_pt    access_handler;  // stream access模块注册的处理函数
} ngx_stream_core_main_conf_t;


typedef void (*ngx_stream_handler_pt)(ngx_stream_session_t *s);

/* ngx_stream_core_module模块srv级别的配置项结构体 */
typedef struct {
    ngx_stream_handler_pt   handler;  // 调用这个模块进行后续处理
    ngx_stream_conf_ctx_t  *ctx;  // 存储解析server块时生成的配置项上下文
    u_char                 *file_name;  // 指向配置文件的名字
    ngx_int_t               line;
    ngx_log_t              *error_log;  // 存储error_log指令的参数
    ngx_flag_t              tcp_nodelay;  // 存储tcp_nodelay指令的参数
} ngx_stream_core_srv_conf_t;


struct ngx_stream_session_s {
    uint32_t                signature;         /* "STRM" */

    ngx_connection_t       *connection;  // 客户端与Nginx之间的连接对象

    off_t                   received;  // 已接收的来自客户端接的数据长度

    ngx_log_handler_pt      log_handler;

    void                  **ctx;  // 模块上下文
    void                  **main_conf;  // stream块中所有stream模块生成的配置项结构体数组
    void                  **srv_conf;  // 请求匹配的server块中所有stream模块生成的配置项结构体数组

    ngx_stream_upstream_t  *upstream;  // upstream对象
};


typedef struct {
    /* 解析完stream块内的所有配置项之后回调 */
    ngx_int_t             (*postconfiguration)(ngx_conf_t *cf);

    /*
     * 创建用于存储stream模块的main级别配置项的结构体
     */
    void                 *(*create_main_conf)(ngx_conf_t *cf);
    /* 解析完main级别配置项之后回调 */
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    /* 创建用于存储stream模块srv级别配置项的结构体 */
    void                 *(*create_srv_conf)(ngx_conf_t *cf);
    /*
     * create_srv_conf创建的结构体所要存储的配置项可能同时出现在main、srv中。
     * merge_srv_conf方法可以把出现在main级别中的配置项值合并到srv级别配置项中
     */
    char                 *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                            void *conf);
} ngx_stream_module_t;


#define NGX_STREAM_MODULE       0x4d525453     /* "STRM" */

#define NGX_STREAM_MAIN_CONF    0x02000000
#define NGX_STREAM_SRV_CONF     0x04000000
#define NGX_STREAM_UPS_CONF     0x08000000


#define NGX_STREAM_MAIN_CONF_OFFSET  offsetof(ngx_stream_conf_ctx_t, main_conf)
#define NGX_STREAM_SRV_CONF_OFFSET   offsetof(ngx_stream_conf_ctx_t, srv_conf)


#define ngx_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define ngx_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define ngx_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define ngx_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

#define ngx_stream_conf_get_module_main_conf(cf, module)                       \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_stream_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define ngx_stream_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[ngx_stream_module.index] ?                                \
        ((ngx_stream_conf_ctx_t *) cycle->conf_ctx[ngx_stream_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)


void ngx_stream_init_connection(ngx_connection_t *c);
void ngx_stream_close_connection(ngx_connection_t *c);


extern ngx_module_t  ngx_stream_module;
extern ngx_uint_t    ngx_stream_max_module;
extern ngx_module_t  ngx_stream_core_module;


#endif /* _NGX_STREAM_H_INCLUDED_ */
