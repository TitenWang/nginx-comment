
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_UPSTREAM_H_INCLUDED_
#define _NGX_STREAM_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event_connect.h>


#define NGX_STREAM_UPSTREAM_CREATE        0x0001
#define NGX_STREAM_UPSTREAM_WEIGHT        0x0002
#define NGX_STREAM_UPSTREAM_MAX_FAILS     0x0004
#define NGX_STREAM_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_STREAM_UPSTREAM_DOWN          0x0010
#define NGX_STREAM_UPSTREAM_BACKUP        0x0020


typedef struct {
    /* 存放的是stream块内出现的所有upstream块的配置信息，动态数组的一个元素对应一个upstream块信息 */
    ngx_array_t                        upstreams;
                                           /* ngx_stream_upstream_srv_conf_t */
} ngx_stream_upstream_main_conf_t;


typedef struct ngx_stream_upstream_srv_conf_s  ngx_stream_upstream_srv_conf_t;


typedef ngx_int_t (*ngx_stream_upstream_init_pt)(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_stream_upstream_init_peer_pt)(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);

/* upstream块内的后端服务器列表以及初始化upstream的方法 */
typedef struct {

    /*
     * 如果使用默认的加权轮询算法，则该函数为ngx_stream_upstream_init_round_robin()，该函数
     * 用于构造后端服务器组成的链表，并挂载到下面的data字段。该函数在解析完stream块下的main
     * 级别配置项之后调用
     */
    ngx_stream_upstream_init_pt        init_upstream;

    /*
     * 如果使用默认的加权轮询算法，则该函数为ngx_stream_upstream_init_round_robin_peer()，
     * 该函数会设置get和free方法，除此之外，也会将下面data字段挂载的后端服务器列表设置到
     * s->upstream->peer.data上。该函数在构造发送往上游服务器的请求时调用.
     */
    ngx_stream_upstream_init_peer_pt   init;

    /* 挂载着后端服务器组成的列表，见ngx_stream_upstream_init_round_robin() */
    void                              *data;
} ngx_stream_upstream_peer_t;

/* 存储upstream块内的server配置指令参数 */
typedef struct {
    ngx_str_t                          name;  // server指令后面跟的主机名字
    ngx_addr_t                        *addrs;  // 一个主机名可能对应多个ip地址，存储多个ip地址的指针数组
    ngx_uint_t                         naddrs;
    ngx_uint_t                         weight;  // 配置的权重值
    ngx_uint_t                         max_fails;  // 在fail_timeout时间内可以失败的最大次数
    time_t                             fail_timeout;

    unsigned                           down:1;  // 服务器是否宕机的标志
    unsigned                           backup:1;  // 服务器是否是备份服务器的标志
} ngx_stream_upstream_server_t;

/* 代表一个upstream块的配置信息结构体 */
struct ngx_stream_upstream_srv_conf_s {
    ngx_stream_upstream_peer_t         peer;  // upstream块内的后端服务器列表以及初始化upstream的方法
    void                             **srv_conf;  // upstream块内所有stream模块生成的配置项结构体指针数组

    ngx_array_t                       *servers;  // upstream块内所有server配置指令信息组成的动态数组
                                              /* ngx_stream_upstream_server_t */

    ngx_uint_t                         flags;  // upstream块内支持出现的功能参数，如backup、fail_timeout等
    ngx_str_t                          host;  // upstream指令后面跟的host名字
    u_char                            *file_name;
    ngx_uint_t                         line;
    in_port_t                          port;
    ngx_uint_t                         no_port;  /* unsigned no_port:1 */

#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_shm_zone_t                    *shm_zone;
#endif
};


typedef struct {
    ngx_peer_connection_t              peer;  // 与后端服务器之间的连接对象
    ngx_buf_t                          downstream_buf;
    ngx_buf_t                          upstream_buf;
    off_t                              received;
    time_t                             start_sec;
    ngx_uint_t                         responses;
#if (NGX_STREAM_SSL)
    ngx_str_t                          ssl_name;
#endif
    unsigned                           connected:1;
    unsigned                           proxy_protocol:1;
} ngx_stream_upstream_t;


ngx_stream_upstream_srv_conf_t *ngx_stream_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);


#define ngx_stream_conf_upstream_srv_conf(uscf, module)                       \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t  ngx_stream_upstream_module;


#endif /* _NGX_STREAM_UPSTREAM_H_INCLUDED_ */
