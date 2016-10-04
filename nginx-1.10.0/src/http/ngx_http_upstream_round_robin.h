
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_upstream_rr_peer_s   ngx_http_upstream_rr_peer_t;

/* 
 * 一个后端服务器对应的配置信息(如果一个后端服务器有多个ip地址，
 * 那么这个结构体对应的就是其中一个ip地址相关信息) 
 */
struct ngx_http_upstream_rr_peer_s {
    struct sockaddr                *sockaddr;  // ip和port信息
    socklen_t                       socklen;
    ngx_str_t                       name;
    ngx_str_t                       server;  // server服务器主机名

    ngx_int_t                       current_weight;  // 当前权重
    ngx_int_t                       effective_weight;  // 有效权重，会根据连接结果降低或者上升
    ngx_int_t                       weight;  // 从配置文件中获取的配置权重

    ngx_uint_t                      conns;  // 记录此后端服务器选中的次数

    ngx_uint_t                      fails;  // 在fail_timeout时间内失败的次数
    time_t                          accessed;
    time_t                          checked;  // 标志一个fail_timeout周期开始的时间

    ngx_uint_t                      max_fails;  // 配置文件中获取
    time_t                          fail_timeout;  // 配置文件中获取

    ngx_uint_t                      down;          /* unsigned  down:1; */

#if (NGX_HTTP_SSL)
    void                           *ssl_session;
    int                             ssl_session_len;
#endif

    /* 如果一个upstream块下有多个server配置项，则用next指针把这些server配置信息连接起来 */
    ngx_http_upstream_rr_peer_t    *next;

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_atomic_t                    lock;
#endif
};


typedef struct ngx_http_upstream_rr_peers_s  ngx_http_upstream_rr_peers_t;

struct ngx_http_upstream_rr_peers_s {
    /* 一个upstream块内所有非备份服务器的个数(以ip计数，而不是主机名，一个主机名可能有多个ip) */
    ngx_uint_t                      number;

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_slab_pool_t                *shpool;
    ngx_atomic_t                    rwlock;
    ngx_http_upstream_rr_peers_t   *zone_next;
#endif

    ngx_uint_t                      total_weight;  // 一个upsteam块内所有非备份服务器的总权重(以ip计数)

    unsigned                        single:1;  // 一个upstream块是否只有一个后端服务器的标志位
    unsigned                        weighted:1;  // 是否自定义了每个后端服务器的配置权重

    ngx_str_t                      *name;  // upstream指令后面跟的主机名

    ngx_http_upstream_rr_peers_t   *next;  //管理一个upstream块中所有备份服务器组成的列表

    /* 存储着一个upstream块内所有服务器组成的列表(备份和非备份服务器分开组织) */
    ngx_http_upstream_rr_peer_t    *peer;
};


#if (NGX_HTTP_UPSTREAM_ZONE)

#define ngx_http_upstream_rr_peers_rlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_rlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_wlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_unlock(peers)                              \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peers->rwlock);                                    \
    }


#define ngx_http_upstream_rr_peer_lock(peers, peer)                           \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peer->lock);                                        \
    }

#define ngx_http_upstream_rr_peer_unlock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peer->lock);                                       \
    }

#else

#define ngx_http_upstream_rr_peers_rlock(peers)
#define ngx_http_upstream_rr_peers_wlock(peers)
#define ngx_http_upstream_rr_peers_unlock(peers)
#define ngx_http_upstream_rr_peer_lock(peers, peer)
#define ngx_http_upstream_rr_peer_unlock(peers, peer)

#endif

/*
 * 存储主动连接本次使用的后端服务器、后端所有服务器组成的列表，以及指示所有后端服务器是否被选中过的
 * 位图。
 */
typedef struct {
    ngx_http_upstream_rr_peers_t   *peers;  // 管理后端服务器列表的对象
    ngx_http_upstream_rr_peer_t    *current;  // 当前所指向的后端服务器对象

    /* 
     * 指向表示后端服务器是否被选中的位图地址，如果后端服务器个数小于uintptr_t类型的位数，
     * 则指向data地址，否则按需申请
     */
    uintptr_t                      *tried;
    /* 如果后端服务器个数小于uintptr_t类型的位数，则用data来存放位图，此时tried指向data地址 */
    uintptr_t                       data;
} ngx_http_upstream_rr_peer_data_t;


ngx_int_t ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);
ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

#if (NGX_HTTP_SSL)
ngx_int_t
    ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif


#endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
