
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

/* 当使用长连接与上游服务器通信时，可以通过该方法从连接池中获取一个新连接(主动连接) */
typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
    void *data);

/* 当使用长连接与上游服务器通信时，可以通过该方法将使用完的连接(主动连接)释放给连接池 */
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
#if (NGX_SSL)

typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
#endif


struct ngx_peer_connection_s {
    /*
     * 一个主动连接也需要ngx_connection_t结构体中的大部分成员，并且出于重用的考虑而
     * 定义了connection成员
     */
    ngx_connection_t                *connection;

    /* 远端服务器的socket地址和长度 */
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    /* 远端服务器的名称 */
    ngx_str_t                       *name;

    /* 表示在连接一个远端服务器时，当前连接出现异常失败后可以重试的次数 */
    ngx_uint_t                       tries;
    ngx_msec_t                       start_time;  // 连接开始处理的时间

    /* 当用长连接与远端服务器通信时，用get和free方法获取和释放主动连接对象 */
    ngx_event_get_peer_pt            get;
    ngx_event_free_peer_pt           free;
    void                            *data;

#if (NGX_SSL)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

    /* 本机地址信息 */
    ngx_addr_t                      *local;

    /* type表示套接字的类型，rcvbuf表示套接字接收缓冲区的大小 */
    int                              type;
    int                              rcvbuf;

    ngx_log_t                       *log;

    /* 为1时表示上面的connection连接已经缓存 */
    unsigned                         cached:1;

                                     /* ngx_connection_log_error_e */
    unsigned                         log_error:2;
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
