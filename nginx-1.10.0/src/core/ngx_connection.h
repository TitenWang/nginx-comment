
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;  //socket套接字句柄

    struct sockaddr    *sockaddr;  //监听的sockaddr地址
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;  //字符串形式的ip地址的最大长度，指定了addr_text的内存大小
    ngx_str_t           addr_text;  //存储字符串形式的ip地址

    int                 type;  //套接字类型，如SOCK_STREAM表示tcp

    /*tcp实现监听时的backlog队列，它表示允许正在通过三次握手建立tcp连接但还没有任何进程开始处理的连接最大个数*/
    int                 backlog;
    /*内核中对于这个套接自的接受缓冲区的大小 发送缓冲区的大小*/
    int                 rcvbuf;
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;  //新的tcp连接成功建立了后的处理方法

    /*用于保存当前监听端口对应着的所有监听地址信息，每个监听地址(ip:port)包含着监听这个地址的所有server信息*/
    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    /*日志对象*/
    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;  //新的tcp连接的内存池大小
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;

    ngx_listening_t    *previous;  //存储的是老版本Nginx中和新版本Nginx监听同一个地址的监听对象
    ngx_connection_t   *connection;  //当前监听端口对应着的连接

    ngx_uint_t          worker;  // worker子进程的编号

    /*为1时表示当前监听句柄有效，且执行ngx_init_cycle时不关闭监听端口*/
    unsigned            open:1;
    /*
     * 为1时表示使用已有的ngx_cycle_t结构体来初始化新的ngx_cycle_t结构体时，不关闭原先打开的监听端口;
     * 为0时表示正常关闭曾经打开的监听端口
     */
    unsigned            remain:1;
    /*
     * 为1时表示跳过设置当前的ngx_listening_t结构体的套接字，为0时正常初始化套接字
     */
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    /*表示当前监听句柄是否来自前一个进程，如果为1，则表示来自前一个进程，一般会保留之前已经设置好的套接字，不做改变*/
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    /*为1时表示当前结构体对应的套接字已经监听*/
    unsigned            listen:1;
    /*表示套接字是否阻塞*/
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    /*为1时表示Nginx会将网络地址转变为字符串形式的地址*/
    unsigned            addr_ntop:1;
    unsigned            wildcard:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
#if (NGX_HAVE_REUSEPORT)
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02


struct ngx_connection_s {
    /*
     * 连接未使用时，data成员用于充当连接池中空闲连接链表的next指针，当连接被使用时，data成员由调用它的模块定义
     */
    void               *data;
    ngx_event_t        *read;  //连接对应的读事件
    ngx_event_t        *write; //连接对应的写事件

    ngx_socket_t        fd;  //该连接对应的套接字句柄

    ngx_recv_pt         recv;  //直接接收网络字节流的方法
    ngx_send_pt         send;  //直接发送网络字节流的方法
    ngx_recv_chain_pt   recv_chain;  //以ngx_chain_t链表为参数来接收网络字节流的方法
    ngx_send_chain_pt   send_chain;  //以ngx_chain_t链表为参数来发送网络字节流的方法

    ngx_listening_t    *listening; //这个连接对应的ngx_listening_t对象，此连接由listening监听端口的事件建立

    off_t               sent;  //连接上已经发送出去的字节数

    ngx_log_t          *log;

    ngx_pool_t         *pool; //这个内存池的大小由listening监听对象中的pool_size成员决定

    int                 type;  //连接类型

    struct sockaddr    *sockaddr;  //客户端的sockaddr结构体
    socklen_t           socklen;  //sockaddr结构体长度
    ngx_str_t           addr_text;  //字符串形式的客户端ip地址

    ngx_str_t           proxy_protocol_addr;

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

    /*本机监听端口对应的sockaddr结构体，也就是listening对象中的sockaddr成员*/
    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    /*用于接收、缓存客户端发来的字节流。每个事件消费模块可以自行决定从连接池中分配多大的空间给buffer*/
    ngx_buf_t          *buffer;

    /*用来将当前连接以双向链表的形式添加到ngx_cycle_t结构体的reusable_connections_queue双向链表中，表示可重用连接*/
    ngx_queue_t         queue;

    /*
     * 连接使用的次数。ngx_connection_t结构体每次建立一条来自客户端的连接,或者用于主动向后端服务器发起连接时，
     * number都会加1.
     */
    ngx_atomic_uint_t   number;

    ngx_uint_t          requests;  //处理的请求次数

    /*缓存中的业务类型*/
    unsigned            buffered:8;

    unsigned            log_error:3;  //日志级别    /* ngx_connection_log_error_e */

    unsigned            unexpected_eof:1;
    unsigned            timedout:1;  //为1表示连接已经超时
    unsigned            error:1;  //为1表示连接处理过程中出错
    unsigned            destroyed:1;

    unsigned            idle:1;  //为1表示处于空闲状态，如keepalive请求中两次请求之间的状态
    unsigned            reusable:1;  //为1表示可重用，表示可以被释放供新连接使用，和上述的queue字段配合使用
    unsigned            close:1;  //表示连接关闭
    unsigned            shared:1;

    unsigned            sendfile:1;  //为1时表示正将文件中的数据发往另一端
    
    /*
     * 为1时表示只有当连接套接字对应的发送缓冲区必须满足最低设置的大小阈值是，事件驱动模块才会分发该事件
     */
    unsigned            sndlowat:1;

    /*tcp连接的nodelay和nopush特性*/
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_conf_t *cf, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
