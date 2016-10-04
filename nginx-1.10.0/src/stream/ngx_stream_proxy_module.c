
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       timeout;
    ngx_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    size_t                           upload_rate;
    size_t                           download_rate;
    ngx_uint_t                       responses;
    ngx_uint_t                       next_upstream_tries;
    ngx_flag_t                       next_upstream;
    ngx_flag_t                       proxy_protocol;
    ngx_addr_t                      *local;

#if (NGX_STREAM_SSL)
    ngx_flag_t                       ssl_enable;
    ngx_flag_t                       ssl_session_reuse;
    ngx_uint_t                       ssl_protocols;
    ngx_str_t                        ssl_ciphers;
    ngx_str_t                        ssl_name;
    ngx_flag_t                       ssl_server_name;

    ngx_flag_t                       ssl_verify;
    ngx_uint_t                       ssl_verify_depth;
    ngx_str_t                        ssl_trusted_certificate;
    ngx_str_t                        ssl_crl;
    ngx_str_t                        ssl_certificate;
    ngx_str_t                        ssl_certificate_key;
    ngx_array_t                     *ssl_passwords;

    ngx_ssl_t                       *ssl;
#endif

    /* 与本次proxy流程相关upstream对象，也就是proxy_pass指定的upstream */
    ngx_stream_upstream_srv_conf_t  *upstream;
} ngx_stream_proxy_srv_conf_t;


static void ngx_stream_proxy_handler(ngx_stream_session_t *s);
static void ngx_stream_proxy_connect(ngx_stream_session_t *s);
static void ngx_stream_proxy_init_upstream(ngx_stream_session_t *s);
static void ngx_stream_proxy_upstream_handler(ngx_event_t *ev);
static void ngx_stream_proxy_downstream_handler(ngx_event_t *ev);
static void ngx_stream_proxy_process_connection(ngx_event_t *ev,
    ngx_uint_t from_upstream);
static void ngx_stream_proxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_proxy_test_connect(ngx_connection_t *c);
static void ngx_stream_proxy_process(ngx_stream_session_t *s,
    ngx_uint_t from_upstream, ngx_uint_t do_write);
static void ngx_stream_proxy_next_upstream(ngx_stream_session_t *s);
static void ngx_stream_proxy_finalize(ngx_stream_session_t *s, ngx_int_t rc);
static u_char *ngx_stream_proxy_log_error(ngx_log_t *log, u_char *buf,
    size_t len);

static void *ngx_stream_proxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_stream_proxy_send_proxy_protocol(ngx_stream_session_t *s);

#if (NGX_STREAM_SSL)

static char *ngx_stream_proxy_ssl_password_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s);
static void ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc);
static ngx_int_t ngx_stream_proxy_ssl_name(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_proxy_set_ssl(ngx_conf_t *cf,
    ngx_stream_proxy_srv_conf_t *pscf);


static ngx_conf_bitmask_t  ngx_stream_proxy_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_null_string, 0 }
};

#endif


static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_downstream_buffer = {
    ngx_conf_deprecated, "proxy_downstream_buffer", "proxy_buffer_size"
};

static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_upstream_buffer = {
    ngx_conf_deprecated, "proxy_upstream_buffer", "proxy_buffer_size"
};


static ngx_command_t  ngx_stream_proxy_commands[] = {

    { ngx_string("proxy_pass"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_proxy_pass,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_bind"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_proxy_bind,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("proxy_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, timeout),
      NULL },

    { ngx_string("proxy_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_downstream_buffer"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      &ngx_conf_deprecated_proxy_downstream_buffer },

    { ngx_string("proxy_upstream_buffer"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      &ngx_conf_deprecated_proxy_upstream_buffer },

    { ngx_string("proxy_upload_rate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, upload_rate),
      NULL },

    { ngx_string("proxy_download_rate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, download_rate),
      NULL },

    { ngx_string("proxy_responses"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, responses),
      NULL },

    { ngx_string("proxy_next_upstream"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream),
      NULL },

    { ngx_string("proxy_next_upstream_tries"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream_tries),
      NULL },

    { ngx_string("proxy_next_upstream_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream_timeout),
      NULL },

    { ngx_string("proxy_protocol"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, proxy_protocol),
      NULL },

#if (NGX_STREAM_SSL)

    { ngx_string("proxy_ssl"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_enable),
      NULL },

    { ngx_string("proxy_ssl_session_reuse"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_session_reuse),
      NULL },

    { ngx_string("proxy_ssl_protocols"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_protocols),
      &ngx_stream_proxy_ssl_protocols },

    { ngx_string("proxy_ssl_ciphers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("proxy_ssl_name"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_name),
      NULL },

    { ngx_string("proxy_ssl_server_name"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_server_name),
      NULL },

    { ngx_string("proxy_ssl_verify"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_verify),
      NULL },

    { ngx_string("proxy_ssl_verify_depth"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("proxy_ssl_trusted_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("proxy_ssl_crl"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_crl),
      NULL },

    { ngx_string("proxy_ssl_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_certificate),
      NULL },

    { ngx_string("proxy_ssl_certificate_key"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_certificate_key),
      NULL },

    { ngx_string("proxy_ssl_password_file"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_proxy_ssl_password_file,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

#endif

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_proxy_module_ctx = {
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_proxy_create_srv_conf,      /* create server configuration */
    ngx_stream_proxy_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_stream_proxy_module = {
    NGX_MODULE_V1,
    &ngx_stream_proxy_module_ctx,          /* module context */
    ngx_stream_proxy_commands,             /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_stream_proxy_handler(ngx_stream_session_t *s)
{
    u_char                          *p;
    ngx_connection_t                *c;
    ngx_stream_upstream_t           *u;
    ngx_stream_proxy_srv_conf_t     *pscf;
    ngx_stream_upstream_srv_conf_t  *uscf;

    c = s->connection;

    /* 获取ngx_stream_proxy_module模块srv级别的配置项 */
    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy connection handler");

    /* 创建upstream对象 */
    u = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_t));
    if (u == NULL) {
        ngx_stream_proxy_finalize(s, NGX_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = ngx_stream_proxy_log_error;

    u->peer.log = c->log;
    u->peer.log_error = NGX_ERROR_ERR;

    /* 用于与后端服务器建链的本机地址信息 */
    u->peer.local = pscf->local;

    /* 设置连接类型，与客户端和nginx之间的连接类型一样 */
    u->peer.type = c->type;

    /* pscf->upstream在解析proxy_pass命令时创建 */
    uscf = pscf->upstream;

    /* 调用初始化负载均衡的函数 */
    if (uscf->peer.init(s, uscf) != NGX_OK) {
        ngx_stream_proxy_finalize(s, NGX_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    /* 转储ngx_stream_proxy_module模块srv级别的proxy_protocol指令标志 */
    u->proxy_protocol = pscf->proxy_protocol;
    u->start_sec = ngx_time();

    /* 设置客户端与nginx连接之间的读写事件回调函数 */
    c->write->handler = ngx_stream_proxy_downstream_handler;
    c->read->handler = ngx_stream_proxy_downstream_handler;

    /* 如果客户端与nginx之间是udp连接，则直接调用ngx_stream_proxy_connect去连接后端服务器 */
    if (c->type == SOCK_DGRAM) {
        ngx_stream_proxy_connect(s);
        return;
    }

    /* 申请大小为buffer_size的内存 */
    p = ngx_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL) {
        ngx_stream_proxy_finalize(s, NGX_ERROR);
        return;
    }

    /*
     * 用缓冲区对象u->downstream_buf来管理这个内存，这个内存是用来存放客户端发给nginx的数据，
     * nginx会从这里获取数据然后发送给后端服务器。
     */
    u->downstream_buf.start = p;
    u->downstream_buf.end = p + pscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    /* 如果配置文件中配置了proxy_protocol指令，则u->proxy_protocol为1 */
    if (u->proxy_protocol
#if (NGX_STREAM_SSL)
        && pscf->ssl == NULL
#endif
        && pscf->buffer_size >= NGX_PROXY_PROTOCOL_MAX_HEADER)
    {
        /* optimization for a typical case */

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy send PROXY protocol header");

        /* 往u->downstream_buf管理的内存写入proxy_protocol协议信息 */
        p = ngx_proxy_protocol_write(c, u->downstream_buf.last,
                                     u->downstream_buf.end);
        if (p == NULL) {
            ngx_stream_proxy_finalize(s, NGX_ERROR);
            return;
        }

        u->downstream_buf.last = p;
        u->proxy_protocol = 0;  // proxy_protocol协议头发送一个就可以了，这里将标志位清零
    }

    /* 如果客户端与nginx之间连接的读事件就绪了，就把读事件加入到ngx_posted_events，延后执行 */
    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    /* 与后端服务器建立连接 */
    ngx_stream_proxy_connect(s);
}

/* 与后端服务器建立连接 */
static void
ngx_stream_proxy_connect(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    /* 这里的连接对象是指客户端与nginx之间的连接 */
    c = s->connection;

    c->log->action = "connecting to upstream";

    u = s->upstream;

    /* 调用socket、connect与后端服务器建立连接 */
    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_stream_proxy_finalize(s, NGX_ERROR);
        return;
    }

    /* 如果返回NGX_BUSY，表示暂时没有合适的后端服务器 */
    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "no live upstreams");
        ngx_stream_proxy_finalize(s, NGX_DECLINED);
        return;
    }

    /* 如果返回NGX_DECLINED，则选择下一个后端服务器 */
    if (rc == NGX_DECLINED) {
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */

    /* pc指的是nginx与后端服务器之间的连接对象 */
    pc = u->peer.connection;

    /* 连接对象的data字段设置为ngx_stream_session_t对象 */
    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NGX_AGAIN) {
        ngx_stream_proxy_init_upstream(s);
        return;
    }

    /*
     * ngx_event_connect_peer()函数返回NGX_AGAIN，表示nginx与后端服务器暂时没有建链成功，
     * 等后端服务器accept之后连接的可写事件就会就绪。
     */

    /* 设置nginx与后端服务器连接的读写事件回调函数 */
    pc->read->handler = ngx_stream_proxy_connect_handler;
    pc->write->handler = ngx_stream_proxy_connect_handler;

    /* 将写事件加入到定时器中，因为nginx与后端服务器建立连接也是有时间限制的 */
    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    ngx_add_timer(pc->write, pscf->connect_timeout);
}


static void
ngx_stream_proxy_init_upstream(ngx_stream_session_t *s)
{
    int                           tcp_nodelay;
    u_char                       *p;
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    /* 如果nginx与后端服务器之间是tcp连接，则需要设置TCP_NODELAY选项 */
    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && pc->tcp_nodelay == NGX_TCP_NODELAY_UNSET)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "tcp_nodelay");

        tcp_nodelay = 1;

        if (setsockopt(pc->fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
            ngx_connection_error(pc, ngx_socket_errno,
                                 "setsockopt(TCP_NODELAY) failed");
            ngx_stream_proxy_next_upstream(s);
            return;
        }

        pc->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }

    /* u->proxy_protocol为1表示配置文件中配置了proxy_protocol命令 */
    if (u->proxy_protocol) {
        /* 向后端服务器发送proxy_protocol协议的头部信息 */
        if (ngx_stream_proxy_send_proxy_protocol(s) != NGX_OK) {
            return;
        }

        u->proxy_protocol = 0;  // proxy_protocol协议头发送一次就可以了，这里将标志位清零
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

#if (NGX_STREAM_SSL)
    if (pc->type == SOCK_STREAM && pscf->ssl && pc->ssl == NULL) {
        ngx_stream_proxy_ssl_init_connection(s);
        return;
    }
#endif

    c = s->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    c->log->action = "proxying connection";

    /* 申请内存，然后用缓冲区对象u->upstream_buf进行管理
     * u->upstream_buf存储后端服务器发给nginx的响应，nginx会从这里获取数据然后发送给客户端 
     */
    if (u->upstream_buf.start == NULL) {
        p = ngx_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            ngx_stream_proxy_finalize(s, NGX_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    /* 如果客户端与nginx之间的连接是udp连接 */
    if (c->type == SOCK_DGRAM) {
        s->received = c->buffer->last - c->buffer->pos;
        u->downstream_buf = *c->buffer;

        if (pscf->responses == 0) {
            pc->read->ready = 0;
            pc->read->eof = 1;
        }
    }

    /* 将connectd置位，表示nginx与上游服务器建链成功 */
    u->connected = 1;

    /* 设置nginx与后端服务器之间的连接对应的读写事件回调函数 */
    pc->read->handler = ngx_stream_proxy_upstream_handler;
    pc->write->handler = ngx_stream_proxy_upstream_handler;

    /*
     * 如果设置nginx与后端服务器之间连接读事件就绪了，也就是接受到了后端服务器发来的数据，那么
     * 先将其加入到队列ngx_posted_events，后续会进行处理。
     */
    if (pc->read->ready || pc->read->eof) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    ngx_stream_proxy_process(s, 0, 1);
}

/* 向后端服务器发送proxy_protocol协议的头部信息 */
static ngx_int_t
ngx_stream_proxy_send_proxy_protocol(ngx_stream_session_t *s)
{
    u_char                       *p;
    ssize_t                       n, size;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;
    u_char                        buf[NGX_PROXY_PROTOCOL_MAX_HEADER];

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy send PROXY protocol header");

    /* 往buf里面写入proxy_protocol协议的信息 */
    p = ngx_proxy_protocol_write(c, buf, buf + NGX_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
        ngx_stream_proxy_finalize(s, NGX_ERROR);
        return NGX_ERROR;
    }

    u = s->upstream;

    /* 获取nginx与后端服务器之间的连接 */
    pc = u->peer.connection;

    size = p - buf;

    /* 往后端服务器发送proxy_protocol协议的信息 */
    n = pc->send(pc, buf, size);

    if (n == NGX_AGAIN) {
        if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_ERROR);
            return NGX_ERROR;
        }

        pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

        ngx_add_timer(pc->write, pscf->timeout);

        /*
         * 将nginx与后台服务器连接写事件回调函数设置为ngx_stream_proxy_connect_handler()
         * 后续在这个函数中会再次调用ngx_stream_proxy_init_upstream初始化upstream。
         */
        pc->write->handler = ngx_stream_proxy_connect_handler;

        return NGX_AGAIN;
    }

    if (n == NGX_ERROR) {
        ngx_stream_proxy_finalize(s, NGX_DECLINED);
        return NGX_ERROR;
    }

    if (n != size) {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "could not send PROXY protocol header at once");

        ngx_stream_proxy_finalize(s, NGX_DECLINED);

        return NGX_ERROR;
    }

    return NGX_OK;
}


#if (NGX_STREAM_SSL)

static char *
ngx_stream_proxy_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_str_t  *value;

    if (pscf->ssl_passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    pscf->ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (pscf->ssl_passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void
ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_connection_t             *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    pc = u->peer.connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (ngx_ssl_create_connection(pscf->ssl, pc, NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_stream_proxy_finalize(s, NGX_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify) {
        if (ngx_stream_proxy_ssl_name(s) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_ERROR);
            return;
        }
    }

    if (pscf->ssl_session_reuse) {
        if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_ERROR);
            return;
        }
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = ngx_ssl_handshake(pc);

    if (rc == NGX_AGAIN) {

        if (!pc->write->timer_set) {
            ngx_add_timer(pc->write, pscf->connect_timeout);
        }

        pc->ssl->handler = ngx_stream_proxy_ssl_handshake;
        return;
    }

    ngx_stream_proxy_ssl_handshake(pc);
}


static void
ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc)
{
    long                          rc;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    s = pc->data;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (pc->ssl->handshaked) {

        if (pscf->ssl_verify) {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            u = s->upstream;

            if (ngx_ssl_check_host(pc, &u->ssl_name) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (pscf->ssl_session_reuse) {
            u = s->upstream;
            u->peer.save_session(&u->peer, u->peer.data);
        }

        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        ngx_stream_proxy_init_upstream(s);

        return;
    }

failed:

    ngx_stream_proxy_next_upstream(s);
}


static ngx_int_t
ngx_stream_proxy_ssl_name(ngx_stream_session_t *s)
{
    u_char                       *p, *last;
    ngx_str_t                     name;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    u = s->upstream;

    name = pscf->ssl_name;

    if (name.len == 0) {
        name = pscf->upstream->host;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, strip it for compatibility
     * with the http module
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = ngx_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = ngx_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!pscf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = ngx_pnalloc(s->connection->pool, name.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection, name.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_ERR, s->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NGX_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return NGX_OK;
}

#endif

/* nginx与客户端之间的连接对应的读写事件回调函数 */
static void
ngx_stream_proxy_downstream_handler(ngx_event_t *ev)
{
    /*
     * nginx与客户端之间的连接写事件发生的时候，ev->write为1，
     * 这个时候nginx需要从上游服务器读取数据然后发送给客户端。
     * 如果是读事件发生，则ev->write为0
     */
    ngx_stream_proxy_process_connection(ev, ev->write);
}

/* nginx与后端服务器之间的连接对应的读写事件回调函数 */
static void
ngx_stream_proxy_upstream_handler(ngx_event_t *ev)
{
    /*
     * nginx与后端服务器之间连接写事件发生的时候，ev->write为1，
     * 这个时候nginx需要从客户端读取数据，然后发送给上游服务器。
     * 如果是读事件发生，那么ev->write为0
     */
    ngx_stream_proxy_process_connection(ev, !ev->write);
}


static void
ngx_stream_proxy_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    /* c是nginx与客户端之间的连接，pc是nginx与后端服务器之间的连接 */
    c = s->connection;
    pc = u->peer.connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    /*
     * ev->timedout为1表示超时了，这个时候需要进一步判断是不是限速引起的超时，如果是限速
     * 引起的超时，那么不应该结束请求，而应该将事件加入到epoll中，继续调度
     */
    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {  // ev->delayed为1表明是限速引起的超时
            ev->delayed = 0;

            /* 如果事件还没有就绪，那么就将事件加入到epoll中 */
            if (!ev->ready) {
                if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                    ngx_stream_proxy_finalize(s, NGX_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    ngx_add_timer(c->write, pscf->timeout);
                }

                return;
            }

        } else {
            if (s->connection->type == SOCK_DGRAM) {
                if (pscf->responses == NGX_MAX_INT32_VALUE) {

                    /*
                     * successfully terminate timed out UDP session
                     * with unspecified number of responses
                     */

                    pc->read->ready = 0;
                    pc->read->eof = 1;

                    ngx_stream_proxy_process(s, 1, 0);
                    return;
                }

                if (u->received == 0) {
                    ngx_stream_proxy_next_upstream(s);
                    return;
                }
            }

            /* 如果是tcp连接超时，那么就需要结束请求 */
            ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
            ngx_stream_proxy_finalize(s, NGX_DECLINED);
            return;
        }

    } else if (ev->delayed) {

        /* 如果事件没有超时，但是需要延迟处理，则把事件加入到epoll中。 */
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    ngx_stream_proxy_process(s, from_upstream, ev->write);
}

/*
 * 如果nginx与后端服务器暂时没有建链成功，也就是nginx调用了connect，但是后端服务器还没有accpet，
 * 所以nginx暂时还不能通过fd与后端服务器进行通信，这个时候就会把这个函数设置为nginx与后端服务器
 * 连接的读写事件回调函数，等后续后端服务器accpet接受了连接后，连接的写事件就会就绪。如果nginx
 * 最后与这台后端服务器因为超时没能成功建链，则nginx会尝试与下一台后端服务器建链。
 */
static void
ngx_stream_proxy_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    /* ev->timeout为1表示nginx与本台后端服务器建链超时了，这个时候nginx会尝试与下一台后端服务器建链 */
    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "upstream timed out");
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    /* 成功建链，删除定时器 */
    ngx_del_timer(c->write);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    /* 测试建链 */
    if (ngx_stream_proxy_test_connect(c) != NGX_OK) {
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    /* 程序到这里表示nginx与上游服务器已经成功建链了，接下来就需要初始化upstream了 */
    ngx_stream_proxy_init_upstream(s);
}


static ngx_int_t
ngx_stream_proxy_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_stream_proxy_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
    ngx_uint_t do_write)
{
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_uint_t                    flags;
    ngx_msec_t                    delay;
    ngx_connection_t             *c, *pc, *src, *dst;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    /* 获取nginx与客户端以及nginx与后端服务器之间的连接对象 */
    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (ngx_terminate || ngx_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        ngx_stream_proxy_finalize(s, NGX_OK);
        return;
    }

    /* 获取ngx_stream_proxy_module模块在当前server块内的配置项结构体 */
    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    /*
     * from_upstream为1，表示需要处理nginx与后端服务器之间的连接请求事件，即从后端服务器
     * 读取内容，然后发送给客户端。from_upstream为0的话，则是客户端读取数据，然后发送给
     * 后端服务器。
     */
    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->upstream_buf;
        limit_rate = pscf->download_rate;  // 往客户端发送数据的最大速率
        received = &u->received;  // 用于记录已接收的来自后端服务器的数据长度

    } else {
        src = c;
        dst = pc;
        b = &u->downstream_buf;
        limit_rate = pscf->upload_rate;  // 往后端服务器发送数据的最大速率
        received = &s->received;  // 用于记录已接收的来自客户端的数据长度
    }

    for ( ;; ) {

        if (do_write) {

            /* 计算last和pos之间待发送的字节数 */
            size = b->last - b->pos;

            /* 如果写事件就绪了，就调用send发送数据 */
            if (size && dst && dst->write->ready) {

                /* 调用send向目标连接发送数据 */
                n = dst->send(dst, b->pos, size);

                if (n == NGX_AGAIN && dst->shared) {
                    /* cannot wait on a shared socket */
                    n = NGX_ERROR;
                }

                /* 发送出错，结束请求 */
                if (n == NGX_ERROR) {
                    if (c->type == SOCK_DGRAM && !from_upstream) {
                        ngx_stream_proxy_next_upstream(s);
                        return;
                    }

                    ngx_stream_proxy_finalize(s, NGX_DECLINED);
                    return;
                }

                /* n > 0表示成功发送了n字节的数据 */
                if (n > 0) {
                    b->pos += n;  // pos指针后移n个字节

                    /*
                     * 如果b->pos == b->last表明所有待发送的数据都发送完了，于是清空缓冲区。
                     * 为后续处理留出空间
                     */
                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        /* 计算缓冲区中剩余可用的空间 */
        size = b->end - b->last;

        /*
         * 如果缓冲区中还有剩余空间，并且读事件已经就绪，且不需要延迟处理，
         * 那么就进行读事件处理。
         */
        if (size && src->read->ready && !src->read->delayed) {

            /* 计算是否需要进行限速，如果需要限速，则调用recv接收数据 */
            if (limit_rate) {
                /*
                 * 先计算从开始处理请求到现在理论上可以接收的字节数，然后与实际接收的字节数
                 * 求差值，如果差值小于0，表示实际接收的数据多了，需要限速。
                 */
                limit = (off_t) limit_rate * (ngx_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    /*
                     * 限速，设置定时器，并将限速标志位置位
                     */
                    src->read->delayed = 1;
                    delay = (ngx_msec_t) (- limit * 1000 / limit_rate + 1);
                    ngx_add_timer(src->read, delay);
                    break;
                }

                /* 计算本次可以接收多少数据，才不会导致超出限速范围 */
                if ((off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            /* 从b->last开始的内存开始接收数据 */
            n = src->recv(src, b->last, size);

            /* n == NGX_AGAIN表示本次没有接收到数据， n == 0表示连接已经断开 */
            if (n == NGX_AGAIN || n == 0) {
                break;
            }

            /* n > 0表示本次接收到了n字节的数据，然后判断本次接收完之后是否需要限速 */
            if (n > 0) {
                if (limit_rate) {
                    delay = (ngx_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        ngx_add_timer(src->read, delay);
                    }
                }

                if (c->type == SOCK_DGRAM && ++u->responses == pscf->responses)
                {
                    src->read->ready = 0;
                    src->read->eof = 1;
                }

                /*
                 * 因为接收到了数据，所以需要立刻发送出去，于是将do_write置位，并后移b->last指针
                 * 更新已接收到的数据长度
                 */
                *received += n;
                b->last += n;
                do_write = 1;

                continue;
            }

            if (n == NGX_ERROR) {
                if (c->type == SOCK_DGRAM && u->received == 0) {
                    ngx_stream_proxy_next_upstream(s);
                    return;
                }

                src->read->eof = 1;
            }
        }

        break;
    }

    /*
     * src->read->eof为1表示当前处理的src连接的字符流已经结束，
     * b->pos == b->last为1表示已经向目标连接发送了全部数据
     * dst && dst->read->eof成立表示dst连接已经读完了数据
     * 如果是这样的话就可以结束upstream请求了。
     */
    if (src->read->eof && (b->pos == b->last || (dst && dst->read->eof))) {
        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "%s%s disconnected"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      src->type == SOCK_DGRAM ? "udp " : "",
                      from_upstream ? "upstream" : "client",
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        ngx_stream_proxy_finalize(s, NGX_OK);
        return;
    }

    /* src->read->eof为1表示从src连接读完了所有数据，可以关闭src连接的读事件了 */
    flags = src->read->eof ? NGX_CLOSE_EVENT : 0;

    if (!src->shared && ngx_handle_read_event(src->read, flags) != NGX_OK) {
        ngx_stream_proxy_finalize(s, NGX_ERROR);
        return;
    }

    if (dst) {
        if (!dst->shared && ngx_handle_write_event(dst->write, 0) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            ngx_add_timer(c->write, pscf->timeout);

        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }
}

/* 尝试继续与其他后端服务器建立连接，后端服务器通过负载均衡算法选择 */
static void
ngx_stream_proxy_next_upstream(ngx_stream_session_t *s)
{
    ngx_msec_t                    timeout;
    ngx_connection_t             *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;

    /*
     * 在和下一台后端服务器建链之前，先调用u->peer.free设置本台建链失败的后端服务器的
     * 一些状态，比如失败次数，更新有效权重之类的。
     */
    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    timeout = pscf->next_upstream_timeout;

    /* 如果可重试次数已经为0或者选择下一台后端服务器的时间也超时了，就需要结束请求，关闭连接了 */
    if (u->peer.tries == 0
        || !pscf->next_upstream
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
        ngx_stream_proxy_finalize(s, NGX_DECLINED);
        return;
    }

    /* 先获取nginx与后端服务器建链失败的连接对象，如果还在，则先关闭这个连接对象 */
    pc = u->peer.connection;

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);

#if (NGX_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void) ngx_ssl_shutdown(pc);
        }
#endif

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    /* 尝试再次与后端服务器建立连接，选择的后端服务器是通过负载均衡算法计算出来的 */
    ngx_stream_proxy_connect(s);
}


static void
ngx_stream_proxy_finalize(ngx_stream_session_t *s, ngx_int_t rc)
{
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->peer.free && u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;
    }

    pc = u->peer.connection;

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (NGX_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(pc);
        }
#endif

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    ngx_stream_close_connection(s->connection);
}


static u_char *
ngx_stream_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_connection_t       *pc;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}


static void *
ngx_stream_proxy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_proxy_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_name = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_certificate = { 0, NULL };
     *     conf->ssl_certificate_key = { 0, NULL };
     *
     *     conf->ssl = NULL;
     *     conf->upstream = NULL;
     */

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upload_rate = NGX_CONF_UNSET_SIZE;
    conf->download_rate = NGX_CONF_UNSET_SIZE;
    conf->responses = NGX_CONF_UNSET_UINT;
    conf->next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->next_upstream = NGX_CONF_UNSET;
    conf->proxy_protocol = NGX_CONF_UNSET;
    conf->local = NGX_CONF_UNSET_PTR;

#if (NGX_STREAM_SSL)
    conf->ssl_enable = NGX_CONF_UNSET;
    conf->ssl_session_reuse = NGX_CONF_UNSET;
    conf->ssl_server_name = NGX_CONF_UNSET;
    conf->ssl_verify = NGX_CONF_UNSET;
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
    conf->ssl_passwords = NGX_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
ngx_stream_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_proxy_srv_conf_t *prev = parent;
    ngx_stream_proxy_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    ngx_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);

    ngx_conf_merge_size_value(conf->upload_rate,
                              prev->upload_rate, 0);

    ngx_conf_merge_size_value(conf->download_rate,
                              prev->download_rate, 0);

    ngx_conf_merge_uint_value(conf->responses,
                              prev->responses, NGX_MAX_INT32_VALUE);

    ngx_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    ngx_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    ngx_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);

    ngx_conf_merge_ptr_value(conf->local, prev->local, NULL);

#if (NGX_STREAM_SSL)

    ngx_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);

    ngx_conf_merge_value(conf->ssl_session_reuse,
                              prev->ssl_session_reuse, 1);

    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1
                               |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2));

    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");

    ngx_conf_merge_str_value(conf->ssl_name, prev->ssl_name, "");

    ngx_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);

    ngx_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);

    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);

    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");

    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    ngx_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");

    ngx_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");

    ngx_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl_enable && ngx_stream_proxy_set_ssl(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#endif

    return NGX_CONF_OK;
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_proxy_set_ssl(ngx_conf_t *cf, ngx_stream_proxy_srv_conf_t *pscf)
{
    ngx_pool_cleanup_t  *cln;

    pscf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (pscf->ssl == NULL) {
        return NGX_ERROR;
    }

    pscf->ssl->log = cf->log;

    if (ngx_ssl_create(pscf->ssl, pscf->ssl_protocols, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = pscf->ssl;

    if (pscf->ssl_certificate.len) {

        if (pscf->ssl_certificate_key.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &pscf->ssl_certificate);
            return NGX_ERROR;
        }

        if (ngx_ssl_certificate(cf, pscf->ssl, &pscf->ssl_certificate,
                                &pscf->ssl_certificate_key, pscf->ssl_passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (SSL_CTX_set_cipher_list(pscf->ssl->ctx,
                                (const char *) pscf->ssl_ciphers.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &pscf->ssl_ciphers);
        return NGX_ERROR;
    }

    if (pscf->ssl_verify) {
        if (pscf->ssl_trusted_certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return NGX_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, pscf->ssl,
                                        &pscf->ssl_trusted_certificate,
                                        pscf->ssl_verify_depth)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_ssl_crl(cf, pscf->ssl, &pscf->ssl_crl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

#endif


static char *
ngx_stream_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_url_t                    u;
    ngx_str_t                   *value, *url;
    ngx_stream_core_srv_conf_t  *cscf;

    if (pscf->upstream) {
        return "is duplicate";
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    /* 设置handler，开启后续流程的处理 */
    cscf->handler = ngx_stream_proxy_handler;

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.no_resolve = 1;

    /* 获取proxy_pass命令参数对应的upstream配置块信息 */
    pscf->upstream = ngx_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_int_t   rc;
    ngx_str_t  *value;

    if (pscf->local != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        pscf->local = NULL;
        return NGX_CONF_OK;
    }

    pscf->local = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
    if (pscf->local == NULL) {
        return NGX_CONF_ERROR;
    }

    rc = ngx_parse_addr(cf->pool, pscf->local, value[1].data, value[1].len);

    switch (rc) {
    case NGX_OK:
        pscf->local->name = value[1];
        return NGX_CONF_OK;

    case NGX_DECLINED:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid address \"%V\"", &value[1]);
        /* fall through */

    default:
        return NGX_CONF_ERROR;
    }
}
