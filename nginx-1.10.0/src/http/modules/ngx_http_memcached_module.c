
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* memcached模块loc级别下配置项结构体 */
typedef struct {
    ngx_http_upstream_conf_t   upstream;  // memcached模块所使用的upstream机制对象配置结构体
    ngx_int_t                  index;  // 存放memcached_key变量的下标
    ngx_uint_t                 gzip_flag;  //memcached_gzip_flag命令解析结果
} ngx_http_memcached_loc_conf_t;


typedef struct {
    /*
     * 表示剩余未接收的标志上游memcached服务器有效响应包体已经结束的标志行的长度，
     * 标志行内容为CRLF "END" CRLF，会紧随在有效响应包体的后面
     */
    size_t                     rest;
    ngx_http_request_t        *request;  // 使用memcached模块的请求对象
    /*
     * 指向存放着从r->variables拷贝过来的变量memcached_key的值的内存，这部分内存其实就是在存放着
     * 发送给上游memcached服务器的请求的内存中，见函数ngx_http_memcached_create_request()
     */
    ngx_str_t                  key;
} ngx_http_memcached_ctx_t;


static ngx_int_t ngx_http_memcached_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_memcached_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_memcached_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_memcached_filter_init(void *data);
static ngx_int_t ngx_http_memcached_filter(void *data, ssize_t bytes);
static void ngx_http_memcached_abort_request(ngx_http_request_t *r);
static void ngx_http_memcached_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static void *ngx_http_memcached_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_memcached_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_memcached_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_bitmask_t  ngx_http_memcached_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("not_found"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};

/* memcahced模块支持的配置指令 */
static ngx_command_t  ngx_http_memcached_commands[] = {

    { ngx_string("memcached_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_memcached_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("memcached_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("memcached_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("memcached_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("memcached_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("memcached_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("memcached_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, upstream.next_upstream),
      &ngx_http_memcached_next_upstream_masks },

    { ngx_string("memcached_next_upstream_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { ngx_string("memcached_next_upstream_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { ngx_string("memcached_gzip_flag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_memcached_loc_conf_t, gzip_flag),
      NULL },

      ngx_null_command
};

/* memcached模块实现的http类型模块的上下文 */
static ngx_http_module_t  ngx_http_memcached_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_memcached_create_loc_conf,    /* create location configuration */
    ngx_http_memcached_merge_loc_conf      /* merge location configuration */
};

/* memcached模块实现的Nginx下模块的通用接口 */
ngx_module_t  ngx_http_memcached_module = {
    NGX_MODULE_V1,
    &ngx_http_memcached_module_ctx,        /* module context */
    ngx_http_memcached_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* 配置文件中使用到的变量memcached_key */
static ngx_str_t  ngx_http_memcached_key = ngx_string("memcached_key");


#define NGX_HTTP_MEMCACHED_END   (sizeof(ngx_http_memcached_end) - 1)
static u_char  ngx_http_memcached_end[] = CRLF "END" CRLF;

/*
 * ngx_http_memcached_module模块的功能入口函数，如果使用了该模块，则该函数最终会设置给
 * r->content_hanlder回调函数，在NGX_HTTP_CONTENT_PHASE阶段会被调用。
 */
static ngx_int_t
ngx_http_memcached_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_memcached_ctx_t       *ctx;
    ngx_http_memcached_loc_conf_t  *mlcf;

    /* 如果客户端请求不是GET或者HEAD，则直接返回NGX_HTTP_NOT_ALLOWED给客户端 */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /*
     * 因为是GET或者HEAD请求，并且memcached模块目前只支持从memcached服务器获取内容，
     * 所以包体是不想要的，所以这个时候就需要读取包体然后丢弃。
     */
    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    /* 设置请求内容的类型 */
    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * 因为需要和后端的memcached服务器进行通信，所以需要先创建upstream对象，upstream对象是
     * 用来访问后端服务器的基础，存放着必要的信息。创建完upstream对象之后，会挂载到请求对象
     * ngx_http_request_t中的upstream成员中。
     */
    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    /* 设置upstream对象中的schema字段，目前该字段只用在打印日志使用 */
    ngx_str_set(&u->schema, "memcached://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_memcached_module;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_memcached_module);

    /* 从ngx_http_memcached_module模块的配置信息中获取upstream机制的配置信息，并设置到upstream对象的conf中 */
    u->conf = &mlcf->upstream;

    /* 设置upstream机制会使用到的几个重要的回调函数 */
    u->create_request = ngx_http_memcached_create_request;
    u->reinit_request = ngx_http_memcached_reinit_request;
    u->process_header = ngx_http_memcached_process_header;
    u->abort_request = ngx_http_memcached_abort_request;
    u->finalize_request = ngx_http_memcached_finalize_request;

    /*
     * 创建ngx_http_memcached_module模块的上下文结构体，用以辅助ngx_http_memcached_module模块
     * 进行上游服务器响应的处理
     */
    ctx = ngx_palloc(r->pool, sizeof(ngx_http_memcached_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 设置ctx->request为发起此次处理的请求 */
    ctx->request = r;

    ngx_http_set_ctx(r, ctx, ngx_http_memcached_module);

    /* 设置处理包体相关的几个回调函数以及传递给这些回调函数的用户自定义数据 */
    u->input_filter_init = ngx_http_memcached_filter_init;
    u->input_filter = ngx_http_memcached_filter;
    u->input_filter_ctx = ctx;

    /*
     * 对于原始请求来说，使用upstream机制向后端服务器发起请求是一个独立的异步动作，所以需要
     * 将原始请求的r->main->count递增。
     */
    r->main->count++;

    /* 因为前面已经创建好了upstream对象，并且做好了一些必要的初始化工作，所以可以启动upstream机制了 */
    ngx_http_upstream_init(r);

    return NGX_DONE;
}

/* 构造发送给上游memcached服务器的请求，生成的请求内容会存放在r->upstream->request_bufs中 */
static ngx_int_t
ngx_http_memcached_create_request(ngx_http_request_t *r)
{
    size_t                          len;
    uintptr_t                       escape;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_memcached_ctx_t       *ctx;
    ngx_http_variable_value_t      *vv;
    ngx_http_memcached_loc_conf_t  *mlcf;

    /* 获取ngx_http_memcached_module模块的loc配置项结构体 */
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_memcached_module);

    /* 获取配置文件中用set命令配置的memcached_key变量的值 */
    vv = ngx_http_get_indexed_variable(r, mlcf->index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the \"$memcached_key\" variable is not set");
        return NGX_ERROR;
    }

    /* 获取需要进行转义的字节长度 */
    escape = 2 * ngx_escape_uri(NULL, vv->data, vv->len, NGX_ESCAPE_MEMCACHED);

    /* 计算完整的请求行长度 */
    len = sizeof("get ") - 1 + vv->len + escape + sizeof(CRLF) - 1;

    /* 申请存放请求所需要的内存 */
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    /* 申请一个缓冲区对象来管理存放请求的内存，主要是为了方便挂载到r->upstream->request_bufs缓冲区链表中 */
    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    /* 将管理着存放请求内存的缓冲区对象挂载到r->upstream->request_bufs中 */
    r->upstream->request_bufs = cl;

    /* 下面开始往内存中填充请求内容，目前官方的memcached模块只支持get命令，即从memcached服务器获取内容 */

    /* 1. 填充'get'命令 */
    *b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';

    /*
     * 2.填充用于从memcached服务器中获取内容的memcached_key值。key值由配置文件中的set命令指定，在解析配置文件的时候
     * 已经进行索引化，存放在了r->variables中了。
     * 除了将memcached_key值填充到请求中，还会将key的值(实际应该只是指向key值的指针)存放在ngx_http_memcached_module
     * 模块下上文的key变量中。
     */
    ctx = ngx_http_get_module_ctx(r, ngx_http_memcached_module);

    /*
     * ctx->key也指向了b->last，后续会将memcached_key变量的值拷贝到b->last指向的内存中.
     */
    ctx->key.data = b->last;

    if (escape == 0) {
        b->last = ngx_copy(b->last, vv->data, vv->len);

    } else {
        b->last = (u_char *) ngx_escape_uri(b->last, vv->data, vv->len,
                                            NGX_ESCAPE_MEMCACHED);
    }

    ctx->key.len = b->last - ctx->key.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http memcached request: \"%V\"", &ctx->key);

    /* 2. 填充完memcached_key的值后，填充CR和LF */
    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}


static ngx_int_t
ngx_http_memcached_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

/* 解析从上游memcached服务器接收到的响应头 */
static ngx_int_t
ngx_http_memcached_process_header(ngx_http_request_t *r)
{
    u_char                         *p, *start;
    ngx_str_t                       line;
    ngx_uint_t                      flags;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_memcached_ctx_t       *ctx;
    ngx_http_memcached_loc_conf_t  *mlcf;

    u = r->upstream;

    /* 从这里的实现可以看到，memcached协议的响应头只有一行 */

    /*
     * 遍历从上游memcached服务器接收到的响应数据，一旦发现出现了LF字符，就表示响应头找到了，
     * 接下来就开始处理这一行响应头数据
     */
    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    /* 程序执行到这里表明还没有接收到完整的响应头，需要继续从上游接收更多的响应数据 */
    return NGX_AGAIN;

found:

    /* 用line指向了u->buffer中的响应头部数据 */
    line.data = u->buffer.pos;
    line.len = p - u->buffer.pos;

    /* 响应头和响应包体之间必须是以CRLF结尾的，所以如果LF前面一个字符不是CR，则表明响应数据是非法的。 */
    if (line.len == 0 || *(p - 1) != CR) {
        goto no_valid;
    }

    *p = '\0';
    line.len--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "memcached: \"%V\"", &line);

    /* p指向了响应头部的开始 */
    p = u->buffer.pos;

    /* 获取ngx_http_memcached_module模块的上下文和loc级别配置项结构体 */
    ctx = ngx_http_get_module_ctx(r, ngx_http_memcached_module);
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_memcached_module);

    /* 判断响应头部是否以"VALUE "开始 */
    if (ngx_strncmp(p, "VALUE ", sizeof("VALUE ") - 1) == 0) {

        /* 更新p指向的内存，偏移之后指向用来访问memcached服务器的key的值开始处 */
        p += sizeof("VALUE ") - 1;

        /*
         * 比较响应头部中key值和用来访问memcached服务器时传递给memcached服务器的key值是否相等，
         * 如果两者不想等，说明memcached处理出错了，这个时候需要返回NGX_HTTP_UPSTREAM_INVALID_HEADER，
         * 表示memcached服务器返回了错误的响应头
         */
        if (ngx_strncmp(p, ctx->key.data, ctx->key.len) != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid key in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* 更新p指向的内存，偏移之后指向返回的响应头部中的key值的下一个地址 */
        p += ctx->key.len;

        /* 响应头部中的key值之后必须是个空格，否则也是非法的头部 */
        if (*p++ != ' ') {
            goto no_valid;
        }

        /* flags */

        start = p;

        /*
         * 遍历剩余响应头部中的内容直到遇到空格' '。如果配置文件中配置了memcached_gzip_flag指令，
         * 那么就需要判断memcached服务器返回的响应包体数据是否也是经过了gzip压缩的。如果没有配置
         * memcached_gzip_flag，那么就从响应头部解析响应包体的长度
         */
        while (*p) {
            if (*p++ == ' ') {
                if (mlcf->gzip_flag) {
                    goto flags;
                } else {
                    goto length;
                }
            }
        }

        goto no_valid;

    flags:

        /* 获取响应头部中返回的flag值 */
        flags = ngx_atoi(start, p - start - 1);

        if (flags == (ngx_uint_t) NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid flags in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /*
         * 如果flags & mlcf->gzip_flag为真，表示memcached服务器返回的响应包体数据是经过压缩的，
         * 所以在将压缩的响应包体发送给客户端之前，需要在发送给客户端的http响应头部中设置
         * 内容编码"Content-Encoding"字段的值为gzip。这样，客户端接收到Nginx发送的响应数据之后
         * 才能正确的进行解码。
         */
        if (flags & mlcf->gzip_flag) {

            /*
             * 将内容编码字段"Content-Encoding"及其值"gzip"设置到r->headers_out.headers，后续将
             * r->headers_out.headers中的内容序列化成发送给客户端的响应头部时也就包含了内容编码
             * 字段及其值了。
             */
            h = ngx_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = 1;
            ngx_str_set(&h->key, "Content-Encoding");
            ngx_str_set(&h->value, "gzip");
            r->headers_out.content_encoding = h;
        }

    length:
    
        /* 从响应头部中获取响应包体的长度 */

        /* 此时p指向的是存放着响应包体长度的内存，在这里设置给了局部变量start。 */
        start = p;

        /*
         * 指向下面这条语句之后，p指向了响应头部末尾，那么p - start就是响应头部中
         * 指示包体长度的字段所占用的内存长度了
         */
        p = line.data + line.len;

        /* 解析响应头部，获取响应包体长度 */
        u->headers_in.content_length_n = ngx_atoof(start, p - start);
        if (u->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid length in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /*
         * 因为程序执行到这里表明memcached服务器返回的响应头部已经成功解析完了，
         * 而且头部也是合法的。所以这里需要设置一些状态标志
         */
        u->headers_in.status_n = 200;
        u->state->status = 200;
        /* 执行完下面的语句后，u->buffer.pos指向的是响应头部下一个位置，也就是包体数据的开始位置 */
        u->buffer.pos = p + sizeof(CRLF) - 1;

        return NGX_OK;
    }

    /* 如果响应头部是"END\x0d"，表明memcached模块发送给memcached服务器的key对应的值在memcached服务器中不存在 */
    if (ngx_strcmp(p, "END\x0d") == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "key: \"%V\" was not found by memcached", &ctx->key);

        /* 因为在memcached服务器中没有找到key对应的值，所以需要设置一些状态 */
        u->headers_in.content_length_n = 0;
        u->headers_in.status_n = 404;
        u->state->status = 404;
        u->buffer.pos = p + sizeof("END" CRLF) - 1;
        u->keepalive = 1;

        return NGX_OK;
    }

    /*
     * 如果响应头部数据既不是以"VALUE "开头，也不是"END\x0d"，那么这个响应数据是非法的，
     * 这个时候会返回NGX_HTTP_UPSTREAM_INVALID_HEADER，表示从服务器接收到的响应头部是非法的。
     */

no_valid:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "memcached sent invalid response: \"%V\"", &line);

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
}

/* 为处理从上游memcached服务器接收到包体做准备 */
static ngx_int_t
ngx_http_memcached_filter_init(void *data)
{
    ngx_http_memcached_ctx_t  *ctx = data;

    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

    /*
     * 如果上游服务器返回的响应头中的响应状态不是404，那么就设置剩余未接收的响应包体长度到u->length中
     * 并初始化memcached模块上下文的rest字段为NGX_HTTP_MEMCACHED_END，表示剩余未接收的标志上游memcached
     * 服务器有效响应包体已经结束的标志行的长度
     */
    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n + NGX_HTTP_MEMCACHED_END;
        ctx->rest = NGX_HTTP_MEMCACHED_END;

    } else {
        u->length = 0;
    }

    return NGX_OK;
}

/* 处理从上游memcached服务器接收到的包体数据 */
static ngx_int_t
ngx_http_memcached_filter(void *data, ssize_t bytes)
{
    ngx_http_memcached_ctx_t  *ctx = data;

    u_char               *last;
    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    /*
     * 从创建memcached模块loc级别下配置项结构体的函数ngx_http_memcached_create_loc_conf()函数中
     * 可以看到，memcached模块会使用固定大小的缓存来接收memcached服务器发送过来的响应数据，缓冲区
     * 就是upstream对象中的buffer。
     */
    u = ctx->request->upstream;
    b = &u->buffer;

    /*
     * 如果u->length == (ssize_t) ctx->rest成立的话，表明已经开始接收标志memcached服务器有效响应包体结束的
     * 标志行(CRLF "END" CRLF)的内容了，但不一定本次就完整接收到了剩余未接收标志行的全部内容。
     */
    if (u->length == (ssize_t) ctx->rest) {

        /* 比较本次接收到的剩余部分是否和剩余未接收的标志行内容一致 */
        if (ngx_strncmp(b->last,
                   ngx_http_memcached_end + NGX_HTTP_MEMCACHED_END - ctx->rest,
                   bytes)
            != 0)
        {
            ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                          "memcached sent invalid trailer");

            u->length = 0;
            ctx->rest = 0;

            return NGX_OK;
        }

        /* 更新剩余未接收的包体长度 */
        u->length -= bytes;
        ctx->rest -= bytes;

        /* 如果u->length等于0，表示接收到了来自上游memcached服务器的全部响应包体内容，包括标志行的内容 */
        if (u->length == 0) {
            u->keepalive = 1;
        }

        return NGX_OK;
    }

    /*
     * 在使用固定大小的缓冲区来存放memcached服务器发送过来的响应时，缓冲区为upstream对象中的
     * buffer字段，对于每次接收到的存放在buffer中的响应包体段，会用一个没有分配实际内存的缓冲区
     * 对象来管理本次接收到的包体数据，然后这个缓冲区对象会挂载到upstream对象的out_bufs缓冲区
     * 链表对象中的末尾。
     */
    /*
     * 循环遍历u->out_bufs缓冲区链表，定位到链表的尾部
     */
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    /* 从u->free_bufs中获取一个空闲的缓冲区对象，用来管理本次接收到的来自上游memcached服务器的包体 */
    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    /*
     * 设置缓冲区对象中的flush和memory标志位，分别表示需要发送以及缓冲区管理的对象在内存中。
     */
    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    /* b->last指向的是本次接收到的包体的地址，在这里设置给局部变量last */
    last = b->last;
    cl->buf->pos = last;  // 缓冲区的pos指针指向包体的起始地址，pos一般指示未处理的内存的开始
    b->last += bytes;  // b->last偏移到本次接收到的包体的下一个位置，为后续接收包体做准备
    cl->buf->last = b->last;  // 缓冲区的last指针指向了本次接收的包体的的下一个位置，和pos共同管理缓存的包体
    cl->buf->tag = u->output.tag;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "memcached filter bytes:%z size:%z length:%O rest:%z",
                   bytes, b->last - b->pos, u->length, ctx->rest);

    /*
     * 如果bytes <= (ssize_t) (u->length - NGX_HTTP_MEMCACHED_END)成立的话，表明还需要从上游服务器接收
     * 更多的包体，这个时候更新upstream中管理的剩余未接收的包体长度，返回NGX_OK，等待下次接收到包体后
     * 再调用本函数进行处理。
     * 在bytes == (ssize_t) (u->length - NGX_HTTP_MEMCACHED_END)情况，就是指有效包体已经接收完毕了，但是
     * 还有标志有效包体结束的标志行还没有接收到，因此还需要接收这部分内容。这个时候更新完u->length之后，
     * 就会出现u->length == ctx->rest的情况了。
     */
    if (bytes <= (ssize_t) (u->length - NGX_HTTP_MEMCACHED_END)) {
        u->length -= bytes;
        return NGX_OK;
    }

    /*
     * 程序执行到这里表明本次接收完之后已经从上游memcached服务器接收到了完整的有效响应包体，但是可能还没有
     * 完整接收到用于指示memcached服务器响应包体已经结束的标志行(CRLF "END" CRLF)。所以需要做进一步的判断。
     */

    /* 先将last指针定位到标志有效响应包体已经结束的标志行的开始位置 */
    last += (size_t) (u->length - NGX_HTTP_MEMCACHED_END);

    /*
     * 判断已经接收的标志有效响应包体结束的标志行是否有效的(这个时候不一定是完整的，注意到第三个参数的长度
     * 并不是标志行的总长度，而是已经接收到了可能是部分标志行的长度) 
     */
    if (ngx_strncmp(last, ngx_http_memcached_end, b->last - last) != 0) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "memcached sent invalid trailer");

        b->last = last;
        cl->buf->last = last;
        u->length = 0;
        ctx->rest = 0;

        return NGX_OK;
    }

    /*
     * 程序执行到这里表示接收到的用来标志memcached服务器响应包体结束的标志行可能还没有接收完整，所以需要记录
     * 当前的这个状态。(用来标志memcached服务器有效响应包体结束的标志行的数据对于Nginx来说并没有什么用，但是
     * 仍然有必要接收，所以可以覆盖这部分内容，从下面的b->last = last可以看出，后续剩余未接收的标志行内容
     * 会直接覆盖已经接收到的部分标志行，因为b->last表示的是下次接收包体的起始位置)。而且这部分内容并不会
     * 挂载到out_bufs缓冲区链表中，也就不会发送给客户端了。
     */
    ctx->rest -= b->last - last;  // 记录标志行剩余未接收的长度
    b->last = last;  // 将u->buffer中的last指针设置为标志行起始地址
    cl->buf->last = last;  //用于管理本次接收到的包体的缓冲区对象的last指针指向了有效包体的下一个地址，即标志行开始
    u->length = ctx->rest;  // 将剩余未接收的包体长度设置为剩余未接收标志行的长度。

    /* 如果u->length等于0，表示接收到了来自上游memcached服务器的全部响应包体内容，包括标志行的内容。 */
    if (u->length == 0) {
        u->keepalive = 1;
    }

    return NGX_OK;
}


static void
ngx_http_memcached_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http memcached request");
    return;
}


static void
ngx_http_memcached_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http memcached request");
    return;
}

/* 创建用于存放memcached模块loc级别下的配置项结构体 */
static void *
ngx_http_memcached_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_memcached_loc_conf_t  *conf;

    /* 申请用于存放memcached模块loc级别下面的配置项结构体内存 */
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_memcached_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     */

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    /*
     * 以下是把memcached模块用到了upstream机制的一些成员进行硬编码，表示某些功能的固化，
     * 比如将buffering设置为0，表明使用固定大小的内存来缓存上游memcached服务器发送过来的
     * 响应，这个时候也就不需要更大的内存缓冲区已经临时文件，所以也会将相关的字段进行设置。
     */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;
    conf->upstream.force_ranges = 1;

    conf->index = NGX_CONF_UNSET;
    conf->gzip_flag = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_memcached_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_memcached_loc_conf_t *prev = parent;
    ngx_http_memcached_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->index == NGX_CONF_UNSET) {
        conf->index = prev->index;
    }

    ngx_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);

    return NGX_CONF_OK;
}

/* memcached_pass指令解析函数，memcached_pass命令后面会携带一个url参数 */
static char *
ngx_http_memcached_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_memcached_loc_conf_t *mlcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    /* 获取url参数 */
    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;  // url没有进行dns解析的标志位

    /*
     * 获取一个存储upstream配置块信息的结构体，这个时候一般不会创建一个新的upstream配置块，
     * 而是从已有的upstream配置块中找出和memcached_pass命令参数匹配的那个upstream配置块，后续
     * 需要使用到这个upstream配置块中的信息，比如用于做负载均衡之类的。proxy_pass命令也是类似
     */
    mlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    /* clcf代表所在location */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    /*
     * 设置clcf->handler回调函数，这个在ngx_http_core_content_phase这个checker函数中就会调用这个函数
     * 进行NGX_HTTP_CONTENT_PHASE阶段的处理。
     * 在ngx_http_update_location_config()函数中会将clcf->handler赋值给r->content_hander。
     */
    clcf->handler = ngx_http_memcached_handler;

    /* 如果location以'/'结尾，则需要进行重定向 */
    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    /* 获取配置文件中设置的memcached_key变量的下标，存放在mlcf->index */
    mlcf->index = ngx_http_get_variable_index(cf, &ngx_http_memcached_key);

    if (mlcf->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
