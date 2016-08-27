
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_discard_request_body_filter(ngx_http_request_t *r,
    ngx_buf_t *b);
static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);

static ngx_int_t ngx_http_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_length_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_chunked_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

/* 启动接收请求包体 */
ngx_int_t
ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler)
{
    size_t                     preread;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    /* 先将主请求的引用计数加1，表示主请求新增了一个动作 */
    r->main->count++;

    /*
     * 1.如果该请求不是原始请求，则不需要接收客户端请求包体，因为子请求不是客户端产生的。
     * 2.检查请求中的request_body成员，如果该成员已经被分配过了，证明之前已经读取过请求体了
     * 不用再读取一遍。
     * 3.如果请求中的discard_body标志位为1，表明之前已经执行过丢弃包体的方法，也不用再继续
     * 读取请求体了。
     */
    if (r != r->main || r->request_body || r->discard_body) {
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_request_body(r, post_handler);
        goto done;
    }
#endif

    /* 检测客户端发送的请求头部中是否有Expect头部 */
    if (ngx_http_test_expect(r) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /* 申请用于接收请求体的对象 */
    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->free = NULL;
     *     rb->busy = NULL;
     *     rb->chunked = NULL;
     */

    rb->rest = -1;
    rb->post_handler = post_handler;  // 设置包体读取完毕的回调方法，通常用于实现模块的业务逻辑

    r->request_body = rb;

    /* 如果模块的Content-Length头部值小于0，则不用接收请求包体 */
    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

    /*
     * 在接收请求头部的流程中，是有可能接收到http请求包体的，所以这里需要检查接收头部的缓冲区
     * 中是否预接收到了包体。我们知道header_in->last和header_in->pos之间的内存就是为解析的字符流。
     * preread如果大于0，表示确实预接收到了包体
     */
    preread = r->header_in->last - r->header_in->pos;

    if (preread) {

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        /* 缓冲区链表指向头部缓冲区header_in */
        out.buf = r->header_in;
        out.next = NULL;

        /* 该函数中会计算剩余未接收的包体长度 */
        rc = ngx_http_request_body_filter(r, &out);

        if (rc != NGX_OK) {
            goto done;
        }

        /* 计算到目前位置已经接收到的请求的长度 */
        r->request_length += preread - (r->header_in->last - r->header_in->pos);

        /*
         * 如果存在剩余未接收的包体，并且剩余包体的长度小于头部缓冲区剩余长度，那么
         * 将会使用头部缓冲区来接收剩余的包体
         */
        if (!r->headers_in.chunked
            && rb->rest > 0
            && rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
        {
            /* the whole request body may be placed in r->header_in */

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            /* 包体缓冲区直接指向了头部缓冲区对应的内存 */
            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;

            rb->buf = b;

            /*
             * 因为接收请求包体的动作可能无法在一次调度中完成，所以需要设置请求读事件处理函数，
             * 这样在连接对应的读事件再次被epoll调度时，可以继续执行接收包体的动作。
             */
            r->read_event_handler = ngx_http_read_client_request_body_handler;
            r->write_event_handler = ngx_http_request_empty_handler;

            /* 从连接对应的内核套接字缓冲区中读取包体 */
            rc = ngx_http_do_read_client_request_body(r);
            goto done;
        }

    } else {
        /* set rb->rest */

        /* 计算剩余未接收的请求包体的长度，即rb->rest */
        if (ngx_http_request_body_filter(r, NULL) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }

    /* rb->rest == 0表明已经接收到了完整的请求包体(其实是在头部缓冲区中就预读取完了请求体) */
    if (rb->rest == 0) {
        /* the whole request body was pre-read */
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

    if (rb->rest < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * 程序执行到这里说明需要分配用于接收请求包体的缓冲区了，缓冲区的长度由配置文件中的
     * client_body_buffer_size配置项指定。
     */
    size = clcf->client_body_buffer_size;
    size += size >> 2;

    /* TODO: honor r->request_body_in_single_buf */

    /* rb->rest < size表明剩余未接收包体用不了size长度，所以分配rb->rest长度就够了 */
    if (!r->headers_in.chunked && rb->rest < size) {
        size = (ssize_t) rb->rest;

        /*
         * 如果r->request_body_in_single_buf标志位为1，表明需要将所有的请求包体存放在一块缓冲区中，
         * 这个时候需要将头部缓冲区中预读取的包体一并复制过来，所以在计算用于接收请求包体的缓冲区长度的时候，
         * 需要为已经存放在头部缓冲区的包体分配相应的内存，因为那部分包体也要复制到该缓冲区中
         */
        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;
    }

    /* 申请用于接收包体的缓冲区 */
    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /* 设置请求读写事件 */
    /*
     * 因为接收请求包体的动作可能无法在一次调度中完成，所以需要设置请求读事件处理函数，
     * 这样在连接对应的读事件再次被epoll调度时，可以继续执行接收包体的动作。
     */
    r->read_event_handler = ngx_http_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    /* 接收包体 */
    rc = ngx_http_do_read_client_request_body(r);

done:

    if (r->request_body_no_buffering
        && (rc == NGX_OK || rc == NGX_AGAIN))
    {
        if (rc == NGX_OK) {
            r->request_body_no_buffering = 0;

        } else {
            /* rc == NGX_AGAIN */
            r->reading_body = 1;  // NGX_AGAIN表明正在读取请求包体
        }

        r->read_event_handler = ngx_http_block_reading;
        post_handler(r);
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        r->main->count--;
    }

    return rc;
}


ngx_int_t
ngx_http_read_unbuffered_request_body(ngx_http_request_t *r)
{
    ngx_int_t  rc;

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_unbuffered_request_body(r);

        if (rc == NGX_OK) {
            r->reading_body = 0;
        }

        return rc;
    }
#endif

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        return NGX_HTTP_REQUEST_TIME_OUT;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc == NGX_OK) {
        r->reading_body = 0;
    }

    return rc;
}


static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    /*
     * 如果read->timedout为1，则表明读取请求包体超时，此时需要将连接上的timeout置位，
     * 结束请求并返回408错误响应
     */
    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    /* 读取请求包体 */
    rc = ngx_http_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}

/*
 * 读取包体，功能如下:
 * 1.把客户端和Nginx之间的tcp连接上的内核套接字缓冲区中的字符流读出来
 * 2.判断字符流是否需要写入文件，以及是否接收到了全部的请求包体
 * 3.在接收到全部的请求包体后激活用于执行读取请求包体的模块业务逻辑的函数post_handler()
 */
static ngx_int_t
ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_chain_t                out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    /* 获取连接对象和存储包体对象 */
    c = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end) {

                if (rb->buf->pos != rb->buf->last) {

                    /* pass buffer to request body filter chain */

                    out.buf = rb->buf;
                    out.next = NULL;

                    rc = ngx_http_request_body_filter(r, &out);

                    if (rc != NGX_OK) {
                        return rc;
                    }

                } else {

                    /* update chains */

                    rc = ngx_http_request_body_filter(r, NULL);

                    if (rc != NGX_OK) {
                        return rc;
                    }
                }

                if (rb->busy != NULL) {
                    if (r->request_body_no_buffering) {
                        if (c->read->timer_set) {
                            ngx_del_timer(c->read);
                        }

                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NGX_AGAIN;
                    }

                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;
            rest = rb->rest - (rb->buf->last - rb->buf->pos);

            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client prematurely closed connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            r->request_length += n;

            if (n == rest) {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %O", rb->rest);

        if (rb->rest == 0) {
            break;
        }

        if (!c->read->ready) {

            if (r->request_body_no_buffering
                && rb->buf->pos != rb->buf->last)
            {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (!r->request_body_no_buffering) {
        r->read_event_handler = ngx_http_block_reading;
        rb->post_handler(r);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_write_request_body(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_chain_t               *cl, *ln;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http write client request body, bufs %p", rb->bufs);

    if (rb->temp_file == NULL) {
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;

        if (rb->bufs == NULL) {
            /* empty body with r->request_body_in_file_only */

            if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                     tf->persistent, tf->clean, tf->access)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    if (rb->bufs == NULL) {
        return NGX_OK;
    }

    n = ngx_write_chain_to_temp_file(rb->temp_file, rb->bufs);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    rb->temp_file->offset += n;

    /* mark all buffers as written */

    for (cl = rb->bufs; cl; /* void */) {

        cl->buf->pos = cl->buf->last;

        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    rb->bufs = NULL;

    return NGX_OK;
}

/*
 * 第一次启动丢弃包体动作 
 *     对于http模块而言，放弃接收包体就是简单地不接收包体，但是对于http框架来说并不是
 * 不接收包体就可以的。因为客户端通常会调用一些阻塞方法来发送包体，如果http框架
 * 一直不接收包体，会导致实现上不够健壮的客户端认为服务器超时无响应而将连接关闭，
 * 但是这个时候Nginx可能还在处理这个连接，这样就会导致出错。
 *     所以http模块放弃接收包体，对http框架来说就是接收包体，但接收后不保存，直接丢弃
 */
ngx_int_t
ngx_http_discard_request_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_int_t     rc;
    ngx_event_t  *rev;

    /*
     * 1. 检查当前请求是不是子请求，如果是子请求的话，就不用处理包体，因为子请求并不是来自
     * 客户端的请求，所以不存在处理http请求包体的概念。所以如果是子请求，直接返回NGX_OK表示丢包成功
     * 2. 检查请求中的discard_body标志位，如果该标志位为1，表示已经在执行丢包的动作，所以这里
     * 直接返回。
     * 3. 检查请求中的request_body，如果不是NULL，说明之前模块执行过读取包体的动作，所以这里
     * 不能再执行丢弃包体的动作了。
     */
    if (r != r->main || r->discard_body || r->request_body) {
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        r->stream->skip_data = 1;
        return NGX_OK;
    }
#endif

    /* 检测Expect头部，并发送响应，激活客户端发送请求体 */
    if (ngx_http_test_expect(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

    /* 
     * 检查当前连接的读事件是否在定时器中，如果在，则从定时器中删除，因为丢弃包体
     * 不用考虑超时的问题。但是有一种情况下会将连接读事件重新加入到定时器当中，那就是
     * 在Nginx已经处理完的请求但是客户端还没有将所有的包体发送完毕，这个时候就需要
     * 将连接读事件假如定时器，并将定时器超时时间设置为lingering_timeout。这个操作
     * 是在ngx_http_finalize_connection()函数中完成的，如果结束请求时发现客户端
     * 还没有发送完请求体，就会将连接读事件加入到定时器中。
     */
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    /* 如果请求头部"Content-Length"指定的长度小于等于0，则直接返回，无需执行丢弃动作 */
    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return NGX_OK;
    }

    /* 检查接收http请求头部的缓冲区中是否已经预接收到了请求包体 */
    size = r->header_in->last - r->header_in->pos;

    /* 如果头部缓冲区中已经接收到了请求包体，则检查是否已经接收到了全部的请求包体 */
    if (size || r->headers_in.chunked) {
        rc = ngx_http_discard_request_body_filter(r, r->header_in);  // 计算剩余未接收包体长度

        if (rc != NGX_OK) {
            return rc;
        }

        /*
         * 丢弃包体的时候，会使用请求对象中的r->headers_in.content_length_n来表示剩余未接收包体的长度
         */

        /* 如果剩余未接收包体长度为0，也就是接收到了所有请求包体，则表示丢弃动作执行成功，返回NGX_OK */
        if (r->headers_in.content_length_n == 0) {
            return NGX_OK;
        }
    }

    /* 读取包体 */
    rc = ngx_http_read_discarded_request_body(r);

    /* ngx_http_read_discarded_request_body返回NGX_OK表示读取包体的动作结束了，后续不用再读取包体了 */
    if (rc == NGX_OK) {
        r->lingering_close = 0;  // 将请求延迟关闭的标志位清零，表示不用再为接收包体而延迟关闭了
        return NGX_OK;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    /*
     *     返回NGX_AGAIN表明需要事件模块多次调度才能完成丢弃所有请求包体的动作，这个时候需要将请求的读事件
     * 处理函数设置为ngx_http_discarded_request_body_handler，后续该请求有读事件时，调用该函数继续读取包体。
     * 设置完之后将事件加入到epoll中进行监控。
     *     除了设置读事件处理函数和监控读事件之外，还需要将请求对象中的discard_body置位，表示当前正在进行
     * 丢弃包体的动作。同时将主请求的引用计数加1，防止Nginx处理完请求，但是客户端还没有发送完包体导致Nginx
     * 释放了请求对象，造成严重问题，在这种情况下，Nginx在结束请求时发现当前还正在进行丢弃包体的动作，所以
     * Nginx会将连接读事件加入到定时器中，并延迟关闭请求，见ngx_http_finalize_connection，如果延迟时间或者
     * 定时器超时，则不管是否接收到了完整的请求体，也会释放请求，见ngx_http_discarded_request_body_handler。
     */
    /* rc == NGX_AGAIN */

    r->read_event_handler = ngx_http_discarded_request_body_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 主请求引用计数加1，置位discard_body标志位 */
    r->count++;
    r->discard_body = 1;

    return NGX_OK;
}

/* 如果调用ngx_http_discard_request_body没能一次性读取所有包体，则后续读取包体的动作由该函数执行 */
void
ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_msec_t                 timer;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    /* 获取连接对象和读事件 */
    c = r->connection;
    rev = c->read;

    /*
     * 如果标志位rev->timedout为1，表示读取包体事件超时，这个时候需要调用ngx_http_finalize_request结束请求。
     * 在ngx_http_discard_request_body中已经将连接读事件从定时器中移除了，那这里为什么又会有定时器超时呢?
     * 原因在于如果Nginx处理完了本次请求，准备关闭请求的时候(见ngx_http_finalize_connection())发现当前请求
     * 还正在执行丢弃包体的动作(可能是客户端还没有将请求包体发送完)，这个时候还不能直接关闭请求，需要等待
     * 读取并丢弃包体动作结束，但是又不能无限制的等待，所以需要设置请求延迟关闭的时间，并将读事件加入到
     * 定时器中，如果定时器超时或者延迟关闭的时间到了，这个时候将不再等待，直接关闭请求
     */
    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* 
     * r->lingering_time也是在请求已经处理完，但是客户端还没有完全发送包体的情况下在
     * ngx_http_finalize_connection()函数中设置的。此时需要检查为接收客户端请求包体而
     * 延迟关闭请求的时间是否到了(请求在业务层面已经处理完毕)，如果到了，也直接关闭请求
     * 在ngx_http_finalize_connection()，会将r->lingering_time赋值为执行ngx_http_finalize_connection()
     * 函数的当前时间加上配置文件中配置的延迟关闭时间，表示从那一刻开始，请求将延迟clcf->lingering_time
     * 时间关闭，如果时间到了，就关闭请求
     */
    if (r->lingering_time) {
        timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();

        /* 检查延迟关闭请求的时间是否到了 */
        if ((ngx_msec_int_t) timer <= 0) {
            r->discard_body = 0;
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

    } else {
        /* 
         * r->lingering_time为0，表明请求在业务层面还没有执行完毕，因为r->lingering_time只有在
         * ngx_http_finalize_connection中会设置，执行ngx_http_finalize_connection函数时，请求已经处理完了 
         */
        timer = 0;
    }

    /* 读取需要丢弃的请求包体 */
    rc = ngx_http_read_discarded_request_body(r);

    /*
     * ngx_http_read_discarded_request_body返回NGX_OK表示丢弃包体动作成功，可以关闭连接，同时
     * 将表示正在丢弃包体的标志位清零，这样在执行ngx_http_finalize_connection()时才能关闭请求，
     * 同时将延迟关闭标志位清零
     */
    if (rc == NGX_OK) {
        r->discard_body = 0;
        r->lingering_close = 0;
        /*
         * 以NGX_DONE为参数调用ngx_http_finalize_request)()，在ngx_http_finalize_request()
         * 如果检测到参数为NGX_DONE，则会调用ngx_http_finalize_connection()将请求引用计数减1，
         * 如果引用计数为0，还是会结束请求的。
         */
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    /* ngx_http_read_discarded_request_body返回值大于等于NGX_HTTP_SPECIAL_RESPONSE表示出错，结束请求 */
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* rc == NGX_AGAIN */

    /*
     * ngx_http_read_discarded_request_body返回NGX_AGAIN，表明还没有接收到完整的请求包体，需要事件模块
     * 再次进行调度，以读取完整的请求包体，所以将连接读事件加入到epoll中
     */
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /*
     * timer不为0，表示请求在业务层面已经处理完毕了，只是为了接收包体而延迟关闭， 这个时候需要将连接对应的
     * 读事件加入到定时器中，如果定时器超时，则不再等待接收请求包体，直接关闭请求，见本函数开头部分
     */
    if (timer) {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        timer *= 1000;

        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }

        /*
         * 调用ngx_add_timer()将读事件加入到定时器中，如果该事件原来就在定时器中，则会删除原有的定时器，
         * 并将事件重新加入到定时器中，这个时候相当于定时时长又更新到了clcf->lingering_timeout。
         * 在请求延迟关闭这段时间内，如果定时器超时会关闭请求，如果事件模块本次调用调度还是没有完成丢弃包体
         * 动作，则需要更新定时器时长，表示新一轮定时。
         */
        ngx_add_timer(rev, timer);
    }
}

/* 接收包体 */
static ngx_int_t
ngx_http_read_discarded_request_body(ngx_http_request_t *r)
{
    size_t     size;
    ssize_t    n;
    ngx_int_t  rc;
    ngx_buf_t  b;
    u_char     buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.temporary = 1;

    /* 循环接收连接对应的内核套接字缓冲区中的字符流 */
    for ( ;; ) {
        /*
         * 检查剩余未接收的包体长度，如果为0，表示已经接收到了完整的包体，这个时候将连接
         * 读事件回调函数设为ngx_http_block_reading，表示再有请求触发读事件时，不做任何
         * 处理，同时返回NGX_OK，告诉上层已经成功丢弃了所有包体
         */
        if (r->headers_in.content_length_n == 0) {
            r->read_event_handler = ngx_http_block_reading;
            return NGX_OK;
        }

        /*
         * r->connection->read->ready为0，表示连接对应的内核套接字缓冲区没有可读的tcp字符流，
         * 返回NGX_AGAIN，等待事件模块再次调度
         */
        if (!r->connection->read->ready) {
            return NGX_AGAIN;
        }

        size = (size_t) ngx_min(r->headers_in.content_length_n,
                                NGX_HTTP_DISCARD_BUFFER_SIZE);

        /* 调用Nginx封装的recv接收内核套接字缓冲区中的字符流 */
        n = r->connection->recv(r->connection, buffer, size);

        /* recv返回NGX_ERROR表示连接出错，置连接中的标志位，返回NGX_OK */
        if (n == NGX_ERROR) {
            r->connection->error = 1;
            return NGX_OK;
        }

        /*
         * recv返回NGX_AGAIN，表示连接对应的内核套接字缓冲区没有可读的tcp字符流，
         * 返回NGX_AGAIN，等待事件模块再次调度
         */
        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* 如果n == 0表示客户端主动关闭了连接，不用再接收包体了，返回NGX_OK */
        if (n == 0) {
            return NGX_OK;
        }

        b.pos = buffer;
        b.last = buffer + n;

        /* 丢弃包体过滤器，即检查是否已经接收到了所有请求包体，如果没有，则计算剩余未接收包体长度 */
        rc = ngx_http_discard_request_body_filter(r, &b);

        if (rc != NGX_OK) {
            return rc;
        }
    }
}

/* 丢弃包体过滤器，即检查是否已经接收到了所有请求包体，如果没有，则计算剩余未接收包体长度 */
static ngx_int_t
ngx_http_discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t                    size;
    ngx_int_t                 rc;
    ngx_http_request_body_t  *rb;

    if (r->headers_in.chunked) {

        rb = r->request_body;

        if (rb == NULL) {

            rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
            if (rb == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
            if (rb->chunked == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->request_body = rb;
        }

        for ( ;; ) {

            rc = ngx_http_parse_chunked(r, b, rb->chunked);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                size = b->last - b->pos;

                if ((off_t) size > rb->chunked->size) {
                    b->pos += (size_t) rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    b->pos = b->last;
                }

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                r->headers_in.content_length_n = 0;
                break;
            }

            if (rc == NGX_AGAIN) {

                /* set amount of data we want to see next time */

                r->headers_in.content_length_n = rb->chunked->length;
                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }

    } else {
        /* 计算缓冲区中已经接收到的包体长度 */
        size = b->last - b->pos;

        /*
         * size > r->headers_in.content_length_n表明缓冲区中已经接收到了完整的请求头部，
         * 这个时候，将指向当前待解析的内存的指针后移content_length_n长度，并将请求对象
         * 中的r->headers_in.content_length_n置为0，表示已经接收到了全部的请求包体
         */
        if ((off_t) size > r->headers_in.content_length_n) {
            b->pos += (size_t) r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;

        } else {
            /*
             * 程序执行到这里，表明目前还没有接收到完整的请求包体，此时将b->pos指针指向
             * b->last表示已经读取并丢弃的请求体，并计算剩余未接收的包体长度
             */
            b->pos = b->last;
            r->headers_in.content_length_n -= size;
        }
    }

    return NGX_OK;
}

/* 检测Expect头部，并发送响应，激活客户端发送请求体 */
static ngx_int_t
ngx_http_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    /* 如果请求头部中并没有Expect头部或者http版本小于http1.1，则不需要检查该头部，那么直接返回NGX_OK */
    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11)
    {
        return NGX_OK;
    }

    /* 将expect_tested标志位置位，表示执行过Expect头部检测 */
    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    /* 校验Expect头部的值 */
    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    /* 往客户端发送"HTTP/1.1 100 Continue"响应，客户端接收到这个响应后开始发送请求体 */
    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (r->headers_in.chunked) {
        return ngx_http_request_body_chunked_filter(r, in);

    } else {
        return ngx_http_request_body_length_filter(r, in);
    }
}


static ngx_int_t
ngx_http_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *tl, *out, **ll;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

    if (rb->rest == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body content length filter");

        rb->rest = r->headers_in.content_length_n;
    }

    out = NULL;
    ll = &out;

    for (cl = in; cl; cl = cl->next) {

        if (rb->rest == 0) {
            break;
        }

        tl = ngx_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->temporary = 1;
        b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
        b->start = cl->buf->pos;
        b->pos = cl->buf->pos;
        b->last = cl->buf->last;
        b->end = cl->buf->end;
        b->flush = r->request_body_no_buffering;

        size = cl->buf->last - cl->buf->pos;

        if ((off_t) size < rb->rest) {
            cl->buf->pos = cl->buf->last;
            rb->rest -= size;

        } else {
            cl->buf->pos += (size_t) rb->rest;
            rb->rest = 0;
            b->last = cl->buf->pos;
            b->last_buf = 1;
        }

        *ll = tl;
        ll = &tl->next;
    }

    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


static ngx_int_t
ngx_http_request_body_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *out, *tl, **ll;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    if (rb->rest == -1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body chunked filter");

        rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
        if (rb->chunked == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_in.content_length_n = 0;
        rb->rest = 3;
    }

    out = NULL;
    ll = &out;

    for (cl = in; cl; cl = cl->next) {

        for ( ;; ) {

            ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                           "http body chunked buf "
                           "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
                           cl->buf->temporary, cl->buf->in_file,
                           cl->buf->start, cl->buf->pos,
                           cl->buf->last - cl->buf->pos,
                           cl->buf->file_pos,
                           cl->buf->file_last - cl->buf->file_pos);

            rc = ngx_http_parse_chunked(r, cl->buf, rb->chunked);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->client_max_body_size
                    && clcf->client_max_body_size
                       - r->headers_in.content_length_n < rb->chunked->size)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "client intended to send too large chunked "
                                  "body: %O+%O bytes",
                                  r->headers_in.content_length_n,
                                  rb->chunked->size);

                    r->lingering_close = 1;

                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->temporary = 1;
                b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
                b->start = cl->buf->pos;
                b->pos = cl->buf->pos;
                b->last = cl->buf->last;
                b->end = cl->buf->end;
                b->flush = r->request_body_no_buffering;

                *ll = tl;
                ll = &tl->next;

                size = cl->buf->last - cl->buf->pos;

                if ((off_t) size > rb->chunked->size) {
                    cl->buf->pos += (size_t) rb->chunked->size;
                    r->headers_in.content_length_n += rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    r->headers_in.content_length_n += size;
                    cl->buf->pos = cl->buf->last;
                }

                b->last = cl->buf->pos;

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                rb->rest = 0;

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->last_buf = 1;

                *ll = tl;
                ll = &tl->next;

                break;
            }

            if (rc == NGX_AGAIN) {

                /* set rb->rest, amount of data we want to see next time */

                rb->rest = rb->chunked->length;

                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


ngx_int_t
ngx_http_request_body_save_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

#if (NGX_DEBUG)

    for (cl = rb->bufs; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = in; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    /* TODO: coalesce neighbouring buffers */

    if (ngx_chain_add_copy(r->pool, &rb->bufs, in) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->request_body_no_buffering) {
        return NGX_OK;
    }

    if (rb->rest > 0) {

        if (rb->buf && rb->buf->last == rb->buf->end
            && ngx_http_write_request_body(r) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_OK;
    }

    /* rb->rest == 0 */

    if (rb->temp_file || r->request_body_in_file_only) {

        if (ngx_http_write_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rb->temp_file->file.offset != 0) {

            cl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;

            rb->bufs = cl;
        }
    }

    return NGX_OK;
}
