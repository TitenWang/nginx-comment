
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_write_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_write_filter_module_ctx,     /* module context */
    NULL,                                  /* module directives */
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

/*
 * 用于发送http响应包体和响应头，第二个参数in就是本次待发送的响应
 */
ngx_int_t
ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                      size, sent, nsent, limit;
    ngx_uint_t                 last, flush, sync;
    ngx_msec_t                 delay;
    ngx_chain_t               *cl, *ln, **ll, *chain;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    /* c->error为1表示当前连接出错，那么直接返回NGX_ERROR */
    if (c->error) {
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */

    /*
     * 请求对象中的out成员保存着上次未发送的响应。例如在调用ngx_http_send_header()方法发送
     * 响应头部时，如果头部过大导致无法一次性发送完毕，那么将会把剩余的响应头部放在out链表
     * 成员中。
     */

    /*
     * 这里就是遍历请求对象中的out链表，计算其中的缓冲区共占用了多大的字节数，并且如果其中的
     * 如果其中的某一个缓冲区设置了flush或recycled，则flush标志位会置位;如果设置了sync，则sync
     * 标志位置位;如果设置了last_buf，则last标志位置位。上面的三个标志位中任意一个置位，则可以
     * 发送响应
     */
    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf); // 累加out链中所有buf的大小

        /* 判断是否设置了flush或者recycled */
        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        /* 判断是否设置了sync */
        if (cl->buf->sync) {
            sync = 1;
        }

        /* 判断是否设置了last_buf */
        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    /*
     * 遍历存放着本次需要发送的响应的in链表，将其加入到out链表的末尾，并计算out缓冲区
     * 共占用多少个字节数，为后续发送响应做准备
     */
    for (ln = in; ln; ln = ln->next) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        /* 如果in链表中的任一缓冲区设置了flush或recycled，则flush置位 */
        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        /* 如果in链表中的任一缓冲区设置了sync，则sync置位 */
        if (cl->buf->sync) {
            sync = 1;
        }
        /* 如果in链表中的任一缓冲区设置了last_buf，则last_buf置位 */
        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    /*
     * 在上面遍历out链表和in链表的中的缓冲区的时候，会检查每个缓冲区中的三个标志位，
     * 分别是flush、recycled、last_buf，如果这三个标志位同时为0，则表示待发送的out链表
     * 中没有一个缓冲区表示响应已经结束或者需要立刻发送出去。而且虽然本次需要发送的缓冲区
     * 链表in并不为空，但上述两个计算缓冲区大小步骤计算出来的大小又小于配置文件中的
     * postpone_output参数，那么说明当前缓冲区是不完整的且没有必要立刻发送，则直接返回
     */
    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return NGX_OK;
    }

    /*
     * 如果当前连接对应的写事件中的delayed标志位为1，表示需要本次调度需要减速，是不可以发送响应的
     * 需要延迟发送。这个时候会设置连接中的buffered标志位为 NGX_HTTP_WRITE_BUFFERED，表示当前响应
     * 被缓存在了NGX_HTTP_WRITE_BUFFERED阶段，同时返回NGX_AGAIN，告诉http框架out缓冲区中还有响应
     * 等待发送。
     */
    if (c->write->delayed) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    if (size == 0
        && !(c->buffered & NGX_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        if (last || flush || sync) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    /*
     * 如果请求对象中的r->limit_rate大于0，则表明发送响应的速度的不能超过
     * limit_rate指定的速度，limit_rate表示的就是每秒可以发送的最大字节数，
     * 超过这个数字就需要限速。然而，限速这个动作必须是在发送limit_rate_after
     * 字节的响应后才能生效
     */
    if (r->limit_rate) {
        if (r->limit_rate_after == 0) {
            r->limit_rate_after = clcf->limit_rate_after;
        }

        /* 计算限速 */
        limit = (off_t) r->limit_rate * (ngx_time() - r->start_sec + 1)
                - (c->sent - r->limit_rate_after);

        /*
         * 如果limit小于0，表示已经发送的需要限速的字节数大于从开始处理请求到现在最多
         * 可以发送的字节数，此时就需要限速了。
         */
        if (limit <= 0) {
            c->write->delayed = 1;  // 将写事件中的延迟发送标志位置位
            delay = (ngx_msec_t) (- limit * 1000 / r->limit_rate + 1);

            /*
             * 将写事件加入到定时器中，这个步骤会将之前在ngx_http_finalize_request中加入的定时器移除，
             * 什么情况下会在ngx_http_finalize_request中将写事件加入定时器呢?其实是在响应头部或者响应体
             * 过大而无法一次性将响应头部或者响应体发送完毕的时候，就会将写事件加入到定时器中和epoll中
             * 让事件模块重新调度发送剩余的响应
             */
            ngx_add_timer(c->write, delay);

            /*
             * 因为本次发送需要限速，所以不能发送响应，则需要将连接中的buffered标志位设置为
             * NGX_HTTP_WRITE_BUFFERED，表示响应缓存在NGX_HTTP_WRITE_BUFFERED阶段，并返回NGX_AGAIN,
             * 告诉http框架out缓冲区链表中仍有未发送的http响应
             */
            c->buffered |= NGX_HTTP_WRITE_BUFFERED;

            return NGX_AGAIN;
        }

        /*
         * 如果limit大于0，表明到目前为止，发送的响应体还没有达到限速的时候，并且limit就是本次可以发送的
         * 响应体长度，当然如果limit大于配置文件中的sendfile_max_chunk，则limit设置为sendfile_max_chunk
         */
        if (clcf->sendfile_max_chunk
            && (off_t) clcf->sendfile_max_chunk < limit)
        {
            limit = clcf->sendfile_max_chunk;
        }

    } else {
        /* 如果r->limit_rate小于等于0，表示不需要限速，则此次发送大小为sendfile_max_chunk */
        limit = clcf->sendfile_max_chunk;
    }

    /* c->sent表示的是已经发送的字节数 */
    sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    /*
     * 调用c->send_chain发送out链表，该函数的返回值即为本次未发送完毕的缓冲区链表头
     */
    chain = c->send_chain(c, r->out, limit);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    /* 如果发送缓冲区链表失败，则将c->error置位，表示连接出错 */
    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    if (r->limit_rate) {

        nsent = c->sent;

        if (r->limit_rate_after) {

            sent -= r->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= r->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        delay = (ngx_msec_t) ((nsent - sent) * 1000 / r->limit_rate);

        if (delay > 0) {
            limit = 0;
            c->write->delayed = 1;
            ngx_add_timer(c->write, delay);
        }
    }

    if (limit
        && c->write->ready
        && c->sent - sent >= limit - (off_t) (2 * ngx_pagesize))
    {
        c->write->delayed = 1;
        ngx_add_timer(c->write, 1);
    }

    /* 释放out缓冲区链表中已经发送出去了的缓冲区内存，未发送的缓冲区链表并没有被释放 */
    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    /*
     * 将r->out成员指向存放剩余未发送的响应的缓冲区链表头部
     */
    r->out = chain;

    /*
     * chain不为空，表明当前仍然有剩余未发送完的响应，那么需要将连接中的buffered标志位设置为
     * NGX_HTTP_WRITE_BUFFERED，表示响应缓存在了NGX_HTTP_WRITE_BUFFERED阶段，同时需要返回
     * NGX_AGAIN，告诉http框架out成员中仍有未发送的响应，需要进行再次调度。这里返回NGX_AGAIN,
     * 其实最终会走到NGX_HTTP_CONTENT_PHASE阶段的checker方法ngx_http_core_content_phase中，
     * 并且请求的r->content_handler也会返回NGX_AGAIN(因为发送响应头或者响应体的函数一般都是在
     * r->content_handler中调用的)，然后在ngx_http_finalize_request函数中
     * 检测到NGX_AGAIN，则会将写事件回调设置为ngx_http_writer，并加入到epoll中，如果没有限速的话，
     * 也会加入到定时器中.
     */
    if (chain) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    /*
     * 程序执行到这里，表明响应在NGX_HTTP_WRITE_BUFFERED阶段已经发送完毕了，因此需要将连接对象的buffered标志位中
     * NGX_HTTP_WRITE_BUFFERED对应的位清空，表明响应并没有缓存在NGX_HTTP_WRITE_BUFFERED阶段
     */
    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

    /*
     * 如果连接对象的buffered标志位中NGX_LOWLEVEL_BUFFERED对应的位为1，表明响应还缓存在更底层，因此还需要再次调度
     * 进行发送
     */
    if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return NGX_AGAIN;
    }

    /*
     * 程序执行到这里表明响应都发送完毕了，此时r->content_handler中也会返回NGX_OK，然后用NGX_OK去调用
     * ngx_http_finalize_request()来结束请求
     */
    return NGX_OK;
}

/* 将ngx_http_write_filter加入到过滤响应包体的链表中 */
static ngx_int_t
ngx_http_write_filter_init(ngx_conf_t *cf)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
