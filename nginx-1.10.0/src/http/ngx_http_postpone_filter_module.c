
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 *     Nginx是多进程的处理架构，所以对于单个进程而言是不能够随意阻塞的，如果一个请求由于某种原因阻塞了当前
 * 进程，则意味着该进程就不能处理该进程之前接收到的所有请求了，也不能继续接收信的请求了。如果在实际应用
 * 场景中某个请求由于处理需要会阻塞进程，那么Nginx的做法是设置该请求的一些状态，并将请求加入到epoll中
 * 进行监控，等待事件模块调度再进行请求处理，然后转去处理其他请求了。这样意味着一个请求可能需要执行多次
 * 才能完成处理，对于一个请求的多个子请求而言，意味着它们完成的先后顺序和它们被创建的顺序不一定是一致的，
 * 而我们知道发送到客户端的数据一定要按照子请求创建顺序来发送，所以需要有一种机制来保证如果有某个子请求
 * 提前完成的请求处理，需要有地方保存它的数据而不是直接输出到out chain中，同时也要能够让可以往客户端发送
 * 数据的请求再完成请求处理后立即发送所产生的数据。这种机制是通过连接对象ngx_connection_t中的data字段、
 * 过滤模块ngx_http_postpone_filter_module和ngx_http_finalize_request中的部分逻辑共同实现的。
 *     上述内容参考: http://blog.csdn.net/fengmo_q/article/details/6685840
 *     在ngx_http_subrequest()函数中提到连接对象中的data字段指向的是当前可以往客户端发送响应的请求。
 */


static ngx_int_t ngx_http_postpone_filter_add(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_postpone_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_postpone_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_postpone_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_postpone_filter_module_ctx,  /* module context */
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

/* 连接所有过滤模块的链表指针 */
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_postpone_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_connection_t              *c;
    ngx_http_postponed_request_t  *pr;

    c = r->connection;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);

    /*
     * r != c->data表明当前请求不能往out chain中发送响应数据(如子请求提前完成)，此时需要将in中的响应数据
     * 保存在自己的postponed链表中，因为该链表既可以用来存放请求产生的子请求，也可以用来
     * 存放请求产生的响应数据。
     */
    if (r != c->data) {

        if (in) {
            ngx_http_postpone_filter_add(r, in);
            return NGX_OK;
        }

#if 0
        /* TODO: SSI may pass NULL */
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "http postpone filter NULL inactive request");
#endif

        return NGX_OK;
    }

    /*
     * 程序执行到这里表明当前请求可以往out chain中发送数据，如果当前请求没有子请求节点，也没有数据节点，
     * 则直接发送的当前响应数据in或者继续发送上次没有发送完的out链表中的响应数据
     */
    if (r->postponed == NULL) {

        if (in || c->buffered) {
            return ngx_http_next_body_filter(r->main, in);
        }

        return NGX_OK;
    }

    /*
     * 程序执行到这里，表明虽然当前请求可以往out chain中发送数据，但是该请求有子请求或者数据节点，在这种情况下
     * 需要先处理子请求或者数据节点，那么这个时候需要先将此次要发送的数据保存在自己的postponed链表中
     */
    if (in) {
        ngx_http_postpone_filter_add(r, in);
    }

    /*
     * 处理当前请求的postponed链表，有可能是子请求节点，也有可能是数据节点
     */
    do {
        pr = r->postponed;

        /*
         * 如果当前r->postponed链表节点存储的是子请求，则将子请求挂载到原始请求的posted_requests链表中
         * 这样可以保证下次执行ngx_http_run_posted_requests()是可以处理到这个子请求
         */
        if (pr->request) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter wake \"%V?%V\"",
                           &pr->request->uri, &pr->request->args);

            r->postponed = pr->next;  // 将r->postponed指向下一个节点

            /* 因为请求的子请求往out chain中发送数据的优先级高于自身，所以将c->date设为子请求 */
            c->data = pr->request;

            /* 将这个子请求加入到原始请求的posted_requests链表末端 */
            return ngx_http_post_request(pr->request, NULL);
        }

        /*
         * 程序执行到这里表明当前处理的posted链表中的节点可能是一个数据节点
         */
         
        if (pr->out == NULL) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "http postpone filter NULL output");

        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter output \"%V?%V\"",
                           &r->uri, &r->args);

            /* 将请求的数据节点中的数据发送到out chain链表中 */
            if (ngx_http_next_body_filter(r->main, pr->out) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        r->postponed = pr->next;  // 继续处理请求对象中r->postponed链表中的下一个节点

    } while (r->postponed);

    return NGX_OK;
}

/*
 * 将请求的产生的数据in挂载到请求的postponed链表末尾节点的out成员中
 */
static ngx_int_t
ngx_http_postpone_filter_add(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_postponed_request_t  *pr, **ppr;

    /*
     * 遍历当前请求的postponed成员链表至末尾，然后在末尾申请一个ngx_http_postponed_request_t类型
     * 的节点，然后将in链表中的数据存放到ngx_http_postponed_request_t类型节点的out字段中
     */
    if (r->postponed) {
        for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

        if (pr->request == NULL) {
            goto found;
        }

        ppr = &pr->next;

    } else {
        ppr = &r->postponed;
    }

    /*
     * 申请用于存放数据的ngx_http_postponed_request_t对象
     */
    pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
    if (pr == NULL) {
        return NGX_ERROR;
    }

    /* 将上面申请到的ngx_http_postponed_request_t对象挂在到请求的postponed链表末尾 */
    *ppr = pr;

    pr->request = NULL;
    pr->out = NULL;
    pr->next = NULL;

found:

    /* 将in中的所有数据缓冲区挂载到chain中 */
    if (ngx_chain_add_copy(r->pool, &pr->out, in) == NGX_OK) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_postpone_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_postpone_filter;

    return NGX_OK;
}
