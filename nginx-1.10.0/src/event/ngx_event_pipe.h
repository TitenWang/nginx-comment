
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_PIPE_H_INCLUDED_
#define _NGX_EVENT_PIPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_pipe_s  ngx_event_pipe_t;

typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
                                                    ngx_buf_t *buf);
typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,
                                                     ngx_chain_t *chain);


struct ngx_event_pipe_s {
    ngx_connection_t  *upstream;  // Nginx与上游服务器之间的连接对象
    ngx_connection_t  *downstream;  // Nginx与下游客户端之间的连接对象

    /*
     * 直接接收上游服务器响应的缓冲区链表(未分配实际内存)，表示一次ngx_event_pipe_read_upstream方法
     * 调用过程中接收到的响应
     */
    ngx_chain_t       *free_raw_bufs;

    /*
     * 表示接收到的上游服务器的响应缓冲区，在input_filter方法中会将free_raw_bufs中的缓冲区挂载到in中
     * in链表中的缓冲区指向的是内存
     */
    ngx_chain_t       *in;

    /* 指向刚刚接收到的缓冲区 */
    ngx_chain_t      **last_in;

    ngx_chain_t       *writing;

    /*
     * 保存着将要发送给客户端的缓冲区链表，在将in链表中的内容写入临时文件时就会将内容已写入的
     * 缓冲区挂载到out中，out链表中的缓冲区对应的也就指向了文件中
     */
    ngx_chain_t       *out;

    /* 空闲可用的的缓冲区链表 */
    ngx_chain_t       *free;

    /*
     * 指向上次发送给客户端时没有发送完的缓冲区链表，这个链表中的缓冲区已经保存到的
     * 请求对象的out链表中，busy仅用于记录还有多大的响应等待发送
     */
    ngx_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */
    /* 处理接收到的来自上游服务器的缓冲区 */
    ngx_event_pipe_input_filter_pt    input_filter;
    
    /* 传递给input_filter方法的参数，一般会设置为ngx_http_request_t对象 */
    void                             *input_ctx;

    /* 发送响应给客户端的方法 */
    ngx_event_pipe_output_filter_pt   output_filter;

    /* 传递给output_filter方法的参数，一般设置为ngx_http_request_t对象 */
    void                             *output_ctx;

#if (NGX_THREADS)
    ngx_int_t                       (*thread_handler)(ngx_thread_task_t *task,
                                                      ngx_file_t *file);
    void                             *thread_ctx;
    ngx_thread_task_t                *thread_task;
#endif

    unsigned           read:1;  // 是否读取到了上游服务器响应的标志位
    unsigned           cacheable:1;  // 是否开启文件缓存标志位
    unsigned           single_buf:1;  // 为1表示接收上游响应时一次只能接收一个ngx_buf_t缓冲区
    unsigned           free_bufs:1;  // 为1表示一旦不接收上游响应包体，将尽可能立即释放缓冲区
    unsigned           upstream_done:1;  // 表示Nginx与上游服务器交互结束
    unsigned           upstream_error:1;  // 表示Nginx与上游服务器之间的连接出错
    unsigned           upstream_eof:1;  // 表示Nginx与上游服务器的连接状态，为1表示连接已经关闭
    /*
     * 表示暂时阻塞读取上游响应的流程，期待通过发送响应给下游客户端来清理出空闲的缓冲区，在用
     * 空闲的缓冲区接收响应。当upstream_blocked为1时，在ngx_event_pipe方法的循环中会先调用
     * ngx_event_pipe_write_to_downstream发送响应，再调用ngx_event_pipe_read_upstream方法来读取
     * 上游响应。
     */
    unsigned           upstream_blocked:1;
    unsigned           downstream_done:1;  // Nginx与下游客户端交互结束标志位
    unsigned           downstream_error:1;  // Nginx与下游客户端连接出错标志位
    unsigned           cyclic_temp_file:1;  // 为1表示试图复用临时文件中曾经使用过的空间
    unsigned           aio:1;  // 正在进行异步io的标志

    /* 已经分配的缓冲区数目，受bufs.num成员的限制 */
    ngx_int_t          allocated;

    /* 
     * bufs记录了用于接收上游服务器响应的内存缓冲区大小，
     * 其中bufs.size表示每个缓冲区大小，bufs.num表示缓冲区数目
     */
    ngx_bufs_t         bufs;
    ngx_buf_tag_t      tag;

    /* 
     * 设置busy缓冲区中待发送响应长度的触发值，当达到busy_size时，必须等待
     * busy缓冲区发送了足够的内容，才能继续发送out和in缓冲区中的内容
     */
    ssize_t            busy_size;

    off_t              read_length;  // 已经接收到的上游响应的长度
    off_t              length;  // 剩余未接收的上游响应的长度

    /* 缓存上游响应的临时文件的最大长度 */
    off_t              max_temp_file_size;

    /* 一次可以往临时文件写入内容的最大长度 */
    ssize_t            temp_file_write_size;

    /* 读取上游响应的超时时间 */
    ngx_msec_t         read_timeout;

    /* 发送响应给下游的超时时间 */
    ngx_msec_t         send_timeout;

    /* 发送响应给下游的tcp连接的缓冲区"水位线" */
    ssize_t            send_lowat;

    ngx_pool_t        *pool;
    ngx_log_t         *log;

    /* 预接收缓冲区，指向在接收响应包头时接收的部分响应包体数据 */
    ngx_chain_t       *preread_bufs;

    /* 预接收的响应包体数据 */
    size_t             preread_size;
    ngx_buf_t         *buf_to_file;  // 用于文件缓存场景

    size_t             limit_rate;  // 限速速率
    time_t             start_sec;  // 开始发送响应的时间戳

    /* 缓存上游服务器响应的临时文件 */
    ngx_temp_file_t   *temp_file;

    /* STUB */ int     num;
};


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
