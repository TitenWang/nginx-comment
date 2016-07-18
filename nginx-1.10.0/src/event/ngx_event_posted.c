
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 *     Nginx出于充分发挥多核cpu架构性能的考虑，使用了多个worker子进程监听相同端口的设计，这样多个worker子进程在accept
 * 建立新连接时会有争抢，从来带来著名的"惊群"问题。另外在建立连接时还会涉及到负载均衡的问题，在多个worker子进程
 * 争抢处理一个新连接事件时，一定只有一个worker子进程最终会成功建立连接，随后它会一直处理这个连接直到连接关闭。
 * 上述两个问题问题的解决离不开Nginx的post机制。这个post机制表示的是允许事件延后执行。Nginx设计了两个post队列，一个
 * 是由被触发的监听连接的读事件构成的ngx_posted_accept_events队列，一个是由普通读/写事件构成的ngx_posted_events队列
 * post机制的具体功能如下:
 *     1.将epoll_wait产生的一批事件，分到这两个队列中，让存放着新连接事件的ngx_posted_accept_events队列优先执行，存放着
 * 普通事件的ngx_posted_events队列后面执行。这是解决负载均衡和"惊群"的关键。
 *     2.如果在处理一个事件的过程中产生了另一个事件，而我们希望这个事件随后执行(不是立刻执行)，就可以将其放入到post
 * 队列中。
 */


ngx_queue_t  ngx_posted_accept_events;  //存放着被触发的监听连接的读事件
ngx_queue_t  ngx_posted_events;  //存放着普通的读写事件

/*处理两个post事件队列*/
void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    while (!ngx_queue_empty(posted)) {

        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        ngx_delete_posted_event(ev);  //从队列中移除这个事件，内存并没有释放，只是从双向链表中脱离

        ev->handler(ev);  //如果是新连接事件，那么这个handler就是ngx_event_accept()建立连接
    }
}
