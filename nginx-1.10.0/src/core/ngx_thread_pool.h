
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NGX_THREAD_POOL_H_INCLUDED_
#define _NGX_THREAD_POOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/* 线程任务对象类型 */
struct ngx_thread_task_s {
    ngx_thread_task_t   *next;  /* 任务用链表进行管理 */
    ngx_uint_t           id;
    void                *ctx;
    /* 线程任务处理函数 */
    void               (*handler)(void *data, ngx_log_t *log);
    ngx_event_t          event;  /* 线程任务对应的事件对象 */
};


typedef struct ngx_thread_pool_s  ngx_thread_pool_t;


ngx_thread_pool_t *ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name);
ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name);

/* 创建一个线程任务 */
ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *pool, size_t size);

/* 线程任务分发，其实就是将任务添加到tp->queue队列中 */
ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task);


#endif /* _NGX_THREAD_POOL_H_INCLUDED_ */
