
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_slab_page_s  ngx_slab_page_t;

struct ngx_slab_page_s {
    uintptr_t         slab;  //多用途，描述页相关信息，bitmap和内存块大小
    ngx_slab_page_t  *next;  //指向双向链表中的下一个页
    uintptr_t         prev;  //指向双向链表前一个页，低2位用于存放内存块类型
};


typedef struct {
    ngx_shmtx_sh_t    lock;      

    size_t            min_size;  //一页中最小内存块(chunk)大小
    size_t            min_shift; //一页中最小内存块对应的偏移

    ngx_slab_page_t  *pages;     //slab内存池中所有页的描述
    ngx_slab_page_t  *last;      //指向最后一个可用页
    ngx_slab_page_t   free;      //内存池中空闲页组成链表头部

    u_char           *start;     //实际页起始地址
    u_char           *end;       //实际页结束地址

    ngx_shmtx_t       mutex;     //slab内存池互斥锁

    u_char           *log_ctx;
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;     
    void             *addr;      //指向内存池起始地址
} ngx_slab_pool_t;


void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
