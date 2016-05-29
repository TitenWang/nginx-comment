
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/*用于描述共享内存的结构体*/
typedef struct {
    u_char      *addr;  //指向共享内存的的起始地址
    size_t       size;  //共享内存的大小
    ngx_str_t    name;  //共享内存的名字
    ngx_log_t   *log;
    ngx_uint_t   exists;   /* unsigned  exists:1;  */ //表示共享内存是否已经分配过
} ngx_shm_t;


ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHMEM_H_INCLUDED_ */
