
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_atomic_t   lock;
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;
#endif
} ngx_shmtx_sh_t;


typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)     //用原子变量实现互斥锁，它指向的是一段共享内存空间，为0表示可以获得锁
    ngx_atomic_t  *lock;      //原子变量锁
#if (NGX_HAVE_POSIX_SEM)      //支持信号量
    ngx_atomic_t  *wait;      //表示等待获取原子变量锁而使用的信号量锁个数(暂时不是很理解)
    ngx_uint_t     semaphore; //semaphore为1表示获取锁时可能使用到信号量
    sem_t          sem;       //信号量锁
#endif
#else                         //用文件锁实现互斥锁
    ngx_fd_t       fd;        //表示文件句柄
    u_char        *name;      //文件名
#endif
    //自旋次数，表示在自旋状态下等待其他处理器执行结果中释放锁的时间(仅在多处理器状态下才有意义)，
    //由文件锁实现时无意义，spin值为-1则是告诉Nginx这把锁不能让进程进入睡眠状态
    ngx_uint_t     spin;
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
