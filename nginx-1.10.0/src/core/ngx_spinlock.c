
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * 1.自旋锁是一种非睡眠锁，也就是说如果某个进程试图获取自旋锁，而锁已经被其他进程获得，那么
 * 不会使当前进程进入睡眠状态，而是始终保持进程在可执行状态，每当内核调度到该进程执行时，
 * 进程会持续检查是否可以获取该锁。
 * 获取不到锁时，该进程会一直在自旋锁代码处执行，直到其他进程释放锁且当前进程获取锁，代码才会
 * 继续向下执行
 * 2.自旋锁要解决的共享资源保护场景是每个进程使用锁的时间非常短，且使用锁的进程不希望自己没有 
 * 获取到锁的时候进入到睡眠状态
 * 3.如果进程拿不到锁，可能会使某一类请求无法执行，而epoll上的其他请求还是可以执行的，此时不能
 * 使用自旋锁，而应该使用非阻塞的互斥锁
 */

/*自旋锁*/
void
ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin)
{

#if (NGX_HAVE_ATOMIC_OPS)

    ngx_uint_t  i, n;

    //无法获取锁时，进程将一直在这段代码中执行
    for ( ;; ) {

        /*
         * *mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)
         * *mtx->lock == 0表明目前没有进程持有锁，多进程的Nginx服务将有可能出现以下情况:
         * 就是第一个语句(*mtx->lock == 0)执行成功,但在执行第二个语句前，又有一个进程拿到了锁，
         * 这时第二个语句会执行失败，这正是ngx_atomic_cmp_set方法自身先判断lock值是否为0的原因，
         * 只有lock值仍为0，才能成功获取锁，并成功设置lock值为当前进程的id
         */
        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
            return;
        }

        if (ngx_ncpu > 1) {

            for (n = 1; n < spin; n <<= 1) {

                //自旋等待一段时间，随着等待的时间越长，尝试获取锁的时间间隔也越来越长
                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();  //执行这个，当前进程没有"让出"处理器
                }

                if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }

        /*
         * 调用这个函数会使当前进程暂时"让出"处理器,但是当前进程仍处于可执行状态，只是让处理器
         * 优先调度其他处于可执行状态的进程，当进程被内核再次调度时，在for循环代码中可以继续尝试
         * 获取锁
         */
        
        ngx_sched_yield();
    }

#else

#if (NGX_THREADS)

#error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !

#endif

#endif

}
