
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
 * ngx_shmtx_t中的lock表示当前锁的状态，如果为0，表示当前没有进程持有锁
 * 当lock值为负数的时候，表示有进程正持有锁
 */

#if (NGX_HAVE_ATOMIC_OPS) //用原子变量实现ngx_shmtx_t互斥锁


static void ngx_shmtx_wakeup(ngx_shmtx_t *mtx);


ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
    /*其实这一步就是把共享内存的首地址赋值给了原子变量锁*/
    mtx->lock = &addr->lock;

    /*mtx->spin为-1时，表示不能使用信号量，直接返回成功*/
    if (mtx->spin == (ngx_uint_t) -1) {
        return NGX_OK;
    }

    /*spin表示的是自旋等待其他处理器释放锁的时间*/
    mtx->spin = 2048;

#if (NGX_HAVE_POSIX_SEM)

    mtx->wait = &addr->wait;

    /*
     * int  sem init (sem_t  sem,  int pshared,  unsigned int value) ,
     * 其中，参数sem即为我们定义的信号量，而参数pshared将指明sem信号量是用于
     * 进程间同步还是用于线程间同步，当pshared为0时表示线程间同步，
     * 而pshared为1时表示进程间同步。由于Nginx的每个进程都是单线程的，
     * 因此将参数pshared设为1即可。参数value表示信号量sem的初始值。
     */
    /*以多进程使用的方式初始化sem信号量，sem初始值为0*/
    if (sem_init(&mtx->sem, 1, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_init() failed");
    } else {
        mtx->semaphore = 1;  //信号量成功初始化后，semaphore置为1，表示获取锁时会使用信号量
    }

#endif

    return NGX_OK;
}


/*该方法的唯一目的就是释放信号量*/
void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)

    //mtx->spin 不为-1，且信号量初始化成功时，mtx->semaphore才为1
    if (mtx->semaphore) {
        if (sem_destroy(&mtx->sem) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}

/*
 * *mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)
 * *mtx->lock == 0表明目前没有进程持有锁，多进程的Nginx服务将有可能出现以下情况:
 * 就是第一个语句(*mtx->lock == 0)执行成功,但在执行第二个语句前，又有一个进程拿到了锁，
 * 这时第二个语句会执行失败，这正是ngx_atomic_cmp_set方法自身先判断lock值是否为0的原因，
 * 只有lock值仍为0，才能成功获取锁，并成功设置lock值为当前进程的id
 */
 
/*
 * 此方法为非阻塞方法，不管有没有获取到锁都会返回，返回1表示获取到锁，返回0表示没有
 */
ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid));
}


/*
 * 此方法为阻塞方法，没有获取到锁不会返回，返回表示已经获取到了锁
 */
void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_uint_t         i, n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");

    /*没有获取到锁时，会一直执行这个死循环内的代码*/
    for ( ;; ) {

        /*尝试获取锁，获取到了就返回，这判断条件的意思在上面已经讲述*/
        if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
            return;
        }

        /*表示有多处理器，其中spin值也只有在多处理器情况下才有意义，否则pause指令不会执行*/
        if (ngx_ncpu > 1) {

            /*随着没有获取到锁等待的时间越长，将会执行更多的pause执行后才会再次尝试获取锁(获取锁的时间间隔会越长)*/
            for (n = 1; n < mtx->spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();  //对于多处理器系统，执行ngx_cpu_pause()可降低功耗
                }

                /*尝试获取锁*/
                if (*mtx->lock == 0
                    && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid))
                {
                    return;
                }
            }
        }

#if (NGX_HAVE_POSIX_SEM)

        /*semaphore字段为1，表示会使用信号量*/
        if (mtx->semaphore) {
            (void) ngx_atomic_fetch_add(mtx->wait, 1);

            /*尝试获取锁*/
            if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
                (void) ngx_atomic_fetch_add(mtx->wait, -1);
                return;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "shmtx wait %uA", *mtx->wait);

            /*
             * sem_wait函数也是一个原子操作，它的作用是从信号量的值减去一个“1”，
             * 但它永远会先等待该信号量为一个非零值才开始做减法。也就是说，如果sem
             * 的值大于0，则该函数会将该sem值减一，表示拿到了信号量互斥锁，然后立即返回；
             * 如果该sem的值为0或者负数，则函数会一直阻塞(睡眠)并等待其他进程把sem值加1后
             * 等待操作系统调度到这个进程时再做减一动作并返回
             * 函数调用成功返回0，调用失败的话返回-1，信号量sem的值不变，错误码有errno指示
             * sem_wait()函数可能会使进程进入睡眠状态，会使当前进程"让出"处理器
             */
            while (sem_wait(&mtx->sem) == -1) {
                ngx_err_t  err;

                err = ngx_errno;

                /*NGX_EINTR,操作被信号处理中断，并不是出错*/
                if (err != NGX_EINTR) {
                    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                                  "sem_wait() failed while waiting on shmtx");
                    break;
                }
            }

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "shmtx awoke");

            //此处加continue是因为当使用了信号量时就不会再调用ngx_sched_yiled()
            continue;
        }

#endif

        //在不使用信号量时，调用这个函数会使当前进程暂时"让出"处理器
        ngx_sched_yield();
    }
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    /*spin != -1表示在多处理器状态下会自旋等待获取锁*/
    if (mtx->spin != (ngx_uint_t) -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
    }

    /*该函数先是判断当前锁是否被当前进程拥有，如果是，则将其置0，表示释放该锁*/
    /*ngx_atomic_cmp_set设置成功返回1*/
    if (ngx_atomic_cmp_set(mtx->lock, ngx_pid, 0)) {
        ngx_shmtx_wakeup(mtx);
    }
}

/*强制性获得锁*/
/*
 * 在ngx_shmtx_lock方法运行一段时间后，如果其他进程始终不释放锁，那么当前金城关
 */
ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx forced unlock");

    if (ngx_atomic_cmp_set(mtx->lock, pid, 0)) {
        ngx_shmtx_wakeup(mtx);
        return 1;
    }

    return 0;
}

/*唤醒进程*/
static void
ngx_shmtx_wakeup(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_uint_t  wait;

    /*semaphore标志位为0，表示不使用信号量，立即返回*/
    if (!mtx->semaphore) {
        return;
    }

    for ( ;; ) {

        wait = *mtx->wait;

        /*如果lock锁原先的值为0，也就是说没有进程持有该锁，直接返回*/
        if ((ngx_atomic_int_t) wait <= 0) {
            return;
        }

        /*将wait值设置为原来的值减一*/
        if (ngx_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx wake %uA", wait);

    /*通过sem_post将信号量的值加1，表示当前进程已经释放了信号量互斥锁，通知其他进程的sem_wait继续执行*/
    if (sem_post(&mtx->sem) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


#else
/*用文件锁实现的互斥锁*/


ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
    if (mtx->name) {

        if (ngx_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return NGX_OK;
        }

        ngx_shmtx_destroy(mtx);
    }

    mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NGX_OK;
}


void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
    if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", mtx->name);
    }
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == NGX_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == NGX_EACCES) {
        return 0;
    }

#endif

    ngx_log_abort(err, ngx_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_lock_fd_n " %s failed", mtx->name);
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_unlock_fd_n " %s failed", mtx->name);
}


ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    return 0;
}

#endif
