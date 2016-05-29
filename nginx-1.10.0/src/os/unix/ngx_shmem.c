
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Nginx各进程间共享数据的主要方式是使用共享内存，一般来说，共享内存是由master进程创建，
 * 在master进程fork出worker子进程后，所有的进程都开始使用这块共享内存中的数据了
 */

//NGX_HAVE_MAP_ANON表示用mmap系统调用实现获取和释放共享内存的方法
#if (NGX_HAVE_MAP_ANON)

ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    /*
     * void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)
     * 1. 该系统调用可以将磁盘文件映射到内存中，由内核同步内存和磁盘文件中的数据
     * 2. fd是文件描述符句柄，表示用来映射的磁盘文件
     * 3. offset表示从文件的这个偏移量开始共享
     * 4. 当flags参数中加入MAP_ANON或者MAP_ANONYMOUS时表示不使用文件映射方式，此时fd和offset无意义
     * 5. prot表示操作此块共享内存的方式，如PROT_READ或者PROT_WRITE等
     * 6. length表示的是此块共享内存的长度
     * 7. start表示的是希望共享内存的起始地址，通常设为NULL
     */
    shm->addr = (u_char *) mmap(NULL, shm->size,
                                PROT_READ|PROT_WRITE,
                                MAP_ANON|MAP_SHARED, -1, 0);

    if (shm->addr == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    /*解除映射，释放共享内存*/
    if (munmap((void *) shm->addr, shm->size) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

//NGX_HAVE_MAP_DEVZERO表示以/dev/zero文件使用mmap实现共享内存
#elif (NGX_HAVE_MAP_DEVZERO)

ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    ngx_fd_t  fd;

    fd = open("/dev/zero", O_RDWR);

    if (fd == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "open(\"/dev/zero\") failed");
        return NGX_ERROR;
    }

    shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ|PROT_WRITE,
                                MAP_SHARED, fd, 0);

    if (shm->addr == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "mmap(/dev/zero, MAP_SHARED, %uz) failed", shm->size);
    }

    if (close(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "close(\"/dev/zero\") failed");
    }

    return (shm->addr == MAP_FAILED) ? NGX_ERROR : NGX_OK;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

//NGX_HAVE_SYSVSHM表示使用shmget系统调用来分配和释放共享内存
#elif (NGX_HAVE_SYSVSHM)

#include <sys/ipc.h>
#include <sys/shm.h>


ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    int  id;

    /*
     * int shmget(key_t key, size_t size, int flag);获取一个共享内存标识符或者
     *      创建一个共享内存对象并返回共享内存标识符
     * 1.key:表示标识符规则 size表示共享内存的大小 flag表示读写权限
     * 2. key标识共享内存的键值: 0/IPC_PRIVATE。 当key的取值为IPC_PRIVATE，
     *   则函数shmget()将创建一块新的共享内存；如果key的取值为0，而参数shmflg中
     *   设置了IPC_PRIVATE这个标志，则同样将创建一块新的共享内存。
     * 3.返回值：成功返回共享存储的id，失败返回-1
     */
    id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));

    if (id == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "shmget(%uz) failed", shm->size);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm->log, 0, "shmget id: %d", id);

    /*
     * void *shmat(int shmid, const void *addr, int flag);把共享内存区对象映射到调用进程的地址空间
     * 1.shmid表示共享存储id
     * 2.addr 一般为0
     * 3.flag 一般为0
     * 4.返回值：如果成功，返回共享存储段地址，出错返回-1
     */
    shm->addr = shmat(id, NULL, 0);

    if (shm->addr == (void *) -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno, "shmat() failed");
    }

    /*
     * int shmctl(int shmid,int cmd,struct shmid_ds *buf) 完成对共享内存的控制
     * 1.shmid共享存储id
     * 2.cmd有以下三种:
     *    1) IPC_STAT:得到共享内存的状态，把共享内出中的shmid_ds结构体复制到buf中
     *    2) IPC_SET:改变共享内存的状态，把buf中的uid，gid，mode等复制到共享内存的shmid_ds中
     *    3) IPC_RMID:删除这块共享内存
     */
    if (shmctl(id, IPC_RMID, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "shmctl(IPC_RMID) failed");
    }

    return (shm->addr == (void *) -1) ? NGX_ERROR : NGX_OK;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    /*
     * int shmdt(const void *shmaddr)
     * 用来断开与共享内存的连接，禁止本进程访问这块共享内存，并不会删除shmaddr指向的共享内存
     */
    if (shmdt(shm->addr) == -1) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "shmdt(%p) failed", shm->addr);
    }
}

#endif
