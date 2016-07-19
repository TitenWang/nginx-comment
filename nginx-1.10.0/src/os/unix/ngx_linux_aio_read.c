
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


extern int            ngx_eventfd;
extern aio_context_t  ngx_aio_ctx;


static void ngx_file_aio_event_handler(ngx_event_t *ev);


static int
io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall(SYS_io_submit, ctx, n, paiocb);
}

/*
 * 初始化文件异步io对象,其中file为要读取的file文件对象，file->aio为读文件的异步io对象
 */
ngx_int_t
ngx_file_aio_init(ngx_file_t *file, ngx_pool_t *pool)
{
    ngx_event_aio_t  *aio;

    /*申请内存*/
    aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
    if (aio == NULL) {
        return NGX_ERROR;
    }

    aio->file = file;  //file为要读取的file文件对象
    aio->fd = file->fd;  //aio->fd即为要读的文件描述符
    
    /*
     * 在这里将异步io事件的data成员赋值为异步io对象，这个在ngx_epoll_eventfd_handler()和
     * ngx_file_aio_event_handler()中有体现
     */
    aio->event.data = aio;
    
    aio->event.ready = 1;
    aio->event.log = file->log;

    file->aio = aio;

    return NGX_OK;
}

/*Nginx封装的异步io事件提交函数*/
ssize_t
ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    ngx_err_t         err;
    struct iocb      *piocb[1];
    ngx_event_t      *ev;
    ngx_event_aio_t  *aio;

    if (!ngx_file_aio) {
        return ngx_read_file(file, buf, size, offset);
    }

    /*ngx_event_aio_t封装的异步io对象，如果file->aio为空，需要初始化file->aio*/
    if (file->aio == NULL && ngx_file_aio_init(file, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    aio = file->aio;
    ev = &aio->event;

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%uz %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->active = 0;
        ev->complete = 0;

        if (aio->res >= 0) {
            ngx_set_errno(0);
            return aio->res;
        }

        ngx_set_errno(-aio->res);

        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "aio read \"%s\" failed", file->name.data);

        return NGX_ERROR;
    }

    /*提交异步事件之前要初始化结构体struct iocb*/
    ngx_memzero(&aio->aiocb, sizeof(struct iocb));

    /*
     * 将struct iocb的aio_data成员赋值为异步io事件对象，下面提交异步事件之后，等该事件完成，在通过io_getevents()
     * 获取到事件后，对应的struct io_event结构体中的data成员就会指向这个事件。
     * struct iocb的aio_data成员和struct io_event的data成员指向的是同一个东西
     */
    aio->aiocb.aio_data = (uint64_t) (uintptr_t) ev;
    aio->aiocb.aio_lio_opcode = IOCB_CMD_PREAD;
    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_buf = (uint64_t) (uintptr_t) buf;
    aio->aiocb.aio_nbytes = size;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_flags = IOCB_FLAG_RESFD;  //设置为IOCB_FLAG_RESFD表示内核有异步io请求处理完时通过eventfd通知应用程序
    aio->aiocb.aio_resfd = ngx_eventfd;  //这个就是eventfd描述符

    /*
     * 当io_getevents()函数中获取到该异步io事件时，会调用该回调函数，在Nginx中并不是直接调用，而是先将其加入到
     * ngx_posted_event队列，等遍历完所有完成的异步io事件后，再依次调用所有事件的回调函数
     */
    ev->handler = ngx_file_aio_event_handler;

    piocb[0] = &aio->aiocb;

    /*将该异步io请求加入到异步io上下文中，等待io完成，内核会通过eventfd通知应用程序*/
    if (io_submit(ngx_aio_ctx, 1, piocb) == 1) {
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return NGX_AGAIN;
    }

    err = ngx_errno;

    if (err == NGX_EAGAIN) {
        return ngx_read_file(file, buf, size, offset);
    }

    ngx_log_error(NGX_LOG_CRIT, file->log, err,
                  "io_submit(\"%V\") failed", &file->name);

    if (err == NGX_ENOSYS) {
        ngx_file_aio = 0;
        return ngx_read_file(file, buf, size, offset);
    }

    return NGX_ERROR;
}

/*文件异步io事件完成后的回调函数*/
static void
ngx_file_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t  *aio;

    aio = ev->data;  //获取事件对应的data对象，即ngx_event_aio_t，这个ngx_file_aio_init()函数中初始化的

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    /*
     * 这个回调是由真正的业务模块实现的，举个例子如果是http cache模块，则会在ngx_http_file_cache_aio_read()函数中
     * 调用完ngx_file_aio_read()后设置为ngx_http_cache_aio_event_handler()进行业务逻辑的处理，为什么要在调用完
     * ngx_file_aio_read()之后再设置呢，因为可能业务模块一开始并没有为ngx_file_t对象设置ngx_event_aio_t对象，而是在
     * ngx_file_aio_read()中调用ngx_file_aio_init()进行初始化的。
     */
    aio->handler(ev);
}
