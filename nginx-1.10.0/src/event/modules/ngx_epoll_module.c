
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

 /*
  * *****************************************epoll机制***********************************************
  * 在Linux内核中申请一个简易的文件系统，调用epoll_create方法建立一个epoll对象(在epoll文件系统中给这个句柄分配资源)
  * 然后在合适的时候调用epoll_ctl向epoll对象中添加、修改或者删除事件，最后调用epoll_wait收集已经发生的事件
  */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_EPOLL)

/* epoll declarations */
/* 表示对应的连接上有数据可以读出(tcp连接的远端主动关闭连接也相当于可读事件，因为需要处理发送来的fin包)*/
#define EPOLLIN        0x001

/*表示对应的连接上有紧急的数据需要读*/
#define EPOLLPRI       0x002

/*表示对应的连接上可以写入数据发送(主动向上游服务器发起非阻塞的tcp连接，连接建立成功的事件也相当于可写事件)*/
#define EPOLLOUT       0x004

#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400

/*表示对应的连接发生错误*/
#define EPOLLERR       0x008

/*表示对应的连接被挂起*/
#define EPOLLHUP       0x010

/*表示tcp连接的远端关闭或者半关闭连接*/
#define EPOLLRDHUP     0x2000

/*表示将事件的触发方式设置为边缘触发(ET)，系统默认为水平出发(LT)*/
#define EPOLLET        0x80000000

/*表示这个事件只处理一次，下次需要处理时需要重新加入epoll*/
#define EPOLLONESHOT   0x40000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};


int epoll_create(int size);

int epoll_create(int size)
{
    return -1;
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}


int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (NGX_HAVE_EVENTFD)
#define SYS_eventfd       323
#endif

#if (NGX_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247

typedef u_int  aio_context_t;

struct io_event {
    uint64_t  data;  /* the data field from the iocb */
    uint64_t  obj;   /* what iocb this event came from */
    int64_t   res;   /* result code for this event */
    int64_t   res2;  /* secondary result */
};


#endif
#endif /* NGX_TEST_BUILD_EPOLL */

/*epoll模块用于存储配置项参数的结构体*/
typedef struct {
    ngx_uint_t  events;
    ngx_uint_t  aio_requests;
} ngx_epoll_conf_t;


static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
#if (NGX_HAVE_EVENTFD)
static ngx_int_t ngx_epoll_notify_init(ngx_log_t *log);
static void ngx_epoll_notify_handler(ngx_event_t *ev);
#endif
static void ngx_epoll_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
#if (NGX_HAVE_EVENTFD)
static ngx_int_t ngx_epoll_notify(ngx_event_handler_pt handler);
#endif
static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);

#if (NGX_HAVE_FILE_AIO)
static void ngx_epoll_eventfd_handler(ngx_event_t *ev);
#endif

static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

/*
 * ep 表示的是epoll句柄
 * event_list 表示的是用来存储内核返回的就绪事件
 * nevents 表示的是epoll_wait一次可以返回的最多事件数目
 */
static int                  ep = -1;
static struct epoll_event  *event_list;  //用于进行epoll_wait系统调用时传递内核态事件
static ngx_uint_t           nevents;  //进行epoll_wait系统调用时一次最多可以返回的事件个数

#if (NGX_HAVE_EVENTFD)
static int                  notify_fd = -1;
static ngx_event_t          notify_event;
static ngx_connection_t     notify_conn;
#endif

#if (NGX_HAVE_FILE_AIO)

int                         ngx_eventfd = -1;  //内核文件异步io对应的描述符，由eventfd系统调用赋值
aio_context_t               ngx_aio_ctx = 0;   //内核文件异步io上下文

static ngx_event_t          ngx_eventfd_event; //内核文件异步io对应的连接对象的读事件
static ngx_connection_t     ngx_eventfd_conn;  //内核文件异步io对应的连接对象

#endif

static ngx_str_t      epoll_name = ngx_string("epoll");

/*epoll事件模块支持的配置项指令*/
static ngx_command_t  ngx_epoll_commands[] = {

    /*
     * 在调用epoll_wait时，将由第二个参数和第三个参数告诉Linux内核一次最多可以返回多少个事件，这个配置项表示,
     * 调用一次epoll_wait最多可以返回的事件数，当然它也会预分配那么多的epoll_event结构体用于存储事件
     */
    { ngx_string("epoll_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, events),
      NULL },

    /*指明在开启异步I/O且使用io_setup系统调用初始化异步I/O上下文环境时，初始分配的异步I/O事件个数*/
    { ngx_string("worker_aio_requests"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, aio_requests),
      NULL },

      ngx_null_command
};

/*ngx_epoll_module模块实现的事件模块的通用接口*/
ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
    ngx_epoll_create_conf,               /* create configuration */
    ngx_epoll_init_conf,                 /* init configuration */

    {
        ngx_epoll_add_event,             /* add an event */
        ngx_epoll_del_event,             /* delete an event */
        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */
        ngx_epoll_add_connection,        /* add an connection */
        ngx_epoll_del_connection,        /* delete an connection */
#if (NGX_HAVE_EVENTFD)
        ngx_epoll_notify,                /* trigger a notify */
#else
        NULL,                            /* trigger a notify */
#endif
        ngx_epoll_process_events,        /* process the events */
        ngx_epoll_init,                  /* init the events */
        ngx_epoll_done,                  /* done the events */
    }
};

/*ngx_epoll_module实现的模块通用接口*/
ngx_module_t  ngx_epoll_module = {
    NGX_MODULE_V1,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 */
/*
 * 初始化文件异步io的上下文，执行成功后ctx就是分配的上下文描述符，这个异步io上下文将至少可以处理nr_reqs个事件
 */
static int
io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}

/*销毁文件异步io上下文*/
static int
io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}

/*
 * 从已完成的文件异步io操作队列中读取操作，将获取[min_nr,nr]个事件，events是执行完成的事件数组,tmo是值在获取
 * min_nr个事件前的等待时间
 */
static int
io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
    struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}


static void
ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

#if (NGX_HAVE_SYS_EVENTFD_H)
    ngx_eventfd = eventfd(0, 0);  //调用eventfd()系统调用可以创建一个efd描述符
#else
    ngx_eventfd = syscall(SYS_eventfd, 0);
#endif

    if (ngx_eventfd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "eventfd() failed");
        ngx_file_aio = 0;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", ngx_eventfd);

    n = 1;

    /*设置ngx_eventfd为非阻塞*/
    if (ioctl(ngx_eventfd, FIONBIO, &n) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

    /*初始化文件异步io上下文，aio_requests表示至少可以处理的异步文件io事件个数*/
    if (io_setup(epcf->aio_requests, &ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "io_setup() failed");
        goto failed;
    }

    /*设置异步io完成时通知的事件*/
    ngx_eventfd_event.data = &ngx_eventfd_conn;  //ngx_event_t->data成员通常就是事件对应的连接对象
    ngx_eventfd_event.handler = ngx_epoll_eventfd_handler;
    ngx_eventfd_event.log = cycle->log;
    ngx_eventfd_event.active = 1;  //active为1，表示就绪，其实是下面就要将其加入到epoll中所以这里置1
    ngx_eventfd_conn.fd = ngx_eventfd;
    ngx_eventfd_conn.read = &ngx_eventfd_event;  //内核文件异步io对应的连接对象读事件为ngx_eventfd_event
    ngx_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;  //监控读事件
    ee.data.ptr = &ngx_eventfd_conn;

    /*将异步文件io的通知的描述符加入到epoll监控中*/
    if (epoll_ctl(ep, EPOLL_CTL_ADD, ngx_eventfd, &ee) != -1) {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(ngx_eventfd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    ngx_eventfd = -1;
    ngx_aio_ctx = 0;
    ngx_file_aio = 0;
}

#endif

/*
 * 初始化epoll模块
 * 1.调用epoll_create方法创建epoll对象
 * 2.创建event_list数组，用于进行epoll_wait调用时传递内核态事件
 * 3.初始化eventfd(如果配置了的话)
 * 4.初始化异步文件IO(如果配置了的话)
 * 5.设置epoll的触发方式为ET模式
 */
static ngx_int_t
ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_epoll_conf_t  *epcf;

	/*获取ngx_epoll_module模块用于存储配置项参数的结构体*/
    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);

    if (ep == -1) {
		/*调用epoll_create系统调用创建epoll句柄*/
        ep = epoll_create(cycle->connection_n / 2);

        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }

#if (NGX_HAVE_EVENTFD)
        if (ngx_epoll_notify_init(cycle->log) != NGX_OK) {
            ngx_epoll_module_ctx.actions.notify = NULL;
        }
#endif

#if (NGX_HAVE_FILE_AIO)

        ngx_epoll_aio_init(cycle, epcf);

#endif
    }

    if (nevents < epcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

		/*申请用于存放epoll_wait返回的就绪事件，注意内存是直接向操作系统申请的*/
        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

	/*初始化nevents*/
    nevents = epcf->events;

    ngx_io = ngx_os_io;

	/*初始化全局事件驱动模块的actions回调方法*/
    ngx_event_actions = ngx_epoll_module_ctx.actions;

#if (NGX_HAVE_CLEAR_EVENT)
	/*默认采用ET触发方式*/
    ngx_event_flags = NGX_USE_CLEAR_EVENT
#else
    ngx_event_flags = NGX_USE_LEVEL_EVENT
#endif
                      |NGX_USE_GREEDY_EVENT
                      |NGX_USE_EPOLL_EVENT;

    return NGX_OK;
}


#if (NGX_HAVE_EVENTFD)

static ngx_int_t
ngx_epoll_notify_init(ngx_log_t *log)
{
    struct epoll_event  ee;

#if (NGX_HAVE_SYS_EVENTFD_H)
    notify_fd = eventfd(0, 0);
#else
    notify_fd = syscall(SYS_eventfd, 0);
#endif

    if (notify_fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "eventfd() failed");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "notify eventfd: %d", notify_fd);

    notify_event.handler = ngx_epoll_notify_handler;
    notify_event.log = log;
    notify_event.active = 1;

    notify_conn.fd = notify_fd;
    notify_conn.read = &notify_event;
    notify_conn.log = log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &notify_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, notify_fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

        if (close(notify_fd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                            "eventfd close() failed");
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_epoll_notify_handler(ngx_event_t *ev)
{
    ssize_t               n;
    uint64_t              count;
    ngx_err_t             err;
    ngx_event_handler_pt  handler;

    if (++ev->index == NGX_MAX_UINT32_VALUE) {
        ev->index = 0;

        n = read(notify_fd, &count, sizeof(uint64_t));

        err = ngx_errno;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "read() eventfd %d: %z count:%uL", notify_fd, n, count);

        if ((size_t) n != sizeof(uint64_t)) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, err,
                          "read() eventfd %d failed", notify_fd);
        }
    }

    handler = ev->data;
    handler(ev);
}

#endif

/*nginx退出服务的时候调用，释放内存及清零全局变量，关闭epoll文件句柄*/
static void
ngx_epoll_done(ngx_cycle_t *cycle)
{
	//关闭epoll句柄
    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (NGX_HAVE_EVENTFD)

    if (close(notify_fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    notify_fd = -1;

#endif

#if (NGX_HAVE_FILE_AIO)

    if (ngx_eventfd != -1) {

        if (io_destroy(ngx_aio_ctx) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "io_destroy() failed");
        }

        if (close(ngx_eventfd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "eventfd close() failed");
        }

        ngx_eventfd = -1;
    }

    ngx_aio_ctx = 0;

#endif

	/*释放event_list*/
    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
}

/*向epoll中添加或者修改事件*/
static ngx_int_t
ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*获取事件对应的连接*/
    c = ev->data;

    /*下面会根据event参数确定当前事件是读事件还是写事件，这会决定events是加上EPOLLIN还是EPOLLOUT标志位*/
    events = (uint32_t) event;

    /*
     * 在Nginx中通过是epoll_ctl来监控读写事件的，这个时候的操作主要有两个，add和mod。当一个fd第一次注册到epoll
     * 时我们使用的是add操作方式，如果之前对这个fd已经添加过读写事件的监控，那么就需要通过mod来修改原来的监控方式
     * 如果一个fd被重复add，会报错
     */
    /*
     * 基于上面所说的epoll_ctl的注意之处，Nginx为了避免这种情况发生，当需要在epoll加入对一个fd的读事件进行监控时，
     * Nginx先看下这个fd对应的写事件的状态，如果这个fd对应的写事件是有效的，即e->active标志位为1，表明之前这个fd
     * 以NGX_WRITE_EVENT加入(add)到epoll中了，此时只需要使用mod方式修改其监控方式即可，不能采用add方式。当加入对一个fd
     * 的写事件的监控也是一个意思。
     */

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (NGX_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
#if (NGX_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

	/*
	 * e是ev事件对应连接的读或者写事件
	 * ev如果是读事件，则e为对应的写事件，如果e为active，表明ev对应的c是存在的，此时op为modify
	 * ev如果是写事件，则e为对应的读事件，如果e为active，表明ev对应的c是存在的，此时op为modify
	 * 相反的，如果e不是active，表明是新增事件
	 */
    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;  //将之前的event也加入到events中，新旧事件标志都需要进行监控

    } else {
        op = EPOLL_CTL_ADD;
    }

    /*加入flags到events标志位中*/
    ee.events = events | (uint32_t) flags;
    /*将事件的instance标志位添加到连接最后一位用于后续判断事件是否过期,在处理事件的时候用来判断事件是否已经过期了*/
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    /*调用epoll_ctl向epoll对象中添加或者修改事件*/
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

	//因为fd对应的该事件已经加入到了epoll中，因此置为活跃
    ev->active = 1;
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NGX_OK;
}

/*用于向epoll中删除或者修改事件*/
static ngx_int_t
ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        return NGX_OK;
    }

    /*获取事件对应的连接*/
    c = ev->data;

	/*此处原理类似于add_event中的实现*/
    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
    }

    /*
     * e->active为1表明这个fd已经通过另一个事件加入到epoll的监控中了，因为我们现在要移除这个fd对应的event类型的事件,
     * 那么我们需要通过mod方式修改，只保留该fd加入到epoll中的除了event之外的其他类型的事件。举个例子，如果这个fd已经
     * 把NGX_READ_EVENT和NGX_WRITE_EVENT都加入到epoll监控中了，此次需要移除NGX_READ_EVENT，那么就只在epoll保留该fd的
     * NGX_WRITE_EVENT类型的事件
     */
    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;  //保留除了此次需要移除的事件类型之外的其他之前已经加入到epoll监控的事件类型
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

	/*因为该fd的该事件已经从epoll中移除了，所以将该fd对应的该事件置为不活跃*/
    ev->active = 0;

    return NGX_OK;
}

/*向epoll中添加一个新的连接*/
static ngx_int_t
ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    /*将连接对应的读写事件都加入epoll中*/
    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

	/* 
	 * 将连接对应的读和写事件均设置为活跃，因为添加一个连接到epoll监控中，那么表示这个连接对应的读写事件均
	 * 加入epoll监控中了
     */
    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}

/*从epoll中移除对一个连接的监控*/
static ngx_int_t
ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    /*
     * 如果flags包含了NGX_CLOSE_EVENT，说明连接对应的fd已经关闭了，那么我们就不需要调用epoll_ctl移除，系统会自动移除
     * 这个时候只需要把连接对应的读写事件的标志位清零即可
     */
    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    /*执行移除操作*/
    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    /*如果是从epoll中移除这个连接，那么需要将这个连接对应的读写事件的active标志位清零*/
    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


#if (NGX_HAVE_EVENTFD)
/*封装了eventfd相关的write系统调用*/
static ngx_int_t
ngx_epoll_notify(ngx_event_handler_pt handler)
{
    static uint64_t inc = 1;

    notify_event.data = handler;

    if ((size_t) write(notify_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
        ngx_log_error(NGX_LOG_ALERT, notify_event.log, ngx_errno,
                      "write() to eventfd %d failed", notify_fd);
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif

/*epoll事件处理函数，用于收集和分发就绪事件*/
static ngx_int_t
ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                events;
    uint32_t           revents;
    ngx_int_t          instance, i;
    ngx_uint_t         level;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    ngx_queue_t       *queue;
    ngx_connection_t  *c;

    /* NGX_TIMER_INFINITE == INFTIM */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);

    /*通过系统调用epoll_wait获取已经发生的事件，返回值为获取的就绪事件个数，如果为-1，表示调用出错*/
    events = epoll_wait(ep, event_list, (int) nevents, timer);

    err = (events == -1) ? ngx_errno : 0;

	//更新时间
    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update();
    }

    /*错误处理*/
    if (err) {
        if (err == NGX_EINTR) {

            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }

	/*如果就绪的事件为0，且timer不为NGX_TIMER_INFINITE，则立刻返回*/
    if (events == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return NGX_ERROR;
    }

	/*循环处理epoll_wait返回的就绪事件*/
    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;  //获取事件对应的连接

        instance = (uintptr_t) c & 1; //取出添加事件到epoll中附加的事件超时标志位instance
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);  //还原连接，去除最后一位的instance标志位

		/*获取读事件*/
        rev = c->read;

		/*事件过期*/
        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

		/*获取事件类型*/
        revents = event_list[i].events;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        /*连接出现错误，EPOLLHUP表示收到了对方发送的rst报文。检测到这两种类型时，tcp连接中可能还有数据未被读取*/
        if (revents & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);
        }

#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif

        /*
         * 1）监听的fd(监听socket)，此fd的设置等待事件：EPOLLIN 或者EPOLLET |EPOLLIN 
         *     
         *    由于此socket只监听有无连接，谈不上写和其他操作。故只有这两类。（默认是LT模式，即EPOLLLT |EPOLLIN）    
         *    说明：如果在这个socket上也设置EPOLLOUT等，也不会出错，只是这个socket不会收到这样的消息。
         *
         * 2）客户端正常关闭,即client 端close()联接
         *     对端正常关闭（程序里close()，shell下kill或ctr+c），触发EPOLLIN和EPOLLRDHUP，
         * 但是不触发EPOLLERR和EPOLLHUP.
         *     server会报某个sockfd可读，即EPOLLIN来临。然后recv一下，如果返回0再掉用epoll_ctl中的
         * EPOLL_CTL_DEL , 同时close(sockfd)。
         *     有些系统会收到一个EPOLLRDHUP，当然检测这个是最好不过了。只可惜是有些系统检测不到，
         * 如果能加上对EPOLLRDHUP的处理那就是万能的了。
         *
         * 3）客户端异常关闭：
         *     客户端异常关闭，会触发EPOLLERR和EPOLLHUP，并不会通知服务器。正常关闭时服务端执行read可以返回0。
         * 异常断开时检测不到的,此时服务器再给一个已经关闭的socket写数据时会出错，服务器才明白对方可能已经异常断开了（读也可以）。
         *     epoll中就是向已经断开的socket写或者读，会发生EPOLLERR，即表明已经断开。
         */

        /*
         * 如果连接发生错误但未置EPOLLIN及EPOLLOUT，这时我们加上EPOLLIN和EPOLLOUT，在调用读/写事件的
         * 回调函数时就会知道为什么出现错误。 如果不加EPOLLIN和EPOLLOUT，后面就没法调用读/写事件的
         * 回调函数也就无法处理该连接了。
         * 只有在采取行动（比如读一个已经关闭的socket，或者写一个已经关闭的socket）时候，才知道对方是否关闭了。
         * 这个时候，如果对方异常关闭了，则会出现EPOLLERR
         */
        if ((revents & (EPOLLERR|EPOLLHUP))
             && (revents & (EPOLLIN|EPOLLOUT)) == 0)
        {
            /*
             * if the error events were returned without EPOLLIN or EPOLLOUT,
             * then add these flags to handle the events at least in one
             * active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

		/*如果是读事件且为活跃*/
        if ((revents & EPOLLIN) && rev->active) {

#if (NGX_HAVE_EPOLLRDHUP)
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }
#endif

            rev->ready = 1;  //读事件准备就绪

			/*
			 * NGX_POST_EVENTS表示延后处理，根据是否是新连接事件将事件加入两个队列。
			 * 如果是新连接事件，则加入到ngx_posted_accept_events，否则加入到ngx_posted_events
			 * 在ngx_event_process_and_timer()中处理完ngx_posted_accept_events后就会释放负载均衡锁
			 */
            if (flags & NGX_POST_EVENTS) {
                queue = rev->accept ? &ngx_posted_accept_events
                                    : &ngx_posted_events;

                ngx_post_event(rev, queue);

            } else {
                rev->handler(rev);  //立即调用读事件的回调方法处理这个事件
            }
        }

		//获取写事件
        wev = c->write;

        if ((revents & EPOLLOUT) && wev->active) {
			//如果过期了
            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            wev->ready = 1;  //写事件准备就绪
#if (NGX_THREADS)
            wev->complete = 1;
#endif
			//延后处理，写事件不可能是新连接事件
            if (flags & NGX_POST_EVENTS) {
                ngx_post_event(wev, &ngx_posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return NGX_OK;
}


#if (NGX_HAVE_FILE_AIO)

/*epoll_wait返回ngx_eventfd_event事件后就会调用其回调该方法处理已经完成的异步io事件*/
static void
ngx_epoll_eventfd_handler(ngx_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    ngx_err_t         err;
    ngx_event_t      *e;
    ngx_event_aio_t  *aio;
    struct io_event   event[64]; //一次性最多处理64个异步io事件
    struct timespec   ts;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    /*通过read获取已经完成的事件数目，并设置到ready中，注意这里的ready可以大于64*/
    n = read(ngx_eventfd, &ready, 8);

    err = ngx_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    while (ready) {

        /*从已完成的异步io队列中读取已完成的事件，返回值代表获取的事件个数*/
        events = io_getevents(ngx_aio_ctx, 1, 64, event, &ts);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %d", events);

        if (events > 0) {
            ready -= events;  //计算剩余已完成的异步io事件

            for (i = 0; i < events; i++) {

                ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %XL %XL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                /*data成员指向这个异步io事件对应着的实际事件*/
                e = (ngx_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;  
                e->ready = 1;  //事件已经就绪

                aio = e->data;
                aio->res = event[i].res;

                ngx_post_event(e, &ngx_posted_events);  //将异步io事件加入到ngx_posted_events普通读写事件队列中
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif

/*创建用于存储ngx_epoll_module配置项参数的结构体*/
static void *
ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;

    epcf = ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = NGX_CONF_UNSET;
    epcf->aio_requests = NGX_CONF_UNSET;

    return epcf;
}

/*对于配置文件中没有出现的配置项，用默认值初始化相对应的结构体成员*/
static char *
ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;

    ngx_conf_init_uint_value(epcf->events, 512);
    ngx_conf_init_uint_value(epcf->aio_requests, 32);

    return NGX_CONF_OK;
}
