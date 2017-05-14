
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) Ruslan Ermilov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_thread_pool.h>


/* 
 * 用于存放配置文件中配置的线程池信息，pools动态数组每个元素都是一个线程池配置对象，
 * 类型为ngx_thread_pool_t，参考ngx_thread_pool_add()
 */
typedef struct {
    ngx_array_t               pools;
} ngx_thread_pool_conf_t;

/* 线程池任务队列 */
typedef struct {
    ngx_thread_task_t        *first;
    ngx_thread_task_t       **last;
} ngx_thread_pool_queue_t;

#define ngx_thread_pool_queue_init(q)                                         \
    (q)->first = NULL;                                                        \
    (q)->last = &(q)->first

/* 线程池对象类型 */
struct ngx_thread_pool_s {
    ngx_thread_mutex_t        mtx;
    ngx_thread_pool_queue_t   queue;  /* 任务等待队列 */
    ngx_int_t                 waiting;  /* 当前任务等待队列中的任务个数 */
    ngx_thread_cond_t         cond;

    ngx_log_t                *log;

    ngx_str_t                 name;  /* 线程池名字 */
    ngx_uint_t                threads;  /* 线程池中线程的数量 */
    /* 
     * 等待队列中任务的最大个数，当线程池中所有线程都处于busy状态时，
     * 任务就会被缓存到队列中，如果队列满了，任务就会返回错误。
     */
    ngx_int_t                 max_queue;

    /* 配置文件的名字 */
    u_char                   *file;

    /* thread_pool命令在配置文件中的行号 */
    ngx_uint_t                line;
};


static ngx_int_t ngx_thread_pool_init(ngx_thread_pool_t *tp, ngx_log_t *log,
    ngx_pool_t *pool);
static void ngx_thread_pool_destroy(ngx_thread_pool_t *tp);
static void ngx_thread_pool_exit_handler(void *data, ngx_log_t *log);

static void *ngx_thread_pool_cycle(void *data);
static void ngx_thread_pool_handler(ngx_event_t *ev);

static char *ngx_thread_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_thread_pool_create_conf(ngx_cycle_t *cycle);
static char *ngx_thread_pool_init_conf(ngx_cycle_t *cycle, void *conf);

static ngx_int_t ngx_thread_pool_init_worker(ngx_cycle_t *cycle);
static void ngx_thread_pool_exit_worker(ngx_cycle_t *cycle);

/* ngx_thread_pool_module模块支持的配置命令 */
static ngx_command_t  ngx_thread_pool_commands[] = {

    { ngx_string("thread_pool"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE23,
      ngx_thread_pool,
      0,
      0,
      NULL },

      ngx_null_command
};

/* ngx_thread_pool_module模块的上下文信息 */
static ngx_core_module_t  ngx_thread_pool_module_ctx = {
    ngx_string("thread_pool"),
    ngx_thread_pool_create_conf,
    ngx_thread_pool_init_conf
};


ngx_module_t  ngx_thread_pool_module = {
    NGX_MODULE_V1,
    &ngx_thread_pool_module_ctx,           /* module context */
    ngx_thread_pool_commands,              /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_thread_pool_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_thread_pool_exit_worker,           /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* 线程池默认名字，如果配置文件中没有配置名字的，则会采用这个默认的名字 */
static ngx_str_t  ngx_thread_pool_default = ngx_string("default");

/* 任务id */
static ngx_uint_t               ngx_thread_pool_task_id;
static ngx_atomic_t             ngx_thread_pool_done_lock;
/* 用于存放处理完的任务(调用了task->handler()回调)的队列 */
static ngx_thread_pool_queue_t  ngx_thread_pool_done;

/* 线程池初始化 */
static ngx_int_t
ngx_thread_pool_init(ngx_thread_pool_t *tp, ngx_log_t *log, ngx_pool_t *pool)
{
    int             err;
    pthread_t       tid;
    ngx_uint_t      n;
    pthread_attr_t  attr;

    if (ngx_notify == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
               "the configured event method cannot be used with thread pools");
        return NGX_ERROR;
    }

    /* 初始化线程中的任务队列 */
    ngx_thread_pool_queue_init(&tp->queue);

    /* 创建pthread_mutex_t */
    if (ngx_thread_mutex_create(&tp->mtx, log) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 创建pthread_cond_t */
    if (ngx_thread_cond_create(&tp->cond, log) != NGX_OK) {
        (void) ngx_thread_mutex_destroy(&tp->mtx, log);
        return NGX_ERROR;
    }

    tp->log = log;

    err = pthread_attr_init(&attr);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      "pthread_attr_init() failed");
        return NGX_ERROR;
    }

#if 0
    err = pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      "pthread_attr_setstacksize() failed");
        return NGX_ERROR;
    }
#endif

    /* 根据配置的线程数量，创建对应数量的线程 */
    for (n = 0; n < tp->threads; n++) {
        err = pthread_create(&tid, &attr, ngx_thread_pool_cycle, tp);
        if (err) {
            ngx_log_error(NGX_LOG_ALERT, log, err,
                          "pthread_create() failed");
            return NGX_ERROR;
        }
    }

    (void) pthread_attr_destroy(&attr);

    return NGX_OK;
}

/* 销毁线程池 */
static void
ngx_thread_pool_destroy(ngx_thread_pool_t *tp)
{
    ngx_uint_t           n;
    ngx_thread_task_t    task;
    volatile ngx_uint_t  lock;

    ngx_memzero(&task, sizeof(ngx_thread_task_t));

    /* 设置一个线程销毁任务 */
    task.handler = ngx_thread_pool_exit_handler;
    task.ctx = (void *) &lock;

    /* 对于线程池中的每一个线程，设置一个线程终止任务 */
    for (n = 0; n < tp->threads; n++) {
        lock = 1;

        /* 任务分发，将任务加入到tp->queue队列中，后续线程池中的线程会从队列中取出任务做处理 */
        if (ngx_thread_task_post(tp, &task) != NGX_OK) {
            return;
        }

        /* 等待 */
        while (lock) {
            ngx_sched_yield();
        }

        task.event.active = 0;
    }

    /* 销毁pthread_cond_t和pthread_mutex_t对象 */
    (void) ngx_thread_cond_destroy(&tp->cond, tp->log)
    (void) ngx_thread_mutex_destroy(&tp->mtx, tp->log);
}

/* 线程调用pthread_exit()让自身终止 */
static void
ngx_thread_pool_exit_handler(void *data, ngx_log_t *log)
{
    ngx_uint_t *lock = data;

    *lock = 0;

    pthread_exit(0);
}


/* 创建一个线程任务 */
ngx_thread_task_t *
ngx_thread_task_alloc(ngx_pool_t *pool, size_t size)
{
    ngx_thread_task_t  *task;

    task = ngx_pcalloc(pool, sizeof(ngx_thread_task_t) + size);
    if (task == NULL) {
        return NULL;
    }

    /* 
     * 因为task类型为ngx_thread_task_t，所以task + 1之后的地址就指向了
     * size部分对应的内存起始地址，即往后偏移了sizeof(ngx_thread_task_t)大小，
     * 这部分内存是留给需要用到线程池的模块用来存放私有数据的。这部分可以参考
     * 函数ngx_thread_write_chain_to_file()
     */
    task->ctx = task + 1;

    return task;
}

/* 给线程分发任务，将任务添加到tp->queue队列中，并唤醒挂起的线程 */
ngx_int_t
ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task)
{
    /* 如果任务对应的事件是活跃的，则不能再次分发该任务 */
    if (task->event.active) {
        ngx_log_error(NGX_LOG_ALERT, tp->log, 0,
                      "task #%ui already active", task->id);
        return NGX_ERROR;
    }

    /* 尝试获取互斥锁tp->mtx */
    if (ngx_thread_mutex_lock(&tp->mtx, tp->log) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 
     * 如果等待队列中任务数量已经超过了max_queue，则返回失败，最多只能缓存
     * tp->max_queue个的任务
     */
    if (tp->waiting >= tp->max_queue) {
        (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);

        ngx_log_error(NGX_LOG_ERR, tp->log, 0,
                      "thread pool \"%V\" queue overflow: %i tasks waiting",
                      &tp->name, tp->waiting);
        return NGX_ERROR;
    }

    /* 将任务对应的事件设置为活跃 */
    task->event.active = 1;

    task->id = ngx_thread_pool_task_id++;
    task->next = NULL;

    /* 
     *     pthread_cond_signal函数的作用是发送一个信号给一个正在处于
     * 阻塞等待状态的线程,使其脱离阻塞状态,继续执行.如果没有线程处在
     * 阻塞等待状态,pthread_cond_signal也会成功返回。当tp->queue队列中
     * 没有任务的时候，线程池中的线程就会挂起，等待任务分发后被唤醒，
     * 这部分可以参考ngx_thread_pool_cycle()这个线程处理函数。
     *     使用pthread_cond_signal不会有“惊群现象”产生，它最多只给一个线程
     * 发信号。假如有多个线程正在阻塞等待着这个条件变量的话，那么是根据各等待
     * 线程优先级的高低确定哪个线程接收到信号开始继续执行。如果各线程优先级相同，
     * 则根据等待时间的长短来确定哪个线程获得信号。但无论如何一个pthread_cond_signal
     * 调用最多发信号一次。
     *     pthread_cond_wait必须放在pthread_mutex_lock和pthread_mutex_unlock之间，
     * 因为它要根据共享变量的状态来决定是否要等待，而为了不永远等待下去。
     * 所以必须要在lock/unlock队中
     */
    if (ngx_thread_cond_signal(&tp->cond, tp->log) != NGX_OK) {
        (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
        return NGX_ERROR;
    }

    /* 将任务加入到线程池等待队列中 */
    *tp->queue.last = task;
    tp->queue.last = &task->next;

    /* 累加等待任务的个数统计 */
    tp->waiting++;

    (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                   "task #%ui added to thread pool \"%V\"",
                   task->id, &tp->name);

    return NGX_OK;
}

/* 线程处理函数 */
static void *
ngx_thread_pool_cycle(void *data)
{
    ngx_thread_pool_t *tp = data;

    int                 err;
    sigset_t            set;
    ngx_thread_task_t  *task;

#if 0
    ngx_time_update();
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, tp->log, 0,
                   "thread in pool \"%V\" started", &tp->name);

    sigfillset(&set);

    sigdelset(&set, SIGILL);
    sigdelset(&set, SIGFPE);
    sigdelset(&set, SIGSEGV);
    sigdelset(&set, SIGBUS);

    err = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, tp->log, err, "pthread_sigmask() failed");
        return NULL;
    }

    for ( ;; ) {
        if (ngx_thread_mutex_lock(&tp->mtx, tp->log) != NGX_OK) {
            return NULL;
        }

        /* the number may become negative */
        /* 
         * 每次循环处理一个任务，所以队列中任务会少一个，等待的任务就少一个。
         * 但是为什么放在这里而不是放在任务处理完了之后呢?
         */
        tp->waiting--;

        /* 
         * 如果tp->queue队列为空，就先挂起等待，后续分发任务之后会被唤醒，
         * 分发任务后唤醒挂起线程这部分处理可以参考ngx_thread_task_post()函数
         */
        while (tp->queue.first == NULL) {
            if (ngx_thread_cond_wait(&tp->cond, &tp->mtx, tp->log)
                != NGX_OK)
            {
                (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
                return NULL;
            }
        }

        /* 从任务等待队列中取出一个任务 */
        task = tp->queue.first;
        tp->queue.first = task->next;

        if (tp->queue.first == NULL) {
            tp->queue.last = &tp->queue.first;
        }

        if (ngx_thread_mutex_unlock(&tp->mtx, tp->log) != NGX_OK) {
            return NULL;
        }

#if 0
        ngx_time_update();
#endif

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                       "run task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        /* 调用任务的处理函数 */
        task->handler(task->ctx, tp->log);

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                       "complete task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        task->next = NULL;

        ngx_spinlock(&ngx_thread_pool_done_lock, 1, 2048);

        /* 将处理完了的任务加入到ngx_thread_pool_done队列中 */
        *ngx_thread_pool_done.last = task;
        ngx_thread_pool_done.last = &task->next;

        ngx_memory_barrier();

        ngx_unlock(&ngx_thread_pool_done_lock);

        /* 
         * 对ngx_thread_pool_done队列中的任务做收尾工作，对于epoll来说，
         * ngx_notify就是指ngx_epoll_notify()函数 
         */
        (void) ngx_notify(ngx_thread_pool_handler);
    }
}

/* 对ngx_thread_pool_done队列中的任务做收尾工作 */
static void
ngx_thread_pool_handler(ngx_event_t *ev)
{
    ngx_event_t        *event;
    ngx_thread_task_t  *task;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "thread pool handler");

    ngx_spinlock(&ngx_thread_pool_done_lock, 1, 2048);

    task = ngx_thread_pool_done.first;
    ngx_thread_pool_done.first = NULL;
    ngx_thread_pool_done.last = &ngx_thread_pool_done.first;

    ngx_memory_barrier();

    ngx_unlock(&ngx_thread_pool_done_lock);

    /* 循环处理ngx_thread_pool_done队列中的任务，做收尾工作 */
    while (task) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "run completion handler for task #%ui", task->id);

        /* 获取任务对应的事件对象 */
        event = &task->event;
        task = task->next;

        /* 将表示事件异步操作完成的标志置位 */
        event->complete = 1;
        event->active = 0;

        /* 调用事件处理函数 */
        event->handler(event);
    }
}

/* 创建用于存放ngx_thread_pool_module模块配置信息的内存 */
static void *
ngx_thread_pool_create_conf(ngx_cycle_t *cycle)
{
    ngx_thread_pool_conf_t  *tcf;

    tcf = ngx_pcalloc(cycle->pool, sizeof(ngx_thread_pool_conf_t));
    if (tcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&tcf->pools, cycle->pool, 4,
                       sizeof(ngx_thread_pool_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return tcf;
}

/* 解析完配置项之后调用 */
static char *
ngx_thread_pool_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_thread_pool_conf_t *tcf = conf;

    ngx_uint_t           i;
    ngx_thread_pool_t  **tpp;

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->threads) {
            continue;
        }

        /* 如果默认的thread_pool没有设置线程数和队列长度，则设置为默认值 */
        if (tpp[i]->name.len == ngx_thread_pool_default.len
            && ngx_strncmp(tpp[i]->name.data, ngx_thread_pool_default.data,
                           ngx_thread_pool_default.len)
               == 0)
        {
            tpp[i]->threads = 32;
            tpp[i]->max_queue = 65536;
            continue;
        }

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "unknown thread pool \"%V\" in %s:%ui",
                      &tpp[i]->name, tpp[i]->file, tpp[i]->line);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* thread_pool命令的解析函数 */
static char *
ngx_thread_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t          *value;
    ngx_uint_t          i;
    ngx_thread_pool_t  *tp;

    /* 存放了配置文件中thread_pool命令的配置信息，第一个元素为命令名，后续为命令参数 */
    value = cf->args->elts;

    /* 添加一个线程池对象到内存中 */
    tp = ngx_thread_pool_add(cf, &value[1]);

    if (tp == NULL) {
        return NGX_CONF_ERROR;
    }

    /* 如果tp->threads不为0，说明之前已经解析过同名的线程池信息，所以返回失败 */
    if (tp->threads) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate thread pool \"%V\"", &tp->name);
        return NGX_CONF_ERROR;
    }

    /* 默认情况下tp->max_queue为65536 */
    tp->max_queue = 65536;

    for (i = 2; i < cf->args->nelts; i++) {

        /* 解析线程池数量信息 */
        if (ngx_strncmp(value[i].data, "threads=", 8) == 0) {

            tp->threads = ngx_atoi(value[i].data + 8, value[i].len - 8);

            if (tp->threads == (ngx_uint_t) NGX_ERROR || tp->threads == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid threads value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        /* 解析等待队列长度信息 */
        if (ngx_strncmp(value[i].data, "max_queue=", 10) == 0) {

            tp->max_queue = ngx_atoi(value[i].data + 10, value[i].len - 10);

            if (tp->max_queue == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_queue value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
    }

    /* 如果配置文件中没有配置线程池中线程的数量，则返回失败 */
    if (tp->threads == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"threads\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* 往ngx_thread_pool_module模块的配置信息中添加一个线程池对象 */
ngx_thread_pool_t *
ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_thread_pool_t       *tp, **tpp;
    ngx_thread_pool_conf_t  *tcf;

    /* 如果没有配置名字，则采用默认的名字 */
    if (name == NULL) {
        name = &ngx_thread_pool_default;
    }

    /* 
     * 尝试用配置文件中配置的线程池名字去内存中查找是否有相同名字的线程池，
     * 如果有，则返回；否则将当前线程池添加到内存中
     */
    tp = ngx_thread_pool_get(cf->cycle, name);

    if (tp) {
        return tp;
    }

    tp = ngx_pcalloc(cf->pool, sizeof(ngx_thread_pool_t));
    if (tp == NULL) {
        return NULL;
    }

    tp->name = *name;
    
    /* 保存配置文件的名字和thread_pool命令在配置文件中的行号 */
    tp->file = cf->conf_file->file.name.data;
    tp->line = cf->conf_file->line;

    /* 获取ngx_thread_pool_module模块的配置项结构体对象 */
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    tpp = ngx_array_push(&tcf->pools);
    if (tpp == NULL) {
        return NULL;
    }

    *tpp = tp;

    return tp;
}

/* 
 * 根据名字，尝试从存放了所有线程池对象的内存中找到对应名字的线程池对象，
 * 如果没有找到，则返回NULL
 */
ngx_thread_pool_t *
ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    /* 遍历所有的线程池对象，找到名字匹配的线程池 */
    tpp = tcf->pools.elts;
    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->name.len == name->len
            && ngx_strncmp(tpp[i]->name.data, name->data, name->len) == 0)
        {
            return tpp[i];
        }
    }

    return NULL;
}

/* 在初始化worker子进程的时候调用 */
static ngx_int_t
ngx_thread_pool_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    /* 获取ngx_thread_pool_module模块的配置信息 */
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    if (tcf == NULL) {
        return NGX_OK;
    }

    /* 初始化任务队列ngx_thread_pool_done */
    ngx_thread_pool_queue_init(&ngx_thread_pool_done);

    /* 按照解析的先后顺序依次初始化配置文件中配置的每一个线程池 */
    tpp = tcf->pools.elts;
    for (i = 0; i < tcf->pools.nelts; i++) {
        if (ngx_thread_pool_init(tpp[i], cycle->log, cycle->pool) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* 在worker子进程退出的时候调用 */
static void
ngx_thread_pool_exit_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return;
    }

    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    if (tcf == NULL) {
        return;
    }

    /* 销毁所有的线程池 */
    tpp = tcf->pools.elts;
    for (i = 0; i < tcf->pools.nelts; i++) {
        ngx_thread_pool_destroy(tpp[i]);
    }
}
