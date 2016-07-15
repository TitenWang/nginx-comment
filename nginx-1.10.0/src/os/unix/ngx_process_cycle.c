
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>


static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
    ngx_int_t type);
static void ngx_start_cache_manager_processes(ngx_cycle_t *cycle,
    ngx_uint_t respawn);
static void ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch);
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle);
static void ngx_master_process_exit(ngx_cycle_t *cycle);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker);
static void ngx_worker_process_exit(ngx_cycle_t *cycle);
static void ngx_channel_handler(ngx_event_t *ev);
static void ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_cache_manager_process_handler(ngx_event_t *ev);
static void ngx_cache_loader_process_handler(ngx_event_t *ev);


ngx_uint_t    ngx_process;  //当前子进程的类型
ngx_uint_t    ngx_worker;  //当前的worker子进程的编号
ngx_pid_t     ngx_pid;  //当前子进程的id

sig_atomic_t  ngx_reap;  //收到CHLD信号，此时有子进程意外结束，需要监控所有的子进程
sig_atomic_t  ngx_sigio;
sig_atomic_t  ngx_sigalrm;  //等待子进程退出的定时器超时信号标志位
sig_atomic_t  ngx_terminate;  //收到TERM和INT信号时，强制关闭进程
sig_atomic_t  ngx_quit;  //收到QUIT信号时，优雅地关闭进程
sig_atomic_t  ngx_debug_quit;  //WINCH信号
ngx_uint_t    ngx_exiting;  //说明开始准备关闭worker进程
sig_atomic_t  ngx_reconfigure;  //收到SIGHUP信号时，重新加载配置文件
sig_atomic_t  ngx_reopen;  //收到USR1信号时，重新打开所有文件

sig_atomic_t  ngx_change_binary;  //收到USR2信号，平滑升级到新版本的nginx程序
ngx_pid_t     ngx_new_binary;  //平滑升级的时候，用来执行系统调用execve的子进程的id,也是新版本nginx程序的id
ngx_uint_t    ngx_inherited;
ngx_uint_t    ngx_daemonized;

sig_atomic_t  ngx_noaccept;  //收到WINCH信号，所有的子进程不再接受处理新的连接，相当于向子进程发送QUIT信号
ngx_uint_t    ngx_noaccepting;  //表明子进程正在不接受新的连接
ngx_uint_t    ngx_restart;  //在master工作流程中作为标志位使用，与信号无关


static u_char  master_process[] = "master process";


static ngx_cache_manager_ctx_t  ngx_cache_manager_ctx = {
    ngx_cache_manager_process_handler, "cache manager process", 0
};

static ngx_cache_manager_ctx_t  ngx_cache_loader_ctx = {
    ngx_cache_loader_process_handler, "cache loader process", 60000
};


static ngx_cycle_t      ngx_exit_cycle;
static ngx_log_t        ngx_exit_log;
static ngx_open_file_t  ngx_exit_log_file;

/*
 * master进程不需要处理网络事件和定时器事件，它不负责业务的执行，只会通过管理worker进程来实现重启服务、
 * 平滑升级、更换日志文件、配置文件实时生效等功能
 */
void
ngx_master_process_cycle(ngx_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    ngx_int_t          i;
    ngx_uint_t         n, sigio;
    sigset_t           set;
    struct itimerval   itv;
    ngx_uint_t         live;
    ngx_msec_t         delay;
    ngx_listening_t   *ls;
    ngx_core_conf_t   *ccf;

    /*注册处理信号*/
    /*
     * sigemptyset 函数初始化信号集合set,将set 设置为空.
     * sigfillset 也初始化信号集合,只是将信号集合设置为所有信号的集合.
     * sigaddset 将信号signo 加入到信号集合之中,sigdelset 将信号从信号集合中删除.
     * sigismember 查询信号是否在信号集合之中.
     * sigprocmask 是最为关键的一个函数.在使用之前要先设置好信号集合set.这个函数的作用是将指定的信号集合set 
     * 加入到进程的信号阻塞集合之中去,如果提供了oset 那么当前的进程信号阻塞集合将会保存在oset 里面.参数how 
     * 决定函数的操作方式：
     *      SIG_BLOCK：增加一个信号集合到当前进程的阻塞集合之中.
     *      SIG_UNBLOCK：从当前的阻塞集合之中删除一个信号集合.
     *      SIG_SETMASK：将当前的信号集合设置为信号阻塞集合.
    */
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    sigemptyset(&set);


    /*下面是修改master进程名字的操作*/
    
    /*1.计算argv数组的总长度*/
    size = sizeof(master_process);

    for (i = 0; i < ngx_argc; i++) {
        size += ngx_strlen(ngx_argv[i]) + 1;
    }

    title = ngx_pnalloc(cycle->pool, size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }
    /*执行完ngx_cpymem后p指向了title下一次复制开始的地址*/
    p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < ngx_argc; i++) {
        *p++ = ' ';
        p = ngx_cpystrn(p, (u_char *) ngx_argv[i], size);
    }

    /*修改进程名字*/
    ngx_setproctitle(title);


    /*获取核心模块存储配置项的指针*/
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    /*创建并启动worker子进程*/
    ngx_start_worker_processes(cycle, ccf->worker_processes,
                               NGX_PROCESS_RESPAWN);
    /*创建并启动cache_manage子进程*/
    ngx_start_cache_manager_processes(cycle, 0);

    ngx_new_binary = 0;
    delay = 0;
    sigio = 0;
    live = 1;

    for ( ;; ) {
        /*
        * delay用来等待子进程退出的时间，由于我们接受到SIGINT信号后，我们需要先发送信号给子进程，而子进程的退出
        * 需要一定的时间，超时时如果子进程已退出，我们父进程就直接退出，否则发送sigkill信号给子进程(强制退出),
        * 然后再退出。
        */
        if (delay) {
            if (ngx_sigalrm) {
                sigio = 0;
                delay *= 2;
                ngx_sigalrm = 0;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "termination cycle: %M", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            /* 
             * int setitimer(int which, const struct itimerval *value, struct itimerval *ovalue);
             *   which为定时器类型，setitimer支持3种类型的定时器：
             *     ITIMER_REAL: 以系统真实的时间来计算，它送出SIGALRM信号。
             *     ITIMER_VIRTUAL: -以该进程在用户态下花费的时间来计算，它送出SIGVTALRM信号。
             *     ITIMER_PROF: 以该进程在用户态下和内核态下所费的时间来计算，它送出SIGPROF信号。
             * setitimer()第一个参数which指定定时器类型（上面三种之一）；第二个参数是结构itimerval的一个实例；第三个参数可不做处理。
             * setitimer()调用成功返回0，否则返回-1。
             */
            /*定时*/
            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        /*sigsuspend用于在接收到某个信号之前，临时用mask替换进程的信号掩码，并暂停进程执行，直到收到信号为止。*/
        /*
         * 进程执行到sigsuspend时，sigsuspend并不会立刻返回，进程处于TASK_INTERRUPTIBLE状态并立刻放弃CPU，
         * 等待UNBLOCK（mask之外的）信号的唤醒。进程在接收到UNBLOCK（mask之外）信号后，调用处理函数，然后把现在
         * 的信号集还原为原来的，sigsuspend返回，进程恢复执行。
         */
        sigsuspend(&set);

        /*更新nginx内核缓存时间*/
        ngx_time_update();

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "wake up, sigio %i", sigio);

        /*有子进程意外退出，监控所有子进程*/
        if (ngx_reap) {
            ngx_reap = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");

            live = ngx_reap_children(cycle);
        }

        /*如果没有worker子进程还存活，并且已经收到了ngx_terminate或者ngx_quit信号，则退出master进程*/
        if (!live && (ngx_terminate || ngx_quit)) {
            ngx_master_process_exit(cycle);
        }

        /*收到了ngx_terminate信号*/
        if (ngx_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            sigio = ccf->worker_processes + 2 /* cache processes */;

            /*向子进程发送TERM信号*/
            if (delay > 1000) {
                ngx_signal_worker_processes(cycle, SIGKILL);  //如果超时，则强制杀死worker  
            } else {
                ngx_signal_worker_processes(cycle,
                                       ngx_signal_value(NGX_TERMINATE_SIGNAL));
            }

            continue;
        }

        /*如果收到了quit信号*/
        if (ngx_quit) {
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));  //向子进程发送quit信号

            /*关闭监听的socket*/
            ls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                if (ngx_close_socket(ls[n].fd) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                                  ngx_close_socket_n " %V failed",
                                  &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;

            continue;
        }

        /*如果收到了SIGHP信号，ngx_reconfigure为1，表示需要重新读取配置文件*/
        if (ngx_reconfigure) {
            ngx_reconfigure = 0;

            /*
             * 在平滑升级的时候，有一个时间段是旧版本的master进程会和新版本的master进程以及新版本的worker进程共存。
             * 此时我们可以决定是继续使用旧版本的nginx还是使用新版本的nginx。如果我们决定使用新版本的nginx，那么旧版本
             * 的nginx也就不会收到SIGHUP的信号，不会进入到ngx_reconfigure为1的分支，而是会退出。那什么情况下会走到这里呢?
             * 其实走到这里是因为我们选择了不使用新版本的nginx，而继续使用旧版本的nginx，所以我们通过kill命令给老版本的nginx
             * 发送了SIGHUP信号，ngx_reconfigure被置位，又由于我们之前做了平滑升级，所以ngx_new_binary就是新版本nginx进程的id
             * 由于旧版本的worker进程处理完请求已经退出了，因此这里需要将worker和cache子进程都拉起来，并开始接受新的请求。
             * 其实这个过程就是平滑重启，nginx 将在不重载配置文件的情况下启动它的工作进程 
             */
            if (ngx_new_binary) {
                ngx_start_worker_processes(cycle, ccf->worker_processes,
                                           NGX_PROCESS_RESPAWN);
                ngx_start_cache_manager_processes(cycle, 0);
                ngx_noaccepting = 0;

                continue;
            }

            /*
             * 程序执行到这里表明不是平滑重启，只是配置文件热启动。
             * nginx此时采取的策略是不再让原来的worker等子进程在重新读取配置文件，而是重新初始化ngx_cycle_t结构体，
             * 用它来重新读取配置文件。再拉起新的worker子进程，销毁就得worker进程。
             */

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            /*读取新的配置文件初始化ngx_cycle_t结构体*/
            /*cycle原来指向的内存并没有释放，这个由nginx的内存池统一释放*/
            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;  //赋值给master进程的ngx_cycle
            ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                   ngx_core_module);

            /*依据新的配置文件启动worker和cache_manage子进程*/
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);  //NGX_PROCESS_JUST_RESPAWN表明新配置文件拉起进程
            ngx_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            ngx_msleep(100);

            live = 1;
            /*此处只会关闭读取配置文件前就存在的老worker子进程，刚创建的worker子进程不关闭，其实是发送quit信号*/
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        /*
         * ngx_restart只会在ngx_reap_children()函数中被置位，如果被置位，说明是平滑升级失败了，需要重新拉起子进程
         */
        if (ngx_restart) {
            ngx_restart = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_RESPAWN);  //创建worker子进程
            ngx_start_cache_manager_processes(cycle, 0);  //创建cache_manage子进程
            live = 1;  //将live标志位置1，表示有子进程存活
        }

        /*重新打开文件信号USR1*/
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, ccf->user);  //打开master进程中的文件
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_REOPEN_SIGNAL));  //向worker子进程发送REOPEN信号
        }

        /*收到USR2信号，表示要平滑升级服务*/
        if (ngx_change_binary) {
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "changing binary");
            ngx_new_binary = ngx_exec_new_binary(cycle, ngx_argv);
        }

        /*
         * 表示要让所有的worker子进程优雅地关闭进程。目前，在平滑升级的时候，如果要让旧版本的nginx进程优雅推出，
         * 则可以通过kill 命令向旧版本nginx进程发送WINCH命令。然后ngx_noaccept置位
         */
        if (ngx_noaccept) {
            ngx_noaccept = 0;
            ngx_noaccepting = 1;  //将ngx_noaccepting置为1，表示正在停止接受新的连接
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));  //向worker子进程发送QUIT信号
        }
    }
}


void
ngx_single_process_cycle(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    /*调用所有模块的init_process回调函数*/
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    /*单进程模式工作循环*/
    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        /*事件收集和分发入口*/
        ngx_process_events_and_timers(cycle);

        /*收到强制关闭或者优雅关闭进程信号，调用所有模块的exit_process回调函数*/
        if (ngx_terminate || ngx_quit) {

            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->exit_process) {
                    cycle->modules[i]->exit_process(cycle);
                }
            }

            /*做一些退出进程前的清理操作*/
            ngx_master_process_exit(cycle);
        }

        /*重新加载配置文件的信号*/
        if (ngx_reconfigure) {
            ngx_reconfigure = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            /*初始化进程唯一的核心结构体ngx_cycle_t*/
            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            /*将初始化好的cycle赋给ngx_cycle*/
            ngx_cycle = cycle;
        }

        /*重新打开所有文件的信号*/
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, (ngx_uid_t) -1);
        }
    }
}

/*fork子进程，并在子进程中调用处理函数*/
static void
ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type)
{
    ngx_int_t      i;
    ngx_channel_t  ch;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start worker processes");

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_OPEN_CHANNEL;

    for (i = 0; i < n; i++) {  //遍历所有的worker子进程

        ngx_spawn_process(cycle, ngx_worker_process_cycle,
                          (void *) (intptr_t) i, "worker process", type);

        //用于向其他已经创建的子进程广播当前子进程的信息
        ch.pid = ngx_processes[ngx_process_slot].pid;  //ngx_process_slot在ngx_spawn_process中被设置为当前操作的子进程
        ch.slot = ngx_process_slot;
        ch.fd = ngx_processes[ngx_process_slot].channel[0];   //对应当前子进程的父进程使用channel[0]套接字

        ngx_pass_open_channel(cycle, &ch);  //用于告诉其他子进程关于本子进程的频道通讯信息
    }
}

/*
 * 在nginx中，如果启用了proxy(或fastcgi) cache功能，那么master进程在启动过程中会启动两个子进程，即
 * cache_manager和cache_loader子进程，用来管理内存和磁盘的缓存个体。cache_manager进程的作用是定期检查
 * 缓存，并将过期的缓存清除，cache_loader进程的作用是在启动的时候将已经缓存在磁盘中的个体映射到内存中,
 * 目前Nginx设定为启动以后60秒，然后退出。
 */

/*拉起cache_manager和cache_loader进程*/
static void
ngx_start_cache_manager_processes(ngx_cycle_t *cycle, ngx_uint_t respawn)
{
    ngx_uint_t       i, manager, loader;
    ngx_path_t     **path;
    ngx_channel_t    ch;

    manager = 0;
    loader = 0;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {  //决定是否启用cache manager进程 
            manager = 1;  
        }

        if (path[i]->loader) {  //决定是否启用cache loader进程 
            loader = 1;
        }
    }

    if (manager == 0) {
        return;
    }

    /*拉起cache manger子进程*/
    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_manager_ctx, "cache manager process",
                      respawn ? NGX_PROCESS_JUST_RESPAWN : NGX_PROCESS_RESPAWN);

    /*通知其他子进程关于cache manager进程的信息*/
    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    ngx_pass_open_channel(cycle, &ch);

    if (loader == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_loader_ctx, "cache loader process",
                      respawn ? NGX_PROCESS_JUST_SPAWN : NGX_PROCESS_NORESPAWN);

    /*通知其他子进程关于cache loader进程的信息*/
    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    ngx_pass_open_channel(cycle, &ch);
}

/*广播channel消息*/
static void
ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch)
{
    ngx_int_t  i;

    for (i = 0; i < ngx_last_process; i++) {

        //跳过刚刚建立的子进程(自己)和还未创建的子进程以及对应父进程套接字关闭的子进程
        if (i == ngx_process_slot   //ngx_process_slot表示当前处理的子进程在ngx_processes中的需要
            || ngx_processes[i].pid == -1
            || ngx_processes[i].channel[0] == -1)
        {
            continue;
        }

        ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                      "pass channel s:%i pid:%P fd:%d to s:%i pid:%P fd:%d",
                      ch->slot, ch->pid, ch->fd,
                      i, ngx_processes[i].pid,
                      ngx_processes[i].channel[0]);

        /* TODO: NGX_AGAIN */
        //用于通知其他子进程关于刚刚创建的子进程(自己)的信息
        ngx_write_channel(ngx_processes[i].channel[0],
                          ch, sizeof(ngx_channel_t), cycle->log);
    }
}

/*master进程向worker子进程发送命令消息*/
static void
ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
{
    ngx_int_t      i;
    ngx_err_t      err;
    ngx_channel_t  ch;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

#if (NGX_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    /*通过频道channel向worker子进程发送消息*/
    switch (signo) {

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
        ch.command = NGX_CMD_QUIT;
        break;

    case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        ch.command = NGX_CMD_TERMINATE;
        break;

    case ngx_signal_value(NGX_REOPEN_SIGNAL):
        ch.command = NGX_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
            continue;
        }

        /*读取配置文件的时候调用ngx_start_worker_processes()的时候会将just_spawn置为1*/
        if (ngx_processes[i].just_spawn) {
            ngx_processes[i].just_spawn = 0;
            continue;
        }

        if (ngx_processes[i].exiting
            && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        /*如果是NGX_CMD_QUIT，NGX_CMD_TERINATE，NGX_CMD_REOPEN信号，则通过频道发送给worker子进程*/
        if (ch.command) {
            if (ngx_write_channel(ngx_processes[i].channel[0],
                                  &ch, sizeof(ngx_channel_t), cycle->log)
                == NGX_OK)
            {
                if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
                    ngx_processes[i].exiting = 1;  //不是NGX_REOPEN_SIGNAL，则为退出信号，将子进程exciting置为1
                }

                continue;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)", ngx_processes[i].pid, signo);

        /*向子进程发送signo信号*/
        if (kill(ngx_processes[i].pid, signo) == -1) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed", ngx_processes[i].pid, signo);

            if (err == NGX_ESRCH) {
                ngx_processes[i].exited = 1;
                ngx_processes[i].exiting = 0;
                ngx_reap = 1;
            }

            continue;
        }

        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}

/*
 * 监控子进程，如果是意外退出，则重新拉起，如果不是意外退出，则不会重新拉起.
 * 返回值如果为1表明仍有存活的子进程，如果返回值为0，表明所有worker子进程都退出了
 */
static ngx_uint_t
ngx_reap_children(ngx_cycle_t *cycle)
{
    ngx_int_t         i, n;
    ngx_uint_t        live;
    ngx_channel_t     ch;
    ngx_core_conf_t  *ccf;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;
    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        if (ngx_processes[i].pid == -1) {  //pid == -1表明子进程已经退出
            continue;
        }

        /*ngx_processes[i].exited为1表明当前子进程已经退出了*/
        if (ngx_processes[i].exited) {

            /*
             * ngx_processes[i].detached为0表明这个子进程不是用来执行execve系统调用执行新版本nginx可执行文件的子进程,
             * 因为这个子进程不是用来处理网络事件的，所以不需要和其他worker进程通信，也就不需要关注channel
             */
            if (!ngx_processes[i].detached) {
                ngx_close_channel(ngx_processes[i].channel, cycle->log);  //关闭当前进程和master进程通讯频道

                ngx_processes[i].channel[0] = -1;
                ngx_processes[i].channel[1] = -1;

                ch.pid = ngx_processes[i].pid;
                ch.slot = i;

                /*告诉其他子进程这个已经关闭的子进程的信息*/
                for (n = 0; n < ngx_last_process; n++) {
                    if (ngx_processes[n].exited
                        || ngx_processes[n].pid == -1
                        || ngx_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                   "pass close channel s:%i pid:%P to:%P",
                                   ch.slot, ch.pid, ngx_processes[n].pid);

                    /* TODO: NGX_AGAIN */

                    ngx_write_channel(ngx_processes[n].channel[0],
                                      &ch, sizeof(ngx_channel_t), cycle->log);
                }
            }

            /*
             * ngx_processes[i].respawn为1表明需要重新拉起这个子进程
             * ngx_processes[i].exiting为0表示此时子进程不是正在退出状态
             * ngx_terminate或者ngx_quit为0，表明master进程并没有收到这两个信号，自然也不会发送这两个信号给子进程
             * 上面的三个条件表明此时是要重新拉起这个意外结束的子进程
             */
            if (ngx_processes[i].respawn
                && !ngx_processes[i].exiting
                && !ngx_terminate
                && !ngx_quit)
            {
                /*重新生成子进程*/
                if (ngx_spawn_process(cycle, ngx_processes[i].proc,
                                      ngx_processes[i].data,
                                      ngx_processes[i].name, i)
                    == NGX_INVALID_PID)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                  "could not respawn %s",
                                  ngx_processes[i].name);
                    continue;
                }


                /*向其他子进程广播这个子进程的信息*/
                ch.command = NGX_CMD_OPEN_CHANNEL;
                ch.pid = ngx_processes[ngx_process_slot].pid;
                ch.slot = ngx_process_slot;
                ch.fd = ngx_processes[ngx_process_slot].channel[0];

                ngx_pass_open_channel(cycle, &ch);

                live = 1;

                continue;
            }

            /*
             * 在nginx进行平滑升级的时候，会生成一个子进程专门用来执行execve系统调用来执行新版本的nginx可执行文件,
             * 从代码实现中我们可以看到，ngx_new_binary保存的正是这个子进程的进程id。另外，当master进程创建了这个
             * 子进程，在这个子进程进行execve系统调用，execve如果执行成功是不会退出的，但是程序执行到这里说明execve返回了，
             * 然后调用exit()退出，这从另外一方面表明拉起新版本的nginx进程失败了。这会触发系统产生SIGCHLD信号，
             * 进而ngx_reap标志位为1，再进入到这个分支。总之，如果退出的子进程是用来执行execve系统调用的子进程，说明
             * 平滑升级失败了。此时需要恢复老版本的nginx，并拉起相应的worker进程。
             */
            if (ngx_processes[i].pid == ngx_new_binary) {

                ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                       ngx_core_module);

                /* int rename(char *oldname, char *newname);*/
                /* 
                 * 2016-07-11不明白的地方:为什么在这个分支中要重命名pid文件，即回退老版本的pid文件，平滑升级失败吗?
                 * 哪里有体现失败?
                 * 2016-07-12问题解决:
                 * 因为触发旧版本master进程收到SIGCHLD信号的是用来执行新版本nginx程序的子进程，说明execve返回了，
                 * execve系统调用如果执行成功是不会返回的，也就是说execve执行失败了，拉起新版本nginx进程失败。
                 */
                if (ngx_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    == NGX_FILE_ERROR)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                  ngx_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, ngx_argv[0]);
                }

                ngx_new_binary = 0;
                /*
                 * ngx_noaccepting为1表明该正在停止接受新的连接.从上面的分析可以知道，程序执行到这里说明平滑升级失败。
                 * 需要让老版本nginx(其实就是自己)服务继续运行，因此需要重启旧版本nginx对应的worker子进程，将ngx_restart
                 * 标志位置为1，并将正在停止接受新连接的标志位清零。
                 */
                if (ngx_noaccepting) {
                    ngx_restart = 1;  //重启进程标志位
                    ngx_noaccepting = 0;  //清零表示可以接受新的连接
                }
            }

            /*
             * 程序执行到这里，说明触发这个处理流程的子进程退出不是意外退出，不需要重新拉起，将pid置为-1.
             * 那为什么这里需要再分两个流程呢?因为如果刚好这个退出的子进程是最后一个有效的子进程，那么直接将
             * 表示最后一个有效子进程的下标减1也就相当于把这个子进程置为无效,这和pid置为-1的效果是一样的。只是
             * 需要进行特殊处理
             */
            if (i == ngx_last_process - 1) {
                ngx_last_process--;

            } else {
                ngx_processes[i].pid = -1;
            }

        /*子进程正在退出或者并不是那个用来平滑升级使用的子进程*/
        } else if (ngx_processes[i].exiting || !ngx_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}

/*
 * *****************************退出master进程**********************************
 * 1.删除nginx.pid文件
 * 2.调用模块的exit_master回调函数
 * 3.关闭监听socket
 * 4.释放内存池
 */
static void
ngx_master_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    /*删除nginx.pid文件*/
    ngx_delete_pidfile(cycle);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");

    /*调用所有模块的exit_master回调函数*/
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    /*关闭监听端口的监听socket*/
    ngx_close_listening_sockets(cycle);

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */


    ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);

    ngx_exit_log_file.fd = ngx_exit_log.file->fd;
    ngx_exit_log.file = &ngx_exit_log_file;
    ngx_exit_log.next = NULL;
    ngx_exit_log.writer = NULL;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    /*释放内存池*/
    ngx_destroy_pool(cycle->pool);

    exit(0);
}

/*worker子进程工作循环*/
static void
ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_int_t worker = (intptr_t) data;  //子进程编号，从0开始

    ngx_process = NGX_PROCESS_WORKER;
    ngx_worker = worker;

    /*初始化worker子进程的一些信息*/
    ngx_worker_process_init(cycle, worker);

    /*修改进程名字*/
    ngx_setproctitle("worker process");

    /*子进程工作循环*/
    for ( ;; ) {

        /*开始准备关闭worker进程。*/
        if (ngx_exiting) {
            ngx_event_cancel_timers();  //将定时器事件清除，并执行事件处理函数

            /*
             * 检查ngx_event_timer_rbtree红黑树是否为空，如果不为空，说明还有事件需要处理，将继续向下执行,
             * 调用ngx_process_events_and_timers()处理事件。如果为空，说明已经处理完所有事件，此时调用
             * ngx_worker_process_exit()函数，销毁内存池，退出整个worker进程
             */
            if (ngx_event_timer_rbtree.root == ngx_event_timer_rbtree.sentinel)
            {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");

                /*退出worker子进程前的一些处理*/
                ngx_worker_process_exit(cycle);
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        /*事件收集和分发函数*/
        ngx_process_events_and_timers(cycle);

        /*强制关闭进程*/
        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");

            ngx_worker_process_exit(cycle);
        }

        /*优雅关闭进程*/
        if (ngx_quit) {
            ngx_quit = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "gracefully shutting down");
            /*修改进程名字*/
            ngx_setproctitle("worker process is shutting down");

            /*ngx_exiting标志位唯一一段设置它的代码在此。ngx_quit只有在首次设置为1时，才会将ngx_exiting设置为1*/
            if (!ngx_exiting) {
                ngx_exiting = 1;
                ngx_close_listening_sockets(cycle);  //关闭监听的socket
                ngx_close_idle_connections(cycle);  //关闭空闲连接(空闲连接也是打开的，只是此时没有请求需要处理)
            }
        }

        /*重新打开所有文件*/
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }
    }
}

/*初始化worker子进程的一些信息*/
static void
ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker)
{
    sigset_t          set;
    ngx_int_t         n;
    ngx_uint_t        i;
    ngx_cpuset_t     *cpu_affinity;
    struct rlimit     rlmt;
    ngx_core_conf_t  *ccf;
    ngx_listening_t  *ls;

    /*设置进程运行的环境变量*/
    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    /*获取核心模块存储配置项的结构体指针*/
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    /*
     * setpriority（）可用来设置进程、进程组和用户的进程执行优先权。
     *  
　　 * 参数which有三种数值，参数who则依which值有不同定义：
　   *　　which 　　　　who代表的意义        who为0代表的意义 
　   *　　PRIO_PROCESS  who为进程识别码     （who为0代表调用进程）
　　 *　  PRIO_PGRP 　　who为进程的组识别码 （who为0代表调用进程的组）
　　 *　  PRIO_USER 　　who为用户识别码     （who为0代表调用进程的用户ID）
　　 *
　　 * 参数prio介于-20至19之间。代表进程执行优先权，数值越低代表有较高的优先次序，执行会较频繁。
     * 执行成功则返回0，如果有错误发生返回值则为-1，错误原因存于errno。
　　 *   ESRCH 参数which或who可能有错，而找不到符合的进程
　　 *   EINVAL 参数which值错误。
　　 *   EPERM 权限不够，无法完成设置
　　 *   EACCES 一般用户无法降低优先权
     */

    /*设置子进程的执行优先级*/
    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setpriority(%d) failed", ccf->priority);
        }
    }

    /*
     * getrlimit()获取资源使用限制 setrlimit()设置资源使用限制。每种资源都有相应的软硬限制
     * 软限制是内核强加给对应资源使用的限制值。硬限制值是软限制值的最大值。非授权调用进程只可以将软限制值
     * 设置为0~硬限制值的范围内，并且可以不可逆转地降低其硬限制值。对于授权调用进程，可以随意设置其软硬限制值
     */

    if (ccf->rlimit_nofile != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;  //rlmt.rlim_cur为软限制
        rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;  //rlmt.rlim_max为硬限制
        //RLIMIT_NOFILE  指定比进程可打开的最大文件描述符大一的值
        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setrlimit(RLIMIT_NOFILE, %i) failed",
                          ccf->rlimit_nofile);
        }
    }

    /*如果设置了coredump文件的大小限制*/
    if (ccf->rlimit_core != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_core;
        //RLIMIT_CORE 指定内核转储文件的最大值，即coredump文件的最大值
        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setrlimit(RLIMIT_CORE, %O) failed",
                          ccf->rlimit_core);
        }
    }

    /*
     * geteuid()获取执行当前进程有效的用户识别码，表示最初执行程序时的用户ID，有效用户识别码用来决定进程执行的权限.
     * getuid()获取当前进程的实际用户识别码，表示程序的实际所有者ID.
     */
    /*setgid()设置进程用户组ID setuid()设置进程用户ID*/
    if (geteuid() == 0) {  //geteuid() == 0表示执行程序的用户是root
        if (setgid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        /*
         * 函数说明 initgroups（）用来从组文件（/etc/group）中读取一项组数据，
         * 若该组数据的成员中有参数user时，便将参数group组识别码加入到此数据中。
         * 返回值 执行成功则返回0，失败则返回-1，错误码存于errno
         */
        if (initgroups(ccf->username, ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "initgroups(%s, %d) failed",
                          ccf->username, ccf->group);
        }

        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }
    }

    /*worker子进程绑核操作*/
    if (worker >= 0) {
        cpu_affinity = ngx_get_cpu_affinity(worker);

        if (cpu_affinity) {
            ngx_setaffinity(cpu_affinity, cycle->log);
        }
    }

#if (NGX_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif
    /*更改当前工作目录*/
    if (ccf->working_directory.len) {
        if (chdir((char *) ccf->working_directory.data) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    srandom((ngx_pid << 16) ^ ngx_time());

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].previous = NULL;
    }

    /*调用所有模块的init_process()回调函数*/
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for (n = 0; n < ngx_last_process; n++) {

        /*
         * 下面的ngx_processes[n].pid == -1 和 ngx_processes[n].channel[1] == -1可能出现的原因是有些子进程还没来得及
         * 创建，所以对应的子进程信息是无效的。举个例子，比如ngx_process_slot为0，表示是第一个worker子进程，但是后面
         * 的子进程还没来得及创建，所以上述信息就无效了;等到ngx_process_slot为1，表示现在创建的是第二个worker子进程，
         * 此时第一个worker子进程的信息是有效的，那么就会执行到下面关闭子进程1中从master进程继承过来的子进程0的读端socket，
         * 因为子进程0的读端socket对子进程1无用，反倒是子进程1中继承得到的子进程0对应的写端socket可以用来当作子进程1给
         * 子进程0发送命令时使用。
         */

        if (ngx_processes[n].pid == -1) {
            continue;
        }

        //如果是当前子进程，不往下处理关闭自身的套接字
        if (n == ngx_process_slot) {
            continue;
        }

        //如果该进程的用于和master进程通讯的套接字不可用，则不往下处理
        if (ngx_processes[n].channel[1] == -1) {
            continue;
        }

        /*
         * ngx_processes[]数组保存的是所有worker进程的信息，是master进程创建的。因为worker进程是从master进程
         * fork得到的，因此worker进程中也继承了master进程的ngx_processes[]数组。因此这里遍历该数组，将属于其他worker
         * 子进程的用于和master进程进行频道通信的读端socket关闭，也就是channel[1]。这里保留写端channel[0]的原因是用于此
         * worker子进程和其他worker子进程通讯用，这样该子进程就可以在需要的时候通过channel[0]给其他worker子进程发送
         * 命令消息，其他worker子进程就可以从对应的读端socket即channel[1]读取数据。每个worker子进程都会继承
         * ngx_processes[]数组，所以这里关闭的只是该子进程中的ngx_processes[]数组中其他worker子进程的读端socket，保留了该
         * 子进程本身的读端socket用于和master进程通信。
         */
        if (close(ngx_processes[n].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "close() channel failed");
        }
    }

    /*
     * ngx_processes[]数组保存的是所有worker进程的信息，是master进程创建的。因为worker进程是从master进程
     * fork得到的，因此worker进程中也继承了master进程的ngx_processes[]数组。这里关闭了从master进程继承过来的对应
     * 该子进程本身的写端socket，因为写端socket在master进程中用来发送命令给子进程本身，子进程只需要读端socket，因此
     * 在子进程中将写端socket关闭
     */
    if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() channel failed");
    }

#if 0
    ngx_last_process = 0;
#endif

    /*ngx_channel就是对应该子进程的读端socket，将ngx_read_event添加到epoll中，当master向worker通过频道发送
     * 命令时，即可获取事件
     */
    if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,
                              ngx_channel_handler)
        == NGX_ERROR)
    {
        /* fatal */
        exit(2);
    }
}

/*退出worker子进程*/
static void
ngx_worker_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

    /*调用所有模块的exit_process回调*/
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    if (ngx_exiting) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                              "*%uA open socket #%d left in connection %ui",
                              c[i].number, c[i].fd, i);
                ngx_debug_quit = 1;
            }
        }

        if (ngx_debug_quit) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "aborting");
            ngx_debug_point();
        }
    }

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */

    ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);

    ngx_exit_log_file.fd = ngx_exit_log.file->fd;
    ngx_exit_log.file = &ngx_exit_log_file;
    ngx_exit_log.next = NULL;
    ngx_exit_log.writer = NULL;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "exit");

    exit(0);
}


static void
ngx_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    for ( ;; ) {

        n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == NGX_ERROR) {

            if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
                ngx_del_conn(c, 0);
            }

            ngx_close_connection(c);
            return;
        }

        if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
            if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return;
            }
        }

        if (n == NGX_AGAIN) {
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "channel command: %ui", ch.command);

        switch (ch.command) {

        case NGX_CMD_QUIT:
            ngx_quit = 1;
            break;

        case NGX_CMD_TERMINATE:
            ngx_terminate = 1;
            break;

        case NGX_CMD_REOPEN:
            ngx_reopen = 1;
            break;

        case NGX_CMD_OPEN_CHANNEL:

            ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "get channel s:%i pid:%P fd:%d",
                           ch.slot, ch.pid, ch.fd);

            ngx_processes[ch.slot].pid = ch.pid;
            ngx_processes[ch.slot].channel[0] = ch.fd;
            break;

        case NGX_CMD_CLOSE_CHANNEL:

            ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "close channel s:%i pid:%P our:%P fd:%d",
                           ch.slot, ch.pid, ngx_processes[ch.slot].pid,
                           ngx_processes[ch.slot].channel[0]);

            if (close(ngx_processes[ch.slot].channel[0]) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "close() channel failed");
            }

            ngx_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}

/*cache manager和cache loader子进程的工作循环*/
static void
ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_cache_manager_ctx_t *ctx = data;

    void         *ident[4];
    ngx_event_t   ev;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    ngx_process = NGX_PROCESS_HELPER;

    ngx_close_listening_sockets(cycle);  //cache manager进程不监听端口，关闭端口

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    ngx_worker_process_init(cycle, -1);  //进程初始化

    ngx_memzero(&ev, sizeof(ngx_event_t));
    ev.handler = ctx->handler;  //设置事件超时处理函数
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *) -1;

    ngx_use_accept_mutex = 0;

    ngx_setproctitle(ctx->name);

    ngx_add_timer(&ev, ctx->delay);  //将事件加入到定时器中

    /*工作循环*/
    for ( ;; ) {

        if (ngx_terminate || ngx_quit) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }

        /*在这里会处理超时的定时器事件，如果cache manager所感兴趣事件超时，则会调用相应的回调*/
        ngx_process_events_and_timers(cycle);
    }
}

/*cache manager进程的超时事件处理函数*/
static void
ngx_cache_manager_process_handler(ngx_event_t *ev)
{
    time_t        next, n;
    ngx_uint_t    i;
    ngx_path_t  **path;

    next = 60 * 60;

    /*调用manager回调处理*/
    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            ngx_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    /*处理完之后又将该事件放入到定时器中等待下次超时*/
    ngx_add_timer(ev, next * 1000);
}

/*cache loader进程的超时事件处理函数*/
static void
ngx_cache_loader_process_handler(ngx_event_t *ev)
{
    ngx_uint_t     i;
    ngx_path_t   **path;
    ngx_cycle_t   *cycle;

    cycle = (ngx_cycle_t *) ngx_cycle;

    /*调用loader回调处理*/
    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (ngx_terminate || ngx_quit) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            ngx_time_update();
        }
    }

    /*执行完之后子进程就退出了*/
    exit(0);
}
