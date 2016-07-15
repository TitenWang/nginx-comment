
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_pid_t           pid;  //子进程pid
    int                 status;  //由waitpid系统调用获取到的进程状态
    ngx_socket_t        channel[2];    //用于存储socketpair创建的套接字对

    ngx_spawn_proc_pt   proc;  //子进程回调
    void               *data;  //子进程回调的入参
    char               *name;  //子进程名字

    unsigned            respawn:1;  //为1表示重新生成子进程
    unsigned            just_spawn:1;  //为1表示正在生成子进程
    unsigned            detached:1;  //为1表示父、子进程分离
    unsigned            exiting:1;  //为1表示子进程正在退出
    unsigned            exited:1;  //为1表示子进程已经退出，当子进程退出后，父进程收到SIGCHLD后，开始waitpid
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024

#define NGX_PROCESS_NORESPAWN     -1
#define NGX_PROCESS_JUST_SPAWN    -2
#define NGX_PROCESS_RESPAWN       -3   //这个标志位是用来说明如果这个类型的子进程退出后默认是要重新拉起来的
#define NGX_PROCESS_JUST_RESPAWN  -4   //这个标志位是用来在重新读取配置文件后拉起新的子进程时候用的type
#define NGX_PROCESS_DETACHED      -5   //这个标志位是用来在平滑升级时创建用来执行execve调用的子进程时使用的type


#define ngx_getpid   getpid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
