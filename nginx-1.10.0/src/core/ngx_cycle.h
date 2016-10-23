
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;  // 作为init方法的参数，用于传递数据
    ngx_shm_t                 shm;   //描述共享内存的结构体
    ngx_shm_zone_init_pt      init;  //在真正创建好slab共享内存池后调用这个方法
    void                     *tag;   //对应于ngx_shared_memory_add的tag参数
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
    /*conf_ctx保存着所有模块存储配置项的结构体指针(conf_ctx最里层那个数组存储的只有核心模块的配置项参数结构体指针数组)*/
    void                  ****conf_ctx;
    ngx_pool_t               *pool;

    ngx_log_t                *log;
    ngx_log_t                 new_log;

    /* error_log指令是否打印到标志错误输出的标志位 */
    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    /*
     * 对于poll、rtsig这样的事件模块，会以有效文件句柄数来预先创建这些ngx_connection_t结构体，以加速事件的收集
     * 和分发。这时files就会保存着所有ngx_connection_t的指针组成的数组，files_n就是数组元素的总数，而文件句柄值
     * 用来访问files数组成员
     */
    ngx_connection_t        **files;

    /*free_connections表示可用连接池，free_connection_n可用连接池总数，两者配合使用*/
    ngx_connection_t         *free_connections;
    ngx_uint_t                free_connection_n;

    /*modules表示nginx中模块组成的数组，包括静态编译和动态加载的*/
    ngx_module_t            **modules;
     /*ngx_modules_n表示当前静态编译进内核的模块数量*/
    ngx_uint_t                modules_n;  
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    /*双向链表容器，元素类型是ngx_connection_t结构体，表示可重复使用的连接队列(长连接)*/
    ngx_queue_t               reusable_connections_queue;

    /*动态数组，每个元素存储着ngx_listening_t成员，表示监听的端口及相关参数*/
    ngx_array_t               listening;

    /*    
     * 动态数组容器，它保存着nginx所有要操作的目录。如果有目录不存在，就会试图创建，而创建目录失败就会导致nginx启动
     * 失败.通过解析配置文件获取到的路径添加到该数组，例如nginx.conf中的client_body_temp_path proxy_temp_path，
     * 参考ngx_conf_set_path_slot.这些配置可能设置重复的路径，因此不需要重复创建，通过ngx_add_path检测添加的路径是否
     * 重复，不重复则添加到paths中
     */
    ngx_array_t               paths;
    ngx_array_t               config_dump;

    /*
     * 单链表容器，元素类型是ngx_open_file_t结构体，它表示Nginx中已经打开的所有文件。事实上，Nginx框架并不会向open_files
     * 中添加文件，而是由对此感兴趣的模块向其中添加文件路径，Nginx框架会在ngx_init_cycle()函数中打开这些文件
     */
    ngx_list_t                open_files;

    /*
     * 单链表容器，元素类型是ngx_shm_zone_t结构体，每个元素表示一块共享内存
     */
    ngx_list_t                shared_memory;

    /*当前进程中所有连接对象总数，与下面的connections read_events write_events配合使用*/
    ngx_uint_t                connection_n;
    ngx_uint_t                files_n;

    /* 
     * connections表示连接池;read_events表示所有读事件;write_events表示所有写事件，三个链表元素一一对应
     * 即一个连接对应一个读事件和一个写事件
     */
    ngx_connection_t         *connections;
    ngx_event_t              *read_events;
    ngx_event_t              *write_events;

    /*临时使用的cycle,其中保存着conf_file conf_prefix conf_param prefix，在ngx_init_cycle()中进行转存*/
    ngx_cycle_t              *old_cycle;

    /*配置文件相对于安装目录的路径名称 默认为安装路径下的NGX_CONF_PATH,见ngx_process_options*/
    ngx_str_t                 conf_file;
    ngx_str_t                 conf_param; //nginx处理配置文件时需要特殊处理的在命令行携带的参数，一般是-g 选项携带的参数
    ngx_str_t                 conf_prefix; // nginx配置文件所在目录的路径
    ngx_str_t                 prefix;  //nginx安装目录的路径
    ngx_str_t                 lock_file;
    ngx_str_t                 hostname; //使用gethostname系统调用获得的主机名
};


typedef struct {
    ngx_flag_t                daemon;  //是否已后台方式运行标志位
    ngx_flag_t                master;  //master模式的标志位

    /*从timer_resolution全局配置中解析到的参数，表示至少隔ms秒执行定时器中断，然后从epoll_wait返回更新内存时间事件*/
    ngx_msec_t                timer_resolution;

    ngx_int_t                 worker_processes;  //工作线程的个数
    ngx_int_t                 debug_points;

    ngx_int_t                 rlimit_nofile;  //比进程可以打开的最大文件描述符大1的值
    off_t                     rlimit_core;  //coredump文件的大小

    int                       priority;  //进程优先级

    ngx_uint_t                cpu_affinity_auto;
    /*
     worker_processes 4;
     worker_cpu_affinity 0001 0010 0100 1000; 四个工作进程分别在四个指定的he上面运行
     
     如果是5核可以这样配置
     worker_cpu_affinity 00001 00010 00100 01000 10000; 其他多核类似
     */
    ngx_uint_t                cpu_affinity_n;  //worker_cpu_affinity命令的参数个数
    ngx_cpuset_t             *cpu_affinity;//worker_cpu_affinity 0001 0010 0100 1000;转换的位图结果就是0x1111

    char                     *username;
    ngx_uid_t                 user;   //进程用户ID
    ngx_gid_t                 group;  //进程用户组ID

    ngx_str_t                 working_directory;
    ngx_str_t                 lock_file;

    ngx_str_t                 pid;
    ngx_str_t                 oldpid;

    ngx_array_t               env;
    char                    **environment;  //环境变量
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
