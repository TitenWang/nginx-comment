
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_THREADS            2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    socklen_t                  socklen;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HTTP_V2)
    unsigned                   http2:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                   ipv6only:1;
#endif
#if (NGX_HAVE_REUSEPORT)
    unsigned                   reuseport:1;
#endif
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];
} ngx_http_listen_opt_t;

/* http请求的11个处理阶段 */
typedef enum {
    /*
     * 接收到完整的http头部后处理的http阶段
     */
    NGX_HTTP_POST_READ_PHASE = 0,

    /*
     * 在将请求的uri和location表达式匹配前，修改请求的uri(重定向)
     */
    NGX_HTTP_SERVER_REWRITE_PHASE,

    /*
     * 根据请求的uri寻找匹配的location表达式,该阶段只能由http框架处理
     */
    NGX_HTTP_FIND_CONFIG_PHASE,

    /*
     * 在NGX_HTTP_FIND_CONFIG_PHASE阶段寻找到匹配的location时候再次修改请求的uri
     */
    NGX_HTTP_REWRITE_PHASE,

    /*
     * 这一阶段用于在rewrite重写uri后，防止错误的nginx.conf配置导致死循环，这一阶段
     * 仅有http框架处理。目前控制死循环的方式很简单，如果一个请求重定向的次数超过
     * 10次就认为进入了rewrite死循环，此时在NGX_HTTP_POST_REWRITE_PHASE阶段就会向
     * 用户返回600，表示服务器内部错误
     */
    NGX_HTTP_POST_REWRITE_PHASE,

    /*
     * 表示在处理NGX_HTTP_ACCESS_PHASE阶段决定请求的访问权限前，http模块可以介入的处理阶段
     */
    NGX_HTTP_PREACCESS_PHASE,

    /*
     * 这个阶段用于让http模块判断是否允许这个请求访问Nginx服务器
     */
    NGX_HTTP_ACCESS_PHASE,

    /*
     * 在NGX_HTTP_ACCESS_PHASE阶段中，当http模块的handler处理函数返回不允许访问的错误码时，
     * 这里将负责向用户发送拒绝服务的错误响应，这个阶段用于给NGX_HTTP_ACCESS_PHASE收尾
     */
    NGX_HTTP_POST_ACCESS_PHASE,

    /*
     * 这个阶段完全是为try_files配置项而设立的，当http请求访问静态文件资源时，try_files配置项
     * 可以使这个请求顺序地访问多个静态文件资源，如果某一次访问失败，则继续访问try_files中指定
     * 的下一个静态资源，这个功能完全是在NGX_HTTP_TRY_FILES_PHASE中实现的
     */
    NGX_HTTP_TRY_FILES_PHASE,

    /*
     * 用于处理http请求内容的阶段，这是大部分http模块介入的阶段
     */
    NGX_HTTP_CONTENT_PHASE,

    /*
     * 处理完请求后记录日志的阶段
     */
    NGX_HTTP_LOG_PHASE
} ngx_http_phases;

/*
 * 对于这11个处理阶段，有些阶段是必备的，比如NGX_HTTP_FIND_CONFIG_PHASE阶段，有些阶段是可以选的，
 * 比如NGX_HTTP_POST_ACCESS_PHASE和NGX_HTTP_POST_REWRITE_PHASE阶段，为什么说这两个阶段是可选的呢?
 * 因为NGX_HTTP_POST_REWRITE_PHASE完全是为了NGX_HTTP_REWRITE_PHASE阶段服务的，因为如果没有任何模块
 * 介入NGX_HTTP_REWRITE_PHASE阶段处理请求，那就没必要检测是否出现重定向死循环，那么NGX_HTTP_POST_REWRITE_PHASE
 * 也就没有必要存在了，同理NGX_HTTP_POST_ACCESS_PHASE之于NGX_HTTP_ACCESS_PHASE阶段也是一个道理，
 * 这个可以在ngx_http_init_phase_handlers()有体现
 */

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

/* 一个http处理阶段中的checker方法仅可由http框架实现，以此控制http请求处理流程 */
typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

/* ngx_http_phase_handler_s对象表示某个处理阶段中的一个处理方法对象 */
struct ngx_http_phase_handler_s {

    /*
     * 在处理到某一个http阶段时，http框架将会在checker方法实现的前提下首先调用checker
     * 方法处理请求，而不会直接调用任何阶段中的handler方法，只有在checker方法中才会调用
     * handler方法
     */
    ngx_http_phase_handler_pt  checker;

    /*
     * 除ngx_http_core_module之外的http模块，只能通过定义handler方法才能介入
     * 某一个处理阶段处理请求
     */
    ngx_http_handler_pt        handler;

    /*
     * 将要执行的下一个处理阶段的第一个处理函数在cmcf->phase_engine.handlers数组中的序号
     */
    ngx_uint_t                 next;
};


typedef struct {
    /*
     * 一个请求可能经历的所有处理方法(所有阶段的所有处理方法都会收集在这个数组中)。
     * handlers数组是如何使用的呢?该数组要配合着ngx_http_request_t结构体中的phase_handler序号
     * 使用，有phase_handler指定着请求将要执行的的阶段处理函数在handlers数组中的序号。
     * 使用方式可以参见ngx_http_core_run_phases()
     */
    ngx_http_phase_handler_t  *handlers;

    /*
     * 表示NGX_HTTP_SERVER_REWRITE_PAHSE阶段第一个ngx_http_phase_handler_t处理方法在
     * handlers数组中的序号，用于在执行http请求处理的任何阶段快速跳转到
     * NGX_HTTP_SERVER_REWRITE_PHASE阶段处理请求
     */
    ngx_uint_t                 server_rewrite_index;

    /*
     * 表示NGX_HTTP_REWRITE_PHASE阶段第一个ngx_http_phase_handler_t处理方法在handlers数组
     * 中的序号，用于在执行http请求处理的任何阶段快速跳转到
     * NGX_HTTP_REWRITE_PHASE阶段处理请求
     */
    ngx_uint_t                 location_rewrite_index;
} ngx_http_phase_engine_t;

/* 一个http阶段中的所有处理方法 */
typedef struct {
    ngx_array_t                handlers;
} ngx_http_phase_t;


typedef struct {
    /* 存储隶属于http{}块的所有server块的ngx_http_core_module模块的配置项结构体 */
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    /* 由所有阶段的所有处理方法构建的阶段引擎，流水式处理http请求的实际数据结构 */
    ngx_http_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;

    ngx_hash_t                 variables_hash;  /*存储变量名的hash表，调用ngx_http_get_variable方法会使用到*/

    /*
     * 存储索引过的变量的数组，各个使用变量模块都会在nginx启动时候从该数组中获得索引,这样，在nginx运行期间，
     * 如果变量值没有没有被缓存，则会通过索引号在variables数组中找到这个变量的定义，再解析出变量值
     */
    ngx_array_t                variables;   
    ngx_uint_t                 ncaptures;

    ngx_uint_t                 server_names_hash_max_size;
    ngx_uint_t                 server_names_hash_bucket_size;

    ngx_uint_t                 variables_hash_max_size;
    ngx_uint_t                 variables_hash_bucket_size;

    ngx_hash_keys_arrays_t    *variables_keys;  /*用于构造variables_hash散列表的初始结构体*/

    /* 存放着http{}块内的所有server块内的listen配置指令监听的端口和ip地址信息 */
    ngx_array_t               *ports;  /* ngx_http_conf_port_t类型 */

    /* 是否配置了try_files指令的标志位 */
    ngx_uint_t                 try_files;       /* unsigned  try_files:1 */

    /*
     * 用于在http框架初始化时帮助各个http模块在任意阶段中添加http处理方法，它是一个有11个
     * 成员的ngx_http_phase_t数组(对应11个处理阶段)，其中每一个ngx_http_phase_t结构体对应
     * 一个http阶段中的所有处理方法
     */
    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t;


typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
    /* 
     * 存储server_name配置指令的参数，即该server的对应的所有主机名，这个在当一个ip:port有多个
     * server监听时很有用，因为在解析出请求的Host头部之前，该请求都是由监听该ip:port的默认server
     * 来处理的，如果触发该请求的server并不是默认server，那么就会用server_names中名字(hash后)
     * 与请求头部中的Host字段做匹配，匹配上之后再由当前的ngx_http_core_srv_conf_t处理请求
     */
    ngx_array_t                 server_names;

    /* server ctx */
    /* 指向当前server所属的ngx_http_conf_ctx_t结构体 */
    ngx_http_conf_ctx_t        *ctx;

    /*
     * 当前server块的虚拟主机名，server_name配置命令中的第一个参数
     */
    ngx_str_t                   server_name;

    size_t                      connection_pool_size;
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    ngx_bufs_t                  large_client_header_buffers;

    ngx_msec_t                  client_header_timeout;

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;  // server配置块中设置了listen配置命令
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
} ngx_http_server_name_t;


typedef struct {
    ngx_hash_combined_t        names;

    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
} ngx_http_virtual_names_t;


struct ngx_http_addr_conf_s {
    /* the default server configuration for this address:port */
    /*
     * 为什么对于一个ip:port需要设置默认的server呢?
     * 报文的收发是通过ip地址来确定的，所以如果一个ip:port有多个server都在监听，
     * 那么在请求的初始阶段是分辨不出来这个请求对应的是哪个server的，所以需要有
     * 一个默认的server对这个ip:port上的报文先进行一般性的处理(接收请求行)，等
     * 解析到请求行或者请求头中的host后，Nginx会用这个字段的值去获取此次请求的
     * 真正server，并让该server接管请求的后续处理
     */
    ngx_http_core_srv_conf_t  *default_server;  // ip:port的默认server

    /*
     * 如果ip:port有多个server同时监听，那么监听这个ip:port的所有server的server names会进行hash，
     * 并将得到的hash表存放在virtual_names，这个用于用于获取请求真正对应的server配置块
     */
    ngx_http_virtual_names_t  *virtual_names;

#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HTTP_V2)
    unsigned                   http2:1;
#endif
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;  //ip:port信息
    ngx_http_addr_conf_t       conf;  //监听则合格ip:port的一些server信息
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;

/* 监听的tcp端口对象 */
typedef struct {
    ngx_int_t                  family;  // socket地址族
    in_port_t                  port;  // 监听的端口
    /* addrs中存放的是当不同的server监听同一个port，但不同ip情况下的ip地址信息 */
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t;

/* 监听的tcp端口对应的一个具体地址对象 */
typedef struct {
    ngx_http_listen_opt_t      opt; // 监听套接字的各种属性，对应listen命令的参数

    /*
     * 以下三个散列表用于加速寻找对应监听端口上的新连接，确定到底使用哪个server{}虚拟主机
     * 下的配置来处理它
     */
    ngx_hash_t                 hash;     // 完全匹配的server_name散列表
    ngx_hash_wildcard_t       *wc_head;  // 通配符前置的散列表
    ngx_hash_wildcard_t       *wc_tail;  // 通配符后置的散列表

#if (NGX_PCRE)
    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    /* 该监听端口(ip:port)下对应的默认server{}虚拟主机 */
    ngx_http_core_srv_conf_t  *default_server;

    /* 
     * 一个监听端口(ip:port)可以有所个虚拟主机所监听， servers存放的便是监听该ip:port的
     * 所有虚拟主机的配置
     */
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;
    ngx_str_t                  args;
} ngx_http_err_page_t;


typedef struct {
    ngx_array_t               *lengths;
    ngx_array_t               *values;
    ngx_str_t                  name;

    unsigned                   code:10;
    unsigned                   test_dir:1;
} ngx_http_try_file_t;


struct ngx_http_core_loc_conf_s {
    /* location的名字，即配置文件中location后面跟的表达式 */
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
#if (NGX_HTTP_DEGRADATION)
    unsigned      gzip_disable_degradation:2;
#endif
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    /*
     * 指向所属location块内的ngx_http_conf_ctx_t结构体中的loc_conf指针数组，
     * 它保存着当前location块内的所有http模块create_loc_conf方法产生的结构体指针
     */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
    ngx_flag_t    aio;                     /* aio */
    ngx_flag_t    aio_write;               /* aio_write */
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_flag_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    ngx_flag_t    etag;                    /* etag */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_THREADS)
    ngx_thread_pool_t         *thread_pool;
    ngx_http_complex_value_t  *thread_pool_value;
#endif

#if (NGX_HAVE_OPENAT)
    ngx_uint_t    disable_symlinks;        /* disable_symlinks */
    ngx_http_complex_value_t  *disable_symlinks_from;
#endif

    ngx_array_t  *error_pages;             /* error_page */
    ngx_http_try_file_t    *try_files;     /* try_files */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    /*
     * 将同一个server块内的多个表达location块的ngx_http_core_loc_conf_t结构体以
     * 双向链表的方式组织起来，该locations指针将指向ngx_http_location_queue_t结构体
     */
    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};

/* 将多个location以双向链表组织起来的链表对象 */
typedef struct {
    /* 双向链表容器，将ngx_http_location_queue_t连接起来 */
    ngx_queue_t                      queue;

    /*
     * 如果location中的字符串可以精确匹配(包括正则表达式)，exact将指向对应的
     * ngx_http_core_loc_conf_t结构体，否则为NULL
     */
    ngx_http_core_loc_conf_t        *exact;

    /*
     * 如果location中的字符串无法精确匹配(通配符),inclusive将指向对应的
     * ngx_http_core_loc_conf_t结果体，否则为NULL
     */
    ngx_http_core_loc_conf_t        *inclusive;

    /* 指向location的名字 */
    ngx_str_t                       *name;

    /* 指向配置文件路径 */
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_http_location_queue_t;


struct ngx_http_location_tree_node_s {
    ngx_http_location_tree_node_t   *left;
    ngx_http_location_tree_node_t   *right;
    ngx_http_location_tree_node_t   *tree;

    ngx_http_core_loc_conf_t        *exact;
    ngx_http_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_try_files_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_set_etag(ngx_http_request_t *r);
void ngx_http_weak_etag(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **sr,
    ngx_http_post_subrequest_t *psr, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);
typedef ngx_int_t (*ngx_http_request_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r,
    ngx_chain_t *chain);


ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);

ngx_int_t ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
    ngx_array_t *headers, ngx_str_t *value, ngx_array_t *proxies,
    int recursive);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

#define ngx_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
