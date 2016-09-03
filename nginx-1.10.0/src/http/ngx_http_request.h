
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10
#define NGX_HTTP_MAX_SUBREQUESTS           50

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001
#define NGX_HTTP_VERSION_20                2000

#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_TRACE                     0x8000

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_09_METHOD   12

#define NGX_HTTP_PARSE_INVALID_HEADER      13


/* unused                                  1 */
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
#define NGX_HTTP_SUBREQUEST_WAITED         4
#define NGX_HTTP_LOG_UNSAFE                8


#define NGX_HTTP_CONTINUE                  100
#define NGX_HTTP_SWITCHING_PROTOCOLS       101
#define NGX_HTTP_PROCESSING                102

#define NGX_HTTP_OK                        200
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_ACCEPTED                  202
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_TEMPORARY_REDIRECT        307

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NGX_HTTP_CLOSE                     444

#define NGX_HTTP_NGINX_CODES               494

#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NGX_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_INSUFFICIENT_STORAGE      507


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NGX_HTTP_WRITE_BUFFERED            0x10
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
    ngx_http_header_handler_pt        handler;
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header_out_t;


typedef struct {
    ngx_list_t                        headers;

    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *if_match;
    ngx_table_elt_t                  *if_none_match;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *expect;
    ngx_table_elt_t                  *upgrade;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;

#if (NGX_HTTP_X_FORWARDED_FOR)
    ngx_array_t                       x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *depth;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *overwrite;
    ngx_table_elt_t                  *date;
#endif

    ngx_str_t                         user;
    ngx_str_t                         passwd;

    ngx_array_t                       cookies;

    ngx_str_t                         server;
    /*
     * 解析完头部行后通过ngx_http_process_request_header来开辟空间从而来存储请求体中的内容，表示请求包体的大小，
     * 如果为-1表示请求中不带包体
     */
    off_t                             content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;
    unsigned                          chunked:1;
    unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;


typedef struct {
    ngx_list_t                        headers;

    ngx_uint_t                        status;
    ngx_str_t                         status_line;

    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_str_t                        *override_charset;

    size_t                            content_type_len;
    ngx_str_t                         content_type;
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;

    ngx_array_t                       cache_control;

    off_t                             content_length_n;
    off_t                             content_offset;
    time_t                            date_time;
    time_t                            last_modified_time;
} ngx_http_headers_out_t;


typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

/* 读取请求包体的对象 */
typedef struct {
    ngx_temp_file_t                  *temp_file;  // 存放http包体的临时文件

    /* 
     * 接收http包体的缓冲区链表，当包体需要全部存放到内存中而一块ngx_buf_t又无法存放完时，
     * 这时就需要使用ngx_chain_t链表来存放
     */
    ngx_chain_t                      *bufs;

    /* 直接接收http包体的缓存 */
    ngx_buf_t                        *buf;

    /* 根据Content-Length和已经接收的包体长度，计算出的还需要接收的包体长度 */
    off_t                             rest;
#if (NGX_HTTP_V2)
    off_t                             received;
#endif
    ngx_chain_t                      *free;
    ngx_chain_t                      *busy;
    ngx_http_chunked_t               *chunked;
    /* http包体接收完毕后执行的回调方法，通常用于执行调用读取包体方法的模块的业务逻辑 */
    ngx_http_client_body_handler_pt   post_handler;
} ngx_http_request_body_t;


typedef struct ngx_http_addr_conf_s  ngx_http_addr_conf_t;

/* 该结构体存储的是服务端与客户端连接对应的[port,ip]配置信息 */
typedef struct {
    ngx_http_addr_conf_t             *addr_conf;  // [port,ip]对应的配置信息，包括默认server等
    ngx_http_conf_ctx_t              *conf_ctx;  // 指向[port,ip]对应的server块配置项结构体数组

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
    ngx_str_t                        *ssl_servername;
#if (NGX_PCRE)
    ngx_http_regex_t                 *ssl_servername_regex;
#endif
#endif

    ngx_buf_t                       **busy;
    ngx_int_t                         nbusy;

    ngx_buf_t                       **free;
    ngx_int_t                         nfree;

#if (NGX_HTTP_SSL)
    unsigned                          ssl:1;
#endif
    unsigned                          proxy_protocol:1;
} ngx_http_connection_t;


typedef void (*ngx_http_cleanup_pt)(void *data);

typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;

struct ngx_http_cleanup_s {
    ngx_http_cleanup_pt               handler;
    void                             *data;
    ngx_http_cleanup_t               *next;
};


typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

/*
 * 该对象中存放的是某个子请求处理完之后会调用的回调函数及传递给回调函数的自定义参数
 */
typedef struct {
    ngx_http_post_subrequest_pt       handler;
    void                             *data;
} ngx_http_post_subrequest_t;


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

/*
 * 该对象中存放的是某个请求派生出的子请求或者请求自己产生的数据，以链表形式存放
 * 一般来说，request成员和out成员是互斥的，即如果一个ngx_http_postponed_request_t
 * 类型的节点中request不为NULL，则表明该节点存放的是一个子请求，如果节点的out成员
 * 不为NULL，而request成员为NUL，则表明该节点是一个数据节点，存放的是请求产生的数据
 */
struct ngx_http_postponed_request_s {
    ngx_http_request_t               *request;  // 派生出的子请求
    ngx_chain_t                      *out;  // 该请求自己产生的数据
    ngx_http_postponed_request_t     *next;  // 链表节点
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

/*
 * 该对象中存放的是某个请求产生的子请求，子请求之间用链表方式连接，一般来说，只有原始请求
 * 中的该类型成员才是有效的，由原始请求派生出来的请求对象中该成员是无效的。
 */
struct ngx_http_posted_request_s {
    ngx_http_request_t               *request; // 原始请求派生出的子(孙)请求
    ngx_http_posted_request_t        *next;
};


typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);


struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    ngx_connection_t                 *connection;  // 请求对应的客户端连接

    void                            **ctx;  // 指向存放所有http模块上下文结构体的指针数组
    void                            **main_conf;  // 指向请求对应的存放main级别配置项结构体的指针数组
    void                            **srv_conf;  // 指向请求对应的存放srv级别的配置项结构体的指针数组
    void                            **loc_conf;  // 指向请求对应的存放loc级别的配置项结构体的指针数组

    ngx_http_event_handler_pt         read_event_handler;  // 请求对应的读事件处理函数(在连接上读事件发生时被调用)
    ngx_http_event_handler_pt         write_event_handler;  // 请求对应的写事件处理函数(在连接上写事件发生时被调用)

#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;
#endif

    ngx_http_upstream_t              *upstream;
    ngx_array_t                      *upstream_states;
                                         /* of ngx_http_upstream_state_t */

    ngx_pool_t                       *pool;  // 请求对应的内存池，区别连接对应的内存池

    /* 指向用于接收、缓存客户端发来的字节流的缓冲区，和ngx_connectoin_t结构体中的buffer字段指向的空间一样 */
    ngx_buf_t                        *header_in;

    /*
     * ngx_http_process_request_headers方法在接收、解析完请求头部后，会把解析到的每一个http头部加入到
     * 加入到headers_in的headers链表中，并构造headers_in中的其他成员
     */
    ngx_http_headers_in_t             headers_in;

    /*
     * http模块会把想要发送的响应头部信息放到headers_out中，期望http框架会把headers_out中的成员序列化为
     * http响应头，然后发送给客户端
     */
    ngx_http_headers_out_t            headers_out;

    /* 用于接收http请求包体的对象 */
    ngx_http_request_body_t          *request_body;

    time_t                            lingering_time;  // 延迟关闭连接的时长
    time_t                            start_sec;  // 请求初始化的时间(单位s)
    ngx_msec_t                        start_msec;  // 请求初始化的时间(单位ms)

    /*
     * 以下9个成员都是调用ngx_http_process_request_line方法时解析出来的请求行信息
     */
    ngx_uint_t                        method;
    ngx_uint_t                        http_version;

    ngx_str_t                         request_line;
    ngx_str_t                         uri;
    ngx_str_t                         args;
    ngx_str_t                         exten;
    ngx_str_t                         unparsed_uri;

    ngx_str_t                         method_name;
    ngx_str_t                         http_protocol;

    /*
     * out成员中存放的是发送给客户端的http响应。这个成员在什么情况下会用到呢，就是在http响应头或者响应体
     * 过大而导致无法一次性将其全部发送给客户端时，就会用out成员存放剩余未发送给客户端的响应内容。
     */
    ngx_chain_t                      *out;

    /*
     * 当前请求可能是用户发送过来的请求，也可能是派生出来的子请求，而main成员始终指向一系列相关的派生子请求
     * 的原始请求，一般可以通过main和当前请求的r的地址是否相等来判断当前请求是否是客户端发来的原始请求
     */
    ngx_http_request_t               *main;
    ngx_http_request_t               *parent;  // 当前请求的父请求
    ngx_http_postponed_request_t     *postponed;  // 存放当前请求的子请求或者当前请求产生的数据
    ngx_http_post_subrequest_t       *post_subrequest;  // 子请求结束时会调用里面的handler方法

    /* 原始请求的所有子请求都会就爱入到这个单链表，只有原始请求的该成员才有效 */
    ngx_http_posted_request_t        *posted_requests;

    /* 表示请求下次应当执行的阶段处理方法在r->phase_engine.handlers数组中的下标 */
    ngx_int_t                         phase_handler;

    /*
     * 表示NGX_HTTP_CONTENT_PHASE阶段提供给http模块处理请求的一种方式,
     * content_handler指向http模块实现的NGX_HTTP_CONTENT_PHASE阶段的请求处理方法
     */
    ngx_http_handler_pt               content_handler;

    /*
     * 在NGX_HTTP_ACCESS_PHASE阶段需要判断请求是否具有访问权限时，通过access_code来传递http
     * 模块的handler方法的返回值，如果access_code为0表示具有访问权限，否则则不具备访问权限。
     */
    ngx_uint_t                        access_code;

    /*
     * 我们知道，变量值的生命周期和请求是一样的，因此缓存变量值的地方一定是请求的结构体。
     * ngx_http_request_s中的variables成员便是缓存变量值的数组，数组的下标就是索引号。
     * 当http请求刚到达nginx的时候，就会创建缓存变量值的variables数组。
     * 每一个http请求都必须为所有缓存的变量建立ngx_http_variable_value_t数组
     * 唯有打算使用的变量才应该进行索引化，把它的值缓存到请求的variables数组中
     */
    ngx_http_variable_value_t        *variables;

#if (NGX_PCRE)
    ngx_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

    size_t                            limit_rate;  // 发送响应的最大速率
    size_t                            limit_rate_after;  // 发送limit_rate_after长度的响应后开始限速

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;  // 响应头的大小，包括响应行

    off_t                             request_length;  // http请求的全部长度，包括请求包体

    ngx_uint_t                        err_status;

    ngx_http_connection_t            *http_connection; // 当前请求对应的七层连接对象
#if (NGX_HTTP_V2)
    ngx_http_v2_stream_t             *stream;
#endif

    ngx_http_log_handler_pt           log_handler;

    ngx_http_cleanup_t               *cleanup;

    /*
     * 当前请求的引用计数。该成员只在原始请求中有效。每当对请求(包括原始请求和其派生出的子请求、孙子请求)
     * 执行一个新的独立操作时，都需要对原始请求的引用计数加1，防止请求处理出错。
     */
    unsigned                          count:16;
    unsigned                          subrequests:8;  // 能创建的子请求个数

    /* 阻塞标志位，仅有aio使用 */
    unsigned                          blocked:8;

    /* aio为1表示当前请求正在进行异步文件io */
    unsigned                          aio:1;

    /* 表示当前请求状态 */
    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with " " */
    unsigned                          space_in_uri:1;

    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;
    unsigned                          uri_changed:1;  // URI是否被rewrite重写的标志位
    unsigned                          uri_changes:4;  // URI被rewrite重写的次数(NGX_HTTP_REWRITE_PHASE阶段)

    /* 请求包体存放策略标志位 */
    unsigned                          request_body_in_single_buf:1;
    unsigned                          request_body_in_file_only:1;
    unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;
    unsigned                          request_body_no_buffering:1;

    unsigned                          subrequest_in_memory:1;  // 子请求产生的数据是否存放在内存中的标志位
    unsigned                          waited:1;//子请求提前完成时是否置done的标志位，如果为1，则提前完成时done立即置位

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;
    unsigned                          gzip_ok:1;
    unsigned                          gzip_vary:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * ngx_http_limit_conn_module and ngx_http_limit_req_module
     * we use the single bits in the request structure
     */
    unsigned                          limit_conn_set:1;
    unsigned                          limit_req_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;
    unsigned                          chunked:1;
    unsigned                          header_only:1;
    unsigned                          keepalive:1;  // 为1表示当前请求是keeplive请求
    unsigned                          lingering_close:1;  // 延迟关闭请求标志位
    unsigned                          discard_body:1;  // 正在丢弃包体的标志位
    unsigned                          reading_body:1;  // 正在读取包体的标志位
    unsigned                          internal:1;  // 子请求标志位
    unsigned                          error_page:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;
    unsigned                          header_sent:1;  // 表示响应头是否已经发送的标志位
    unsigned                          expect_tested:1;  // expect机制测试标志位
    unsigned                          root_tested:1;
    unsigned                          done:1;  // 请求完成的标志位
    unsigned                          logged:1;

    unsigned                          buffered:4;  // 表示缓冲区中是否有带发送内容的标志位

    unsigned                          main_filter_need_in_memory:1;
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;
    unsigned                          allow_ranges:1;
    unsigned                          subrequest_ranges:1;
    unsigned                          single_range:1;
    unsigned                          disable_not_modified:1;

#if (NGX_STAT_STUB)
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
#endif

    /* used to parse HTTP headers */

    /* Nginx中状态机来解析http请求时用state来表示当前的解析状态 */
    ngx_uint_t                        state;

    ngx_uint_t                        header_hash;
    ngx_uint_t                        lowcase_index;
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char                           *header_name_start;
    u_char                           *header_name_end;
    u_char                           *header_start;
    u_char                           *header_end;

    /*
     * a memory that can be reused after parsing a request line
     * via ngx_http_ephemeral_t
     */

    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;

    unsigned                          http_minor:16;
    unsigned                          http_major:16;
};


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
} ngx_http_ephemeral_t;


#define ngx_http_ephemeral(r)  (void *) (&r->uri_start)


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#define ngx_http_set_log_request(log, r)                                      \
    ((ngx_http_log_ctx_t *) log->data)->current_request = r


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
