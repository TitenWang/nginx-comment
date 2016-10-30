
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


static void *ngx_stream_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_stream_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_core_commands[] = {

    { ngx_string("server"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_core_listen,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("error_log"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_core_error_log,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tcp_nodelay"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_core_srv_conf_t, tcp_nodelay),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_core_module_ctx = {
    NULL,                                  /* postconfiguration */

    ngx_stream_core_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_core_create_srv_conf,       /* create server configuration */
    ngx_stream_core_merge_srv_conf         /* merge server configuration */
};


ngx_module_t  ngx_stream_core_module = {
    NGX_MODULE_V1,
    &ngx_stream_core_module_ctx,           /* module context */
    ngx_stream_core_commands,              /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* 创建用于存储ngx_stream_core_module模块生成的mian级别的配置项结构体 */
static void *
ngx_stream_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_stream_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_stream_listen_t))
        != NGX_OK)
    {
        return NULL;
    }

    return cmcf;
}


static void *
ngx_stream_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->handler = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
    cscf->tcp_nodelay = NGX_CONF_UNSET;

    return cscf;
}


static char *
ngx_stream_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_core_srv_conf_t *prev = parent;
    ngx_stream_core_srv_conf_t *conf = child;

    if (conf->handler == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no handler for server in %s:%ui",
                      conf->file_name, conf->line);
        return NGX_CONF_ERROR;
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            /*
             * 如果父配置块中也没有配置error_log指令，则用全局唯一的ngx_cycle_t对象中的new_log。
             * 这里将全局唯一的ngx_cycle_t对象中的new_log地址赋给了conf->error_log。如果全局配置块
             * 中也没有配置error_log指令，那么在解析完配置文件之后，Nginx会打开一个默认的配置文件，
             * logs/error.log。见ngx_log_open_default().
             */
            conf->error_log = &cf->cycle->new_log;
        }
    }

    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    return NGX_CONF_OK;
}

/*
 * ngx_stream_core_module模块中的error_log命令的解析函数，该命令可以配置在stream块内的NGX_STREAM_MAIN_CONF、
 * NGX_STREAM_SRV_CONF中。后面涉及到合并，解析的结果存放到ngx_stream_core_srv_conf_t对象的error_log成员中
 */
static char *
ngx_stream_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf = conf;

    return ngx_log_set_log(cf, &cscf->error_log);
}

/* 解析到stream块内的server{}配置块时就会调用这个函数 */
static char *
ngx_stream_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                         *rv;
    void                         *mconf;
    ngx_uint_t                    m;
    ngx_conf_t                    pcf;
    ngx_stream_module_t          *module;
    ngx_stream_conf_ctx_t        *ctx, *stream_ctx;
    ngx_stream_core_srv_conf_t   *cscf, **cscfp;
    ngx_stream_core_main_conf_t  *cmcf;

    /*
     * 在解析到stream块内的server配置块的时候，会建立属于这个server块的上下文，ngx_stream_conf_ctx_t
     */
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    /* server块下的配置上下文的main_conf指针数组将指向stream块下的配置上下文的main_conf指针数组 */
    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the server{}'s srv_conf */

    /* 分配用于存储出现在server块内的所有stream模块srv级别配置项结构体的指针数组 */
    ctx->srv_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* 遍历所有stream模块，调用stream模块的create_srv_conf创建存储srv级别的配置项的结构体 */
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    /* 获取ngx_stream_core_module模块的srv级别的配置项结构体，这个配置项结构体就代表了这个server块 */
    cscf = ctx->srv_conf[ngx_stream_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_stream_core_module.ctx_index];
    
    /*
     * 将ngx_stream_core_module模块的srv级别的配置项结构体挂载到ngx_stream_core_module模块的main级别
     * 配置项结构体的servers动态数组中。其实可以这么说，ngx_stream_core_module模块的mian级别配置项
     * 结构体代表的就是stream配置块，而解析server配置块时生成的ngx_stream_core_module模块的srv级别的
     * 配置项结构体代表的就是server配置块。
     */
    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    /* 开始解析server配置块里面的配置项 */
    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_STREAM_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}

/* 解析到server块内的listen配置项时会调用这个函数 */
static char *
ngx_stream_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    size_t                        len, off;
    in_port_t                     port;
    ngx_str_t                    *value;
    ngx_url_t                     u;
    ngx_uint_t                    i, backlog;
    struct sockaddr              *sa;
    struct sockaddr_in           *sin;
    ngx_stream_listen_t          *ls;
    ngx_stream_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
#endif

    /* 获取listen指令的参数 */
    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    /* 解析listen命令的第一个参数，即url */
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    /* 获取ngx_stream_core_module模块的main级别配置项结构体 */
    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    ls = cmcf->listen.elts;

    /*
     * 遍历已经解析到的listen命令，但本次解析到的是否和之前已经解析过的listen命令一样，
     * 如果一样的话，这样是不允许的，因为不允许两个server块内同时监听同一个ip:port.
     * 在这个版本中采用的是"port != u.port"，不知道为什么用主机序和网络序的比较。
     * 这样比较是不能实现一个ip:port只能被一个server监听的，除非一个port的网络序和主机序相等。
     * 在最新版本中修改了比较方式，即用同一种字节序的进行比较，这样可以保证同一个ip:port
     * 不会被两个server块同时监听。
     */
    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = &ls[i].u.sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            off = offsetof(struct sockaddr_in6, sin6_addr);
            len = 16;
            sin6 = &ls[i].u.sockaddr_in6;
            port = sin6->sin6_port;
            break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            off = offsetof(struct sockaddr_un, sun_path);
            len = sizeof(((struct sockaddr_un *) sa)->sun_path);
            port = 0;
            break;
#endif

        default: /* AF_INET */
            off = offsetof(struct sockaddr_in, sin_addr);
            len = 4;
            sin = &ls[i].u.sockaddr_in;
            port = sin->sin_port;
            break;
        }

        if (ngx_memcmp(ls[i].u.sockaddr_data + off, u.sockaddr + off, len)
            != 0)
        {
            continue;
        }

        /*
         * 主机序和网络序进行比较，感觉实现有点不大对。查看了最新版本，在最新版本中已经修改了
         * 比较方式，即用同一种字节序的port进行比较。
         */
        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    /*
     * 从ngx_stream_core_module模块main级别配置项结构体的listen动态数组中申请一个元素，
     * 存储本次listen命令的参数 
     */
    ls = ngx_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_stream_listen_t));

    ngx_memcpy(&ls->u.sockaddr, u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->backlog = NGX_LISTEN_BACKLOG;
    ls->type = SOCK_STREAM;  // 监听的socket类型为SOCK_STREAM
    ls->wildcard = u.wildcard;
    ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    ls->ipv6only = 1;
#endif

    backlog = 0;

    /* 
     * 下面开始遍历listen命令后续的参数，并进行响应解析，然后将解析结果设置到
     * ngx_stream_listen_t中的对应字段中 
     */
    for (i = 2; i < cf->args->nelts; i++) {

#if !(NGX_WIN32)
        if (ngx_strcmp(value[i].data, "udp") == 0) {
            ls->type = SOCK_DGRAM;  // 设置监听的socket类型为udp
            continue;
        }
#endif

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == NGX_ERROR || ls->backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            backlog = 1;

            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            u_char  buf[NGX_SOCKADDR_STRLEN];

            sa = &ls->u.sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    ls->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    ls->ipv6only = 0;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
                len = ngx_sock_ntop(sa, ls->socklen, buf,
                                    NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[i].data, "reuseport") == 0) {
#if (NGX_HAVE_REUSEPORT)
            ls->reuseport = 1;
            ls->bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (ngx_strcmp(value[i].data, "ssl") == 0) {
#if (NGX_STREAM_SSL)
            ls->ssl = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_stream_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (ngx_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;

            } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
                ls->so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepidle = ngx_parse_time(&s, 1);
                    if (ls->tcp_keepidle == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepintvl = ngx_parse_time(&s, 1);
                    if (ls->tcp_keepintvl == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    ls->tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if (ls->tcp_keepcnt == NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0
                    && ls->tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                ls->so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            ls->bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    /* 如果监听的是udp，则判断配置命令是否合法。因为有些参数不适用于udp */
    if (ls->type == SOCK_DGRAM) {
        if (backlog) {
            return "\"backlog\" parameter is incompatible with \"udp\"";
        }

#if (NGX_STREAM_SSL)
        if (ls->ssl) {
            return "\"ssl\" parameter is incompatible with \"udp\"";
        }
#endif

        if (ls->so_keepalive) {
            return "\"so_keepalive\" parameter is incompatible with \"udp\"";
        }
    }

    return NGX_CONF_OK;
}
