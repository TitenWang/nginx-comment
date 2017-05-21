
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_stream.h>


static char *ngx_stream_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_stream_listen_t *listen);
static char *ngx_stream_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);
static ngx_int_t ngx_stream_add_addrs(ngx_conf_t *cf, ngx_stream_port_t *stport,
    ngx_stream_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_stream_add_addrs6(ngx_conf_t *cf,
    ngx_stream_port_t *stport, ngx_stream_conf_addr_t *addr);
#endif
static ngx_int_t ngx_stream_cmp_conf_addrs(const void *one, const void *two);


ngx_uint_t  ngx_stream_max_module;


static ngx_command_t  ngx_stream_commands[] = {

    { ngx_string("stream"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_stream_module_ctx = {
    ngx_string("stream"),
    NULL,
    NULL
};


ngx_module_t  ngx_stream_module = {
    NGX_MODULE_V1,
    &ngx_stream_module_ctx,                /* module context */
    ngx_stream_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * 当配置文件中出现stream{}配置项的时候就会调用这个函数，开启stream块内所有配置项的解析
 */
static char *
ngx_stream_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                          *rv;
    ngx_uint_t                     i, m, mi, s;
    ngx_conf_t                     pcf;
    ngx_array_t                    ports;
    ngx_stream_listen_t           *listen;
    ngx_stream_module_t           *module;
    ngx_stream_conf_ctx_t         *ctx;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_core_main_conf_t   *cmcf;

    /* 如果配置文件中出现了两个stream块，那么在解析第二个stream块的时候就会报错 */
    if (*(ngx_stream_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main stream context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_stream_conf_ctx_t **) conf = ctx;

    /* count the number of the stream modules and set up their indices */

    ngx_stream_max_module = ngx_count_modules(cf->cycle, NGX_STREAM_MODULE);


    /* the stream main_conf context, it's the same in the all stream contexts */

    /* 创建用于存储所有stream模块main级别配置项结构体的指针数组 */
    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_stream_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the stream null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    /* 创建用于存储所有stream模块在main级别下面的srv级别的配置项结构体的指针数组 */
    ctx->srv_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's and the null srv_conf's of the all stream modules
     */

    /*
     * 遍历所有的stream模块，分别调用stream模块实现的用于存储main级别下面的配置项的结构体
     * 并挂载到上面刚刚创建的结构体指针数组中。
     */
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* 创建main级别下面的配置项结构体 */
        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        /* 创建在main级别下面的srv级别的配置项结构体 */
        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the stream{} block */

    /*
     * 上面创建好了存储stream{}模块内部可能出现的模块的配置项的结构体，下面就可以
     * 开始解析stream{}内部的配置项了。
     */
    pcf = *cf;
    cf->ctx = ctx;

    cf->module_type = NGX_STREAM_MODULE;
    cf->cmd_type = NGX_STREAM_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init stream{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[ngx_stream_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    /*
     * 程序执行到这里表明stream{}块下的配置项都已经解析完毕，所以就需要做一个初始化工作，
     * 以及合并srv级别的配置项。
     */
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init stream{} main_conf's */

        cf->ctx = ctx;

        /* 调用所有的stream模块实现的init_main_conf做一些初始化工作 */
        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        /* 合并srv级别的配置项 */
        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    /* 调用所有stream模块实现的postconfiguration方法 */
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    *cf = pcf;


    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_stream_conf_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* cmcf->listen存放的是解析stream块内所有server块的listen命令的信息 */
    listen = cmcf->listen.elts;

    /* 遍历所有的listen命令配置信息，新增监听套接口信息 */
    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (ngx_stream_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_stream_optimize_servers(cf, &ports);
}

/* 新增监听套接口信息 */
static ngx_int_t
ngx_stream_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_stream_listen_t *listen)
{
    in_port_t                p;
    ngx_uint_t               i;
    struct sockaddr         *sa;
    struct sockaddr_in      *sin;
    ngx_stream_conf_port_t  *port;
    ngx_stream_conf_addr_t  *addr;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6     *sin6;
#endif

    sa = &listen->u.sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = &listen->u.sockaddr_in6;
        p = sin6->sin6_port;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        p = 0;
        break;
#endif

    /* ipv4的addr和port信息 */
    default: /* AF_INET */
        sin = &listen->u.sockaddr_in;
        p = sin->sin_port;
        break;
    }

    /* 遍历已经加入到ports中的port，看本次需要添加的port是否已经加入过了 */
    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {

        /* 如果监听的是同一个端口，并且是同一个协议族以及相同的socket类型，则说明port添加过了 */
        if (p == port[i].port
            && listen->type == port[i].type
            && sa->sa_family == port[i].family)
        {
            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    /* 从ports动态数组中申请一个元素，用于存放本次需要添加的port信息 */
    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    /* 设置port的一些信息 */
    port->family = sa->sa_family;
    port->type = listen->type;
    port->port = p;

    /*
     * 因为对于同一个端口，可能会监听不同的ip地址，所以需要为存放不同的ip地址做准备.
     * 例如，server a { listen 192.168.0.1:80; } server b { listen 192.168.0.2:80; }，
     * 那么对于同一个端口不同的ip的情况，就会将ip地址存放在port->addrs中。
     */
    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(ngx_stream_conf_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

found:

    /* 从port->addrs动态数组中申请一个元素，存放ip地址信息 */
    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    /* 将listen命令的参数信息存放到ip地址信息的opt字段中 */
    addr->opt = *listen;

    return NGX_OK;
}


static char *
ngx_stream_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{
    ngx_uint_t                   i, p, last, bind_wildcard;
    ngx_listening_t             *ls;
    ngx_stream_port_t           *stport;
    ngx_stream_conf_port_t      *port;
    ngx_stream_conf_addr_t      *addr;
    ngx_stream_core_srv_conf_t  *cscf;

    /* 遍历配置文件中stream块内的所有listen命令监听的port端口 */
    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        /* 对监听同一个端口的所有ip地址进行排序，经过这个排序，带有通配符的地址会在后面 */
        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_stream_conf_addr_t), ngx_stream_cmp_conf_addrs);

        /* addr保存着解析配置文件过程得到的监听同一个端口的所有地址信息 */
        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        /*
         * 经过上面的排序，对应于同一个端口的多个ip地址，如果存在有通配符(对应的ip
         * 地址为0.0.0.0)，那么带有通配符的地址会排在最后面。所以这里检测最后一个
         * ip地址，如果该地址包含有通配符，那么就会设置通配符标志位，后面流程对于
         * 这个端口就只会建立一个ngx_listening_t结构体对象。
         */
        if (addr[last - 1].opt.wildcard) {
            addr[last - 1].opt.bind = 1;  /* 带有通配符的地址该标志位会设置为1 */
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        /*
         * 遍历监听同一个端口的所有ip地址，如果存放通配符的情况，那么针对这个端口，只会创建
         * 一个监听套接口，例如 listen *:80; listen 192.168.0.1:80; listen 192.168.0.2:80;
         * 对于上面的这种情况，只会创建一个ngx_listening_t结构体。如果不存在通配符的情况，如:
         * listen 192.168.0.1:80; listen 192.168.0.2:80;，这个时候就会创建两个ngx_listening_t
         * 监听套接口。
         */
        while (i < last) {

            /* 如果监听该端口包含的ip地址含有通配符且地址信息中bind标志位为0，条件判断才为真 */
            if (bind_wildcard && !addr[i].opt.bind) {
                /* i只有在这个地方会进行递增，否则一直是0 */
                i++;
                continue;
            }

            /* 创建一个ngx_listening_t结构体对象 */
            ls = ngx_create_listening(cf, &addr[i].opt.u.sockaddr,
                                      addr[i].opt.socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            /* 设置ngx_listening_t结构体一些信息 */
            ls->addr_ntop = 1;
            ls->handler = ngx_stream_init_connection; //  新的tcp连接成功建立了后的处理方法
            ls->pool_size = 256;
            ls->type = addr[i].opt.type;

            cscf = addr->opt.ctx->srv_conf[ngx_stream_core_module.ctx_index];

            /*
             * 获取解析配置文件得到的日志对象，在ngx_configure_listening_sockets()函数中会
             * 将ls->logp中存放的日志对象赋值给ls->log。
             */
            ls->logp = cscf->error_log;
            
            /* 设置日志对象处理回调及相关参数 */
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

            ls->backlog = addr[i].opt.backlog;

            ls->wildcard = addr[i].opt.wildcard;

            ls->keepalive = addr[i].opt.so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].opt.tcp_keepidle;
            ls->keepintvl = addr[i].opt.tcp_keepintvl;
            ls->keepcnt = addr[i].opt.tcp_keepcnt;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            ls->ipv6only = addr[i].opt.ipv6only;
#endif

#if (NGX_HAVE_REUSEPORT)
            ls->reuseport = addr[i].opt.reuseport;
#endif

            stport = ngx_palloc(cf->pool, sizeof(ngx_stream_port_t));
            if (stport == NULL) {
                return NGX_CONF_ERROR;
            }

            /* 存放着监听该端口的所有地址信息 */
            ls->servers = stport;

            /* 该ngx_listening_t类型的对象包含的ip地址个数 */
            stport->naddrs = i + 1;

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                if (ngx_stream_add_addrs6(cf, stport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (ngx_stream_add_addrs(cf, stport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            if (ngx_clone_listening(cf, ls) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            addr++;
            last--;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_add_addrs(ngx_conf_t *cf, ngx_stream_port_t *stport,
    ngx_stream_conf_addr_t *addr)
{
    u_char                *p;
    size_t                 len;
    ngx_uint_t             i;
    struct sockaddr_in    *sin;
    ngx_stream_in_addr_t  *addrs;
    u_char                 buf[NGX_SOCKADDR_STRLEN];

    /*
     * 申请用于存放监听同一个端口的所有ip地址信息的内存，当配置存在通配符情况，
     * 对于该端口只会创建一个监听套接口，因此需要将监听同一个端口的多个地址信息
     * 管理起来，后续该端口有请求来的时候才知道是由哪个地址来处理。
     */
    stport->addrs = ngx_pcalloc(cf->pool,
                                stport->naddrs * sizeof(ngx_stream_in_addr_t));
    if (stport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin = &addr[i].opt.u.sockaddr_in;
        addrs[i].addr = sin->sin_addr.s_addr;  // 保存ip地址信息

        addrs[i].conf.ctx = addr[i].opt.ctx;  // 保存监听该地址所在server块的配置上下文
#if (NGX_STREAM_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif

        /* 下面用于生成字符串形式的ip地址信息，并保存在addrs[i].conf.addr_text */
        len = ngx_sock_ntop(&addr[i].opt.u.sockaddr, addr[i].opt.socklen, buf,
                            NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_stream_add_addrs6(ngx_conf_t *cf, ngx_stream_port_t *stport,
    ngx_stream_conf_addr_t *addr)
{
    u_char                 *p;
    size_t                  len;
    ngx_uint_t              i;
    struct sockaddr_in6    *sin6;
    ngx_stream_in6_addr_t  *addrs6;
    u_char                  buf[NGX_SOCKADDR_STRLEN];

    stport->addrs = ngx_pcalloc(cf->pool,
                                stport->naddrs * sizeof(ngx_stream_in6_addr_t));
    if (stport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin6 = &addr[i].opt.u.sockaddr_in6;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].opt.ctx;
#if (NGX_STREAM_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif

        len = ngx_sock_ntop(&addr[i].opt.u.sockaddr, addr[i].opt.socklen, buf,
                            NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs6[i].conf.addr_text.len = len;
        addrs6[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_stream_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_stream_conf_addr_t  *first, *second;

    first = (ngx_stream_conf_addr_t *) one;
    second = (ngx_stream_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}
