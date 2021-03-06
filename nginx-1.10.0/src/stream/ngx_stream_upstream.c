
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


static char *ngx_stream_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);
static char *ngx_stream_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_stream_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_init_main_conf(ngx_conf_t *cf, void *conf);


static ngx_command_t  ngx_stream_upstream_commands[] = {

    { ngx_string("upstream"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_stream_upstream,
      0,
      0,
      NULL },

    { ngx_string("server"),
      NGX_STREAM_UPS_CONF|NGX_CONF_1MORE,
      ngx_stream_upstream_server,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_module_ctx = {
    NULL,                                  /* postconfiguration */

    ngx_stream_upstream_create_main_conf,  /* create main configuration */
    ngx_stream_upstream_init_main_conf,    /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_module_ctx,       /* module context */
    ngx_stream_upstream_commands,          /* module directives */
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

/* 当配置文件中出现upstream块的时候就会调用这个函数进行解析 */
static char *
ngx_stream_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                            *rv;
    void                            *mconf;
    ngx_str_t                       *value;
    ngx_url_t                        u;
    ngx_uint_t                       m;
    ngx_conf_t                       pcf;
    ngx_stream_module_t             *module;
    ngx_stream_conf_ctx_t           *ctx, *stream_ctx;
    ngx_stream_upstream_srv_conf_t  *uscf;

    ngx_memzero(&u, sizeof(ngx_url_t));

    value = cf->args->elts;
    u.host = value[1];  // upstream命令第一个参数是主机名而不是完整的url
    u.no_resolve = 1;  // 不进行域名解析，因为upstream后面跟的名字一般都是内部指定的，所以没必要域名解析
    u.no_port = 1;  // 不带有port信息，因为upstream后面跟的名字一般都是内部指定的，所以都不带端口信息

    /*
     * 因为是解析到一个upstream块，所以需要以所有的flags调用ngx_stream_upstream_add。那什么情况下
     * 会以0调用ngx_stream_upstream_add函数呢?就是在解析proxy_pass命令的时候，因为在解析这个命令的
     * 时候，其目的是找到对应的upstream块的配置信息，而对应的upstream块配置信息就是在解析到具体的
     * upstream{}的时候创建的。
     */
    uscf = ngx_stream_upstream_add(cf, &u, NGX_STREAM_UPSTREAM_CREATE
                                           |NGX_STREAM_UPSTREAM_WEIGHT
                                           |NGX_STREAM_UPSTREAM_MAX_FAILS
                                           |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
                                           |NGX_STREAM_UPSTREAM_DOWN
                                           |NGX_STREAM_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return NGX_CONF_ERROR;
    }


    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    /* upstream块内的main级别配置项直接指向stream块内的main级别配置项 */
    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    /* 分配用于存放所有stream模块生成的srv级别配置项结构体的指针数组 */
    ctx->srv_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->srv_conf[ngx_stream_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;

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

    /*一个upstream块内可能会出现多个server指令，所以以动态数组进行组织*/
    uscf->servers = ngx_array_create(cf->pool, 4,
                                     sizeof(ngx_stream_upstream_server_t));
    if (uscf->servers == NULL) {
        return NGX_CONF_ERROR;
    }


    /* parse inside upstream{} */

    /* 开始解析upstream块，当解析到server指令的时候，就会调用ngx_stream_upstream_server进行server指令解析 */
    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_STREAM_UPS_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /* upstream块内必须至少配置一个server指令，否则是非法的 */
    if (uscf->servers->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return NGX_CONF_ERROR;
    }

    return rv;
}

/* 当upstream块内出现server配置项的就会调用该函数去解析 */
static char *
ngx_stream_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_upstream_srv_conf_t  *uscf = conf;

    time_t                         fail_timeout;
    ngx_str_t                     *value, s;
    ngx_url_t                      u;
    ngx_int_t                      weight, max_fails;
    ngx_uint_t                     i;
    ngx_stream_upstream_server_t  *us;

    /* 从upstream配置块信息中申请一个存放server配置块信息的结构体 */
    us = ngx_array_push(uscf->servers);
    if (us == NULL) {
        return NGX_CONF_ERROR;
    }

    /* 初始化清空 */
    ngx_memzero(us, sizeof(ngx_stream_upstream_server_t));

    value = cf->args->elts;

    /* weight、max_fails和fail_timeout的默认值 */
    weight = 1;
    max_fails = 1;
    fail_timeout = 10;

    /* 解析weight、max_fails以及fail_timeout等参数 */
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NGX_STREAM_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NGX_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NGX_STREAM_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NGX_STREAM_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = ngx_parse_time(&s, 1);

            if (fail_timeout == (time_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & NGX_STREAM_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (ngx_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & NGX_STREAM_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    /* 解析server配置项后面的第一个url参数 */
    u.url = value[1];

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    if (u.no_port) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no port in upstream \"%V\"", &u.url);
        return NGX_CONF_ERROR;
    }

    /* 保存解析结果 */
    us->name = u.url;
    us->addrs = u.addrs;  // 一个主机名字可能会有多个ip地址
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;

not_supported:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return NGX_CONF_ERROR;
}

/* 获取一个存储upstream块配置信息的结构体 */
ngx_stream_upstream_srv_conf_t *
ngx_stream_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags)
{
    ngx_uint_t                        i;
    ngx_stream_upstream_server_t     *us;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_stream_upstream_main_conf_t  *umcf;

    /*
     * 如果flags里面不包含NGX_STREAM_UPSTREAM_CREATE标志位，则说明并不是在配置文件中解析到upstream
     * 块时调用这个函数，而是在解析到proxy_pass命令时调用的，这个时候是用相应的url参数来匹配解析
     * upstream块的时候创建的那个结构体。但是如果这个时候还没有解析到upstream块呢?则也会创建一个
     * 对应的用来存储upstream配置信息的结构体，只是这个时候里面的很多信息没有初始化，等真正解析
     * 到upstream配置块的时候，会以包含NGX_STREAM_UPSTREAM_CREATE位的flags来调用该函数，那个时候
     * 就可以索引出此次创建的结构体。
     */
    if (!(flags & NGX_STREAM_UPSTREAM_CREATE)) {

        if (ngx_parse_url(cf->pool, u) != NGX_OK) {
            if (u->err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    /*
     * 获取ngx_stream_upstream_module的main级别配置结构体，里面包含了stream块内
     * 所有upstream块的配置信息结构体
     */
    umcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_upstream_module);

    uscfp = umcf->upstreams.elts;

    /* 
     * 遍历stream配置块内所有的upstream配置块，匹配是否之前已经创建过用来存储
     * upstream块配置信息的结构体 
     */
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || ngx_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & NGX_STREAM_UPSTREAM_CREATE)
             && (uscfp[i]->flags & NGX_STREAM_UPSTREAM_CREATE))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & NGX_STREAM_UPSTREAM_CREATE) && !u->no_port) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & NGX_STREAM_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port != u->port) {
            continue;
        }

        if (flags & NGX_STREAM_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
        }

        return uscfp[i];
    }

    /* 程序执行到这里表明需要重新创建一个存储upstream配置块信息的结构体 */
    uscf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->no_port = u->no_port;

    /* u->naddrs == 1成立的话表明该域名只对应一个ip地址 */
    if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
        uscf->servers = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_stream_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = ngx_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        ngx_memzero(us, sizeof(ngx_stream_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    /*
     * 从umcf->upstreams中申请一个元素，存储此次解析到的upstream块信息，同时将解析到的upstream块信息
     * 作为返回值返回
     */
    uscfp = ngx_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


static void *
ngx_stream_upstream_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_main_conf_t  *umcf;

    umcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(ngx_stream_upstream_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
ngx_stream_upstream_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_stream_upstream_main_conf_t *umcf = conf;

    ngx_uint_t                        i;
    ngx_stream_upstream_init_pt       init;
    ngx_stream_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    /*
     * 遍历stream块内的所有upstream块，进行后端服务器负载均衡的初始化，这里的负载均衡
     * 和http模块的负载均衡如出一辙。
     */
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream
                                         ? uscfp[i]->peer.init_upstream
                                         : ngx_stream_upstream_init_round_robin;

        /*
         * 调用uscfp[i]->peer.init_upstream初始化负载均衡，主要就是利用解析配置文件
         * 得到的server信息来构造后端服务器列表。
         */
        if (init(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
