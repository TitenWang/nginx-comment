
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    in_addr_t         mask;  // 掩码地址
    in_addr_t         addr;  // ip地址
    /* 因为这个结构体是allow和deny共用，所以需要一个标志位来区分两者 */
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_stream_access_rule_t;

#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr   addr;
    struct in6_addr   mask;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_stream_access_rule6_t;

#endif

#if (NGX_HAVE_UNIX_DOMAIN)

typedef struct {
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_stream_access_rule_un_t;

#endif

typedef struct {
    ngx_array_t      *rules;     /* array of ngx_stream_access_rule_t */
#if (NGX_HAVE_INET6)
    ngx_array_t      *rules6;    /* array of ngx_stream_access_rule6_t */
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_array_t      *rules_un;  /* array of ngx_stream_access_rule_un_t */
#endif
} ngx_stream_access_srv_conf_t;


static ngx_int_t ngx_stream_access_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_access_inet(ngx_stream_session_t *s,
    ngx_stream_access_srv_conf_t *ascf, in_addr_t addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_stream_access_inet6(ngx_stream_session_t *s,
    ngx_stream_access_srv_conf_t *ascf, u_char *p);
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
static ngx_int_t ngx_stream_access_unix(ngx_stream_session_t *s,
    ngx_stream_access_srv_conf_t *ascf);
#endif
static ngx_int_t ngx_stream_access_found(ngx_stream_session_t *s,
    ngx_uint_t deny);
static char *ngx_stream_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_stream_access_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_access_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_stream_access_init(ngx_conf_t *cf);


static ngx_command_t  ngx_stream_access_commands[] = {

    { ngx_string("allow"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_access_rule,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("deny"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_access_rule,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



static ngx_stream_module_t  ngx_stream_access_module_ctx = {
    ngx_stream_access_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_access_create_srv_conf,     /* create server configuration */
    ngx_stream_access_merge_srv_conf       /* merge server configuration */
};


ngx_module_t  ngx_stream_access_module = {
    NGX_MODULE_V1,
    &ngx_stream_access_module_ctx,         /* module context */
    ngx_stream_access_commands,            /* module directives */
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

/* access模块处理函数 */
static ngx_int_t
ngx_stream_access_handler(ngx_stream_session_t *s)
{
    struct sockaddr_in            *sin;
    ngx_stream_access_srv_conf_t  *ascf;
#if (NGX_HAVE_INET6)
    u_char                        *p;
    in_addr_t                      addr;
    struct sockaddr_in6           *sin6;
#endif

    ascf = ngx_stream_get_module_srv_conf(s, ngx_stream_access_module);

    /* 判断nginx与客户端之间的连接的协议族 */
    switch (s->connection->sockaddr->sa_family) {

    case AF_INET:
        /* ascf->rules不为空说明在配置文件中配置了access规则 */
        if (ascf->rules) {
            /* 获取客户端地址信息 */
            sin = (struct sockaddr_in *) s->connection->sockaddr;
            return ngx_stream_access_inet(s, ascf, sin->sin_addr.s_addr);
        }
        break;

#if (NGX_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (ascf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return ngx_stream_access_inet(s, ascf, htonl(addr));
        }

        if (ascf->rules6) {
            return ngx_stream_access_inet6(s, ascf, p);
        }

        break;

#endif

#if (NGX_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        if (ascf->rules_un) {
            return ngx_stream_access_unix(s, ascf);
        }

        break;

#endif
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_stream_access_inet(ngx_stream_session_t *s,
    ngx_stream_access_srv_conf_t *ascf, in_addr_t addr)
{
    ngx_uint_t                 i;
    ngx_stream_access_rule_t  *rule;

    /* 遍历解析配置文件时得到的规则动态数组，看addr是否在规则之中 */
    rule = ascf->rules->elts;
    for (i = 0; i < ascf->rules->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       addr, rule[i].mask, rule[i].addr);

        /* 如果在规则数组中找到了对应的ip地址，则需要进一步处理 */
        if ((addr & rule[i].mask) == rule[i].addr) {
            return ngx_stream_access_found(s, rule[i].deny);
        }
    }

    /* 如果客户端ip地址不在规则数组中，则返回NGX_DECLINED，主流程往下继续执行 */
    return NGX_DECLINED;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_stream_access_inet6(ngx_stream_session_t *s,
    ngx_stream_access_srv_conf_t *ascf, u_char *p)
{
    ngx_uint_t                  n;
    ngx_uint_t                  i;
    ngx_stream_access_rule6_t  *rule6;

    rule6 = ascf->rules6->elts;
    for (i = 0; i < ascf->rules6->nelts; i++) {

#if (NGX_DEBUG)
        {
        size_t  cl, ml, al;
        u_char  ct[NGX_INET6_ADDRSTRLEN];
        u_char  mt[NGX_INET6_ADDRSTRLEN];
        u_char  at[NGX_INET6_ADDRSTRLEN];

        cl = ngx_inet6_ntop(p, ct, NGX_INET6_ADDRSTRLEN);
        ml = ngx_inet6_ntop(rule6[i].mask.s6_addr, mt, NGX_INET6_ADDRSTRLEN);
        al = ngx_inet6_ntop(rule6[i].addr.s6_addr, at, NGX_INET6_ADDRSTRLEN);

        ngx_log_debug6(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
        }
#endif

        for (n = 0; n < 16; n++) {
            if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
                goto next;
            }
        }

        return ngx_stream_access_found(s, rule6[i].deny);

    next:
        continue;
    }

    return NGX_DECLINED;
}

#endif


#if (NGX_HAVE_UNIX_DOMAIN)

static ngx_int_t
ngx_stream_access_unix(ngx_stream_session_t *s,
    ngx_stream_access_srv_conf_t *ascf)
{
    ngx_uint_t                    i;
    ngx_stream_access_rule_un_t  *rule_un;

    rule_un = ascf->rules_un->elts;
    for (i = 0; i < ascf->rules_un->nelts; i++) {

        /* TODO: check path */
        if (1) {
            return ngx_stream_access_found(s, rule_un[i].deny);
        }
    }

    return NGX_DECLINED;
}

#endif


static ngx_int_t
ngx_stream_access_found(ngx_stream_session_t *s, ngx_uint_t deny)
{
    /* 如果是deny的话，则返回NGX_ABORT，表明当前ip不允许访问 */
    if (deny) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "access forbidden by rule");
        return NGX_ABORT;
    }

    /* 如果是allow，则返回NGX_OK，表明当前ip允许访问 */
    return NGX_OK;
}

/* allow和deny命令解析函数 */
static char *
ngx_stream_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_access_srv_conf_t *ascf = conf;

    ngx_int_t                     rc;
    ngx_uint_t                    all;
    ngx_str_t                    *value;
    ngx_cidr_t                    cidr;
    ngx_stream_access_rule_t     *rule;
#if (NGX_HAVE_INET6)
    ngx_stream_access_rule6_t    *rule6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_stream_access_rule_un_t  *rule_un;
#endif

    ngx_memzero(&cidr, sizeof(ngx_cidr_t));

    value = cf->args->elts;

    /* 判断allow参数是不是"all"，如果是的话则all为1 */
    all = (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0);

    if (!all) {

#if (NGX_HAVE_UNIX_DOMAIN)

        if (value[1].len == 5 && ngx_strcmp(value[1].data, "unix:") == 0) {
            cidr.family = AF_UNIX;
            rc = NGX_OK;

        } else {
            rc = ngx_ptocidr(&value[1], &cidr);
        }

#else
        rc = ngx_ptocidr(&value[1], &cidr); // 计算ip地址和掩码
#endif

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "invalid parameter \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value[1]);
        }
    }

    /* ipv4 */
    if (cidr.family == AF_INET || all) {

        /* 创建存储可访问和禁止访问规则的动态数组 */
        if (ascf->rules == NULL) {
            ascf->rules = ngx_array_create(cf->pool, 4,
                                           sizeof(ngx_stream_access_rule_t));
            if (ascf->rules == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        /* 从动态数组中申请一个元素 */
        rule = ngx_array_push(ascf->rules);
        if (rule == NULL) {
            return NGX_CONF_ERROR;
        }

        /* 将allow或deny中配置的ip信息记录下来 */
        rule->mask = cidr.u.in.mask;
        rule->addr = cidr.u.in.addr;
        rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }

#if (NGX_HAVE_INET6)
    if (cidr.family == AF_INET6 || all) {

        if (ascf->rules6 == NULL) {
            ascf->rules6 = ngx_array_create(cf->pool, 4,
                                            sizeof(ngx_stream_access_rule6_t));
            if (ascf->rules6 == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule6 = ngx_array_push(ascf->rules6);
        if (rule6 == NULL) {
            return NGX_CONF_ERROR;
        }

        rule6->mask = cidr.u.in6.mask;
        rule6->addr = cidr.u.in6.addr;
        rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    if (cidr.family == AF_UNIX || all) {

        if (ascf->rules_un == NULL) {
            ascf->rules_un = ngx_array_create(cf->pool, 1,
                                          sizeof(ngx_stream_access_rule_un_t));
            if (ascf->rules_un == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule_un = ngx_array_push(ascf->rules_un);
        if (rule_un == NULL) {
            return NGX_CONF_ERROR;
        }

        rule_un->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

    return NGX_CONF_OK;
}


static void *
ngx_stream_access_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_access_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_access_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_stream_access_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_access_srv_conf_t  *prev = parent;
    ngx_stream_access_srv_conf_t  *conf = child;

    if (conf->rules == NULL
#if (NGX_HAVE_INET6)
        && conf->rules6 == NULL
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        && conf->rules_un == NULL
#endif
    ) {
        conf->rules = prev->rules;
#if (NGX_HAVE_INET6)
        conf->rules6 = prev->rules6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        conf->rules_un = prev->rules_un;
#endif
    }

    return NGX_CONF_OK;
}

/* 解析完stream块内所有配置项之后回调 */
static ngx_int_t
ngx_stream_access_init(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    /* 注册access_handler */
    cmcf->access_handler = ngx_stream_access_handler;

    return NGX_OK;
}
