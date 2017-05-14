
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    u_char                     color;
    u_char                     len;  //客户端ip地址的长度
    u_short                    conn;  // 客户端已经发起的连接数
    u_char                     data[1];  // 客户端ip地址
} ngx_stream_limit_conn_node_t;


typedef struct {
    ngx_shm_zone_t            *shm_zone;
    ngx_rbtree_node_t         *node;
} ngx_stream_limit_conn_cleanup_t;


typedef struct {
    ngx_rbtree_t              *rbtree;
} ngx_stream_limit_conn_ctx_t;


typedef struct {
    ngx_shm_zone_t            *shm_zone;  // limit_conn第一个参数指定的共享内存
    ngx_uint_t                 conn;  // 一个ip同时可以发起的最大连接数
} ngx_stream_limit_conn_limit_t;


typedef struct {
    ngx_array_t                limits;
    ngx_uint_t                 log_level;
} ngx_stream_limit_conn_conf_t;


static ngx_rbtree_node_t *ngx_stream_limit_conn_lookup(ngx_rbtree_t *rbtree,
    ngx_str_t *key, uint32_t hash);
static void ngx_stream_limit_conn_cleanup(void *data);
static ngx_inline void ngx_stream_limit_conn_cleanup_all(ngx_pool_t *pool);

static void *ngx_stream_limit_conn_create_conf(ngx_conf_t *cf);
static char *ngx_stream_limit_conn_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_stream_limit_conn_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_stream_limit_conn_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_stream_limit_conn_commands[] = {

    { ngx_string("limit_conn_zone"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_stream_limit_conn_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_conn"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
      ngx_stream_limit_conn,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_conn_log_level"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_limit_conn_conf_t, log_level),
      &ngx_stream_limit_conn_log_levels },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_limit_conn_module_ctx = {
    ngx_stream_limit_conn_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_limit_conn_create_conf,     /* create server configuration */
    ngx_stream_limit_conn_merge_conf,      /* merge server configuration */
};


ngx_module_t  ngx_stream_limit_conn_module = {
    NGX_MODULE_V1,
    &ngx_stream_limit_conn_module_ctx,       /* module context */
    ngx_stream_limit_conn_commands,          /* module directives */
    NGX_STREAM_MODULE,                       /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * ngx_stream_limit_conn_module模块的处理函数，用于判断当前建链的客户端是否还可以继续建链，如果不可以
 * 建链，则会结束主流程中已经建立的连接
 */
static ngx_int_t
ngx_stream_limit_conn_handler(ngx_stream_session_t *s)
{
    size_t                            n;
    uint32_t                          hash;
    ngx_str_t                         key;
    ngx_uint_t                        i;
    ngx_slab_pool_t                  *shpool;
    ngx_rbtree_node_t                *node;
    ngx_pool_cleanup_t               *cln;
    struct sockaddr_in               *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6              *sin6;
#endif
    ngx_stream_limit_conn_ctx_t      *ctx;
    ngx_stream_limit_conn_node_t     *lc;
    ngx_stream_limit_conn_conf_t     *lccf;
    ngx_stream_limit_conn_limit_t    *limits;
    ngx_stream_limit_conn_cleanup_t  *lccln;

    /* 判断客户端和nginx之间的连接协议族 */
    switch (s->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) s->connection->sockaddr;

        /* 获取客户端ip地址 */
        key.len = sizeof(in_addr_t);
        key.data = (u_char *) &sin->sin_addr;

        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;

        key.len = sizeof(struct in6_addr);
        key.data = sin6->sin6_addr.s6_addr;

        break;
#endif

    default:
        return NGX_DECLINED;
    }

    /* 用crc32计算ip地址对应的hash值 */
    hash = ngx_crc32_short(key.data, key.len);

    lccf = ngx_stream_get_module_srv_conf(s, ngx_stream_limit_conn_module);
    limits = lccf->limits.elts;

    /*
     *     从下面的循环实现可以看出，如果同一个server块中配置了多个limit_conn命令(前提是他们
     * 指定的共享内存不是同一个)，那么所有这些limit_conn命令的配置都会起作用，并且会以
     * 并发连接数最小的那个配置来决定客户端的连接是否会被断开。举个例子，如果有如下配置:
     * server { limit_conn zone0 2; limit_conn zone1 3; }。对于一个客户端来说，如果并发
     * 连接数大于2的时候，那么会由于zone0配置的限制而导致第三个开始的后续连接都会被断开。
     *     另外，limit_conn_zone命令针对所有连接到nginx上的客户端ip，即不同的客户端ip使用的
     * 是同一块共享内存。从该命令及下面的实现可以看出，客户端ip地址被用作会话的key值(即一个客户端
     * 发起的多个连接的共有信息对应红黑树中一个节点，红黑树节点的内存都是从共享内存中申请的)。
     * 而共享内存是有限的，其所能承受的会话数(发起连接的客户端ip数量)也是有限的，超过了会话数上限的
     * 客户端连接也会被断开。
     * the key is a client IP address set by the $binary_remote_addr variable. The size of 
     * $binary_remote_addr is 4 bytes for IPv4 addresses or 16 bytes for IPv6 addresses. 
     * The stored state always occupies 32 or 64 bytes on 32-bit platforms and 64 bytes 
     * on 64-bit platforms. One megabyte zone can keep about 32 thousand 32-byte states or 
     * about 16 thousand 64-byte states. If the zone storage is exhausted, the server will 
     * close the connection. 
     */
    for (i = 0; i < lccf->limits.nelts; i++) {
        ctx = limits[i].shm_zone->data;

        shpool = (ngx_slab_pool_t *) limits[i].shm_zone->shm.addr;

        ngx_shmtx_lock(&shpool->mutex);

        /* 用ip地址hash值到红黑树中查找对应的节点 */
        node = ngx_stream_limit_conn_lookup(ctx->rbtree, &key, hash);

        /* 如果node == NULL，说明该ip地址还没有发起过连接 */
        if (node == NULL) {

            n = offsetof(ngx_rbtree_node_t, color)
                + offsetof(ngx_stream_limit_conn_node_t, data)
                + key.len;

            /* 
             * 从共享内存中分配用于存储红黑树节点的内存。共享内存用来存储同一个ip
             * 对应的多个连接之间共有的状态信息。
             */
            node = ngx_slab_alloc_locked(shpool, n);

            if (node == NULL) {
                ngx_shmtx_unlock(&shpool->mutex);
                ngx_stream_limit_conn_cleanup_all(s->connection->pool);
                return NGX_ABORT;
            }

            lc = (ngx_stream_limit_conn_node_t *) &node->color;

            node->key = hash;  // 红黑树节点的key值为客户端ip的hash值
            lc->len = (u_char) key.len;  // 记录客户端ip地址长度
            lc->conn = 1;  // 该ip地址首次连接，conn置为1
            ngx_memcpy(lc->data, key.data, key.len);  // 记录客户端ip地址

            ngx_rbtree_insert(ctx->rbtree, node);  // 将当前节点加入到红黑树中

        } else {

            lc = (ngx_stream_limit_conn_node_t *) &node->color;

            /*
             * 判断ip地址已经发起的连接总数是否达到了限制的阈值，如果达到了，返回NGX_ABORT，断开此次连接
             */
            if ((ngx_uint_t) lc->conn >= limits[i].conn) {

                ngx_shmtx_unlock(&shpool->mutex);

                ngx_log_error(lccf->log_level, s->connection->log, 0,
                              "limiting connections by zone \"%V\"",
                              &limits[i].shm_zone->shm.name);

                ngx_stream_limit_conn_cleanup_all(s->connection->pool);
                return NGX_ABORT;
            }

            /* 程序执行到这里表明当前ip已经发起的连接数还没有达到限制的阈值，递增已连接数，然后做后续处理 */
            lc->conn++;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "limit conn: %08Xi %d", node->key, lc->conn);

        ngx_shmtx_unlock(&shpool->mutex);

        /* 设置本次连接结束后的清理方法 */

        /*
         * 从客户端连接对应的连接池中申请一块内存，并将这块内存挂载到连接池对应的c->cleanup链表中。
         * 等这块内存池释放的时候就会调用c->cleanup链表中的函数来做一些清理工作。那么客户端连接对应的
         * 的内存池什么时候会释放呢?当客户端和nginx之间的连接结束的时候就会释放。
         */
        cln = ngx_pool_cleanup_add(s->connection->pool,
                                   sizeof(ngx_stream_limit_conn_cleanup_t));
        if (cln == NULL) {
            return NGX_ERROR;
        }

        /*
         * 本次连接结束后会调用该方法，在ngx_stream_limit_conn_cleanup()函数中会把该ip地址对应的
         * 已连接数减一，如果该ip地址已连接数为0，则从红黑树中删除该节点，并释放共享内存
         */
        cln->handler = ngx_stream_limit_conn_cleanup;
        lccln = cln->data;

        lccln->shm_zone = limits[i].shm_zone;
        lccln->node = node;
    }

    /* 返回NGX_DECLINED，则主流程接着往下处理 */
    return NGX_DECLINED;
}


static void
ngx_stream_limit_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t             **p;
    ngx_stream_limit_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_stream_limit_conn_node_t *) &node->color;
            lcnt = (ngx_stream_limit_conn_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_rbtree_node_t *
ngx_stream_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key,
    uint32_t hash)
{
    ngx_int_t                      rc;
    ngx_rbtree_node_t             *node, *sentinel;
    ngx_stream_limit_conn_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;
    /*
     * 遍历整个红黑树，查找到hash值对应的节点，如果找到，则返回该节点，没有则返回NULL。
     */
    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (ngx_stream_limit_conn_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

/*
 * 客户端连接结束后清理内存池的时候会调用该方法做一些和ngx_stream_limit_conn_module
 * 模块功能相关的收尾操作
 */
static void
ngx_stream_limit_conn_cleanup(void *data)
{
    ngx_stream_limit_conn_cleanup_t  *lccln = data;

    ngx_slab_pool_t               *shpool;
    ngx_rbtree_node_t             *node;
    ngx_stream_limit_conn_ctx_t   *ctx;
    ngx_stream_limit_conn_node_t  *lc;

    ctx = lccln->shm_zone->data;
    shpool = (ngx_slab_pool_t *) lccln->shm_zone->shm.addr;
    node = lccln->node;
    lc = (ngx_stream_limit_conn_node_t *) &node->color;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08Xi %d", node->key, lc->conn);

    /*
     * 因为调用ngx_stream_limit_conn_cleanup()这个方法的时候是要结束连接的时候，所以需要把已经建立的
     * 连接数减1.
     */
    lc->conn--;

    /* 如果某个客户端对应的所有连接都已经结束的话，则需要删除其所在红黑树节点及共享内存数据 */
    if (lc->conn == 0) {
        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);
    }

    ngx_shmtx_unlock(&shpool->mutex);
}

/* 调用内存池中ngx_stream_limit_conn_module模块所有的清理方法 */
static ngx_inline void
ngx_stream_limit_conn_cleanup_all(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == ngx_stream_limit_conn_cleanup) {
        ngx_stream_limit_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


static ngx_int_t
ngx_stream_limit_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_stream_limit_conn_ctx_t  *octx = data;

    size_t                        len;
    ngx_slab_pool_t              *shpool;
    ngx_rbtree_node_t            *sentinel;
    ngx_stream_limit_conn_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->rbtree = octx->rbtree;

        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;

        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_stream_limit_conn_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static void *
ngx_stream_limit_conn_create_conf(ngx_conf_t *cf)
{
    ngx_stream_limit_conn_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_limit_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->log_level = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_stream_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_limit_conn_conf_t *prev = parent;
    ngx_stream_limit_conn_conf_t *conf = child;

    /* 如果server块中没有配置任何的limit_conn命令，则直接继承main级别下面的limit_conn命令的配置 */
    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);

    return NGX_CONF_OK;
}


static char *
ngx_stream_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                       *p;
    ssize_t                       size;
    ngx_str_t                    *value, name, s;
    ngx_uint_t                    i;
    ngx_shm_zone_t               *shm_zone;
    ngx_stream_limit_conn_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_limit_conn_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    /* 解析limit_conn_zone命令剩余的参数，以解析共享内存的名字和大小 */
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    /*
     * 申请一块shm共享内存，在ngx_stream_limit_conn_zone函数中也会调用这个函数告诉nginx需要初始化shm
     * 共享内存，可以发现，这两个地方的调用的名字和tag是可以对应起来的，也就是说他们要申请的其实
     * 是同一块共享内存，在ngx_stream_limit_conn中传递进去的大小是0，因为limit_conn指令并不知道
     * 共享内存的实际大小，所以只是先以0作为一个初值向nginx提交申请，后续等解析到limit_conn_zone
     * 命令的时候则会有共享内存的实际大小，并会替换之前的0。如果是先解析到了limit_conn_zone而后解析
     * 到limit_conn，则大小会limit_conn_zone中大小为准。这也是nginx没有限制limit_conn_zone和
     * limit_conn配置顺序的设计方法。
     */
    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_stream_limit_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    /* 一块共享内存只能和客户端ip绑定一次 */
    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key "
                           "\"$binary_remote_addr\"",
                           &cmd->name, &name);
        return NGX_CONF_ERROR;
    }

    /* limit_conn_zone命令的第一个参数只能是$binary_remote_addr */
    if (ngx_strcmp(value[1].data, "$binary_remote_addr") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unsupported key \"%V\", use "
                           "$binary_remote_addr", &value[1]);
        return NGX_CONF_ERROR;
    }

    /* 设置共享内存的init和data，一块共享内存对应一个ctx，即一棵红黑树 */
    shm_zone->init = ngx_stream_limit_conn_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}

/* limit_conn命令对应的回调函数 */
static char *
ngx_stream_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_shm_zone_t                 *shm_zone;
    ngx_stream_limit_conn_conf_t   *lccf = conf;
    ngx_stream_limit_conn_limit_t  *limit, *limits;

    ngx_str_t   *value;
    ngx_int_t    n;
    ngx_uint_t   i;

    value = cf->args->elts;

    /*
     * 申请一块shm共享内存，在ngx_stream_limit_conn_zone函数中也会调用这个函数告诉nginx需要初始化shm
     * 共享内存，可以发现，这两个地方的调用的名字和tag是可以对应起来的，也就是说他们要申请的其实
     * 是同一块共享内存，在ngx_stream_limit_conn中传递进去的大小是0，因为limit_conn指令并不知道
     * 共享内存的实际大小，所以只是先以0作为一个初值向nginx提交申请，后续等解析到limit_conn_zone
     * 命令的时候则会有共享内存的实际大小，并会替换之前的0。如果是先解析到了limit_conn_zone而后解析
     * 到limit_conn，则大小会limit_conn_zone中大小为准。这也是nginx没有限制limit_conn_zone和
     * limit_conn配置顺序的设计方法。
     */
    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_stream_limit_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    limits = lccf->limits.elts;

    if (limits == NULL) {
        if (ngx_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(ngx_stream_limit_conn_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    /* 判断是否已经有重复的共享内存，也就是说不同的limit_conn命令不能指定同一个共享内存 */
    for (i = 0; i < lccf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    /* 获取limit_conn第二个参数，因为是限制的ip的连接数，所以将其转换为数字 */
    n = ngx_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (n > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return NGX_CONF_ERROR;
    }

    limit = ngx_array_push(&lccf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    /* 保存解析结果 */
    limit->conn = n;
    limit->shm_zone = shm_zone;

    return NGX_CONF_OK;
}

/* 向ngx_stream_core_module模块注册limit_conn回调函数 */
static ngx_int_t
ngx_stream_limit_conn_init(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    cmcf->limit_conn_handler = ngx_stream_limit_conn_handler;

    return NGX_OK;
}
