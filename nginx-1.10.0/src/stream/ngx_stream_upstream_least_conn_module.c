
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


static ngx_int_t ngx_stream_upstream_init_least_conn_peer(
    ngx_stream_session_t *s, ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_least_conn_peer(
    ngx_peer_connection_t *pc, void *data);
static char *ngx_stream_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_upstream_least_conn_commands[] = {

    { ngx_string("least_conn"),
      NGX_STREAM_UPS_CONF|NGX_CONF_NOARGS,
      ngx_stream_upstream_least_conn,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_least_conn_module_ctx = {
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_least_conn_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_least_conn_module_ctx, /* module context */
    ngx_stream_upstream_least_conn_commands, /* module directives */
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


static ngx_int_t
ngx_stream_upstream_init_least_conn(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0,
                   "init least conn");

    /*
     * 该函数用于构造后端服务器组成的链表，并挂载到ngx_stream_upstream_srv_conf_t中
     * ngx_stream_upstream_peer_t的data字段。
     */
    if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 初始化least_conn负载均衡算法 */
    us->peer.init = ngx_stream_upstream_init_least_conn_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_least_conn_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "init least conn peer");

    /*
     * 该函数会设置get和free方法，以及构造指示所有后端服务器是否被选择过的位图，除此之外，
     * 也会将us->peer.data字段挂载的后端服务器列表设置到s->upstream->peer.data上。
     */
    if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 设置选择本次连接需要连接的后端服务器对象的函数 */
    s->upstream->peer.get = ngx_stream_upstream_get_least_conn_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_least_conn_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t *rrp = data;

    time_t                           now;
    uintptr_t                        m;
    ngx_int_t                        rc, total;
    ngx_uint_t                       i, n, p, many;
    ngx_stream_upstream_rr_peer_t   *peer, *best;
    ngx_stream_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    /* 如果只配置了一个后端服务器，那么直接调用round-robin算法获取本次用于连接的后端服务器 */
    if (rrp->peers->single) {
        return ngx_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->connection = NULL;

    /* 获取当前缓存时间 */
    now = ngx_time();

    peers = rrp->peers;

    ngx_stream_upstream_rr_peers_wlock(peers);

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {

        /*
         * i表示当前遍历到的后端服务器的编号，从0开始
         * n表示当前遍历到的后端服务器所在的位图
         * m表示当前遍历到的后端服务器在所在位图的具体位置
         */
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        /* 如果本次遍历到的后端服务器位图显示之前已经选择过了，那么本次不选 */
        if (rrp->tried[n] & m) {
            continue;
        }

        /* 状态为down的服务器不选 */
        if (peer->down) {
            continue;
        }

        /* 在一个fail_timeout周期内失败次数达到max_fails的服务器不选 */
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        /*
         * select peer with least number of connections; if there are
         * multiple peers with the same number of connections, select
         * based on round-robin
         */
        /*
         * 选择最合适的服务器，如果有多台后端服务器满足least-conn算法的条件，则在用
         * round-robin算法从满足条件的多台服务器中选择一台当前权重最高的。
         */

        if (best == NULL
            || peer->conns * best->weight < best->conns * peer->weight)
        {
            best = peer;
            many = 0;
            p = i;  // 记录被选为best的后端服务器编号

        } else if (peer->conns * best->weight == best->conns * peer->weight) {
            many = 1;  // 有多台后端服务器可供选择，则后面会采用round-robin算法进一步选择
        }
    }

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    if (many) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, many");

        /* 
         * 从第一个被指定为best的后端服务器开始往后遍历之后的所有后端服务器，以
         * round-robin算法从这些服务器中选择一个最合适的。
         */
        for (peer = best, i = p;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }

            if (peer->down) {
                continue;
            }

            /*
             * 只从满足peer->conns * best->weight == best->conns * peer->weight条件的服务器中
             * 选择，因为只有满足peer->conns * best->weight != best->conns * peer->weight的服务器
             * 当中才有最合适的服务器。
             */
            if (peer->conns * best->weight != best->conns * peer->weight) {
                continue;
            }

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    /* 更新此次选择的后端服务器的当前权重 */
    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    /* 获取地址信息和主机名 */
    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    /* 递增被选中次数 */
    best->conns++;

    rrp->current = best;

    /* 记录位图 */
    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    ngx_stream_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    /* 从备份服务器列表中选择一台最合适的服务器 */
    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, backup servers");

        rrp->peers = peers->next;

        /* 计算所有备份服务器需要多少个位图来指示服务器选择情况 */
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_stream_upstream_rr_peers_unlock(peers);

        rc = ngx_stream_upstream_get_least_conn_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_stream_upstream_rr_peers_wlock(peers);
    }

    /* all peers failed, mark them as live for quick recovery */

    /*
     * 程序执行到这里表明所有的后端服务器选择都失败了，这个时候需要将后端服务器的状态信息重置
     * 以使他们重新可用
     */
    for (peer = peers->peer; peer; peer = peer->next) {
        peer->fails = 0;
    }

    ngx_stream_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;
    /* 返回NGX_BUSY，主流程ngx_stream_proxy_connect中会结束此次请求 */
    return NGX_BUSY;
}

/* least_conn指令的解析函数，一般会将least_conn指令配置在upstream块的最开始 */
static char *
ngx_stream_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_upstream_srv_conf_t  *uscf;

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    /*
     * 设置初始化upstream负载均衡方法的回调函数，该回调函数会在_upstream机制的
     * init_main_conf回调方法ngx_stream_upstream_init_main_conf中调用。解析完配置文件
     * 中的main级别配置项之后会被调用
     */
    uscf->peer.init_upstream = ngx_stream_upstream_init_least_conn;

    /*
     *     用于创建upstream块配置信息结构体的功能标记，这个地方有点不大理解，因为在
     *     问题: 解析upstream块的时候就会以下面这些flags来创建upstream块配置信息的结构体，
     * 为什么这里又需要再重新设置呢?这个函数是在解析到least_conn之后才会调用，这个时候
     * 存储upstream块配置信息的结构体已经创建好了，flags也设置好了，这里为什么需要在设置呢?
     */
    uscf->flags = NGX_STREAM_UPSTREAM_CREATE
                  |NGX_STREAM_UPSTREAM_WEIGHT
                  |NGX_STREAM_UPSTREAM_MAX_FAILS
                  |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NGX_STREAM_UPSTREAM_DOWN
                  |NGX_STREAM_UPSTREAM_BACKUP;

    return NGX_CONF_OK;
}
