
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


#define ngx_stream_upstream_tries(p) ((p)->number                             \
                                      + ((p)->next ? (p)->next->number : 0))


static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_get_peer(
    ngx_stream_upstream_rr_peer_data_t *rrp);

#if (NGX_STREAM_SSL)

static ngx_int_t ngx_stream_upstream_set_round_robin_peer_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_stream_upstream_save_round_robin_peer_session(
    ngx_peer_connection_t *pc, void *data);

#endif

/*
 * 该函数用于构造后端服务器组成的链表，并挂载到下面的data字段。该函数在解析完stream块下的main
 * 级别配置项之后调用
 */

ngx_int_t
ngx_stream_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_url_t                        u;
    ngx_uint_t                       i, j, n, w;
    ngx_stream_upstream_server_t    *server;
    ngx_stream_upstream_rr_peer_t   *peer, **peerp;
    ngx_stream_upstream_rr_peers_t  *peers, *backup;

    /*
     * 该函数会设置get和free方法，除此之外，也会将data字段挂载的后端服务器列表设置到
     * s->upstream->peer.data上。该函数在构造发送往上游服务器的请求时调用.
     */
    us->peer.init = ngx_stream_upstream_init_round_robin_peer;

    if (us->servers) {
        server = us->servers->elts;

        n = 0;
        w = 0;

        /* 遍历upstream块中的所有非备份服务器，计算非备份后端服务器总数以及总权重(以ip计数) */
        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no servers in upstream \"%V\" in %s:%ui",
                          &us->host, us->file_name, us->line);
            return NGX_ERROR;
        }

        /* 申请管理后端服务器列表的对象 */
        peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        /* 申请用于存放一个后端服务器信息的对象(以ip计数) */
        peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NGX_ERROR;
        }

        peers->single = (n == 1);  // 判断upstream块中是否只有一个非备份服务器
        peers->number = n;  // 设置upstream块中所有非备份服务器的总数(以ip计数)
        peers->weighted = (w != n);  // 设置是否自定义的配置权重的标志位
        peers->total_weight = w;  // 记录所有非备份服务器的总权重(以ip计数)
        peers->name = &us->host;  // 记录upstream命令url参数对应的主机名

        n = 0;
        peerp = &peers->peer;

        /* 将从配置文件中获取的非备份后端服务器信息保存到ngx_stream_upstream_rr_peer_t对象中统一管理 */
        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            /* 一个后端服务器可能存在多个ip地址(一个域名可能有多个冗余ip) */
            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;  // 初始有效权重设为配置权重
                peer[n].current_weight = 0;  // 初始当前权重为0
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        /* 将管理着非备份后端服务器列表的ngx_http_upstream_rr_peers_t对象挂载到us->peer.data中 */        
        us->peer.data = peers;

        /* backup servers */

        n = 0;
        w = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;
        }

        if (n == 0) {
            return NGX_OK;
        }

        backup = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
        if (backup == NULL) {
            return NGX_ERROR;
        }

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NGX_ERROR;
        }

        peers->single = 0;
        backup->single = 0;
        backup->number = n;
        backup->weighted = (w != n);
        backup->total_weight = w;
        backup->name = &us->host;

        n = 0;
        peerp = &backup->peer;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
                peer[n].current_weight = 0;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        /* 将备份后端服务器组成的列表管理对象挂载到非备份后端服务器列表管理对象的next字段下 */
        peers->next = backup;

        return NGX_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. *
    /*
     * 程序执行到这里表明没有配置upstream块，只是用proxy_pass等命令配置了一个url，用来指定
     * 后端服务器，这个时候也会创建一个存储upstream块配置信息的结构体，只是这个结构体里面
     * servers等信息为NULL。这个时候就需要用url参数指定的域名来解析ip地址。如果url参数对应
     * 的域名也对应多个ip地址，那么也需要进行管理，另外，这个时候是没有备份服务器的
     */

    if (us->port == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    /* 获取主机字符串和端口信息 */
    u.host = us->host;
    u.port = us->port;

    /* 域名解析获取ip地址和主机名字 */
    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

    n = u.naddrs;  // 一个域名可能对应多个ip地址

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peers->single = (n == 1);
    peers->number = n;  // proxy_pass等命令配置的后端服务器个数(以ip计数)
    peers->weighted = 0;
    peers->total_weight = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    /* 将域名对应的多个ip地址分别用一个后端服务器信息对象进行管理 */
    for (i = 0; i < u.naddrs; i++) {
        peer[i].sockaddr = u.addrs[i].sockaddr;
        peer[i].socklen = u.addrs[i].socklen;
        peer[i].name = u.addrs[i].name;
        peer[i].weight = 1;
        peer[i].effective_weight = 1;
        peer[i].current_weight = 0;
        peer[i].max_fails = 1;
        peer[i].fail_timeout = 10;
        *peerp = &peer[i];
        peerp = &peer[i].next;
    }

    /* 将管理后端服务器列表的对象挂载到us->peer.data */
    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NGX_OK;
}

/*
 * 该函数会设置get和free方法，以及构造指示所有后端服务器是否被选择过的位图，除此之外，
 * 也会将us->peer.data字段挂载的后端服务器列表设置到s->upstream->peer.data上。该函数在构造
 * 发送往上游服务器的请求时调用。
 */

ngx_int_t
ngx_stream_upstream_init_round_robin_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_uint_t                           n;
    ngx_stream_upstream_rr_peer_data_t  *rrp;

    rrp = s->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(s->connection->pool,
                         sizeof(ngx_stream_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        s->upstream->peer.data = rrp;
    }

    /*
     *     将后端服务器列表挂载到peers字段中。对于不同的客户端请求，函数
     * ngx_stream_upstream_init_round_robin_peer()都会被调用一次，s->upstream->peer.data
     * 也会被重新创建，但是构造us->peer.data后端服务器列表信息的函数只会在配置文件解析完main级别
     * 配置项之后调用一次，之后不会再调用(函数为:ngx_stream_upstream_init_round_robin)。
     *     rrp->peers = us->peer.data;这条赋值语句表明对于不同的客户端请求，他们所使用的后端服务器
     * 列表信息是同一份的，也就是说先来的客户端请求会对后来的客户端请求如何选择后端服务器有影响。
     * 举个例子，假如有两个客户端连接，第一个客户端连接选择了其中一台后端服务器，那么就会更新这一台
     * 后端服务器的一些信息，比如当前权重，被选中次数及有效权重等信息到后端服务器列表中的对应位置，
     * 这些都会对后续第二个客户端请求有影响，因为不同的客户端请求之间所使用的后端服务器列表信息是同一份。
     *     但是下面用来指示后端服务器是否被选中的位图是每个请求都会创建一份，也就是说位图在不同的客户端
     * 请求之间是不共用的。比如对于同一台后端服务器，在第一个客户端请求的时候被选中了，它的权重信息被
     * 第一个请求处理更新了，位图中对应位置也被置位了。此时来了第二个客户端请求，由于这台后端服务器权重
     * 信息被第一个请求更新过，所以会影响第二个客户端请求的选择，但是在第二个请求中对应该后端服务器的
     * 位图中的位是没有被置位的。因为位图是每个请求独有的。
     */
    rrp->peers = us->peer.data;
    rrp->current = NULL;

    n = rrp->peers->number;  // upstream块中配置的非备份服务器的数量(以ip计数) 

    /*
     * 如果存在备份的后端服务器，并且备份的后端服务器总数(以ip计数)比非备份的后端服务器总数多，
     * 则以非备份的后端服务器总数赋值给局部变量n
     */
    if (rrp->peers->next && rrp->peers->next->number > n) {
        n = rrp->peers->next->number;
    }

    /*
     * 比较后端服务器总数(以ip计数)是否超过了一个uintptr_t类型的位数，用于后续构造位图，
     * 如果总数n小于uintptr_t类型的位数，则用一个uintptr_t类型的变量来存储位图，这个位图
     * 是用来标记在一轮选择中，某个后端服务器是否被选中的标志位。位图是面向一轮选择的，即
     * 针对一个客户端请求。
     */
    if (n <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        /*
         * 程序执行到这里表明后端服务器的总数超过了一个uintptr_t类型的位数，那么就需要多个
         * uintptr_t类型的变量来存放位图了，下面就是计算需要多少个uintptr_t类型变量的算法，
         * 这里以37台后端服务器为例说明下，假设是在32位机器上，那么uintptr_t类型就是32位的。
         * 那么我们就需要两个uintptr_t类型的变量，所以有:
         * (37 + 31)/32 = 2
         */
        n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    /* 设置get、free方法 */
    s->upstream->peer.get = ngx_stream_upstream_get_round_robin_peer;
    s->upstream->peer.free = ngx_stream_upstream_free_round_robin_peer;
    s->upstream->peer.tries = ngx_stream_upstream_tries(rrp->peers);
#if (NGX_STREAM_SSL)
    s->upstream->peer.set_session =
                             ngx_stream_upstream_set_round_robin_peer_session;
    s->upstream->peer.save_session =
                             ngx_stream_upstream_save_round_robin_peer_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_stream_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t *rrp = data;

    ngx_int_t                        rc;
    ngx_uint_t                       i, n;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    pc->connection = NULL;

    peers = rrp->peers;
    ngx_stream_upstream_rr_peers_wlock(peers);

    if (peers->single) {
        peer = peers->peer;

        if (peer->down) {
            goto failed;
        }

        rrp->current = peer;

    } else {

        /* there are several peers */

        peer = ngx_stream_upstream_get_peer(rrp);

        if (peer == NULL) {
            goto failed;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get rr peer, current: %p %i",
                       peer, peer->current_weight);
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    /* 更新被选中的次数 */
    peer->conns++;

    ngx_stream_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    if (peers->next) {

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_stream_upstream_rr_peers_unlock(peers);

        rc = ngx_stream_upstream_get_round_robin_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_stream_upstream_rr_peers_wlock(peers);
    }

    /* all peers failed, mark them as live for quick recovery */

    /*
     * 程序执行到这里表明upstream块中的所有server都是不可用的(包括备份和非备份)，对于此次选择后端
     * 服务器的请求，则会选择失败，返回NGX_BUSY。这个时候就需要将所有的后端服务器(包括备份和非备份，
     * 备份服务器会在第二层嵌套调用该函数自身的时候执行下面的操作的清零操作)的peer->fails记录的失败
     * 次数清零，将所有服务器恢复到初始状态，激活所有的后端服务器，防止后面的请求也会返回NGX_BUSY
     */
    for (peer = peers->peer; peer; peer = peer->next) {
        peer->fails = 0;
    }

    ngx_stream_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NGX_BUSY;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_get_peer(ngx_stream_upstream_rr_peer_data_t *rrp)
{
    time_t                          now;
    uintptr_t                       m;
    ngx_int_t                       total;
    ngx_uint_t                      i, n, p;
    ngx_stream_upstream_rr_peer_t  *peer, *best;

    now = ngx_time();

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    p = 0;
#endif

    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {

        /* 
         * i的值为当前遍历的后端服务器的索引，
         * n的值为具体的某个位图，
         * m的值为当前所遍历的后端服务器在某个位图中对应的位
         */
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        /* 如果遍历到的后端服务器对应的位图已经置位，则此次不选 */
        if (rrp->tried[n] & m) {
            continue;
        }

        /* 状态为down的不选 */
        if (peer->down) {
            continue;
        }

        /*
         * 如果在fail_timeout时间范围内某台服务器的连接失败次数达到了max_fails，
         * 那么这台服务器本轮选择跳过，但是等过了fail_timeout这个时间范围后，本台服务器
         * 又可以重新参与连接了，这个时候会更新checked时间
         */
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        /* 计算本次遍历的后端服务器的当前权重 */
        peer->current_weight += peer->effective_weight;
        total += peer->effective_weight;  // 累加当前可选的所有后端服务器的有效权重。

        /* 更新本台后端服务器的有效权重 */
        if (peer->effective_weight < peer->weight) {
            peer->effective_weight++;
        }

        /* 遍历到目前为止，选择当前权重最高的后端服务器作为best */
        if (best == NULL || peer->current_weight > best->current_weight) {
            best = peer;
            p = i;  // 记录best服务器对应的编号，后续用于记录位图用
        }
    }

    if (best == NULL) {
        return NULL;
    }

    /* 设置本次选中的最合适的后端服务器 */
    rrp->current = best;

    /*
     * 计算本台服务器所在的位图以及在位图的具体哪个位上，后续需要将对应位置位表示选中过
     */
    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    /* 更新本次选中的后端服务器的当前权重 */
    best->current_weight -= total;

    /*
     *     如果现在距离这台服务器上次被选中但处理失败的时间(这台服务器此前在fail_timeout内处理失败次数大于
     * max_fails次而不参与选举)大于fail_timeout，则说明这台服务器又可以重新参与连接了，本台后端服务器此次
     * 被选中，更新checked。如果本台服务器后续连接处理也成功了，这个时候会在ngx_stream_upstream_free_round_robin_peer
     * 函数中将fails次数清零，激活这台服务器(因为这个时候checked肯定不等于accessed)。如果本台服务器后续连接
     * 处理又失败了，那么accessed和checked时间又会被更新为出异常时间，这样的话本台服务器的fails次数在原来
     * max_fails基础上又被递增了。下一个客户端请求来的时候就可能会因为now - best->checked小于fail_timeout
     * 会不选这台服务器，对于处于这种状态的服务器，只有过了fail_timeout时间被选中并且后续处理也成功，才有
     * 机会被激活(fails清零)，否则每次都只能等fail_timeout过了，才会参与选举，如果选举成功但是后续处理失败，
     * 又只能等fail_timeout过了再参与选举(上面498行的判断由fail_timeout和fails同时制约)，以此类推。
     */
    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    return best;
}


void
ngx_stream_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    time_t                          now;
    ngx_stream_upstream_rr_peer_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    peer = rrp->current;

    ngx_stream_upstream_rr_peers_rlock(rrp->peers);
    ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);

    /* 如果只有一个后端服务器，那么将该后端服务器的被选中次数减一 */
    if (rrp->peers->single) {
        peer->conns--;

        ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
        ngx_stream_upstream_rr_peers_unlock(rrp->peers);

        /* 当前连接出现异常后可重试次数清零 */
        pc->tries = 0;
        return;
    }

    /*
     * NGX_PEER_FAILED表示被选中的这台服务器在upstream处理过程中建链失败或者处理请求失败，
     * 这个时候需要对这太服务器的状态做一些记录
     */
    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        peer->fails++;  // 失败次数递增
        peer->accessed = now;  // 本台后端服务器异常，更新accessed时间为当前检测到其异常的时间
        peer->checked = now;  // 更新checked时间

        if (peer->max_fails) {
            peer->effective_weight -= peer->weight / peer->max_fails;  // 更新有效权重

            /* 如果失败次数大于max_fails，则该台服务器暂时需要停止提供服务 */
            /*
             * 如果本台服务器的重连次数已经达到了在规定时间内允许失败的最大次数，
             * 那么这台服务器就只能暂时不提供服务了，后续再选择的时候，由于
             * peer->fails和now - peer->checked <= peer->fail_timeout不满足而不被选中，
             * 这个从ngx_http_upstream_get_peer中可以看到。
             * 并且由于peer->fails没有清零，只能等到now - peer->checked > fail_timeout
             * 时，也就是现在距离最近一次被选中但后续处理失败的时间过了fail_timeout这个
             * 时间范围后，才能重新参与选择，如果重新参与选择，被选中的话，checked被更新
             * 并且后续如果处理成功，那么就会走下面那个else分支，由于accessed小于checked，
             * 那么就会将这台服务器的fails清零，激活这台服务器。但是如果重新参与选择，也
             * 被选中，checked被更新，但是后续处理不成功，那么由于fails没有被清零，则又会
             * 进入到这个分支，后续这台服务器又会暂时停止服务，等过了fail_timeout后才能
             * 重新参与选择，以此类推。
             */
            if (peer->fails >= peer->max_fails) {
                ngx_log_error(NGX_LOG_WARN, pc->log, 0,
                              "upstream server temporarily disabled");
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "free rr peer failed: %p %i",
                       peer, peer->effective_weight);

        if (peer->effective_weight < 0) {
            peer->effective_weight = 0;
        }

    } else {

        /* mark peer live if check passed */

        /*
         * 从上面那个if分支可以看出，只要后端服务器被选中但是后续处理过程中失败了，那么checked和accessed
         * 的时间总是一样的，那什么时候accessed和checked会不一样呢?我们知道accessed记录的是最近一次检测到
         * 后端服务器异常的时间点，checked什么时候会被单独更新呢?
         * 如果某台服务器(这台服务器此前在fail_timeout内处理失败次数大于max_fails次而不参与选举)过了fail_timeout后
         * 重新参与连接并被被选中，更新checked。如果本台服务器后续连接处理也成功了(会执行到这里)，这个时候会
         * 将fails次数清零，激活这台服务器(因为这个时候checked肯定不等于accessed)。如果本台服务器后续连接
         * 处理又失败了，那么accessed和checked时间又会被更新为出异常时间(上面的if分支)，这样的话本台服务器的
         * fails次数在原来max_fails基础上又被递增了。下一个客户端请求来的时候就可能会因为now - best->checked
         * 小于fail_timeout会不选这台服务器，对于处于这种状态的服务器，只有过了fail_timeout时间被选中并且后续
         * 处理也成功，才有机会被激活(fails清零)，否则每次都只能等fail_timeout过了，才会参与选举，如果选举成功
         * 但是后续处理失败，又只能等fail_timeout过了再参与选举，以此类推。
         */
        if (peer->accessed < peer->checked) {
            peer->fails = 0;
        }
    }

    /* 当前服务器被选中次数减一 */
    peer->conns--;

    ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
    ngx_stream_upstream_rr_peers_unlock(rrp->peers);

    /* 当前连接可重试次数减一 */
    if (pc->tries) {
        pc->tries--;
    }
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                        rc;
    ngx_ssl_session_t               *ssl_session;
    ngx_stream_upstream_rr_peer_t   *peer;
#if (NGX_STREAM_UPSTREAM_ZONE)
    int                              len;
#if OPENSSL_VERSION_NUMBER >= 0x0090707fL
    const
#endif
    u_char                          *p;
    ngx_stream_upstream_rr_peers_t  *peers;
    u_char                           buf[NGX_SSL_MAX_SESSION_SIZE];
#endif

    peer = rrp->current;

#if (NGX_STREAM_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {
        ngx_stream_upstream_rr_peers_rlock(peers);
        ngx_stream_upstream_rr_peer_lock(peers, peer);

        if (peer->ssl_session == NULL) {
            ngx_stream_upstream_rr_peer_unlock(peers, peer);
            ngx_stream_upstream_rr_peers_unlock(peers);
            return NGX_OK;
        }

        len = peer->ssl_session_len;

        ngx_memcpy(buf, peer->ssl_session, len);

        ngx_stream_upstream_rr_peer_unlock(peers, peer);
        ngx_stream_upstream_rr_peers_unlock(peers);

        p = buf;
        ssl_session = d2i_SSL_SESSION(NULL, &p, len);

        rc = ngx_ssl_set_session(pc->connection, ssl_session);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "set session: %p", ssl_session);

        ngx_ssl_free_session(ssl_session);

        return rc;
    }
#endif

    ssl_session = peer->ssl_session;

    rc = ngx_ssl_set_session(pc->connection, ssl_session);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "set session: %p", ssl_session);

    return rc;
}


static void
ngx_stream_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_stream_upstream_rr_peer_data_t  *rrp = data;

    ngx_ssl_session_t               *old_ssl_session, *ssl_session;
    ngx_stream_upstream_rr_peer_t   *peer;
#if (NGX_STREAM_UPSTREAM_ZONE)
    int                              len;
    u_char                          *p;
    ngx_stream_upstream_rr_peers_t  *peers;
    u_char                           buf[NGX_SSL_MAX_SESSION_SIZE];
#endif

#if (NGX_STREAM_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {

        ssl_session = SSL_get0_session(pc->connection->ssl->connection);

        if (ssl_session == NULL) {
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "save session: %p", ssl_session);

        len = i2d_SSL_SESSION(ssl_session, NULL);

        /* do not cache too big session */

        if (len > NGX_SSL_MAX_SESSION_SIZE) {
            return;
        }

        p = buf;
        (void) i2d_SSL_SESSION(ssl_session, &p);

        peer = rrp->current;

        ngx_stream_upstream_rr_peers_rlock(peers);
        ngx_stream_upstream_rr_peer_lock(peers, peer);

        if (len > peer->ssl_session_len) {
            ngx_shmtx_lock(&peers->shpool->mutex);

            if (peer->ssl_session) {
                ngx_slab_free_locked(peers->shpool, peer->ssl_session);
            }

            peer->ssl_session = ngx_slab_alloc_locked(peers->shpool, len);

            ngx_shmtx_unlock(&peers->shpool->mutex);

            if (peer->ssl_session == NULL) {
                peer->ssl_session_len = 0;

                ngx_stream_upstream_rr_peer_unlock(peers, peer);
                ngx_stream_upstream_rr_peers_unlock(peers);
                return;
            }

            peer->ssl_session_len = len;
        }

        ngx_memcpy(peer->ssl_session, buf, len);

        ngx_stream_upstream_rr_peer_unlock(peers, peer);
        ngx_stream_upstream_rr_peers_unlock(peers);

        return;
    }
#endif

    ssl_session = ngx_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "save session: %p", ssl_session);

    peer = rrp->current;

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    if (old_ssl_session) {

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "old session: %p", old_ssl_session);

        /* TODO: may block */

        ngx_ssl_free_session(old_ssl_session);
    }
}

#endif
