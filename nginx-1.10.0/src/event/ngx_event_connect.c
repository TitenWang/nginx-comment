
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

/* 调用socket、connect与远端服务器建立连接 */
ngx_int_t
ngx_event_connect_peer(ngx_peer_connection_t *pc)
{
    int                rc, type;
    ngx_int_t          event;
    ngx_err_t          err;
    ngx_uint_t         level;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c;

    /* 从本次连接对应的upstream块内选择一个合适的后端服务器 */
    rc = pc->get(pc, pc->data);
    if (rc != NGX_OK) {
        return rc;
    }

    /* 获取连接类型 */
    type = (pc->type ? pc->type : SOCK_STREAM);

    /* 调用socket接口获取一个socket描述符 */
    s = ngx_socket(pc->sockaddr->sa_family, type, 0);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0, "%s socket %d",
                   (type == SOCK_STREAM) ? "stream" : "dgram", s);

    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }


    /* 从连接池中获取一个空闲连接，这个是一个被动连接的连接对象 */
    c = ngx_get_connection(s, pc->log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_close_socket_n "failed");
        }

        return NGX_ERROR;
    }

    c->type = type;

    /* 设置连接的接受缓冲区大小 */
    if (pc->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &pc->rcvbuf, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");
            goto failed;
        }
    }

    /* 将连接设置为非阻塞 */
    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        goto failed;
    }

    /* local中存储的是Nginx所在的本机地址信息不为空，则会将描述符绑定到本机地址上 */
    if (pc->local) {
        if (bind(s, pc->local->sockaddr, pc->local->socklen) == -1) {
            ngx_log_error(NGX_LOG_CRIT, pc->log, ngx_socket_errno,
                          "bind(%V) failed", &pc->local->name);

            goto failed;
        }
    }

    if (type == SOCK_STREAM) {
        /* 设置读写缓冲区的方法 */
        c->recv = ngx_recv;
        c->send = ngx_send;
        c->recv_chain = ngx_recv_chain;
        c->send_chain = ngx_send_chain;

        c->sendfile = 1;

        if (pc->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

#if (NGX_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }

    } else { /* type == SOCK_DGRAM */
        c->recv = ngx_udp_recv;
        c->send = ngx_send;
    }

    c->log_error = pc->log_error;

    rev = c->read;
    wev = c->write;

    rev->log = pc->log;
    wev->log = pc->log;

    /* 将被动连接对象设置到主动连接对象的connection成员中 */
    pc->connection = c;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    /* 将Nginx与上游服务器的连接加入到epoll中同时监控读写事件 */
    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            goto failed;
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0,
                   "connect to %V, fd:%d #%uA", pc->name, s, c->number);

    /*
     * 调用connect方法建立与上游服务器的连接，因为socket描述符设置为非阻塞套接字，因此connect方法不会
     * 阻塞，也因此该方法返回时不一定就表示与上游服务器成功建立了连接
     */
    rc = connect(s, pc->sockaddr, pc->socklen);

    /*
     * 如果connect返回-1，则需要根据错误码来判断连接建立的状态，否则表示Nginx与上游服务器的连接成功建立
     */
    if (rc == -1) {
        err = ngx_socket_errno;

        /* 如果错误码不是EINPROGRESS，则表明与客户端建立失败 */
        if (err != NGX_EINPROGRESS
#if (NGX_WIN32)
            /* Winsock returns WSAEWOULDBLOCK (NGX_EAGAIN) */
            && err != NGX_EAGAIN
#endif
            )
        {
            if (err == NGX_ECONNREFUSED
#if (NGX_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == NGX_EAGAIN
#endif
                || err == NGX_ECONNRESET
                || err == NGX_ENETDOWN
                || err == NGX_ENETUNREACH
                || err == NGX_EHOSTDOWN
                || err == NGX_EHOSTUNREACH)
            {
                level = NGX_LOG_ERR;

            } else {
                level = NGX_LOG_CRIT;
            }

            ngx_log_error(level, c->log, err, "connect() to %V failed",
                          pc->name);

            ngx_close_connection(c);
            pc->connection = NULL;

            return NGX_DECLINED;
        }
    }

    /*
     * ngx_add_conn不是NULL,则在上面就已经将连接对应的读写事件加入到epoll中了，所以如果上面connect方法
     * 的返回值为-1，则直接返回NGX_AGAIN，表明Nginx暂时还没有与上游服务器建立连接，需要等待epoll调度进行
     * 下一步处理(等到连接成功建立时epoll会调度该socket描述符对应的写事件处理函数进行进一步处理)
     */
    if (ngx_add_conn) {
        if (rc == -1) {

            /* NGX_EINPROGRESS */

            return NGX_AGAIN;
        }

        /*
         * 程序执行到这里表明Nginx与远端服务器的连接已经成功建立，可以往远端服务器发送请求了，所以下面需要
         * 将写事件设置为就绪
         */
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pc->log, 0, "connected");

        wev->ready = 1;

        return NGX_OK;
    }

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pc->log, ngx_socket_errno,
                       "connect(): %d", rc);

        if (ngx_blocking(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_blocking_n " failed");
            goto failed;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use NGX_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        return NGX_OK;
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NGX_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NGX_LEVEL_EVENT;
    }

    /*使用epoll的话，则会以边缘触发方式将连接对应的读事件加入到epoll中*/
    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
        goto failed;
    }

    /*
     * connect返回-1,并且错误码为EINPROGRESS，表明Nginx暂时还没有与远端服务器建立连接，所以需要将
     * 连接对应的写事件加入到epoll中，等到连接成功建立后再让epoll调度进行写事件的进一步处理
     */
    if (rc == -1) {

        /* NGX_EINPROGRESS */

        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            goto failed;
        }

        return NGX_AGAIN;
    }

    /*
     * 程序执行到这里表明Nginx与远端服务器的连接已经成功建立，可以往远端服务器发送请求了，所以下面需要
     * 将写事件设置为就绪
     */
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pc->log, 0, "connected");

    wev->ready = 1;

    return NGX_OK;

failed:

    ngx_close_connection(c);
    pc->connection = NULL;

    return NGX_ERROR;
}


ngx_int_t
ngx_event_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}
