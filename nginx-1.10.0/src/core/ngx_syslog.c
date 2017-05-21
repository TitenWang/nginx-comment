
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_SYSLOG_MAX_STR                                                    \
    NGX_MAX_ERROR_STR + sizeof("<255>Jan 01 00:00:00 ") - 1                   \
    + (NGX_MAXHOSTNAMELEN - 1) + 1 /* space */                                \
    + 32 /* tag */ + 2 /* colon, space */


static char *ngx_syslog_parse_args(ngx_conf_t *cf, ngx_syslog_peer_t *peer);
static ngx_int_t ngx_syslog_init_peer(ngx_syslog_peer_t *peer);
static void ngx_syslog_cleanup(void *data);


static char  *facilities[] = {
    "kern", "user", "mail", "daemon", "auth", "intern", "lpr", "news", "uucp",
    "clock", "authpriv", "ftp", "ntp", "audit", "alert", "cron", "local0",
    "local1", "local2", "local3", "local4", "local5", "local6", "local7",
    NULL
};

/* note 'error/warn' like in nginx.conf, not 'err/warning' */
static char  *severities[] = {
    "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug", NULL
};

static ngx_log_t    ngx_syslog_dummy_log;
static ngx_event_t  ngx_syslog_dummy_event;

/* 解析配置的syslog信息 */
char *
ngx_syslog_process_conf(ngx_conf_t *cf, ngx_syslog_peer_t *peer)
{
    peer->pool = cf->pool;
    peer->facility = NGX_CONF_UNSET_UINT;
    peer->severity = NGX_CONF_UNSET_UINT;

    /* 解析配置文件中xxx_log指令指定的syslog信息 */
    if (ngx_syslog_parse_args(cf, peer) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    /* 判断xxx_log指定的syslog信息是否包含了syslog server的地址信息 */
    if (peer->server.sockaddr == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no syslog server specified");
        return NGX_CONF_ERROR;
    }

    /* 如果xxx_log指定的syslog信息没有facility和severity，则设置facility和severity为默认值 */
    
    if (peer->facility == NGX_CONF_UNSET_UINT) {
        peer->facility = 23; /* local7 */
    }

    if (peer->severity == NGX_CONF_UNSET_UINT) {
        peer->severity = 6; /* info */
    }

    if (peer->tag.data == NULL) {
        ngx_str_set(&peer->tag, "nginx");
    }

    /* 初始化Nginx和syslog server连接的socket描述符 */
    peer->conn.fd = (ngx_socket_t) -1;

    return NGX_CONF_OK;
}


static char *
ngx_syslog_parse_args(ngx_conf_t *cf, ngx_syslog_peer_t *peer)
{
    u_char      *p, *comma, c;
    size_t       len;
    ngx_str_t   *value;
    ngx_url_t    u;
    ngx_uint_t   i;

    /*
     * 获取xxx_log指令及其参数。下面流程的注解以下面这个例子为例:
     * error_log syslog:server=[2001:db8::1]:12345,facility=local7,tag=nginx,severity=info combined;
     */
    value = cf->args->elts;

    /* 获取指向syslog:后面一个字符的指针，以上面为例，此时p指向"server"的's'字符位置 */
    p = value[1].data + sizeof("syslog:") - 1;

    for ( ;; ) {
        /* 获取字符串p中首次出现','的位置 */
        comma = (u_char *) ngx_strchr(p, ',');

        /*
         * comma不为NULL，表明字符串中存在','字符，计算从p到','字符之间的字符串长度，以
         * 上面的配置为例，此时计算的就是"server=[2001:db8::1]:12345"的长度
         */
        if (comma != NULL) {
            len = comma - p;
            *comma = '\0';

        } else {
            /* 计算从p开始到第一个参数结束的字符串长度 */
            len = value[1].data + value[1].len - p;
        }

        /* 解析server参数，即"server=[2001:db8::1]:12345" */
        if (ngx_strncmp(p, "server=", 7) == 0) {

            if (peer->server.sockaddr != NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"server\"");
                return NGX_CONF_ERROR;
            }

            /* 解析"server=[2001:db8::1]:12345"中的地址信息 */
            ngx_memzero(&u, sizeof(ngx_url_t));

            u.url.data = p + 7;
            u.url.len = len - 7;
            u.default_port = 514;

            if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
                if (u.err) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s in syslog server \"%V\"",
                                       u.err, &u.url);
                }

                return NGX_CONF_ERROR;
            }

            /*
             * 获取解析url参数得到的ip地址信息数组的第一个ip地址，因为一个url可能对应多个ip地址
             */
            peer->server = u.addrs[0];

        } else if (ngx_strncmp(p, "facility=", 9) == 0) {

            /* 解析facility参数，即"facility=local7" */
            
            if (peer->facility != NGX_CONF_UNSET_UINT) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"facility\"");
                return NGX_CONF_ERROR;
            }

            /* 
             * 从全局facilities数组中匹配配置文件中配置的facility参数的值，
             * 并记录参数值在facilities数组对应的下标 
             */
            for (i = 0; facilities[i] != NULL; i++) {

                if (ngx_strcmp(p + 9, facilities[i]) == 0) {
                    peer->facility = i;
                    goto next;
                }
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown syslog facility \"%s\"", p + 9);
            return NGX_CONF_ERROR;

        } else if (ngx_strncmp(p, "severity=", 9) == 0) {

            /* 解析"severity"参数，即severity=info */
            
            if (peer->severity != NGX_CONF_UNSET_UINT) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"severity\"");
                return NGX_CONF_ERROR;
            }

            /*
             * 从全局severities数组中匹配配置文件中配置的severity参数的值，
             * 并记录参数值在全局severities数组中的下标
             */
            for (i = 0; severities[i] != NULL; i++) {

                if (ngx_strcmp(p + 9, severities[i]) == 0) {
                    peer->severity = i;
                    goto next;
                }
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown syslog severity \"%s\"", p + 9);
            return NGX_CONF_ERROR;

        } else if (ngx_strncmp(p, "tag=", 4) == 0) {

            /* 解析"tag"参数，即"tag=nginx" */
            
            if (peer->tag.data != NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"tag\"");
                return NGX_CONF_ERROR;
            }

            /*
             * RFC 3164: the TAG is a string of ABNF alphanumeric characters
             * that MUST NOT exceed 32 characters.
             */
            /* tag的参数值不能超过32个字节，减4是除去开头的"tag=" */
            if (len - 4 > 32) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "syslog tag length exceeds 32");
                return NGX_CONF_ERROR;
            }

            /* 校验"tag="后面的字符串是否合法 */
            for (i = 4; i < len; i++) {
                c = ngx_tolower(p[i]);

                if (c < '0' || (c > '9' && c < 'a' && c != '_') || c > 'z') {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "syslog \"tag\" only allows "
                                       "alphanumeric characters "
                                       "and underscore");
                    return NGX_CONF_ERROR;
                }
            }

            /* 保存tag参数的值 */
            peer->tag.data = p + 4;
            peer->tag.len = len - 4;

        } else if (len == 10 && ngx_strncmp(p, "nohostname", 10) == 0) {
            /* 如果syslog配置信息中出现了"nohostname"，则将相应的标志位置位 */
            peer->nohostname = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown syslog parameter \"%s\"", p);
            return NGX_CONF_ERROR;
        }

    next:

        if (comma == NULL) {
            break;
        }

        p = comma + 1;
    }

    return NGX_CONF_OK;
}

/* 往缓冲区中写入syslog头信息 */
u_char *
ngx_syslog_add_header(ngx_syslog_peer_t *peer, u_char *buf)
{
    ngx_uint_t  pri;

    pri = peer->facility * 8 + peer->severity;

    if (peer->nohostname) {
        return ngx_sprintf(buf, "<%ui>%V %V: ", pri, &ngx_cached_syslog_time,
                           &peer->tag);
    }

    return ngx_sprintf(buf, "<%ui>%V %V %V: ", pri, &ngx_cached_syslog_time,
                       &ngx_cycle->hostname, &peer->tag);
}


void
ngx_syslog_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf,
    size_t len)
{
    u_char             *p, msg[NGX_SYSLOG_MAX_STR];
    ngx_uint_t          head_len;
    ngx_syslog_peer_t  *peer;

    peer = log->wdata;

    /* 如果远端机器处于busy状态，则不往其发送信息 */
    if (peer->busy) {
        return;
    }

    /* 接下来会往远端机器发送信息，因此需要将远端机器的状态设置为busy，防止其他流程也往其中发送信息 */
    peer->busy = 1;
    peer->severity = level - 1;

    /* 往缓冲区中写入syslog的头信息 */
    p = ngx_syslog_add_header(peer, msg);
    head_len = p - msg;

    len -= NGX_LINEFEED_SIZE;

    if (len > NGX_SYSLOG_MAX_STR - head_len) {
        len = NGX_SYSLOG_MAX_STR - head_len;
    }

    /* 将外部传入的缓冲区信息写入到缓冲区中 */
    p = ngx_snprintf(p, len, "%s", buf);

    /* 发送缓冲区中信息 */
    (void) ngx_syslog_send(peer, msg, p - msg);

    /* 无论上面是否发送成功，都会将远端服务器状态设置为空闲，以让其他流程可以往其写入syslog信息 */
    peer->busy = 0;
}

/* 将缓冲区中的信息发送到远端机器中 */
ssize_t
ngx_syslog_send(ngx_syslog_peer_t *peer, u_char *buf, size_t len)
{
    ssize_t  n;

    /* 初始化本机和远端机器的连接 */
    if (peer->conn.fd == (ngx_socket_t) -1) {
        if (ngx_syslog_init_peer(peer) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* log syslog socket events with valid log */
    peer->conn.log = ngx_cycle->log;

    /* 发送内容 */
    if (ngx_send) {
        n = ngx_send(&peer->conn, buf, len);

    } else {
        /* event module has not yet set ngx_io */
        n = ngx_os_io.send(&peer->conn, buf, len);
    }

#if (NGX_HAVE_UNIX_DOMAIN)

    if (n == NGX_ERROR && peer->server.sockaddr->sa_family == AF_UNIX) {

        if (ngx_close_socket(peer->conn.fd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        peer->conn.fd = (ngx_socket_t) -1;
    }

#endif

    return n;
}

/* 初始化本机和打印syslog的目标机器之间的连接 */
static ngx_int_t
ngx_syslog_init_peer(ngx_syslog_peer_t *peer)
{
    ngx_socket_t         fd;
    ngx_pool_cleanup_t  *cln;

    peer->conn.read = &ngx_syslog_dummy_event;
    peer->conn.write = &ngx_syslog_dummy_event;

    ngx_syslog_dummy_event.log = &ngx_syslog_dummy_log;

    /* 以SOCK_DGRAM调用socket()获取udp socket描述符 */
    fd = ngx_socket(peer->server.sockaddr->sa_family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    /* 将socket设置为非阻塞 */
    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");
        goto failed;
    }

    /*
     * 对于是否调用connect的udp socket，做如下解释:
     * 1. An unconnected udp socket, the default when we create a udp socket.
     * 2. A connected udp socket, the result of calling connect on a udp socket.
     * 调用connect和远端机器建立连接。其实udp调用connect的作用一般有三个:
     * 1. 指定一个远端机器的ip地址和端口(可以通过再次调用connect指定新的ip地址和端口)。
     *    调用connect指定远端ip和port后，就可以调用read和write在这个udp socket上来接收和发送
     *    udp信息了，就可以不用在每次调用recvfrom和sendto时指定一个远端ip和port。内核会帮我
     *    们关联这个udp socket对应的远端ip和port。
     * 2. 对于一个已经调用过connect的udp socket，以AF_UNSPEC再次调用connect可以"断开"
     *    一个connected udp socket。
     * 3. 我们知道，对于"未连接"的udp socket(即默认没有调用connect的udp socket)，我们不能获取
     *    相关的异步错误，但是对于"已连接"的udp socket，我们就可以通过errno获取异步错误。
     * 另外，对于"connected udp socket"，其性能也会好于"unconnected udp socket"。
     */
    if (connect(fd, peer->server.sockaddr, peer->server.socklen) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      "connect() failed");
        goto failed;
    }

    /* 往内存池中的清理链表中加入一个节点，用于内存池释放时清理一些资源 */
    cln = ngx_pool_cleanup_add(peer->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->data = peer;
    cln->handler = ngx_syslog_cleanup;

    /* 保存本机和目标机器之间的socket fd */
    peer->conn.fd = fd;

    /* UDP sockets are always ready to write */
    /* 对于udp socket，随时都可以写，所以这里将其写事件的ready置位 */
    peer->conn.write->ready = 1;

    return NGX_OK;

failed:

    if (ngx_close_socket(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    return NGX_ERROR;
}


static void
ngx_syslog_cleanup(void *data)
{
    ngx_syslog_peer_t  *peer = data;

    /* prevents further use of this peer */
    peer->busy = 1;

    if (peer->conn.fd == (ngx_socket_t) -1) {
        return;
    }

    if (ngx_close_socket(peer->conn.fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }
}
