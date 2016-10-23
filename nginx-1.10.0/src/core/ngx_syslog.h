
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SYSLOG_H_INCLUDED_
#define _NGX_SYSLOG_H_INCLUDED_

/* syslog对象 */
typedef struct {
    ngx_pool_t       *pool;
    ngx_uint_t        facility;  // 存储的是配置文件中指定的facility参数值对应全局facilities数组的下标
    ngx_uint_t        severity;  // 存储的是配置文件中指定的severity参数值对应全局severities数组的下标
    ngx_str_t         tag;  // 存储的是tag参数的值

    ngx_addr_t        server;  // 存储的是syslog中配置的server信息，即打印syslog的目标服务器地址信息
    ngx_connection_t  conn;  // 本机Nginx和syslog server之间的连接对象
    unsigned          busy:1;
    unsigned          nohostname:1;  // syslog配置信息中是否配置了"nohostname"的标志位
} ngx_syslog_peer_t;


char *ngx_syslog_process_conf(ngx_conf_t *cf, ngx_syslog_peer_t *peer);
u_char *ngx_syslog_add_header(ngx_syslog_peer_t *peer, u_char *buf);
void ngx_syslog_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf,
    size_t len);
ssize_t ngx_syslog_send(ngx_syslog_peer_t *peer, u_char *buf, size_t len);


#endif /* _NGX_SYSLOG_H_INCLUDED_ */
