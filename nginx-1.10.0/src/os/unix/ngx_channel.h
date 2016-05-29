
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_uint_t  command;   //传递的tcp消息中的命令
    ngx_pid_t   pid;       //进程ID，一般是命令发送方的进程ID
    ngx_int_t   slot;      //命令发送方在ngx_processes进程数组中的序号(数组下标)
    ngx_fd_t    fd;        //通信的套接字句柄
} ngx_channel_t;

/*
 * 对ngx_channel_t结构体中的command成员，已定义的命令有如下几个:
 * 1.NGX_CMD_OPEN_CHANNEL   使用频道通信前必须发送的命令，打开频道
 * 2.NGX_CMD_CLOSE_CHANNEL  使用完频道通信后必须发送的命令，关闭频道
 * 3.NGX_CMD_QUIT           要求命令接收方正常地退出进程
 * 4.NGX_CMD_TERMINATE      要求命令接收方强制性退出进程
 * 5.NGX_CMD_REOPEN         要求命令接收方重新打开进程已经打开过的文件
 */


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);


#endif /* _NGX_CHANNEL_H_INCLUDED_ */
