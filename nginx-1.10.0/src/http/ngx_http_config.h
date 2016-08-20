
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * 代码注释中出现的一些术语:
 * main级别配置项:  直接隶属于http{}块内的配置项
 * srv级别配置项:   直接隶属于server{}块内的配置项
 * loc级别的配置项: 直接隶属于location{}块内的配置项 
 */

/*用于存储http{}块内所有配置项的指针数组结构体*/
typedef struct {

    /*
     * 指向一个指针数组，数组中的每个成员都是由所有http模块的create_main_conf方法创建的
     * 存放全局配置项的结构体，它们存放着解析直属于http{}块内的main级别配置项参数
     */
    void        **main_conf;

    /*
     * 指向一个指针数组，数组中的每个成员都是由所有http模块的create_srv_conf方法创建的
     * 与server配置块功能相关的结构体，它们或存放main级别配置项，或存放srv级别配置项，
     * 这与当前的ngx_http_conf_ctx_t是在解析http{}还是server{}块时创建的有关
     */
    void        **srv_conf;

    /*
     * 指向一个指针数组，数组中的每个成员都是由所有http模块的create_loc_conf方法创建的与
     * location配置块功能相关的结构体，它们可能存放着main、srv、loc级别的配置项，这与当前
     * 的ngx_http_conf_ctx_t是在http{}、server{}、还是location{}块创建的有关
     */
    void        **loc_conf;
} ngx_http_conf_ctx_t;


typedef struct {
    /* 在解析http{}块内的配置项之前回调 */
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);

    /* 在解析http{}块内的配置项之后回调 */
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);

    /*
     * 创建用于存储http全局配置项的结构体，该结构体的成员将保存直属于http{}块配置项参数
     * 它会在解析main级别配置项前调用
     */
    void       *(*create_main_conf)(ngx_conf_t *cf);

    /* 解析完main级别配置项后回调 */
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    /*
     * 创建用于存储可同时出现在main、srv级别的配置项的结构体，该结构体的成员是与server块配置项
     * 功能相关联的
     */
    void       *(*create_srv_conf)(ngx_conf_t *cf);

    /*
     * create_srv_conf函数产生的结构体所要解析的配置项，可能同时出现在main和srv级别中，
     * merge_srv_conf函数用于把出现在main级别中的配置项值合并到srv级别配置项中
     */
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);

    /*
     * 创建用于存储可同时出现在main、srv、loc级别的配置项的结构体，该结构体的成员是与location配置
     * 块功能相关联的
     */
    void       *(*create_loc_conf)(ngx_conf_t *cf);

    /*
     * create_loc_conf函数产生的结构体所要解析的配置项，可能同时出现在main、srv和loc级别中，
     * merge_loc_conf函数用于把出现在main、srv级别的配置项值合并到loc级别的配置项中，如果存在
     * location嵌套，那么还会合并loc和loc级别的配置项
     */
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_http_module_t;


/*http模块类型*/
#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */

/* 配置项命令可以出现的的配置块级别 */
#define NGX_HTTP_MAIN_CONF        0x02000000
#define NGX_HTTP_SRV_CONF         0x04000000
#define NGX_HTTP_LOC_CONF         0x08000000
#define NGX_HTTP_UPS_CONF         0x10000000
#define NGX_HTTP_SIF_CONF         0x20000000
#define NGX_HTTP_LIF_CONF         0x40000000
#define NGX_HTTP_LMT_CONF         0x80000000

/* 配置项存放在main、srv或者loc级别的结构体的偏移量 */
#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)



/* 获取模块配置项结构体的宏 */

#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
