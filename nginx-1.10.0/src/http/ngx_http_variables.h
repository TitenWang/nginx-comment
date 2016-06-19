
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_VARIABLES_H_INCLUDED_
#define _NGX_HTTP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_variable_value_t  ngx_http_variable_value_t;

#define ngx_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_http_variable_s  ngx_http_variable_t;

typedef void (*ngx_http_set_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/*
 * *************************************************解析变量函数指针*********************************************
 *     参数r和data都是用来帮助生成指针，v则是用来存放变量值的(内存在调用该函数的地方已经分配好了),当然这里分配好的
 * 内存是不包括存放变量值的内存的。而存放变量值的内存则可以用请求r中的内存池进行分配，这样请求结束时变量的内存
 * 就会被释放，变量值的生命周期和请求是一致的,而变量名则不然。
 * 
 *     uintptr_t data的通用玩法:
 * 1. 该参数不起作用。如果只是生成一些和请求无关的变量值，则可以不用该参数值
 * 2. 该参数做指针使用。常见于解析五类特殊变量的时候使用，特殊变量以特殊的字符串打头，这些变量的解析方法大同小异，
 *    都是通过遍历解析出来的r->headers_in.headers数组，找到对应的变量名后返回其值即可。此时data便作保存变量名地址用。
 * 3. 该参数做整型使用。常用于保存结构体中成员的偏移量。有些时候，变量值很可能就是原始http字符流中的一部分连续字符串，
 *    如果能直接复用，就不用再为变量值分配内存;另外，http框架很有可能在请求的解析过程中已经得到了相应的变量值，此时
 *    也可以复用。如http_host，其已经在解析请求头部的时候解析完了。复用的依据是:http框架解析过后的变量值，其定义成员
 *    在ngx_http_request_t结构体里的位置是固定不变的。这样就可以用data来承载偏移量，把ngx_http_variable_value_t的
 *    data和len成员指向变量值字符串即可。
 */
typedef ngx_int_t (*ngx_http_get_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


/*变量的特性，值可变、不缓存、索引化、不hash*/
#define NGX_HTTP_VAR_CHANGEABLE   1
#define NGX_HTTP_VAR_NOCACHEABLE  2
#define NGX_HTTP_VAR_INDEXED      4
#define NGX_HTTP_VAR_NOHASH       8

/*     一个变量可以同时既被索引又被hash，但一定只有一个变量解析方法，所以一个变量可以同时拥有两个ngx_http_variable_t
 * 结构体，此时的差别在于两个结构体的flags成员不同。
 *
 *     存储变量值的结构体ngx_http_variable_value_t可能在读取变量值的时候被创建，也有可能在初始化一个http请求的
 * 时候被创建在ngx_http_request_t结构体对象中，具体采用那种方式视ngx_http_variable_t结构体成员的赋值情况而定
 */

/*变量定义结构体*/
struct ngx_http_variable_s {
    ngx_str_t                     name;   /*变量名，但不包括前置的$符号*//* must be first to build the hash */
    ngx_http_set_variable_pt      set_handler;  /*如果需要变量在最初赋值的时候进行变量值设置，需实现该方法*/
    ngx_http_get_variable_pt      get_handler;  /*每次获取变量值时会调用该方法*/
    uintptr_t                     data;   /*作为get_handler或者set_handler方法的参数*/
    ngx_uint_t                    flags;  /*变量的特性，如值可变、索引化、不缓存、不hash等*/
    ngx_uint_t                    index;  /*变量值在请求的缓存数组中的索引值*/
};


ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);
ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_http_variable_value_t *ngx_http_get_indexed_variable(ngx_http_request_t *r,
    ngx_uint_t index);
ngx_http_variable_value_t *ngx_http_get_flushed_variable(ngx_http_request_t *r,
    ngx_uint_t index);

ngx_http_variable_value_t *ngx_http_get_variable(ngx_http_request_t *r,
    ngx_str_t *name, ngx_uint_t key);

ngx_int_t ngx_http_variable_unknown_header(ngx_http_variable_value_t *v,
    ngx_str_t *var, ngx_list_part_t *part, size_t prefix);


#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_http_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;
    ngx_uint_t                    ncaptures;
    ngx_http_regex_variable_t    *variables;
    ngx_uint_t                    nvariables;
    ngx_str_t                     name;
} ngx_http_regex_t;


typedef struct {
    ngx_http_regex_t             *regex;
    void                         *value;
} ngx_http_map_regex_t;


ngx_http_regex_t *ngx_http_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re,
    ngx_str_t *s);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_http_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_http_map_t;


void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map,
    ngx_str_t *match);


ngx_int_t ngx_http_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_http_variables_init_vars(ngx_conf_t *cf);


extern ngx_http_variable_value_t  ngx_http_variable_null_value;
extern ngx_http_variable_value_t  ngx_http_variable_true_value;


#endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
