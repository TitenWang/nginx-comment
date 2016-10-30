
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_SCRIPT_H_INCLUDED_
#define _NGX_HTTP_SCRIPT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * ********************************脚本上下文(脚本引擎)**********************************
 * ngx_http_script_engine_t是随着http请求到来时才创建的。所以它无法保存Nginx启动时就编译出来的脚本。
 * 保存编译后脚本的这个工作实际上是由ngx_http_rewrite_loc_conf_t结构体承担的。
 */
/*
 * 同一段脚本被编译进Nginx中，在不同的请求里执行时效果是完全不同的。
 * 所以，每一个请求都必须有其独特的脚本执行上下文，或者称为脚本引擎。
 * set 定义的外部变量只能作为索引变量使用
 */
typedef struct {
    u_char                     *ip;  //指向待执行的脚本指令。
    u_char                     *pos; //指向下面的buf，即最后变量的值存放的地方
    ngx_http_variable_value_t  *sp;  //变量值构成的栈

    ngx_str_t                   buf;  //解析一个复杂值参数的变量时，该复杂值参数最后解析的结果就存放在buf中
    ngx_str_t                   line;

    /* the start of the rewritten arguments */
    u_char                     *args;

    unsigned                    flushed:1;
    unsigned                    skip:1;  // 置1表示没有需要拷贝的数据，直接跳过数据拷贝步骤
    unsigned                    quote:1;
    unsigned                    is_args:1;
    unsigned                    log:1;

    ngx_int_t                   status;   //脚本引擎执行状态
    ngx_http_request_t         *request;  //指向脚本引擎所属的http请求
} ngx_http_script_engine_t;

/* 脚本编译对象 */
typedef struct {
    ngx_conf_t                 *cf;
    ngx_str_t                  *source;   //指向set第二个值参数字符串

    ngx_array_t               **flushes;  //存放的是变量对应的index索引号
    ngx_array_t               **lengths;  //存放用于获取变量对应值长度的脚本，每个元素为1个字节
    ngx_array_t               **values;   //指向lcf->codes数组，存放用于获取变量值的脚本，每个元素为1个字节

    ngx_uint_t                  variables;  //表示set第二个值参数中有多少个变量
    ngx_uint_t                  ncaptures;
    ngx_uint_t                  captures_mask;
    ngx_uint_t                  size;    //变量值中常量字符串的总长度

    void                       *main;

    unsigned                    compile_args:1;
    unsigned                    complete_lengths:1;
    unsigned                    complete_values:1;
    unsigned                    zero:1;  //values数组运行时，得到的字符串是否追加'\0'结尾   
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;

    unsigned                    dup_capture:1;
    unsigned                    args:1;
} ngx_http_script_compile_t;


typedef struct {
    ngx_str_t                   value;
    ngx_uint_t                 *flushes;
    void                       *lengths;
    void                       *values;
} ngx_http_complex_value_t;


typedef struct {
    ngx_conf_t                 *cf;
    ngx_str_t                  *value;
    ngx_http_complex_value_t   *complex_value;

    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;
} ngx_http_compile_complex_value_t;


typedef void (*ngx_http_script_code_pt) (ngx_http_script_engine_t *e);
typedef size_t (*ngx_http_script_len_code_pt) (ngx_http_script_engine_t *e);


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   len;
} ngx_http_script_copy_code_t;

/*编译变量名的结构体*/
typedef struct {
    ngx_http_script_code_pt     code;  //code指向的脚本指令方法为ngx_http_script_set_var_code
    uintptr_t                   index; //表示ngx_http_request_t结构体中被索引、缓存的变量值数组variables中，当前解析的、set设置的外部变量所在的索引号
} ngx_http_script_var_code_t;

/*对于已经定义过的内部变量，如果希望在配置文件中通过set修改其值，则使用如下结构体进行编译*/
typedef struct {
    ngx_http_script_code_pt     code;     //code指向的脚本指令方法为ngx_http_script_var_set_handler_code
    ngx_http_set_variable_pt    handler;  //设置变量值的回调方法  
    uintptr_t                   data;
} ngx_http_script_var_handler_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   n;
} ngx_http_script_copy_capture_code_t;


#if (NGX_PCRE)

typedef struct {
    ngx_http_script_code_pt     code;
    ngx_http_regex_t           *regex;
    ngx_array_t                *lengths;
    uintptr_t                   size;
    uintptr_t                   status;
    uintptr_t                   next;

    uintptr_t                   test:1;
    uintptr_t                   negative_test:1;
    uintptr_t                   uri:1;
    uintptr_t                   args:1;

    /* add the r->args to the new arguments */
    uintptr_t                   add_args:1;

    uintptr_t                   redirect:1;
    uintptr_t                   break_cycle:1;

    ngx_str_t                   name;
} ngx_http_script_regex_code_t;


typedef struct {
    ngx_http_script_code_pt     code;

    uintptr_t                   uri:1;
    uintptr_t                   args:1;

    /* add the r->args to the new arguments */
    uintptr_t                   add_args:1;

    uintptr_t                   redirect:1;
} ngx_http_script_regex_end_code_t;

#endif


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   conf_prefix;
} ngx_http_script_full_name_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   status;
    ngx_http_complex_value_t    text;
} ngx_http_script_return_code_t;


typedef enum {
    ngx_http_script_file_plain = 0,
    ngx_http_script_file_not_plain,
    ngx_http_script_file_dir,
    ngx_http_script_file_not_dir,
    ngx_http_script_file_exists,
    ngx_http_script_file_not_exists,
    ngx_http_script_file_exec,
    ngx_http_script_file_not_exec
} ngx_http_script_file_op_e;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   op;
} ngx_http_script_file_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   next;
    void                      **loc_conf;
} ngx_http_script_if_code_t;


/*编译复杂变量值(内嵌其他变量)的结构体*/
typedef struct {
    ngx_http_script_code_pt     code;      //code指向的脚本指令方法为ngx_http_script_complex_value_code   
    ngx_array_t                *lengths;
} ngx_http_script_complex_value_code_t;

/*编译变量值(纯字符串)的结构体*/
typedef struct {
    ngx_http_script_code_pt     code;      //code指向的脚本指令方法为ngx_http_script_value_code
    uintptr_t                   value;     //外部变量值如果为整数，则转为整数后赋值给value，否则value为0
    uintptr_t                   text_len;  //外部变量值(set的第二个参数)的长度
    uintptr_t                   text_data; //外部变量值的起始地址
} ngx_http_script_value_code_t;


void ngx_http_script_flush_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *val);
ngx_int_t ngx_http_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *val, ngx_str_t *value);
ngx_int_t ngx_http_compile_complex_value(ngx_http_compile_complex_value_t *ccv);
char *ngx_http_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


ngx_int_t ngx_http_test_predicates(ngx_http_request_t *r,
    ngx_array_t *predicates);
char *ngx_http_set_predicate_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

ngx_uint_t ngx_http_script_variables_count(ngx_str_t *value);
ngx_int_t ngx_http_script_compile(ngx_http_script_compile_t *sc);
u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void ngx_http_script_flush_no_cacheable_variables(ngx_http_request_t *r,
    ngx_array_t *indices);

void *ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes,
    size_t size);
void *ngx_http_script_add_code(ngx_array_t *codes, size_t size, void *code);

size_t ngx_http_script_copy_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_var_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_var_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_mark_args_code(ngx_http_script_engine_t *e);
void ngx_http_script_start_args_code(ngx_http_script_engine_t *e);
#if (NGX_PCRE)
void ngx_http_script_regex_start_code(ngx_http_script_engine_t *e);
void ngx_http_script_regex_end_code(ngx_http_script_engine_t *e);
#endif
void ngx_http_script_return_code(ngx_http_script_engine_t *e);
void ngx_http_script_break_code(ngx_http_script_engine_t *e);
void ngx_http_script_if_code(ngx_http_script_engine_t *e);
void ngx_http_script_equal_code(ngx_http_script_engine_t *e);
void ngx_http_script_not_equal_code(ngx_http_script_engine_t *e);
void ngx_http_script_file_code(ngx_http_script_engine_t *e);
void ngx_http_script_complex_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_set_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_set_handler_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_nop_code(ngx_http_script_engine_t *e);


#endif /* _NGX_HTTP_SCRIPT_H_INCLUDED_ */
