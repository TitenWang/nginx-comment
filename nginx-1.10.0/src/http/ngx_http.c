
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_init_phases(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_headers_in_hash(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_phase_handlers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);

static ngx_int_t ngx_http_add_addresses(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
    ngx_http_listen_opt_t *lsopt);
static ngx_int_t ngx_http_add_address(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
    ngx_http_listen_opt_t *lsopt);
static ngx_int_t ngx_http_add_server(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_addr_t *addr);

static char *ngx_http_merge_servers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
static char *ngx_http_merge_locations(ngx_conf_t *cf,
    ngx_queue_t *locations, void **loc_conf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
static ngx_int_t ngx_http_init_locations(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_core_loc_conf_t *pclcf);
static ngx_int_t ngx_http_init_static_location_trees(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *pclcf);
static ngx_int_t ngx_http_cmp_locations(const ngx_queue_t *one,
    const ngx_queue_t *two);
static ngx_int_t ngx_http_join_exact_locations(ngx_conf_t *cf,
    ngx_queue_t *locations);
static void ngx_http_create_locations_list(ngx_queue_t *locations,
    ngx_queue_t *q);
static ngx_http_location_tree_node_t *
    ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
    size_t prefix);

static ngx_int_t ngx_http_optimize_servers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_array_t *ports);
static ngx_int_t ngx_http_server_names(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_conf_addr_t *addr);
static ngx_int_t ngx_http_cmp_conf_addrs(const void *one, const void *two);
static int ngx_libc_cdecl ngx_http_cmp_dns_wildcards(const void *one,
    const void *two);

static ngx_int_t ngx_http_init_listening(ngx_conf_t *cf,
    ngx_http_conf_port_t *port);
static ngx_listening_t *ngx_http_add_listening(ngx_conf_t *cf,
    ngx_http_conf_addr_t *addr);
static ngx_int_t ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr);
#endif

ngx_uint_t   ngx_http_max_module;


ngx_http_output_header_filter_pt  ngx_http_top_header_filter;
ngx_http_output_body_filter_pt    ngx_http_top_body_filter;
ngx_http_request_body_filter_pt   ngx_http_top_request_body_filter;


ngx_str_t  ngx_http_html_default_types[] = {
    ngx_string("text/html"),
    ngx_null_string
};


static ngx_command_t  ngx_http_commands[] = {

    { ngx_string("http"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_http_module_ctx = {
    ngx_string("http"),
    NULL,
    NULL
};


ngx_module_t  ngx_http_module = {
    NGX_MODULE_V1,
    &ngx_http_module_ctx,                  /* module context */
    ngx_http_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_uint_t                   mi, m, s;
    ngx_conf_t                   pcf;
    ngx_http_module_t           *module;
    ngx_http_conf_ctx_t         *ctx;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    if (*(ngx_http_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main http context */
	/*http{}配置块下main级别配置项上下文*/
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_http_conf_ctx_t **) conf = ctx;


    /* count the number of the http modules and set up their indices */

    ngx_http_max_module = ngx_count_modules(cf->cycle, NGX_HTTP_MODULE);


    /* the http main_conf context, it is the same in the all http contexts */
	/*创建用于所有http模块用来存储main级别配置项结构体的指针*/
    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_http_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the http null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the http null loc_conf context, it is used to merge
     * the server{}s' loc_conf's
     */

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all http modules
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;
		/*创建用于存储main级别配置项的结构体*/
        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (ctx->loc_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

	/*保存cf，用于后续还原*/
    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
		/*解析配置项前调用preconfiguration*/
        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* parse inside the http{} block */
	/*解析配置项并存储到相应文职*/
    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        goto failed;
    }

    /*
     * init http{} main_conf's, merge the server{}s' srv_conf's
     * and its location{}s' loc_conf's
     */

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init http{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

		/*合并配置项,包括srv和loc级别*/
        rv = ngx_http_merge_servers(cf, cmcf, module, mi);
        if (rv != NGX_CONF_OK) {
            goto failed;
        }
    }


    /* create location trees */
	/*创建并初始化用于索引location的静态平衡二叉树*/
    for (s = 0; s < cmcf->servers.nelts; s++) {

        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (ngx_http_init_locations(cf, cscfp[s], clcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

	/*初始化阶段处理函数，申请内存*/
    if (ngx_http_init_phases(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

	/*初始化请求头的字段hash*/
    if (ngx_http_init_headers_in_hash(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

		/*
		 * 解析完配置项后执行，一般用于将阶段处理函数添加到handlers数组
		 */
        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* 初始化Nginx将会使用到的变量 */
    if (ngx_http_variables_init_vars(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * http{}'s cf->ctx was needed while the configuration merging
     * and in postconfiguration process
     */

	/*恢复*/
    *cf = pcf;

	/*设置阶段对应的checker函数，并设置checker对应的handler函数(在postconfiguration里面设置)*/
    if (ngx_http_init_phase_handlers(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    /* optimize the lists of ports, addresses and server names */

    if (ngx_http_optimize_servers(cf, cmcf, cmcf->ports) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

failed:

    *cf = pcf;

    return rv;
}

/*
 * 初始化阶段处理函数，handler函数只能被对应的checker函数调用。在11个处理阶段中，只有
 * 下面的7个阶段可以由第三方http模块介入，而其余4个阶段由于不能由第三方http模块介入，
 * 所以也就不需要初始化阶段处理函数
 */
static ngx_int_t
ngx_http_init_phases(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers,
                       cf->pool, 2, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers,
                       cf->pool, 4, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*初始化请求头hash*/
static ngx_int_t
ngx_http_init_headers_in_hash(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_array_t         headers_in;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    ngx_http_header_t  *header;

    if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (header = ngx_http_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &cmcf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*设置阶段对应的checker函数，并设置checker对应的handler函数(在postconfiguration里面设置)*/
static ngx_int_t
ngx_http_init_phase_handlers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_int_t                   j;
    ngx_uint_t                  i, n;
    ngx_uint_t                  find_config_index, use_rewrite, use_access;
    ngx_http_handler_pt        *h;
    ngx_http_phase_handler_t   *ph;
    ngx_http_phase_handler_pt   checker;

    cmcf->phase_engine.server_rewrite_index = (ngx_uint_t) -1;
    cmcf->phase_engine.location_rewrite_index = (ngx_uint_t) -1;
    find_config_index = 0;

    /*
     * 对于这11个处理阶段，有些阶段是必备的，比如NGX_HTTP_FIND_CONFIG_PHASE阶段，有些阶段是可以选的，
     * 比如NGX_HTTP_POST_ACCESS_PHASE和NGX_HTTP_POST_REWRITE_PHASE阶段，为什么说这两个阶段是可选的呢?
     * 因为NGX_HTTP_POST_REWRITE_PHASE完全是为了NGX_HTTP_REWRITE_PHASE阶段服务的，因为如果没有任何模块
     * 介入NGX_HTTP_REWRITE_PHASE阶段处理请求，那就没必要检测是否出现重定向死循环，那么NGX_HTTP_POST_REWRITE_PHASE
     * 也就没有必要存在了，同理NGX_HTTP_POST_ACCESS_PHASE之于NGX_HTTP_ACCESS_PHASE阶段也是一个道理，
     * 这个可以在ngx_http_init_phase_handlers()有体现.
     * 如果NGX_HTTP_REWRITE_PHASE中的没有处理方法，则表示没有模块介入该阶段，也就不需要NGX_HTTP_POST_REWRITE_PHASE
     * 如果NGX_HTTP_ACCESS_PHASE中的没有处理方法，则表示没有模块介入该阶段，也就不需要NGX_HTTP_POST_ACCESS_PHASE
     */
    use_rewrite = cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers.nelts ? 1 : 0;
    use_access = cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers.nelts ? 1 : 0;

    /*
     * NGX_HTTP_FIND_CONFIG_PHASE阶段是必备的，如果配置文件中配置了try_files命令，
     * 则会有NGX_HTTP_TRY_FILES_PHASE阶段
     */
    n = use_rewrite + use_access + cmcf->try_files + 1 /* find config phase */;

    /*
     * 从这里的实现可以看出，在NGX_HTTP_LOG_PHASE阶段注册的模块处理函数并不会被加入到
     * cmcf->pahse_engine.handlers数组中，因为这里只收集了NGX_HTTP_LOG_PHASE之前的处理
     * 函数，那么NGX_HTTP_LOG_PHASE阶段注册的处理函数在什么时候被调用的呢?其实是在结束
     * 请求的函数ngx_http_free_request()中调用ngx_http_log_request()调用NGX_HTTP_LOG_PHASE
     * 阶段的处理函数
     */
    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    ph = ngx_pcalloc(cf->pool,
                     n * sizeof(ngx_http_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return NGX_ERROR;
    }

    /* 将所有阶段的处理函数存放在cmcf->phase_engine.handlers数组中 */
    cmcf->phase_engine.handlers = ph;
    n = 0;

    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        h = cmcf->phases[i].handlers.elts;  //存放在cmcf->phase数组中的当前阶段的所有处理方法

        switch (i) {

        case NGX_HTTP_SERVER_REWRITE_PHASE:
            if (cmcf->phase_engine.server_rewrite_index == (ngx_uint_t) -1) {
                /* 
                 * server_rewrite_index为NGX_HTTP_SERVER_REWRITE_PHASE阶段的第一个处理方法
                 * 在cmcf->phase_engine.handlers数组中的序号    
                 */
                cmcf->phase_engine.server_rewrite_index = n;
            }
            checker = ngx_http_core_rewrite_phase;

            break;

        case NGX_HTTP_FIND_CONFIG_PHASE:
            /*
             * find_config_index表示的就是NGX_HTTP_FIND_CONFIG_PHASE阶段的第一个处理方法
             * 在cmcf->phase_engine.handlers数组中的序号
             */
            find_config_index = n;

            ph->checker = ngx_http_core_find_config_phase;
            n++;  // 虽然这个阶段不允许http模块介入处理，但在cmcf->phase_engine.handlers还是要占一位
            ph++;  // cmcf->phase_engine.handlers数组中下一个未使用的位置

            /*
             * 这个阶段不允许http模块介入，所以不往下执行向cmcf->phase_engine.handlers数组中
             * 添加自定义处理方法的步骤
             */
            continue;

        case NGX_HTTP_REWRITE_PHASE:
            if (cmcf->phase_engine.location_rewrite_index == (ngx_uint_t) -1) {
                /* 
                 * location_rewrite_index为NGX_HTTP_REWRITE_PHASE阶段的第一个处理方法
                 * 在cmcf->phase_engine.handlers数组中的序号    
                 */
                cmcf->phase_engine.location_rewrite_index = n;
            }
            checker = ngx_http_core_rewrite_phase;

            break;

        case NGX_HTTP_POST_REWRITE_PHASE:
            if (use_rewrite) {
                ph->checker = ngx_http_core_post_rewrite_phase;
                ph->next = find_config_index;  // 下一个处理阶段是NGX_HTTP_FIND_CONFIG_PHASE，因为重定向
                n++;  // 虽然这个阶段不允许http模块介入处理，但在cmcf->phase_engine.handlers还是要占一位
                ph++; // cmcf->phase_engine.handlers数组中下一个未使用的位置
            }

            /*
             * 这个阶段不允许http模块介入，所以不往下执行向cmcf->phase_engine.handlers数组中
             * 添加自定义处理方法的步骤
             */
            continue;

        case NGX_HTTP_ACCESS_PHASE:
            checker = ngx_http_core_access_phase;
            n++;
            break;

        case NGX_HTTP_POST_ACCESS_PHASE:
            /* use_access表明有模块介入了NGX_HTTP_ACCESS_PHASE，因此本阶段也是需要的 */
            if (use_access) {
                ph->checker = ngx_http_core_post_access_phase; // 直接指定checker方法
                ph->next = n;  // 为什么下一个处理阶段是自身呢?
                ph++; // cmcf->phase_engine.handlers数组中下一个未使用的位置
            }

            /*
             * 这个阶段不允许http模块介入，所以不往下执行向cmcf->phase_engine.handlers数组中
             * 添加自定义处理方法的步骤
             */
            continue;

        case NGX_HTTP_TRY_FILES_PHASE:
            /* cmcf->try_files表明配置了try_files指令，也就有了这个阶段 */
            if (cmcf->try_files) {
                ph->checker = ngx_http_core_try_files_phase;
                n++;
                ph++;
            }

            /*
             * 这个阶段不允许http模块介入，所以不往下执行向cmcf->phase_engine.handlers数组中
             * 添加自定义处理方法的步骤
             */
            continue;

        case NGX_HTTP_CONTENT_PHASE:
            checker = ngx_http_core_content_phase;
            break;

        default:
            checker = ngx_http_core_generic_phase;
        }

        /* 
         * n的值存放的是到目前处理阶段为止，所有处理阶段中的处理方法的数目总和，同时也是当前处理阶段的下一个
         * 处理阶段的第一个处理方法在cmcf->phase_engine.handlers数组中的序号
         */
        n += cmcf->phases[i].handlers.nelts;

        /* 将当前处理阶段中的所有处理方法逆序存放到cmcf->phase_engine.handlers数组中 */
        for (j = cmcf->phases[i].handlers.nelts - 1; j >=0; j--) {
            ph->checker = checker;
            ph->handler = h[j];

            /* 
             * 将要执行的下一个处理阶段的序号，也就是下一个处理阶段第一个处理方法在
             * cmcf->phase_engine.handlers数组中的序号
             */
            ph->next = n;
            ph++;  // cmcf->phase_engine.handlers数组中下一个未使用的位置
        }
    }

    return NGX_OK;
}


static char *
ngx_http_merge_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_http_module_t *module, ngx_uint_t ctx_index)
{
    char                        *rv;
    ngx_uint_t                   s;
    ngx_http_conf_ctx_t         *ctx, saved;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;

    cscfp = cmcf->servers.elts;

    /* 这个ctx是http{}块下的全局ngx_http_conf_ctx_t结构体 */
    ctx = (ngx_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;
    rv = NGX_CONF_OK;

    /* 遍历该http{}块内的所有server配置块的ngx_http_core_srv_conf_t结构体 */
    for (s = 0; s < cmcf->servers.nelts; s++) {

        /* merge the server{}s' srv_conf's */
        /* ctx->srv_conf将指向所有http模块产生的server相关的srv级别的配置项结构体 */
        ctx->srv_conf = cscfp[s]->ctx->srv_conf;

        /* 如果当前模块实现了merge_srv_conf方法 */
        if (module->merge_srv_conf) {

            /*
             * 在这里合并配置项时，saved.srv_conf[ctx_index]参数是当前http模块在http{}
             * 块下有create_srv_conf方法创建的结构体，而cscfp[s]->ctx->srv_conf[ctx_index]
             * 参数则是在解析server{}块下由create_srv_conf方法产生的结构体
             */
            rv = module->merge_srv_conf(cf, saved.srv_conf[ctx_index],
                                        cscfp[s]->ctx->srv_conf[ctx_index]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        /* 如果当前http模块实现了merge_loc_conf方法 */
        if (module->merge_loc_conf) {

            /* merge the server{}'s loc_conf */

            /*
             * cscfp[s]->ctx->loc_conf这个动态数组中的成员都是由server{}块下的所有http
             * 模块的create_loc_conf方法创建的结构体指针
             */
            ctx->loc_conf = cscfp[s]->ctx->loc_conf;

            /*
             * 首先将http{}块下的main级别与server{}块下srv级别的location相关的结构体合并
             */
            rv = module->merge_loc_conf(cf, saved.loc_conf[ctx_index],
                                        cscfp[s]->ctx->loc_conf[ctx_index]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }

            /* merge the locations{}' loc_conf's */

            /*
             * clcf是server块下的ngx_http_core_module模块使用create_loc_conf方法产生的
             * ngx_http_core_loc_conf_t结构体，其中的locations成员以双向链表方法关联
             * 所有属于当前server{}块下的location块。
             */
            clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

            /*
             * 将server{}块与其所包含的location{}块下的结构体进行合并
             */
            rv = ngx_http_merge_locations(cf, clcf->locations,
                                          cscfp[s]->ctx->loc_conf,
                                          module, ctx_index);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }
    }

failed:

    *ctx = saved;

    return rv;
}

/*合并location相关的配置项*/
static char *
ngx_http_merge_locations(ngx_conf_t *cf, ngx_queue_t *locations,
    void **loc_conf, ngx_http_module_t *module, ngx_uint_t ctx_index)
{
    char                       *rv;
    ngx_queue_t                *q;
    ngx_http_conf_ctx_t        *ctx, saved;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_location_queue_t  *lq;

    /*
     * 如果locations链表为空，说明当前server块下没有location块。
     */
    if (locations == NULL) {
        return NGX_CONF_OK;
    }

    /*
     * 此时cf->ctx中存放的是解析server{}块时产生的ngx_http_conf_ctx_t对象
     */
    ctx = (ngx_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;

    /* 遍历locations双向链表 */
    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;
        /* clcf->loc_conf保存着解析当前location时产生的所有http模块使用create_loc_conf方法产生的结构体指针 */
        ctx->loc_conf = clcf->loc_conf;

        /* 
         * 调用merge_loc_conf方法合并srv、loc级别的location相关的配置项，其中loc_conf[ctx_index]
         * 是srv级别的location相关的配置项
         */
        rv = module->merge_loc_conf(cf, loc_conf[ctx_index],
                                    clcf->loc_conf[ctx_index]);
        if (rv != NGX_CONF_OK) {
            return rv;
        }

        /* 因为location可以嵌套，所以接着合并当前location和其下嵌套的location之间的配置项 */
        rv = ngx_http_merge_locations(cf, clcf->locations, clcf->loc_conf,
                                      module, ctx_index);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    *ctx = saved;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_init_locations(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_core_loc_conf_t *pclcf)
{
    ngx_uint_t                   n;
    ngx_queue_t                 *q, *locations, *named, tail;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_location_queue_t   *lq;
    ngx_http_core_loc_conf_t   **clcfp;
#if (NGX_PCRE)
    ngx_uint_t                   r;
    ngx_queue_t                 *regex;
#endif

    locations = pclcf->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    ngx_queue_sort(locations, ngx_http_cmp_locations);

    named = NULL;
    n = 0;
#if (NGX_PCRE)
    regex = NULL;
    r = 0;
#endif

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (ngx_http_init_locations(cf, NULL, clcf) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_PCRE)

        if (clcf->regex) {
            r++;

            if (regex == NULL) {
                regex = q;
            }

            continue;
        }

#endif

        if (clcf->named) {
            n++;

            if (named == NULL) {
                named = q;
            }

            continue;
        }

        if (clcf->noname) {
            break;
        }
    }

    if (q != ngx_queue_sentinel(locations)) {
        ngx_queue_split(locations, q, &tail);
    }

    if (named) {
        clcfp = ngx_palloc(cf->pool,
                           (n + 1) * sizeof(ngx_http_core_loc_conf_t *));
        if (clcfp == NULL) {
            return NGX_ERROR;
        }

        cscf->named_locations = clcfp;

        for (q = named;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        ngx_queue_split(locations, named, &tail);
    }

#if (NGX_PCRE)

    if (regex) {

        clcfp = ngx_palloc(cf->pool,
                           (r + 1) * sizeof(ngx_http_core_loc_conf_t *));
        if (clcfp == NULL) {
            return NGX_ERROR;
        }

        pclcf->regex_locations = clcfp;

        for (q = regex;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        ngx_queue_split(locations, regex, &tail);
    }

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_init_static_location_trees(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *pclcf)
{
    ngx_queue_t                *q, *locations;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_location_queue_t  *lq;

    locations = pclcf->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    if (ngx_queue_empty(locations)) {
        return NGX_OK;
    }

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_http_join_exact_locations(cf, locations) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_create_locations_list(locations, ngx_queue_head(locations));

    pclcf->static_locations = ngx_http_create_locations_tree(cf, locations, 0);
    if (pclcf->static_locations == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
    ngx_http_core_loc_conf_t *clcf)
{
    ngx_http_location_queue_t  *lq;

    if (*locations == NULL) {
        *locations = ngx_palloc(cf->temp_pool,
                                sizeof(ngx_http_location_queue_t));
        if (*locations == NULL) {
            return NGX_ERROR;
        }

        ngx_queue_init(*locations);
    }

    lq = ngx_palloc(cf->temp_pool, sizeof(ngx_http_location_queue_t));
    if (lq == NULL) {
        return NGX_ERROR;
    }

    if (clcf->exact_match
#if (NGX_PCRE)
        || clcf->regex
#endif
        || clcf->named || clcf->noname)
    {
        lq->exact = clcf;
        lq->inclusive = NULL;

    } else {
        lq->exact = NULL;
        lq->inclusive = clcf;
    }

    lq->name = &clcf->name;
    lq->file_name = cf->conf_file->file.name.data;
    lq->line = cf->conf_file->line;

    ngx_queue_init(&lq->list);

    ngx_queue_insert_tail(*locations, &lq->queue);

    return NGX_OK;
}


static ngx_int_t
ngx_http_cmp_locations(const ngx_queue_t *one, const ngx_queue_t *two)
{
    ngx_int_t                   rc;
    ngx_http_core_loc_conf_t   *first, *second;
    ngx_http_location_queue_t  *lq1, *lq2;

    lq1 = (ngx_http_location_queue_t *) one;
    lq2 = (ngx_http_location_queue_t *) two;

    first = lq1->exact ? lq1->exact : lq1->inclusive;
    second = lq2->exact ? lq2->exact : lq2->inclusive;

    if (first->noname && !second->noname) {
        /* shift no named locations to the end */
        return 1;
    }

    if (!first->noname && second->noname) {
        /* shift no named locations to the end */
        return -1;
    }

    if (first->noname || second->noname) {
        /* do not sort no named locations */
        return 0;
    }

    if (first->named && !second->named) {
        /* shift named locations to the end */
        return 1;
    }

    if (!first->named && second->named) {
        /* shift named locations to the end */
        return -1;
    }

    if (first->named && second->named) {
        return ngx_strcmp(first->name.data, second->name.data);
    }

#if (NGX_PCRE)

    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }

#endif

    rc = ngx_filename_cmp(first->name.data, second->name.data,
                          ngx_min(first->name.len, second->name.len) + 1);

    if (rc == 0 && !first->exact_match && second->exact_match) {
        /* an exact match must be before the same inclusive one */
        return 1;
    }

    return rc;
}


static ngx_int_t
ngx_http_join_exact_locations(ngx_conf_t *cf, ngx_queue_t *locations)
{
    ngx_queue_t                *q, *x;
    ngx_http_location_queue_t  *lq, *lx;

    q = ngx_queue_head(locations);

    while (q != ngx_queue_last(locations)) {

        x = ngx_queue_next(q);

        lq = (ngx_http_location_queue_t *) q;
        lx = (ngx_http_location_queue_t *) x;

        if (lq->name->len == lx->name->len
            && ngx_filename_cmp(lq->name->data, lx->name->data, lx->name->len)
               == 0)
        {
            if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "duplicate location \"%V\" in %s:%ui",
                              lx->name, lx->file_name, lx->line);

                return NGX_ERROR;
            }

            lq->inclusive = lx->inclusive;

            ngx_queue_remove(x);

            continue;
        }

        q = ngx_queue_next(q);
    }

    return NGX_OK;
}


static void
ngx_http_create_locations_list(ngx_queue_t *locations, ngx_queue_t *q)
{
    u_char                     *name;
    size_t                      len;
    ngx_queue_t                *x, tail;
    ngx_http_location_queue_t  *lq, *lx;

    if (q == ngx_queue_last(locations)) {
        return;
    }

    lq = (ngx_http_location_queue_t *) q;

    if (lq->inclusive == NULL) {
        ngx_http_create_locations_list(locations, ngx_queue_next(q));
        return;
    }

    len = lq->name->len;
    name = lq->name->data;

    for (x = ngx_queue_next(q);
         x != ngx_queue_sentinel(locations);
         x = ngx_queue_next(x))
    {
        lx = (ngx_http_location_queue_t *) x;

        if (len > lx->name->len
            || ngx_filename_cmp(name, lx->name->data, len) != 0)
        {
            break;
        }
    }

    q = ngx_queue_next(q);

    if (q == x) {
        ngx_http_create_locations_list(locations, x);
        return;
    }

    ngx_queue_split(locations, q, &tail);
    ngx_queue_add(&lq->list, &tail);

    if (x == ngx_queue_sentinel(locations)) {
        ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));
        return;
    }

    ngx_queue_split(&lq->list, x, &tail);
    ngx_queue_add(locations, &tail);

    ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));

    ngx_http_create_locations_list(locations, x);
}


/*
 * to keep cache locality for left leaf nodes, allocate nodes in following
 * order: node, left subtree, right subtree, inclusive subtree
 */

static ngx_http_location_tree_node_t *
ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
    size_t prefix)
{
    size_t                          len;
    ngx_queue_t                    *q, tail;
    ngx_http_location_queue_t      *lq;
    ngx_http_location_tree_node_t  *node;

    q = ngx_queue_middle(locations);

    lq = (ngx_http_location_queue_t *) q;
    len = lq->name->len - prefix;

    node = ngx_palloc(cf->pool,
                      offsetof(ngx_http_location_tree_node_t, name) + len);
    if (node == NULL) {
        return NULL;
    }

    node->left = NULL;
    node->right = NULL;
    node->tree = NULL;
    node->exact = lq->exact;
    node->inclusive = lq->inclusive;

    node->auto_redirect = (u_char) ((lq->exact && lq->exact->auto_redirect)
                           || (lq->inclusive && lq->inclusive->auto_redirect));

    node->len = (u_char) len;
    ngx_memcpy(node->name, &lq->name->data[prefix], len);

    ngx_queue_split(locations, q, &tail);

    if (ngx_queue_empty(locations)) {
        /*
         * ngx_queue_split() insures that if left part is empty,
         * then right one is empty too
         */
        goto inclusive;
    }

    node->left = ngx_http_create_locations_tree(cf, locations, prefix);
    if (node->left == NULL) {
        return NULL;
    }

    ngx_queue_remove(q);

    if (ngx_queue_empty(&tail)) {
        goto inclusive;
    }

    node->right = ngx_http_create_locations_tree(cf, &tail, prefix);
    if (node->right == NULL) {
        return NULL;
    }

inclusive:

    if (ngx_queue_empty(&lq->list)) {
        return node;
    }

    node->tree = ngx_http_create_locations_tree(cf, &lq->list, prefix + len);
    if (node->tree == NULL) {
        return NULL;
    }

    return node;
}

/*
 * 当Nginx的http配置块解析完后，http块内的所有server中的监听套接口信息就被收集起来了，先按照port端口分类
 * 形成数组存储在cmcf->ports中，然后再在每一个port内按照ip地址分类形成数组存储在port->addrs中，也就是一个
 * [port, addr]的二维数组。另外，一个[port, addr]可以对应多个server配置块，也就是说多个server块内可以监听
 * 同一个ip:port,但是对应的server配置块多少并不会影响到监听套接口的创建，因为创建套接口依赖的是[port, addr]，
 * 并不是他对应的server配置块，具体见ngx_http_init_listening()。
 */
ngx_int_t
ngx_http_add_listen(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_listen_opt_t *lsopt)
{
    in_port_t                   p;
    ngx_uint_t                  i;
    struct sockaddr            *sa;
    struct sockaddr_in         *sin;
    ngx_http_conf_port_t       *port;
    ngx_http_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    /* 获取权益唯一的ngx_http_core_module模块的main_conf配置项结构体 */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (cmcf->ports == NULL) {
        cmcf->ports = ngx_array_create(cf->temp_pool, 2,
                                       sizeof(ngx_http_conf_port_t));
        if (cmcf->ports == NULL) {
            return NGX_ERROR;
        }
    }

    sa = &lsopt->u.sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = &lsopt->u.sockaddr_in6;
        p = sin6->sin6_port;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        p = 0;
        break;
#endif

    default: /* AF_INET */
        sin = &lsopt->u.sockaddr_in;
        p = sin->sin_port;  // 获取listen配置项监听的port
        break;
    }

    /* 遍历cmcf->ports中已经存在的port，看是否已经有server配置块监听了这个port */
    port = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; i++) {

        /* 判断是否port已经被其他已经解析过的server监听了 */
        if (p != port[i].port || sa->sa_family != port[i].family) {
            continue;
        }

        /* a port is already in the port list */
        return ngx_http_add_addresses(cf, cscf, &port[i], lsopt);
    }

    /* add a port to the port list */

    /* 
     * 程序执行到这里表明在已经解析过的server中，并没有server监听了这个port，
     * 所以需要在cmcf->ports数组中新增一个元素。
     */
    port = ngx_array_push(cmcf->ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;
    port->addrs.elts = NULL;  // port->addrs数组中存放的便是监听同一个port，但ip不同的地址。

    /* 往这个新增的port中添加addrs地址信息 */
    return ngx_http_add_address(cf, cscf, port, lsopt);
}


static ngx_int_t
ngx_http_add_addresses(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
{
    u_char                *p;
    size_t                 len, off;
    ngx_uint_t             i, default_server, proxy_protocol;
    struct sockaddr       *sa;
    ngx_http_conf_addr_t  *addr;
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un    *saun;
#endif
#if (NGX_HTTP_SSL)
    ngx_uint_t             ssl;
#endif
#if (NGX_HTTP_V2)
    ngx_uint_t             http2;
#endif

    /*
     * we cannot compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    /* 获取listen配置指令监听的ip和port */
    sa = &lsopt->u.sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        off = offsetof(struct sockaddr_in6, sin6_addr);
        len = 16;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        off = offsetof(struct sockaddr_un, sun_path);
        len = sizeof(saun->sun_path);
        break;
#endif

    default: /* AF_INET */
        off = offsetof(struct sockaddr_in, sin_addr);  // 计算ip地址sin_addr在sockaddr_in中的偏移
        len = 4;
        break;
    }

    p = lsopt->u.sockaddr_data + off;

    addr = port->addrs.elts;

    /* 遍历监听这个port的所有地址 */
    for (i = 0; i < port->addrs.nelts; i++) {

        /* 
         * 判断这个listen监听的ip地址是否已经有其他server监听了，因为其他server监听了，
         * 就会加入到ports->addrs中 
         */
        if (ngx_memcmp(p, addr[i].opt.u.sockaddr_data + off, len) != 0) {
            continue;
        }

        /* the address is already in the address list */
        /* 这个listen监听的ip地址已经有其他server监听过了，所以此时需要将这个server的信息放到addrs.servers中 */
        if (ngx_http_add_server(cf, cscf, &addr[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        /* preserve default_server bit during listen options overwriting */
        /* 获取这个监听的ip地址是否已经被其他server设置为default server的标志位 */
        default_server = addr[i].opt.default_server;

        proxy_protocol = lsopt->proxy_protocol || addr[i].opt.proxy_protocol;

#if (NGX_HTTP_SSL)
        ssl = lsopt->ssl || addr[i].opt.ssl;
#endif
#if (NGX_HTTP_V2)
        http2 = lsopt->http2 || addr[i].opt.http2;
#endif

        if (lsopt->set) {

            if (addr[i].opt.set) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "duplicate listen options for %s", addr[i].opt.addr);
                return NGX_ERROR;
            }

            addr[i].opt = *lsopt;
        }

        /* check the duplicate "default" server for this address:port */

        /* lsopt->default_server等于1表明当前解析的这个server块被设置为了这个ip:port默认的server */
        if (lsopt->default_server) {

            if (default_server) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "a duplicate default server for %s", addr[i].opt.addr);
                return NGX_ERROR;
            }

            default_server = 1;
            addr[i].default_server = cscf;  // 将这个ip:port的默认的server设为当前server
        }

        addr[i].opt.default_server = default_server;
        addr[i].opt.proxy_protocol = proxy_protocol;
#if (NGX_HTTP_SSL)
        addr[i].opt.ssl = ssl;
#endif
#if (NGX_HTTP_V2)
        addr[i].opt.http2 = http2;
#endif

        return NGX_OK;
    }

    /* add the address to the addresses list that bound to this port */

    /*
     * 程序执行到这里表明这个ip地址目前在已经解析过的server块中还没有被监听，所以这里
     * 需要将这个ip地址信息添加到cmcf->ports数组中。
     */
    return ngx_http_add_address(cf, cscf, port, lsopt);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */
static ngx_int_t
ngx_http_add_address(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
{
    ngx_http_conf_addr_t  *addr;

    if (port->addrs.elts == NULL) {
        if (ngx_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(ngx_http_conf_addr_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

#if (NGX_HTTP_V2 && NGX_HTTP_SSL                                              \
     && !defined TLSEXT_TYPE_application_layer_protocol_negotiation           \
     && !defined TLSEXT_TYPE_next_proto_neg)

    if (lsopt->http2 && lsopt->ssl) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "nginx was built with OpenSSL that lacks ALPN "
                           "and NPN support, HTTP/2 is not enabled for %s",
                           lsopt->addr);
    }

#endif

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    /* 将之前解析到的listen配置项的信息赋值到具体的addr中，因为listen配置项是针对ip:port的 */
    addr->opt = *lsopt;
    addr->hash.buckets = NULL;
    addr->hash.size = 0;
    addr->wc_head = NULL;
    addr->wc_tail = NULL;
#if (NGX_PCRE)
    addr->nregex = 0;
    addr->regex = NULL;
#endif
    /* 如果有多个server监听同一个ip:port，那么第一个解析到的server会被当作是default server */
    addr->default_server = cscf;
    addr->servers.elts = NULL;  /* addr->servers数组中存放的便是监听同一个ip:port的多个server的信息 */

    /* 将监听这个ip:port的server信息存放到addr->servers数组中，因为可能有多个server会监听同一个ip:port */
    return ngx_http_add_server(cf, cscf, addr);
}


/* add the server core module configuration to the address:port */
/* 将监听这个ip:port的server信息存放到addr->servers数组中，因为可能有多个server会监听同一个ip:port */
static ngx_int_t
ngx_http_add_server(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                  i;
    ngx_http_core_srv_conf_t  **server;

    if (addr->servers.elts == NULL) {
        if (ngx_array_init(&addr->servers, cf->temp_pool, 4,
                           sizeof(ngx_http_core_srv_conf_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        server = addr->servers.elts;
        for (i = 0; i < addr->servers.nelts; i++) {
            if (server[i] == cscf) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a duplicate listen %s", addr->opt.addr);
                return NGX_ERROR;
            }
        }
    }

    /* 将监听这个ip:port的server信息设置到addr->servers中收集起来 */
    server = ngx_array_push(&addr->servers);
    if (server == NULL) {
        return NGX_ERROR;
    }

    *server = cscf;

    return NGX_OK;
}

/*
 * ngx_http_optimize_servers()这个函数主要作用如下:
 *     1. 如果一个ip:port有多个server块同时监听，那么需要将监听这个ip:port的所有server的server_name进行hash，
 * 之所以进行hash是为了后续处理请求的时候用于快速获取请求真正对应的server块。这个地方需要说明下: 就是在请求
 * 的初期，具体就是在解析到请求头部的host字段之前，一直都是用监听这个ip:port的指定的default server来处理这个
 * 这个请求的，等到解析到请求头中的host字段时，就会用host字段值去获取对应的server块，接着请求就不再使用默认
 * server处理，而是用获取到的真正server块去处理。那为什么只有在ip:port有多个server监听的情况下才会将server_name
 * 做hash，而只有一个server监听的情况下不用呢?原因就是如果ip:port只有一个server监听，那么这个server就是default
 * server，那么就不用再去获取真正处理请求的server了，因为默认server就是真正的处理请求的server
 *     2. 因为在解析所有server的时候已经将监听的ip:port都收集起来了，所以接下来需要创建和ip:port对应起来的
 * 用于事件模块建链的监听对象，即ngx_listening_t对象。
 */
static ngx_int_t
ngx_http_optimize_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_array_t *ports)
{
    ngx_uint_t             p, a;
    ngx_http_conf_port_t  *port;
    ngx_http_conf_addr_t  *addr;

    if (ports == NULL) {
        return NGX_OK;
    }

    /* ports数组中存放的就是http配置块下所有server块监听的ip:port集合 */
    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        /* 将同一个port的所有addr进行排序，通过这个排序， 通配符的地址信息排到的最后*/
        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_http_conf_addr_t), ngx_http_cmp_conf_addrs);

        /*
         * check whether all name-based servers have the same
         * configuration as a default server for given address:port
         */

        /* 遍历同一个port下的所有监听的ip地址 */
        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {
			/* 有多个server监听同一个ip:port */
            if (addr[a].servers.nelts > 1
#if (NGX_PCRE)
                || addr[a].default_server->captures
#endif
               )
            {
                /* 将监听用一个ip:port的多个server块的名字进行hash处理，原因在函数开头已经有说明 */
                if (ngx_http_server_names(cf, cmcf, &addr[a]) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
        }

        /* 用解析server块中listen配置项得到的信息初始化cycle->listening中的监听对象 */
        if (ngx_http_init_listening(cf, &port[p]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* 将server配置块中的server_names做hash处理，构造hash表 */
static ngx_int_t
ngx_http_server_names(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_http_conf_addr_t *addr)
{
    ngx_int_t                   rc;
    ngx_uint_t                  n, s;
    ngx_hash_init_t             hash;
    ngx_hash_keys_arrays_t      ha;
    ngx_http_server_name_t     *name;
    ngx_http_core_srv_conf_t  **cscfp;
#if (NGX_PCRE)
    ngx_uint_t                  regex, i;

    regex = 0;
#endif

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;

    /* 遍历监听同一个ip:port的所有server块，将名字进行hash处理 */
    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {

#if (NGX_PCRE)
            if (name[n].regex) {
                regex++;
                continue;
            }
#endif

            /* 
             * 这里以server_name作为key， server配置块作为value进行hash，后续在解析到请求
             * 头中的host字段时，就会用这个host求hash后到hash表中去获取server配置块
             */
            rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NGX_HASH_WILDCARD_KEY);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid server name or wildcard \"%V\" on %s",
                              &name[n].name, addr->opt.addr);
                return NGX_ERROR;
            }

            if (rc == NGX_BUSY) {
                ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                              "conflicting server name \"%V\" on %s, ignored",
                              &name[n].name, addr->opt.addr);
            }
        }
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    /* 
     * 下面的三个if语句会分别对三种类型的server names进行hash初始化，并将结果设置到
     * 当前这个ip地址对象ports->addrs的hash、wc_head、wc_tail中
     */
    
    if (ha.keys.nelts) {
        hash.hash = &addr->hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

#if (NGX_PCRE)

    if (regex == 0) {
        return NGX_OK;
    }

    addr->nregex = regex;
    addr->regex = ngx_palloc(cf->pool, regex * sizeof(ngx_http_server_name_t));
    if (addr->regex == NULL) {
        return NGX_ERROR;
    }

    i = 0;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
            if (name[n].regex) {
                addr->regex[i++] = name[n];
            }
        }
    }

#endif

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_http_conf_addr_t  *first, *second;

    first = (ngx_http_conf_addr_t *) one;
    second = (ngx_http_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}


static int ngx_libc_cdecl
ngx_http_cmp_dns_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_dns_strcmp(first->key.data, second->key.data);
}

/* 用解析server块中listen配置项得到的信息初始化cycle->listening中的监听对象 */
/*
 * 关于创建cycle->listening中的监听对象，需要注意如下:
 *   1.如果某个端口上有任意数目ip的listen配置，即有通配符的情况，那么在该端口上只会创建一个监听对象ngx_listening_t
 * 不管是否还有其他ip在该端口上有listen配置，在后面创建监听对象时也只会创建一个，例如:server { listen 127.0.0.1:80;}
 * server {listen 80;}。而如果某个端口上面所有监听的ip地址没有通配符，那么一个ip:port就会创建一个监听对象，例如:
 * server {listen 192.168.0.1:80;} server {listen 192.168.1.1:80;}就会创建两个ngx_listening_t.
 */
static ngx_int_t
ngx_http_init_listening(ngx_conf_t *cf, ngx_http_conf_port_t *port)
{
    ngx_uint_t                 i, last, bind_wildcard;
    ngx_listening_t           *ls;
    ngx_http_port_t           *hport;
    ngx_http_conf_addr_t      *addr;

    addr = port->addrs.elts;
    last = port->addrs.nelts;

    /*
     * If there is a binding to an "*:port" then we need to bind() to
     * the "*:port" only and ignore other implicit bindings.  The bindings
     * have been already sorted: explicit bindings are on the start, then
     * implicit bindings go, and wildcard binding is in the end.
     */

    /* 判断监听这个port的地址中是否有通配符的情况 */
    if (addr[last - 1].opt.wildcard) {
        addr[last - 1].opt.bind = 1;
        bind_wildcard = 1;

    } else {
        bind_wildcard = 0;
    }

    i = 0;

    while (i < last) {

        if (bind_wildcard && !addr[i].opt.bind) {
            i++;
            continue;
        }

        /* 创建并初始化一个监听对象ngx_listening_t */
        ls = ngx_http_add_listening(cf, &addr[i]);
        if (ls == NULL) {
            return NGX_ERROR;
        }

        hport = ngx_pcalloc(cf->pool, sizeof(ngx_http_port_t));
        if (hport == NULL) {
            return NGX_ERROR;
        }

        /* 
         * ls->servers中记录的是监听这个ip:port的所有server的信息，因为开始处理用户请求之后就不会在使用
         * cmcf->ports->addrs中的信息，所以需要将其中记录的一些有用的信息存放到ls->servers中
         */
        ls->servers = hport;

        hport->naddrs = i + 1;

        switch (ls->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            if (ngx_http_add_addrs6(cf, hport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
#endif
        default: /* AF_INET */
            if (ngx_http_add_addrs(cf, hport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        }

        if (ngx_clone_listening(cf, ls) != NGX_OK) {
            return NGX_ERROR;
        }

        addr++;
        last--;
    }

    return NGX_OK;
}


static ngx_listening_t *
ngx_http_add_listening(ngx_conf_t *cf, ngx_http_conf_addr_t *addr)
{
    ngx_listening_t           *ls;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    /* 创建一个监听对象ngx_listening_t */
    ls = ngx_create_listening(cf, &addr->opt.u.sockaddr, addr->opt.socklen);
    if (ls == NULL) {
        return NULL;
    }

    ls->addr_ntop = 1;

    /* 新的tcp连接成功建立了后的处理方法 */
    ls->handler = ngx_http_init_connection;

    /* 获取监听这个ip:port的默认server */
    cscf = addr->default_server;
    ls->pool_size = cscf->connection_pool_size;
    ls->post_accept_timeout = cscf->client_header_timeout;

    clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    /*
     * 获取解析配置文件得到的日志对象，在ngx_configure_listening_sockets()函数中会
     * 将ls->logp中存放的日志对象赋值给ls->log。
     */
    ls->logp = clcf->error_log;
    
    /* 设置日志对象处理回调及相关参数 */
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

#if (NGX_WIN32)
    {
    ngx_iocp_conf_t  *iocpcf = NULL;

    if (ngx_get_conf(cf->cycle->conf_ctx, ngx_events_module)) {
        iocpcf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_iocp_module);
    }
    if (iocpcf && iocpcf->acceptex_read) {
        ls->post_accept_buffer_size = cscf->client_header_buffer_size;
    }
    }
#endif

    /* 下面开始将从listen配置指令中解析到的信息设置到监听对象中 */
    ls->backlog = addr->opt.backlog;
    ls->rcvbuf = addr->opt.rcvbuf;
    ls->sndbuf = addr->opt.sndbuf;

    ls->keepalive = addr->opt.so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    ls->keepidle = addr->opt.tcp_keepidle;
    ls->keepintvl = addr->opt.tcp_keepintvl;
    ls->keepcnt = addr->opt.tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    ls->accept_filter = addr->opt.accept_filter;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ls->deferred_accept = addr->opt.deferred_accept;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    ls->ipv6only = addr->opt.ipv6only;
#endif

#if (NGX_HAVE_SETFIB)
    ls->setfib = addr->opt.setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    ls->fastopen = addr->opt.fastopen;
#endif

#if (NGX_HAVE_REUSEPORT)
    ls->reuseport = addr->opt.reuseport;
#endif

    return ls;
}


static ngx_int_t
ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    ngx_http_in_addr_t        *addrs;
    struct sockaddr_in        *sin;
    ngx_http_virtual_names_t  *vn;

    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(ngx_http_in_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin = &addr[i].opt.u.sockaddr_in;

        /* addr.opt.u.sockaddr_in存放的便是监听这个port的某个ip地址的信息 */
        addrs[i].addr = sin->sin_addr.s_addr;
        /* 
         * 将监听这个ip:port的default server设置到ls->servers->addrs.conf.default_server中，
         * 因为在接收到用户发来数据开始处理请求但还未解析出请求头部的host字段之前，会用
         * ls->servers->addrs.conf.default_server来处理这个请求，即使这个请求的真正server并不是
         * 这个默认server，那什么获取真正的server呢?当解析到host后，就会用host字段值去获取真正的server，
         * 然后用真正的server处理这个请求
         */
        addrs[i].conf.default_server = addr[i].default_server;
#if (NGX_HTTP_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NGX_HTTP_V2)
        addrs[i].conf.http2 = addr[i].opt.http2;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NGX_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        /* 
         * 将在函数ngx_http_server_names()中构造的server name的hash表设置到ls->servers->addrs.conf.virtual_names中
         * 在接收到用户发来数据处理请求但还未解析出请求头部的host字段之前，会用
         * ls->servers->addrs.conf.default_server来处理这个请求，即使这个请求的真正server并不是
         * 这个默认server，那什么获取真正的server呢?当解析到host后，就会用host字段值做hash到这个hash表中
         * 去获取真正的server，然后用真正的server处理这个请求
         */
        addrs[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    ngx_http_in6_addr_t       *addrs6;
    struct sockaddr_in6       *sin6;
    ngx_http_virtual_names_t  *vn;

    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(ngx_http_in6_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin6 = &addr[i].opt.u.sockaddr_in6;
        addrs6[i].addr6 = sin6->sin6_addr;
        addrs6[i].conf.default_server = addr[i].default_server;
#if (NGX_HTTP_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NGX_HTTP_V2)
        addrs6[i].conf.http2 = addr[i].opt.http2;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NGX_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        addrs6[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NGX_OK;
}

#endif


char *
ngx_http_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_array_t     **types;
    ngx_str_t        *value, *default_type;
    ngx_uint_t        i, n, hash;
    ngx_hash_key_t   *type;

    types = (ngx_array_t **) (p + cmd->offset);

    if (*types == (void *) -1) {
        return NGX_CONF_OK;
    }

    default_type = cmd->post;

    if (*types == NULL) {
        *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
        if (*types == NULL) {
            return NGX_CONF_ERROR;
        }

        if (default_type) {
            type = ngx_array_push(*types);
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->key = *default_type;
            type->key_hash = ngx_hash_key(default_type->data,
                                          default_type->len);
            type->value = (void *) 4;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 1 && value[i].data[0] == '*') {
            *types = (void *) -1;
            return NGX_CONF_OK;
        }

        hash = ngx_hash_strlow(value[i].data, value[i].data, value[i].len);
        value[i].data[value[i].len] = '\0';

        type = (*types)->elts;
        for (n = 0; n < (*types)->nelts; n++) {

            if (ngx_strcmp(value[i].data, type[n].key.data) == 0) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate MIME type \"%V\"", &value[i]);
                goto next;
            }
        }

        type = ngx_array_push(*types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = (void *) 4;

    next:

        continue;
    }

    return NGX_CONF_OK;
}


char *
ngx_http_merge_types(ngx_conf_t *cf, ngx_array_t **keys, ngx_hash_t *types_hash,
    ngx_array_t **prev_keys, ngx_hash_t *prev_types_hash,
    ngx_str_t *default_types)
{
    ngx_hash_init_t  hash;

    if (*keys) {

        if (*keys == (void *) -1) {
            return NGX_CONF_OK;
        }

        hash.hash = types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, (*keys)->elts, (*keys)->nelts) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (prev_types_hash->buckets == NULL) {

        if (*prev_keys == NULL) {

            if (ngx_http_set_default_types(cf, prev_keys, default_types)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

        } else if (*prev_keys == (void *) -1) {
            *keys = *prev_keys;
            return NGX_CONF_OK;
        }

        hash.hash = prev_types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, (*prev_keys)->elts, (*prev_keys)->nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    *types_hash = *prev_types_hash;

    return NGX_CONF_OK;

}


ngx_int_t
ngx_http_set_default_types(ngx_conf_t *cf, ngx_array_t **types,
    ngx_str_t *default_type)
{
    ngx_hash_key_t  *type;

    *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
    if (*types == NULL) {
        return NGX_ERROR;
    }

    while (default_type->len) {

        type = ngx_array_push(*types);
        if (type == NULL) {
            return NGX_ERROR;
        }

        type->key = *default_type;
        type->key_hash = ngx_hash_key(default_type->data,
                                      default_type->len);
        type->value = (void *) 4;

        default_type++;
    }

    return NGX_OK;
}
