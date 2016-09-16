
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_pipe.h>


static ngx_int_t ngx_event_pipe_read_upstream(ngx_event_pipe_t *p);
static ngx_int_t ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p);

static ngx_int_t ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p);
static ngx_inline void ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf);
static ngx_int_t ngx_event_pipe_drain_chains(ngx_event_pipe_t *p);

/*
 *   提供缓存转发响应功能
 * 当do_write参数为0表示只读取上游服务器的响应，然后根据读取结果决定是否向客户端发送响应
 * 当do_write参数为1表示先发送响应到客户端，然后在接收上游服务器的响应
 */
ngx_int_t
ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write)
{
    ngx_int_t     rc;
    ngx_uint_t    flags;
    ngx_event_t  *rev, *wev;

    for ( ;; ) {
        if (do_write) {  // do_write标志位为1，表示需要向下游客户端发送响应
            p->log->action = "sending to client";

            /* 调用ngx_event_pipe_write_to_downstream()方法向下游发送响应 */
            rc = ngx_event_pipe_write_to_downstream(p);

            /* ngx_event_pipe_write_to_downstream()返回NGX_ABORT，表示请求处理失败，ngx_event_pipe结束 */
            if (rc == NGX_ABORT) {
                return NGX_ABORT;
            }

            /* ngx_event_pipe_write_to_downstream()方法返回NGX_BUSY，则表示暂时不执行读取上游响应的操作 */
            if (rc == NGX_BUSY) {
                return NGX_OK;
            }
        }

        /* 清空read和upstream_blocked标志位 */
        p->read = 0;
        p->upstream_blocked = 0;

        p->log->action = "reading upstream";

        /* 读取上游服务器的响应 */
        if (ngx_event_pipe_read_upstream(p) == NGX_ABORT) {
            return NGX_ABORT;
        }

        /* 如果read和upstream_blocked均为0，则跳出循环，否则将do_write置位，然后执行向下游发送响应的流程 */
        if (!p->read && !p->upstream_blocked) {
            break;
        }

        /* do_write置位，表示读取到了上游响应，需要继续向下游客户端发送响应 */
        do_write = 1;
    }

    /* p->upstream->fd != -1表示Nginx与上游服务器的socket有效 */
    if (p->upstream->fd != (ngx_socket_t) -1) {
        rev = p->upstream->read;

        flags = (rev->eof || rev->error) ? NGX_CLOSE_EVENT : 0;

        if (ngx_handle_read_event(rev, flags) != NGX_OK) {
            return NGX_ABORT;
        }

        /*
         * 如果读事件没有设置延迟处理的话，则需要将读事件加入定时器中，超时时间为read_timeout。
         * 如果读事件设置了延迟处理，那么这里就没有必要加入定时器(此时已在定时器中)，因为设置
         * 读事件需要延迟处理的时候已经将读事件加入到定时器了，此时超时时间是根据限速速率计算出来的。
         */
        if (!rev->delayed) {
            if (rev->active && !rev->ready) {
                ngx_add_timer(rev, p->read_timeout);

            } else if (rev->timer_set) {
                ngx_del_timer(rev);
            }
        }
    }

    /* 
     * p->downstream->fd != -1表示Nginx与下游客户端之间的连接有效，并且
     * p->downstream->data == p->output_ctx表明当前请求是有权利向下游客户端发送响应的，
     * 因此也必须及时向下游发送响应，否则后续的子请求就一直不能向下游转发响应
     */
    if (p->downstream->fd != (ngx_socket_t) -1
        && p->downstream->data == p->output_ctx)
    {
        wev = p->downstream->write;
        if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
            return NGX_ABORT;
        }

        /*
         * 如果写事件没有设置延迟处理的话，则需要将写事件加入到定时器中，超时时间为send_timeout。
         * 如果写事件设置了延迟处理，那么这里就没有必要将写事件加入定时器了(此时已在定时器中)，
         * 因为在设置写事件需要延迟处理的时候已经将写事件加入到定时器中，超时时间就是用限速速率计算出来的
         */
        if (!wev->delayed) {
            if (wev->active && !wev->ready) {
                ngx_add_timer(wev, p->send_timeout);

            } else if (wev->timer_set) {
                ngx_del_timer(wev);
            }
        }
    }

    return NGX_OK;
}

/*
 *     以上游网速优先转发响应时，此方法用于接收上游服务器的响应，该方法会将接收到额响应存放在
 * 内存或者磁盘文件中，同时用ngx_buf_t缓冲区指向这些响应，最后用out链表和in链表把这些缓冲区。
 * 管理起来。(ngx_buf_t对象既可以指向内存，也可以指向文件)
 *     此方法会遇到以下四种情况:
 * 1. 接收响应头部的时候接收到了部分的响应包体
 * 2. 如果没有达到bufs.num上限，那么可以分配bufs.size大小的内存块充当接收缓冲区
 * 3. 如果恰好Nginx与下游客户端连接可写，则应该优先发送响应给客户端清理出空闲缓冲区
 * 4. 如果缓冲区全部写满，则应该写入临时文件
 */
static ngx_int_t
ngx_event_pipe_read_upstream(ngx_event_pipe_t *p)
{
    off_t         limit;
    ssize_t       n, size;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_msec_t    delay;
    ngx_chain_t  *chain, *cl, *ln;

    /* 判断上游连接是否结束，下面三个任意一个为1都表示上游连接需要结束 */
    if (p->upstream_eof || p->upstream_error || p->upstream_done) {
        return NGX_OK;
    }

#if (NGX_THREADS)
    if (p->aio) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe read upstream: aio");
        return NGX_AGAIN;
    }
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe read upstream: %d", p->upstream->read->ready);

    for ( ;; ) {

        /* 判断上游连接是否结束，任意一个为1都表示上游连接需要结束 */
        if (p->upstream_eof || p->upstream_error || p->upstream_done) {
            break;
        }

        /*
         * 如果在接收响应包头的时候没有预接收到部分包体，并且Nginx与上游服务器连接的读事件
         * 也还没有就绪，这个时候需要跳出循环，
         */
        if (p->preread_bufs == NULL && !p->upstream->read->ready) {
            break;
        }

        /*
         * p->preread_bufs不为空，表明在接收响应头的时候接收到了部分包体，这个时候要对这部分包体
         * 先进行处理
         */
        if (p->preread_bufs) {

            /* use the pre-read bufs if they exist */

            /* chain指向p->preread_bufs，用于后续的处理用 */
            chain = p->preread_bufs;
            p->preread_bufs = NULL;  // 清空p->preread_bufs，保证p->preread_bufs只会被处理一次
            n = p->preread_size;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe preread: %z", n);

            if (n) {
                p->read = 1;  // read标志位置位，表示读取到了上游的响应包体
            }

        } else {

#if (NGX_HAVE_KQUEUE)

            /*
             * kqueue notifies about the end of file or a pending error.
             * This test allows not to allocate a buf on these conditions
             * and not to call c->recv_chain().
             */

            if (p->upstream->read->available == 0
                && p->upstream->read->pending_eof)
            {
                p->upstream->read->ready = 0;
                p->upstream->read->eof = 1;
                p->upstream_eof = 1;
                p->read = 1;

                if (p->upstream->read->kq_errno) {
                    p->upstream->read->error = 1;
                    p->upstream_error = 1;
                    p->upstream_eof = 0;

                    ngx_log_error(NGX_LOG_ERR, p->log,
                                  p->upstream->read->kq_errno,
                                  "kevent() reported that upstream "
                                  "closed connection");
                }

                break;
            }
#endif

            /* p->limit_rate不为0，表示需要设置限速功能 */
            if (p->limit_rate) {
                if (p->upstream->read->delayed) {  // delayed为1，表示需要延迟处理(限速的结果)，跳出循环
                    break;
                }

                /*
                 * 计算如果按照limit_rate速率发送响应，理论上发送的响应长度和实际发送的响应长度差值
                 * 如果差值小于0，表明已经超发了响应内容，需要进行限速了。
                 */
                limit = (off_t) p->limit_rate * (ngx_time() - p->start_sec + 1)
                        - p->read_length;

                /*
                 * limit <= 0表明已经超发了响应，需要限速，则将延迟处理标志位置位，并计算需要延迟处理的时长，
                 * 并以这个时长将读事件加入到定时器中
                 */
                if (limit <= 0) {
                    p->upstream->read->delayed = 1;
                    delay = (ngx_msec_t) (- limit * 1000 / p->limit_rate + 1);
                    ngx_add_timer(p->upstream->read, delay);
                    break;
                }

            } else {
                limit = 0;  // 如果没有设置限速功能，则不需要延迟处理
            }

            /*
             * 检查free_raw_bufs缓冲区链表是否为空，即判断这个缓冲区链表中是否有空间来存放此次调用
             * ngx_event_pipe_read_upstream接收到的上游响应，如果有，则继续使用剩余空间来存放响应。
             * 否则通过p->allocated < p->bufs.num判断是否可以继续从内存池中申请内存用于缓存响应，
             * 如果已经达到了内存缓冲区使用上限，则继续判断是否开启了临时文件缓存，如果没有则停止
             * 接收上游响应，等到发送响应给客户端清理出空闲缓冲区后继续接收，如果开启了临时文件
             * 缓存，则用临时文件存放响应
             */
            if (p->free_raw_bufs) {

                /* use the free bufs if they exist */
                /* 获取free_raw_bufs */
                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;  // 清空free_raw_bufs
                }

            } else if (p->allocated < p->bufs.num) {

                /* allocate a new buf if it's still allowed */
                /*
                 * 程序进入这个分支，说明free_raw_bufs中没有空闲缓冲区，且缓冲区使用没有达到内存上限，
                 * 此时会继续从内存中分配缓冲区用于接收响应
                 */
                b = ngx_create_temp_buf(p->pool, p->bufs.size);
                if (b == NULL) {
                    return NGX_ABORT;
                }

                p->allocated++;

                chain = ngx_alloc_chain_link(p->pool);
                if (chain == NULL) {
                    return NGX_ABORT;
                }

                chain->buf = b;
                chain->next = NULL;

            } else if (!p->cacheable
                       && p->downstream->data == p->output_ctx
                       && p->downstream->write->ready
                       && !p->downstream->write->delayed)
            {
                /*
                 * if the bufs are not needed to be saved in a cache and
                 * a downstream is ready then write the bufs to a downstream
                 */
                /*
                 * 进入这个分支说明需要暂时接收上游服务器的响应，会将upstream_blocked置位，表示先给
                 * 客户端发送响应以清理出空闲缓冲区用于接收上游响应
                 */
                
                p->upstream_blocked = 1;

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe downstream ready");

                break;

            } else if (p->cacheable  // 检查临时文件中已经写入的响应内容长度，如果达到文件上限，则暂时不接收响应
                       || p->temp_file->offset < p->max_temp_file_size)
            {

                /*
                 * if it is allowed, then save some bufs from p->in
                 * to a temporary file, and add them to a p->out chain
                 */

                /*
                 * 如果程序进入到这个分支，则会将p->in中的内容写入临时文件，再把写入临时文件的缓冲区由in
                 * 缓冲区链表中移出，添加到out缓冲区链表中
                 */
                rc = ngx_event_pipe_write_chain_to_temp_file(p);

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe temp offset: %O", p->temp_file->offset);

                if (rc == NGX_BUSY) {
                    break;
                }

                if (rc != NGX_OK) {
                    return rc;
                }

                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } else {

                /* there are no bufs to read in */

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "no pipe bufs to read in");

                break;
            }

            /* 调用recv_chain方法接收来自上游服务器的响应 */
            n = p->upstream->recv_chain(p->upstream, chain, limit);

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe recv chain: %z", n);

            /* 将接收到的内容挂在到p->free_raw_bufs缓冲区链表的首部 */
            if (p->free_raw_bufs) {
                chain->next = p->free_raw_bufs;
            }
            p->free_raw_bufs = chain;

            /* recv_chain返回NGX_ERROR，表示连接出错，返回 */
            if (n == NGX_ERROR) {
                p->upstream_error = 1;
                return NGX_ERROR;
            }

            /* recv_chain返回NGX_AGAIN表示没有接收到内容 */
            if (n == NGX_AGAIN) {
                if (p->single_buf) {
                    ngx_event_pipe_remove_shadow_links(chain->buf);
                }

                break;
            }

            p->read = 1;  // rread标志位置位，表示读取到上游服务器响应

            /* recv_chain返回0，表明响应接收已经接受完了，可以关闭Nginx与上游服务器的连接了 */
            if (n == 0) {
                p->upstream_eof = 1;
                break;
            }
        }

        delay = p->limit_rate ? (ngx_msec_t) n * 1000 / p->limit_rate : 0;

        p->read_length += n;  // 更新接收到的响应长度
        cl = chain;
        p->free_raw_bufs = NULL;

        /*遍历接收到响应的缓冲区链表chain，每次取出一个缓冲区进行判断处理*/
        while (cl && n > 0) {

            /*
             * 将这块缓冲区的shadow域去掉，因为刚刚接收到的缓冲区必然不存在多次引用的情况，
             * 所以shadow域要清空
             */
            ngx_event_pipe_remove_shadow_links(cl->buf);

            /* 计算当前遍历到的缓冲区中最多可以接收到的响应长度(缓冲区剩余可用空间) */
            size = cl->buf->end - cl->buf->last;

            /*
             * 如果此次接收到的总响应长度大于这块缓冲区中的长度，那么表明其余响应内容存到了
             * 后续缓冲区中，这块缓冲区已经满了
             */
            if (n >= size) {
                cl->buf->last = cl->buf->end;

                /* STUB */ cl->buf->num = p->num++;

                /* 
                 * 处理这个缓冲区中的响应包体，默认方法ngx_event_pipe_copy_input_filter
                 * 会将cl->buf挂载到p->in链表中
                 */
                if (p->input_filter(p, cl->buf) == NGX_ERROR) {
                    return NGX_ABORT;
                }

                n -= size;  // 更新此次接收到的未处理包体长度
                ln = cl;
                cl = cl->next;  // 获取下一次缓冲区
                ngx_free_chain(p->pool, ln);  // 归还这个缓冲区到内存池中

            } else {
                /* 程序进入这个分支，表明此次接收的所有响应都存放在一个缓冲区中，这个时候缓冲区内容
                 * 是没有调用input_filter方法处理的，在本函数的后面会进行处理
                 */
                cl->buf->last += n;  // 更新缓冲区last指针，用于下次接收包体的起始地址
                n = 0;  // 将n设置为0，跳出循环
            }
        }

        /*
         * 如果通过上面的循环处理，cl仍然不为空，表明仍有缓冲区可以用来后续接收响应包体之用(已有的响应
         * 内容未处理)，此时的cl指向的就是可用的缓冲区(链)，所以将这部分缓冲区(链)挂载到free_raw_bufs
         * 链表的头部用于下次接收响应包体
         */
        if (cl) {
            for (ln = cl; ln->next; ln = ln->next) { /* void */ }

            ln->next = p->free_raw_bufs;
            p->free_raw_bufs = cl;
        }

        /* 将读事件进行限速 */
        if (delay > 0) {
            p->upstream->read->delayed = 1;
            ngx_add_timer(p->upstream->read, delay);
            break;
        }
    }

#if (NGX_DEBUG)

    for (cl = p->busy; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf busy s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->out; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf out  s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->in; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf in   s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->free_raw_bufs; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf free s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe length: %O", p->length);

#endif

    if (p->free_raw_bufs && p->length != -1) {
        cl = p->free_raw_bufs;

        /*
         * 判断free_raw_bufs中的第一个缓冲区中仍存没有处理的包体是否大于剩余未接收的上游响应长度，
         * 如果是，则处理这部分包体，并释放这块缓冲区给内存池。为什么这里不循环处理free_raw_bufs中
         * 所有的缓冲区呢?因为通过上面的流程，可能最后一个没有满的缓冲区(已挂载到free_raw_bufs头部)
         * 中仍有部分包体没有处理，这个时候就调用input_filter方法进行处理。
         * 如果free_raw_bufs中第一个缓冲区可能存在的包体小于剩余未接收的包体长度，则暂时不处理包体，
         * 等到这块缓冲区满了才会处理这块缓冲区中的包体内容
         */
        if (cl->buf->last - cl->buf->pos >= p->length) {

            p->free_raw_bufs = cl->next;

            /* STUB */ cl->buf->num = p->num++;

            /* 调用input_filter进行处理 */
            if (p->input_filter(p, cl->buf) == NGX_ERROR) {
                return NGX_ABORT;
            }

            ngx_free_chain(p->pool, cl);
        }
    }

    /* 如果剩余未接收的响应包体长度为0，表明已经接收完了上游响应，将相关标志位置位 */
    if (p->length == 0) {
        p->upstream_done = 1;
        p->read = 1;
    }

    /*
     * 如果Nginx与上游服务器之间的连接已经关闭或者出错，而p->free_raw_bufs不为空，那么表明
     * p->free_raw_bufs中存放着响应包体，这部分响应包体之所以没有处理是因为响应包体所在的
     * 缓冲区并没有满，只有等到后续继续接收响应满了才会处理。那为什么这个地方又要处理呢?
     * 因为Nginx与上游服务器之间的连接已经关闭或者出错了，不能从上游服务器中继续读取响应了
     * 那么就需要把已接收但未处理的包体进行处理
     */
    if ((p->upstream_eof || p->upstream_error) && p->free_raw_bufs) {

        /* STUB */ p->free_raw_bufs->buf->num = p->num++;

        /* 处理包体(只处理可能剩余的最后一个未满的缓冲区) */
        if (p->input_filter(p, p->free_raw_bufs->buf) == NGX_ERROR) {
            return NGX_ABORT;
        }

        p->free_raw_bufs = p->free_raw_bufs->next;

        /*
         * 检查free_bufs标志位，如果free_bufs为1，则说明需要尽快释放缓冲区中用到的内存，这个时候调用
         * ngx_free方法释放shadow域为空的缓冲区
         */
        if (p->free_bufs && p->buf_to_file == NULL) {
            for (cl = p->free_raw_bufs; cl; cl = cl->next) {
                if (cl->buf->shadow == NULL) {
                    ngx_pfree(p->pool, cl->buf->start);
                }
            }
        }
    }

    if (p->cacheable && (p->in || p->buf_to_file)) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write chain");

        rc = ngx_event_pipe_write_chain_to_temp_file(p);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}

/*
 * 向下游客户端发送响应的方法，负责将ngx_event_pipe_t对象中的in和out链表中管理的缓冲区发送给客户端
 */
static ngx_int_t
ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p)
{
    u_char            *prev;
    size_t             bsize;
    ngx_int_t          rc;
    ngx_uint_t         flush, flushed, prev_last_shadow;
    ngx_chain_t       *out, **ll, *cl;
    ngx_connection_t  *downstream;

    /* 获取Nginx与下游客户端直接的连接 */
    downstream = p->downstream;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe write downstream: %d", downstream->write->ready);

#if (NGX_THREADS)

    if (p->writing) {
        rc = ngx_event_pipe_write_chain_to_temp_file(p);

        if (rc == NGX_ABORT) {
            return NGX_ABORT;
        }
    }

#endif

    flushed = 0;

    for ( ;; ) {
        if (p->downstream_error) {
            return ngx_event_pipe_drain_chains(p);
        }

        /*
         * 检查上游连接是否已经结束，如果upstream_eof、upstream_error、upstream_done
         * 任意一个为1，则表示不会再从上游接收到响应了。
         */
        if (p->upstream_eof || p->upstream_error || p->upstream_done) {

            /* pass the p->out and p->in chains to the output filter */

            /*
             * 将busy指向的缓冲区链表中的所有缓冲区的recycled清零，也就是将请求对象ngx_http_request_t
             * 结构体中的out成员中的缓冲区recycled清零
             */
            for (cl = p->busy; cl; cl = cl->next) {
                cl->buf->recycled = 0;
            }

            if (p->out) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush out");
                /* 将p->out中的所有缓冲区的recycled标志位清零 */
                for (cl = p->out; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }
                /*
                 * 将p->out中管理的存放在文件中的内容发送出去，此时会先发送请求对象r的out成员中缓存的未发送
                 * 完毕的内容，再发送p->out中管理的内容
                 */
                rc = p->output_filter(p->output_ctx, p->out);

                if (rc == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_event_pipe_drain_chains(p);
                }

                p->out = NULL;  // 清空，未一次性发送完的内容会挂载到请求对象r的out成员中
            }

            if (p->writing) {
                break;
            }

            /* 如果p->in中有响应内容，则发送给客户端 */
            if (p->in) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush in");

                for (cl = p->in; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                /*
                 * 将p->in中管理的存放在内存中的内容发送出去，此时会先发送请求对象r的out成员中缓存的未发送
                 * 完毕的内容，再发送p->in中管理的内容。
                 */
                rc = p->output_filter(p->output_ctx, p->in);

                if (rc == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_event_pipe_drain_chains(p);
                }

                p->in = NULL;   //清空，未一次性发送完的内容会挂载到请求对象r的out成员中
            }

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe write downstream done");

            /* TODO: free unused bufs */
            /* 将downstream_done标志位置位 */
            p->downstream_done = 1;
            break;
        }

        /* 程序执行到这里表明Nginx与上游服务器之间的连接是正常的，依旧有数据交互 */

        /*
         * downstream->data != p->output_ctx表明当前请求并没有权利往客户端发送响应，因为其他请求的优先级更高
         * 如果Nginx与下游连接写事件没有就绪或者需要延迟处理，这三种情况都不会下客户端发送响应
         */
        if (downstream->data != p->output_ctx
            || !downstream->write->ready
            || downstream->write->delayed)
        {
            break;
        }

        /* bsize is the size of the busy recycled bufs */

        prev = NULL;
        bsize = 0;

        /* 计算p->busy缓冲区链表中的待发送的响应长度 */
        for (cl = p->busy; cl; cl = cl->next) {

            if (cl->buf->recycled) {
                if (prev == cl->buf->start) {
                    continue;
                }

                bsize += cl->buf->end - cl->buf->start;
                prev = cl->buf->start;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write busy: %uz", bsize);

        out = NULL;

        /*
         * 如果p->busy中待发送的响应长度大于p->busy_size，则优先发送ngx_http_request_t的out成员存放的
         * 响应给给客户端，不再发送out和in中管理的内容
         */
        if (bsize >= (size_t) p->busy_size) {
            flush = 1;
            goto flush;
        }

        flush = 0;
        ll = NULL;
        prev_last_shadow = 1;

        for ( ;; ) {
            /*
             * 判断out缓冲区链表是否为空，如果有，则循环从out缓冲区链表中取出一个ngx_buf_t缓冲区，后面会
             * 挂载到本次会发送的out缓冲区链表中
             */
            if (p->out) {
                cl = p->out;

                if (cl->buf->recycled) {
                    ngx_log_error(NGX_LOG_ALERT, p->log, 0,
                                  "recycled buffer in pipe out chain");
                }

                p->out = p->out->next;

            } else if (!p->cacheable && !p->writing && p->in) {
                /* 
                 * 判断in链表是否为空，如果不为空，则循环从p->in缓冲区链表中取出一个ngx_buf_t缓冲区，
                 * 后面会挂载到本次会发送的out缓冲区链表中
                 */
                cl = p->in;

                ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write buf ls:%d %p %z",
                               cl->buf->last_shadow,
                               cl->buf->pos,
                               cl->buf->last - cl->buf->pos);

                if (cl->buf->recycled && prev_last_shadow) {
                    if (bsize + cl->buf->end - cl->buf->start > p->busy_size) {
                        flush = 1;
                        break;
                    }

                    bsize += cl->buf->end - cl->buf->start;
                }

                prev_last_shadow = cl->buf->last_shadow;

                p->in = p->in->next;

            } else {
                break;
            }

            cl->next = NULL;

            /* 将p->out和p->in中的缓冲区先后添加到out中，后续调用output_filter发送out中的内容 */
            if (out) {
                *ll = cl;
            } else {
                out = cl;
            }
            ll = &cl->next;
        }

    flush:

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write: out:%p, f:%ui", out, flush);

        if (out == NULL) {

            if (!flush) {
                break;
            }

            /* a workaround for AIO */
            if (flushed++ > 10) {
                return NGX_BUSY;
            }
        }
        /* 调用output_filter发送out中的内容 */
        rc = p->output_filter(p->output_ctx, out);

        /* 更新busy、free缓冲区链表 */
        ngx_chain_update_chains(p->pool, &p->free, &p->busy, &out, p->tag);

        if (rc == NGX_ERROR) {
            p->downstream_error = 1;
            return ngx_event_pipe_drain_chains(p);
        }

        for (cl = p->free; cl; cl = cl->next) {

            /* 检查p->free中的缓冲区是否指向的是文件中的内容，如果没有开启文件
             * 缓存功能(不同于用临时文件缓存包体)，则需要判断文件中的内容是否都发送出去了
             */
            if (cl->buf->temp_file) {
                if (p->cacheable || !p->cyclic_temp_file) {
                    continue;
                }

                /* reset p->temp_offset if all bufs had been sent */
                /*
                 * 如果临时文件中的内容都已经发送出去了，那么将文件内容清空，其实就是将偏移复位，后续
                 * 需要的话继续从头开始写
                 */
                if (cl->buf->file_last == p->temp_file->offset) {
                    p->temp_file->offset = 0;
                }
            }

            /* TODO: free buf if p->free_bufs && upstream done */

            /* add the free shadow raw buf to p->free_raw_bufs */

            if (cl->buf->last_shadow) {
                if (ngx_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
                    return NGX_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            /*
             * 将p->free中的缓冲区对象的shadow域清空，因为其中的内容已经发出去了，也就不存在所谓的多个
             * 缓冲区引用同一块内存的说法了，就可以继续用来接收上游服务器的响应内容了
             */
            cl->buf->shadow = NULL;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p)
{
    ssize_t       size, bsize, n;
    ngx_buf_t    *b;
    ngx_uint_t    prev_last_shadow;
    ngx_chain_t  *cl, *tl, *next, *out, **ll, **last_out, **last_free;

#if (NGX_THREADS)

    if (p->writing) {

        if (p->aio) {
            return NGX_AGAIN;
        }

        out = p->writing;
        p->writing = NULL;

        n = ngx_write_chain_to_temp_file(p->temp_file, NULL);

        if (n == NGX_ERROR) {
            return NGX_ABORT;
        }

        goto done;
    }

#endif

    if (p->buf_to_file) {
        out = ngx_alloc_chain_link(p->pool);
        if (out == NULL) {
            return NGX_ABORT;
        }

        out->buf = p->buf_to_file;
        out->next = p->in;

    } else {
        out = p->in;
    }

    if (!p->cacheable) {

        size = 0;
        cl = out;
        ll = NULL;
        prev_last_shadow = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe offset: %O", p->temp_file->offset);

        do {
            bsize = cl->buf->last - cl->buf->pos;

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe buf ls:%d %p, pos %p, size: %z",
                           cl->buf->last_shadow, cl->buf->start,
                           cl->buf->pos, bsize);

            if (prev_last_shadow
                && ((size + bsize > p->temp_file_write_size)
                    || (p->temp_file->offset + size + bsize
                        > p->max_temp_file_size)))
            {
                break;
            }

            prev_last_shadow = cl->buf->last_shadow;

            size += bsize;
            ll = &cl->next;
            cl = cl->next;

        } while (cl);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "size: %z", size);

        if (ll == NULL) {
            return NGX_BUSY;
        }

        if (cl) {
            p->in = cl;
            *ll = NULL;

        } else {
            p->in = NULL;
            p->last_in = &p->in;
        }

    } else {
        p->in = NULL;
        p->last_in = &p->in;
    }

#if (NGX_THREADS)
    p->temp_file->thread_write = p->thread_handler ? 1 : 0;
    p->temp_file->file.thread_task = p->thread_task;
    p->temp_file->file.thread_handler = p->thread_handler;
    p->temp_file->file.thread_ctx = p->thread_ctx;
#endif

    n = ngx_write_chain_to_temp_file(p->temp_file, out);

    if (n == NGX_ERROR) {
        return NGX_ABORT;
    }

#if (NGX_THREADS)

    if (n == NGX_AGAIN) {
        p->writing = out;
        p->thread_task = p->temp_file->file.thread_task;
        return NGX_AGAIN;
    }

done:

#endif

    if (p->buf_to_file) {
        p->temp_file->offset = p->buf_to_file->last - p->buf_to_file->pos;
        n -= p->buf_to_file->last - p->buf_to_file->pos;
        p->buf_to_file = NULL;
        out = out->next;
    }

    if (n > 0) {
        /* update previous buffer or add new buffer */

        if (p->out) {
            for (cl = p->out; cl->next; cl = cl->next) { /* void */ }

            b = cl->buf;

            if (b->file_last == p->temp_file->offset) {
                p->temp_file->offset += n;
                b->file_last = p->temp_file->offset;
                goto free;
            }

            last_out = &cl->next;

        } else {
            last_out = &p->out;
        }

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NGX_ABORT;
        }

        b = cl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->tag = p->tag;

        b->file = &p->temp_file->file;
        b->file_pos = p->temp_file->offset;
        p->temp_file->offset += n;
        b->file_last = p->temp_file->offset;

        b->in_file = 1;
        b->temp_file = 1;

        *last_out = cl;
    }

free:

    for (last_free = &p->free_raw_bufs;
         *last_free != NULL;
         last_free = &(*last_free)->next)
    {
        /* void */
    }

    for (cl = out; cl; cl = next) {
        next = cl->next;

        cl->next = p->free;
        p->free = cl;

        b = cl->buf;

        if (b->last_shadow) {

            tl = ngx_alloc_chain_link(p->pool);
            if (tl == NULL) {
                return NGX_ABORT;
            }

            tl->buf = b->shadow;
            tl->next = NULL;

            *last_free = tl;
            last_free = &tl->next;

            b->shadow->pos = b->shadow->start;
            b->shadow->last = b->shadow->start;

            ngx_event_pipe_remove_shadow_links(b->shadow);
        }
    }

    return NGX_OK;
}


/* the copy input filter */

ngx_int_t
ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    /* buf->pos == buf->last表明这块缓冲区的内容已经处理过了 */
    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    /* 从p->free缓冲区链表中获取一块空闲的缓冲区对象ngx_buf_t */
    cl = ngx_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;

    /* 把接收到响应的buf中的内容拷贝到cl->buf中 */
    ngx_memcpy(b, buf, sizeof(ngx_buf_t));
    b->shadow = buf;  // 将shadow域设置为接收到响应的buf
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;  // 将接收到响应的buf的shadow域设置为cl->buf，二者指向同一块内存

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;  // last_in表示刚接收到的响应缓冲区
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;  // 将刚接收到响应包体的缓冲区添加到in链表中

    if (p->length == -1) {
        return NGX_OK;
    }

    p->length -= b->last - b->pos;  // 更新剩余未接收的包体长度

    return NGX_OK;
}


static ngx_inline void
ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf)
{
    ngx_buf_t  *b, *next;

    b = buf->shadow;

    if (b == NULL) {
        return;
    }

    while (!b->last_shadow) {
        next = b->shadow;

        b->temporary = 0;
        b->recycled = 0;

        b->shadow = NULL;
        b = next;
    }

    b->temporary = 0;
    b->recycled = 0;
    b->last_shadow = 0;

    b->shadow = NULL;

    buf->shadow = NULL;
}


ngx_int_t
ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(p->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    if (p->buf_to_file && b->start == p->buf_to_file->start) {
        b->pos = p->buf_to_file->last;
        b->last = p->buf_to_file->last;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    b->shadow = NULL;

    cl->buf = b;

    if (p->free_raw_bufs == NULL) {
        p->free_raw_bufs = cl;
        cl->next = NULL;

        return NGX_OK;
    }

    if (p->free_raw_bufs->buf->pos == p->free_raw_bufs->buf->last) {

        /* add the free buf to the list start */

        cl->next = p->free_raw_bufs;
        p->free_raw_bufs = cl;

        return NGX_OK;
    }

    /* the first free buf is partially filled, thus add the free buf after it */

    cl->next = p->free_raw_bufs->next;
    p->free_raw_bufs->next = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_drain_chains(ngx_event_pipe_t *p)
{
    ngx_chain_t  *cl, *tl;

    for ( ;; ) {
        if (p->busy) {
            cl = p->busy;
            p->busy = NULL;

        } else if (p->out) {
            cl = p->out;
            p->out = NULL;

        } else if (p->in) {
            cl = p->in;
            p->in = NULL;

        } else {
            return NGX_OK;
        }

        while (cl) {
            if (cl->buf->last_shadow) {
                if (ngx_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
                    return NGX_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
            tl = cl->next;
            cl->next = p->free;
            p->free = cl;
            cl = tl;
        }
    }
}
