
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
 * 每一个c程序都有一个main函数，main函数的原型为int main(int argc, char *argv[])，其中argc表示的是命令行
 * 参数的个数，argv表示的是命令行参数的内容，其中argv[0]表示的是进程的名字。
 * Linux中有进程运行时的环境变量，其可通过全局变量访问: char **environ。
 * 一个很重要的信息是: 命令行参数argv和环境变量信息environ是在一块连续的内存中存放的，且环境变量信息environ
 * 紧跟在argv数组之后。
 */


#if (NGX_SETPROCTITLE_USES_ENV)

/*
 * To change the process title in Linux and Solaris we have to set argv[1]
 * to NULL and to copy the title to the same place where the argv[0] points to.
 * However, argv[0] may be too small to hold a new title.  Fortunately, Linux
 * and Solaris store argv[] and environ[] one after another.  So we should
 * ensure that is the continuous memory and then we allocate the new memory
 * for environ[] and copy it.  After this we could use the memory starting
 * from argv[0] for our process title.
 *
 * The Solaris's standard /bin/ps does not show the changed process title.
 * You have to use "/usr/ucb/ps -w" instead.  Besides, the UCB ps does not
 * show a new title if its length less than the origin command line length.
 * To avoid it we append to a new title the origin command line in the
 * parenthesis.
 */

/*environ存储为操作系统的环境变量*/
extern char **environ;

static char *ngx_os_argv_last;

/*初始化进程的名字*/
ngx_int_t
ngx_init_setproctitle(ngx_log_t *log)
{
    u_char      *p;
    size_t       size;
    ngx_uint_t   i;

    size = 0;

    /*
     * 下面的算法是为了解决修改进程名字时可能引起的内存覆盖。在Linux中，进程名字是保存在main函数的argv[0]中的，
     * 本来修改进程名字只需要修改argv[0]就可以了，但是如果新的进程名字长度比老的进程名字长的话，那么argv[1]的
     * 内容可能会被覆盖。
     */

    /*计算存储环境变量需要的内存长度，这里的加1操作是环境变量和环境变量之间需要空格*/
    for (i = 0; environ[i]; i++) {
        size += ngx_strlen(environ[i]) + 1;
    }

    p = ngx_alloc(size, log);
    if (p == NULL) {
        return NGX_ERROR;
    }

    /*ngx_os-argv_last始终指向下一个要处理的argv和environ参数*/
    
    ngx_os_argv_last = ngx_os_argv[0];

    for (i = 0; ngx_os_argv[i]; i++) {
        if (ngx_os_argv_last == ngx_os_argv[i]) {
            ngx_os_argv_last = ngx_os_argv[i] + ngx_strlen(ngx_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (ngx_os_argv_last == environ[i]) {

            size = ngx_strlen(environ[i]) + 1;
            ngx_os_argv_last = environ[i] + size;

            ngx_cpystrn(p, (u_char *) environ[i], size);
            /*
             * 这里之所以需要执行这一步是因为ngx_cpystrn()函数会该表environ[i]的指向,这也是为什么不直接将ngx_cpystrn()
             * 返回值赋给p而是在这一步之后手动加size修改p
             */
            environ[i] = (char *) p;
            p += size;
        }
    }

    /*执行完上面的循环后ngx_os_argv_last指向了一个无效的内存处，因此需要减1让其指向有效内存处*/
    ngx_os_argv_last--;

    return NGX_OK;
}

/*修改进程名字*/
void
ngx_setproctitle(char *title)
{
    u_char     *p;

#if (NGX_SOLARIS)

    ngx_int_t   i;
    size_t      size;

#endif

    ngx_os_argv[1] = NULL;

    /*ngx_os_argv[0]保存的是进程的名字，此处操作是覆盖原有的内容*/
    p = ngx_cpystrn((u_char *) ngx_os_argv[0], (u_char *) "nginx: ",
                    ngx_os_argv_last - ngx_os_argv[0]);

    /*将title指向的内容拷贝到ngx_os_argv[0]之后*/
    p = ngx_cpystrn(p, (u_char *) title, ngx_os_argv_last - (char *) p);

#if (NGX_SOLARIS)

    size = 0;

    for (i = 0; i < ngx_argc; i++) {
        size += ngx_strlen(ngx_argv[i]) + 1;
    }

    if (size > (size_t) ((char *) p - ngx_os_argv[0])) {

        /*
         * ngx_setproctitle() is too rare operation so we use
         * the non-optimized copies
         */

        p = ngx_cpystrn(p, (u_char *) " (", ngx_os_argv_last - (char *) p);

        for (i = 0; i < ngx_argc; i++) {
            p = ngx_cpystrn(p, (u_char *) ngx_argv[i],
                            ngx_os_argv_last - (char *) p);
            p = ngx_cpystrn(p, (u_char *) " ", ngx_os_argv_last - (char *) p);
        }

        if (*(p - 1) == ' ') {
            *(p - 1) = ')';
        }
    }

#endif

    /*将结尾处置为'\0'*/
    if (ngx_os_argv_last - (char *) p) {
        ngx_memset(p, NGX_SETPROCTITLE_PAD, ngx_os_argv_last - (char *) p);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "setproctitle: \"%s\"", ngx_os_argv[0]);
}

#endif /* NGX_SETPROCTITLE_USES_ENV */
