
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SLAB_PAGE_MASK   3
#define NGX_SLAB_PAGE        0
#define NGX_SLAB_BIG         1
#define NGX_SLAB_EXACT       2
#define NGX_SLAB_SMALL       3

#if (NGX_PTR_SIZE == 4)

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffff
#define NGX_SLAB_PAGE_START  0x80000000

#define NGX_SLAB_SHIFT_MASK  0x0000000f
#define NGX_SLAB_MAP_MASK    0xffff0000
#define NGX_SLAB_MAP_SHIFT   16

#define NGX_SLAB_BUSY        0xffffffff

#else /* (NGX_PTR_SIZE == 8) */

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NGX_SLAB_PAGE_START  0x8000000000000000

#define NGX_SLAB_SHIFT_MASK  0x000000000000000f
#define NGX_SLAB_MAP_MASK    0xffffffff00000000
#define NGX_SLAB_MAP_SHIFT   32

#define NGX_SLAB_BUSY        0xffffffffffffffff

#endif


#if (NGX_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)     ngx_memset(p, 0xA5, size)

#elif (NGX_HAVE_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)                                                \
    if (ngx_debug_malloc)          ngx_memset(p, 0xA5, size)

#else

#define ngx_slab_junk(p, size)

#endif

static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool,
    ngx_uint_t pages);
static void ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages);
static void ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level,
    char *text);

/*
 * 1. ngx_slab_max_size 表示一页的最大字节数,为ngx_slab_max_size = ngx_pagesize / 2
 * 2. ngx_slab_max_size 表示一页的基准字节数,为ngx_slab_max_size = 128 Bytes
 * 3. ngx_slab_exact_shift 表示一页基准字节数对应的位移,ngx_slab_exact_shift = 7
 * 4. ngx_slab_max_size = 128 来源就是一个指针长度刚好可以用位图来表示一页中的每个
 *    内存块是否已使用
 */
static ngx_uint_t  ngx_slab_max_size;
static ngx_uint_t  ngx_slab_exact_size;
static ngx_uint_t  ngx_slab_exact_shift;

/*
 * ngx_slab_init函数用来初始化slab内存池，主要包括以下内容:
 * 1. 为上面三个全局变量赋值
 * 2. 初始化slots数组、pages数组
 * 3. 给slab内存池管理结构ngx_slab_pool_t相关成员赋值
 */
void
ngx_slab_init(ngx_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    ngx_int_t         m;
    ngx_uint_t        i, n, pages;
    ngx_slab_page_t  *slots;

    /* STUB */
    /*
     * 1.ngx_slab_exact_size是一个基准值，其所对应的一页中的内存块数量刚好可以用
     *   uintptr_t指针变量的位来表示(8 * sizeof(uintptr_t)表示)uintptr_t含有的二进制位数，
     *   ngx_pagesize / (8 * sizeof(uintptr_t))即表示所对应的内存块(chunk)的长度
     * 2.在slab内存池中，常见就是内存块所对应的位移大小，通常用于计算内存块大小和
     *   定位这种大小的内存块对应的slot数组的元素
     */
    if (ngx_slab_max_size == 0) {
        ngx_slab_max_size = ngx_pagesize / 2;
        ngx_slab_exact_size = ngx_pagesize / (8 * sizeof(uintptr_t));
        for (n = ngx_slab_exact_size; n >>= 1; ngx_slab_exact_shift++) {
            /* void */
        }
    }
    /**/

    /*
     * min_size表示的是slab内存池中一页内的最小内存块(chunk)大小
     * 目前版本中min_shift = 3，即表示最小内存块大小为 2 ^ 3 = 8 Bytes
     */
    pool->min_size = 1 << pool->min_shift;

    /*从slab内存池偏移sizeof(ngx_slab_pool_t)大小，此时p指向的slots数组首地址*/
    p = (u_char *) pool + sizeof(ngx_slab_pool_t);
    size = pool->end - p;

    ngx_slab_junk(p, size);

    /*
     * 每种内存块大小在slots数组中都会有一个元素与之对应
     * ngx_pagesize_shift对应的是页的偏移，min_shift对应的是最小内存块的偏移
     * ngx_pagesize_shift - pool->min_shift 表示slab内存池中包含的内存块的种类
     */
    slots = (ngx_slab_page_t *) p;
    n = ngx_pagesize_shift - pool->min_shift;

    for (i = 0; i < n; i++) {
        slots[i].slab = 0;
        slots[i].next = &slots[i];  //初始化的时候，slots数组元素指向自身，表示空
        slots[i].prev = 0;
    }

    /*p在slots数组的基础上偏移n * sizeof(ngx_slab_page_t)，指向pages数组*/
    p += n * sizeof(ngx_slab_page_t);

    /*
     * 用于初步计算slab内存中含有的4k页的数量,由于后续每页的起始地址要求4k对齐，
     * 所以对齐后可能有部分内存空间会浪费，导致实际的页的数量比这里计算的少
     * 这里计算有个疑问，就是上面求的size大小不包含slots数组的长度会不会更准确些?
     * 即size = pool->end -p;语句放在这里是不是会更准确些(其实这里的计算的pages在
     * 后面地址对齐后会重新计算)
     */
    pages = (ngx_uint_t) (size / (ngx_pagesize + sizeof(ngx_slab_page_t)));

    ngx_memzero(p, pages * sizeof(ngx_slab_page_t));

    /*初始化slab内存池中pages数组的首地址*/
    pool->pages = (ngx_slab_page_t *) p;

    /*
     * free用于指向内存池中的空闲页组成的链表，初始情况下指向pages数组首地址，
     * 表示所有页都是空闲的，pool->free.next指向下次从内存池中分配页的地址
     */
    pool->free.prev = 0;
    pool->free.next = (ngx_slab_page_t *) p;

    /*
     * 初始情况下pool->pages，即第一个内存页中的slab表示的是整个缓存区剩余页的数目
     * pool->pages->next和pool->pages->prev都指向pool->free,用以链成双向链表
     */
    pool->pages->slab = pages;
    pool->pages->next = &pool->free;
    pool->pages->prev = (uintptr_t) &pool->free;

    /*
     * pool->start指向slab内存中用于实际分配给用户的内存的首地址，这里首地址是要保证
     * 4k对齐的，之所以要4k对齐，是方便后面pages数组和实际对应的用于分配的页可以通过
     * 偏移量进行关联，方便页和内存块的申请与释放
     */
    pool->start = (u_char *)
                  ngx_align_ptr((uintptr_t) p + pages * sizeof(ngx_slab_page_t),
                                 ngx_pagesize);

    /*
     * 在这里，用对齐之后的地址求出用于分配页的总大小，除以页大小ngx_pagesize
     * 结果就是slab内存中实际包含的页的数量
     */
    m = pages - (pool->end - pool->start) / ngx_pagesize;
    if (m > 0) {
        pages -= m;
        pool->pages->slab = pages;
    }

    /*
     * pool->last指向pages数组中末尾，即最后一页后的地址，其实pages数组是用来管理页的，
     * 他们是一一对应的，即每个页都有一个ngx_slab_page_t管理结构
     */
    pool->last = pool->pages + pages;

    pool->log_nomem = 1;
    pool->log_ctx = &pool->zero;
    pool->zero = '\0';
}

/*
 * 通常要用到slab内存池的都是跨进程间通信的场景，因此ngx_slab_alloc_locked和
 * ngx_slab_free_locked这对不加锁保护的内存分配和释放方法较少使用，除非模块中
 * 已经有其他同步锁可以使用
 */

/*共享内存，进程间需要用锁来保持同步，加锁的共享内存分配方法*/
void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    /*以阻塞方式获取锁*/
    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_alloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


/*不加锁的内存分配方法*/
void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, n, m, mask, *bitmap;
    ngx_uint_t        i, slot, shift, map;
    ngx_slab_page_t  *page, *prev, *slots;

    /*
     * 如果要分配的内存大于ngx_slab_max_size(ngx_pagesize/2),则说明需要申请的内存
     * 至少要为一个页才够用来分配size大小的内存块
     */
    if (size > ngx_slab_max_size) {

        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                       "slab alloc: %uz", size);

        /*
         * (size >> ngx_pagesize_shift)+ ((size % ngx_pagesize) ? 1 : 0)表示此次
         * 需要申请的页的数量，最后剩余不足一页的需要申请一个页
         */
        page = ngx_slab_alloc_pages(pool, (size >> ngx_pagesize_shift)
                                          + ((size % ngx_pagesize) ? 1 : 0));
        if (page) {
            /*
             * 1.首先获取新申请的页对应的page元素相对于pages数组首地址的偏移
             * 2.然后用偏移量加上pool->start，即指向了真正用于分配的数据页首地址
             */
            p = (page - pool->pages) << ngx_pagesize_shift;
            p += (uintptr_t) pool->start;

        } else {
            p = 0;
        }

        goto done;
    }

    /*
     * 1.如果申请的内存小于ngx_slab_max_size但是大于min_size，则计算需要申请的内存块(chunk)
     * 大小对应的偏移量，如申请size为54bytes，其实申请的内存块大小应该为64bytes，这里获取的是
     * 64bytes对应的偏移量shift,然后用shift-min_shift定位内存块对应的slot数组下标，指向对应
     * 内存块大小的半满页链表，然后从半满页链表中申请内存块
     * 2.如果申请的size小于内核支持的最小内存块大小，则按最小内存块进行内存申请
     */
    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        size = pool->min_size;
        shift = pool->min_shift;
        slot = 0;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);

    /*获取slot数组的首地址，结合上面获取到的此次待申请内存块对应的下标获取半满页链表*/
    slots = (ngx_slab_page_t *) ((u_char *) pool + sizeof(ngx_slab_pool_t));
    page = slots[slot].next;  //slots[slot].next指向下次分配内存的首个链表元素

    /*
     * page->next != page表明此前已经有申请过shift对应的内存块，并且仍有剩余的chunk
     * 可以用于分配(因为全满页会脱离链表)
     * 另外，在初始化过程中由于链表中暂时没有元素，slots[slot].next指向自身
     */
    if (page->next != page) {

        /*如果申请的内存小于128bytes，则进入该分支*/
        if (shift < ngx_slab_exact_shift) {

            do {
                /*
                 * 对于size < ngx_slab_exact_shift，由于一页中所能均分的内存块数量会大于
                 * uintptr_t类型的位数，因此需要用页中实际用于分配的内存块来存储用于
                 * 指示某块内存块是否使用的标志组合，即bitmap
                 * 需要注意的是，用于存放bitmap的内存块正是页中首地址开始分配的
                 * 对于nginx内核支持的分配的内存块大小，其用于存储bitmap所需的内存块数量计算如下:
                 * (1 << (ngx_pagesize_shift - shift)) / 8 / (1 << shift),不足一个按一个计算
                 */
                p = (page - pool->pages) << ngx_pagesize_shift;
                bitmap = (uintptr_t *) (pool->start + p);

                /*计算用于存储表示对应内存块是否使用的bitmap的数量*/
                map = (1 << (ngx_pagesize_shift - shift))
                          / (sizeof(uintptr_t) * 8);

                /*遍历bitmap，用于获取可用于分配的内存块*/
                for (n = 0; n < map; n++) {

                    /*bitmap[n] != NGX_SLAB_BUSY表示第n个bitmap有空闲内存块可用于分配*/
                    if (bitmap[n] != NGX_SLAB_BUSY) {

                        /*i初始用于表示申请到的内存块在bitmap中的位置*/
                        for (m = 1, i = 0; m; m <<= 1, i++) {

                            /*从右到左获取第一个可分配的内存块*/
                            if ((bitmap[n] & m)) {
                                continue;
                            }

                            /*将此次获取的内存块已使用标志位置1，表示已使用，下次不会分配此块*/
                            bitmap[n] |= m;

                            /*此时i表示的是此次申请到的内存块对所在页首地址的偏移量*/
                            i = ((n * sizeof(uintptr_t) * 8) << shift)
                                + (i << shift);

                            /*
                             * 这个分支用于判断所在页是否已经再无可分配内存块，
                             * 如果没有，说明该页已经从半满页变为了全满页，需要脱离
                             * 所在半满页链表
                             */
                            if (bitmap[n] == NGX_SLAB_BUSY) {
                                for (n = n + 1; n < map; n++) {
                                    if (bitmap[n] != NGX_SLAB_BUSY) {
                                        p = (uintptr_t) bitmap + i;

                                        goto done;
                                    }
                                }

                                /*
                                 * 程序如果执行到这里，说明该页已是全满页
                                 * ngx_slab_page_t中的prev除了用于指向链表中的上一个元素外，其
                                 * 最后两位用于指示所在页的内存块的种类
                                 */
                                prev = (ngx_slab_page_t *)
                                            (page->prev & ~NGX_SLAB_PAGE_MASK);
                                prev->next = page->next;
                                page->next->prev = page->prev;

                                /*
                                 * 全满页的prev指针不指向任何东西，仅用于存储指示其中内存块的种类的标志
                                 * next指针也不指向任何东西，置为NULL
                                 */
                                page->next = NULL;
                                page->prev = NGX_SLAB_SMALL; 
                            }

                            /*定位此次分配的内存块的地址*/
                            p = (uintptr_t) bitmap + i;

                            goto done;
                        }
                    }
                }

                page = page->next;

            } while (page);

        } else if (shift == ngx_slab_exact_shift) { //所需要申请的内存块大小为128bytes

            do {
                /*
                 * 对于大小为ngx_slab_exact_size的内存块，其页管理结构中的slab用于表示bitmap
                 * 即用于表示对应内存块是否已使用
                 */
                if (page->slab != NGX_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if ((page->slab & m)) {
                            continue;
                        }

                        page->slab |= m;  //对应bitmap位置位

                        /*判断对应的半满页是否退化成全满页，如果是，则脱离半满页链表*/
                        if (page->slab == NGX_SLAB_BUSY) {
                            prev = (ngx_slab_page_t *)
                                            (page->prev & ~NGX_SLAB_PAGE_MASK);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NGX_SLAB_EXACT;
                        }

                        /*利用page对pages数组的偏移获取申请的内存块所在页对于start的偏移*/
                        p = (page - pool->pages) << ngx_pagesize_shift;
                        p += i << shift; //获取申请的内存块对所在页的偏移量
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);

        } else { /* shift > ngx_slab_exact_shift */

            /*
             * 此时申请的内存块的大小介于(ngx_slab_exact_size,ngx_slab_max_slab)开区间
             * 因为内存大于128bytes，所以所需要用来指示内存块是否使用的位数小于32位，也就是说
             * 一个uintptr_t类型的变量足以用于表示bitmap，剩余的位数用来表示内存块大小，因此
             * ngx_slab_page_t页管理结构体中的slab高16位用来表示bitmap，低四位用来表示内存块
             * 大小对应的偏移，低四位可以表示的内存块大小偏移足以
             */
             
            /*
             * page->slab & NGX_SLAB_SHIFT_MASK即为内存块大小对应的偏移
             * 1 << (page->slab & NGX_SLAB_SHIFT_MASK)即为一页内存中对应偏移为shift的内存块
             * 数量，
             */ 
            n = ngx_pagesize_shift - (page->slab & NGX_SLAB_SHIFT_MASK);
            n = 1 << n;
            n = ((uintptr_t) 1 << n) - 1;   //获取内存块数量对应的掩码
            mask = n << NGX_SLAB_MAP_SHIFT; //因为高16位才是用来表示bitmap的，所以需要左移16位

            do {
                /*page->slab & NGX_SLAB_MAP_MASK获取内存块使用情况，如果值为不为mask，说明该页仍然是半满页*/
                if ((page->slab & NGX_SLAB_MAP_MASK) != mask) {

                    /*
                     * 该循环从bitmap的最低位开始判断对应的内存块是否使用
                     * page->slab & m为1表示对应内存块已经使用，继续往下遍历
                     * i表示的是所申请的内存块是所在页的第几块内存块
                     */
                    for (m = (uintptr_t) 1 << NGX_SLAB_MAP_SHIFT, i = 0;
                         m & mask;
                         m <<= 1, i++)
                    {
                        if ((page->slab & m)) {
                            continue;
                        }

                        /*找到第一块可用内存，bitmap位置1*/
                        page->slab |= m;

                        /*page->slab & NGX_SLAB_MAP_MASK) == mask表明该页已满，需要脱离半满页链表*/
                        if ((page->slab & NGX_SLAB_MAP_MASK) == mask) {
                            prev = (ngx_slab_page_t *)
                                            (page->prev & ~NGX_SLAB_PAGE_MASK); //prev最低两位用来表示内存块种类，在取指针的时候，需要屏蔽这两位
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            /*对于全满页，prev和next均不再指向任何东西，next置为NULL，prev置为内存块种类的值*/
                            page->next = NULL;
                            page->prev = NGX_SLAB_BIG;
                        }

                        /*
                         * 1.计算申请内存块所在页对应与页首的偏移量(实际用于分配的数据页的对应的偏移)
                         * 2.计算申请到的内存块对所在页的偏移量
                         * 3.计算申请到的内存块的绝对地址
                         */
                        p = (page - pool->pages) << ngx_pagesize_shift;
                        p += i << shift;
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);
        }
    }

    /*
     * 程序如果执行到这里表明size所对应的半满页链表中不存在可分配的内存的页
     * 可能之前对应于偏移为shift的半满页链表中有元素，由于全满页脱离导致链表变空 或者
     * 在这之前nginx内核就没有为偏移为shift大小的内存块分配过页，所以链表为空
     * 对于上面两种可能情况，都需要重新申请一块页，用来分配对应于偏移为shift的内存块
     */
    page = ngx_slab_alloc_pages(pool, 1);

    if (page) {

        /*shift偏移量小于基准偏移量(7)*/
        if (shift < ngx_slab_exact_shift) {
            p = (page - pool->pages) << ngx_pagesize_shift; //计算申请的页相对于页首的偏移量
            bitmap = (uintptr_t *) (pool->start + p);  //从上面分析我们知道，对于内存块大小小于基准内存块大小时，需要使用内存块来存储bitmap

            s = 1 << shift;  //内存块大小
            
            /* 
             * (1 << (ngx_pagesize_shift - shift)) / 8 计算的是bitmap所要占的字节数,
             * 再除以一个内存块大小，得到bitmap需要占用多少个内存块，不足一个按一个计算
             */
            n = (1 << (ngx_pagesize_shift - shift)) / 8 / s;  
            if (n == 0) {
                n = 1;
            }

            bitmap[0] = (2 << n) - 1; //将用于存储bitmap的内存块对应的bitmap位置为1，表示内存块已使用

            /*map值即表示有多少个bitmap， sizeof(uintptr_t) * 8表示一个bitmap所能指示的内存块数量*/
            map = (1 << (ngx_pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            for (i = 1; i < map; i++) {
                bitmap[i] = 0; //未使用内存块对应bitmap位初始化为0
            }

            /*shift < ngx_slab_exact_shift时，page->slab用于表示内存块大小*/
            page->slab = shift;
            /*插入到对应slots元素链表的首部，目前只有一个页，所以page->next指向链表头部 [头部和首部不一样]*/
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;

            slots[slot].next = page;

            /*
             * ((page - pool->pages) << ngx_pagesize_shift)表示该页对应的首页的偏移量
             * s * n表示的是内存块对于所在页的偏移量(此时就是可用于分配的第一个数据页，即紧接着用于存放bitmap的页之后的页)
             */
            p = ((page - pool->pages) << ngx_pagesize_shift) + s * n;
            p += (uintptr_t) pool->start;

            goto done;

        } else if (shift == ngx_slab_exact_shift) {

            /*
             * 申请内存块的偏移刚好为ngx_slab_exact_shift,此时slab表示的是bitmap
             */
            page->slab = 1;

            /*插入所在slots数组的半满页链表的首部*/
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;

            slots[slot].next = page;

            /*获取所申请的页对于页首的偏移量，然后获取申请页的绝对地址，也是第一次分配的内存块的地址*/
            p = (page - pool->pages) << ngx_pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;

        } else { /* shift > ngx_slab_exact_shift */

            /*
             * ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT)将用于表示bitmap的第一位置1，表示对应内存块以使用,
             * 再与shift按位取或，将表示内存块的大小的位移放到slab的低四位中
             */
            page->slab = ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT) | shift;

            /*插入对应的slots数组组成的半满页链表的首部*/
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;

            slots[slot].next = page;

            /* 
             * 计算并返回所申请的内存块的地址(首次申请即为页的首地址，
             * 如果是NGX_SLAB_SMALL则首次申请的时候内存块地址不等于页首地址,因为页首地址所在内存块存放的是bitmap)
             */
            p = (page - pool->pages) << ngx_pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;
        }
    }

    p = 0;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

    return (void *) p;
}

/*
 * ngx_slab_calloc这个函数相比ngx_slab_alloc多了个清零操作
 */
void *
ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_calloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}

/*ngx_slab_calloc_locked这个函数相比ngx_slab_alloc_locked多了个清零操作*/
void *
ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    p = ngx_slab_alloc_locked(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}

/*加锁的内存释放方法*/
void
ngx_slab_free(ngx_slab_pool_t *pool, void *p)
{
    ngx_shmtx_lock(&pool->mutex);

    ngx_slab_free_locked(pool, p);

    ngx_shmtx_unlock(&pool->mutex);
}


/*不加锁保护的内存释放方法*/
/*p指向的是待分配内存的首地址*/
void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    ngx_uint_t        n, type, slot, shift, map;
    ngx_slab_page_t  *slots, *page;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0, "slab free: %p", p);

    /*首先校验所要释放的内存是否在slab内存池中*/
    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
        goto fail;
    }

    /*
     * 1.首先计算待释放内存块首地址对应的pages数组中的元素,即获取对应的内存块管理结构
     * 2.获取page->slab，用于后面获取页中对应内存块的一些信息，详细见后面
     * 3.用于获取该页对应存放的内存块的类型(BIG,EXACT,SMALL,PAGE)
     */
    n = ((u_char *) p - pool->start) >> ngx_pagesize_shift; //计算偏移量
    page = &pool->pages[n];
    slab = page->slab;
    type = page->prev & NGX_SLAB_PAGE_MASK; 

    switch (type) {

    case NGX_SLAB_SMALL:

        /*
         * 1.对于NGX_SLAB_SMALL,其bitmap存放在开始处的内存块chunk中，而其对应的内存块
         *   大小的偏移量则是放在slab的的后四位
         * 2.计算内存块的大小
         */
        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = 1 << shift;

        /*
         * 因为所有实际分配页的页首地址是4k对齐的，而且每个页大小是4k，所以每个页的页地址都是4k对齐的
         * 因为所有可分配的内存块只有8bytes,16bytes,32bytes,...,2048bytes,所以每个内存块的地址对于该内存
         * 块大小来说都是对齐的
         */
        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        /*
         * 1. p & (ngx_pagesize - 1)获取的是该待释放内存块(chunk)相对于所在页的首地址的
         *   偏移量(取后15位),再右移shift位，则计算出来的是待释放内存块在该页中是第几个内存块
         * 2. n & (sizeof(uintptr_t) * 8 - 1)取余数，计算的是该内存块在bitmap中所处的位置，
             然后将该内存块所处的bitmap的对应的位置1， 例如n=37,则 37&31=5,1<<5将bitmap对应位置1
         * 3.n /= (sizeof(uintptr_t) * 8)计算的是该内存块在那个bitmap中
         * 4. (uintptr_t) p & ~((uintptr_t) ngx_pagesize - 1)计算的是该内存块所在页的首地址，
             也就是bitmap的首地址
         */
        n = ((uintptr_t) p & (ngx_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n & (sizeof(uintptr_t) * 8 - 1));
        n /= (sizeof(uintptr_t) * 8);
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) ngx_pagesize - 1));

        /*再次判断bitmap对应位是否为1*/
        if (bitmap[n] & m) {

            /*
             * page->next == NULL表明此页当前是全满页，由于释放了一个内存块，退化为半满页，
             * 需要加入对应的半满页链表中
             */
            if (page->next == NULL) {
                /*获取该页对应的半满页链表*/
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = shift - pool->min_shift;

                /*
                 * 将该页加入到对应内存块大小的半满页链表的首部,
                 * slots[slot].next获取原半满页链表首部
                 */
                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NGX_SLAB_SMALL;
            }

            /*将该内存块对应的bitmap位清零*/
            bitmap[n] &= ~m;

            /*
             * 计算的是所有用于存放指示内存块是否使用的bitmap占用了几个内存块，不足一个则为一个
             * 1 << (ngx_pagesize_shift - shift)计算的是一页中内存块的数量，除以8，
             * 表示需要的sizeof(uintptr_t)的总字节数，再除以内存块大小，则是需要几个内存块用来存放所有bitmap
             */
            n = (1 << (ngx_pagesize_shift - shift)) / 8 / (1 << shift);

            if (n == 0) {
                n = 1;
            }

            /*
             * 下面的流程主要用于判断该页中的所有内存块是否都没有使用，如果是则加入到free链表中
             * 因为可用于分配的前n个内存块用于存放bitmap，所以((uintptr_t) 1 << n) - 1)计算的是
             * 存放bitmap的内存块在第一个bitmap中的对应位置1的情况
             * bitmap[0] & ~(((uintptr_t) 1 << n) - 1)为1，表明有内存块还在使用着没有释放
             */
            if (bitmap[0] & ~(((uintptr_t) 1 << n) - 1)) {
                goto done;
            }

            /*计算的是这样的内存块在一页中需要使用多少个bitmap才能够表示使用情况*/
            map = (1 << (ngx_pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            /*判断其余bitmap是否有内存块在使用*/
            for (n = 1; n < map; n++) {
                if (bitmap[n]) {
                    goto done;
                }
            }

            /*
             * 如果程序执行到这里表明这个页中所有可用于分配的内存块都没有使用(除用于存放bitmap的那个内存块)，
             * 则需要将该页加入到free链表(空闲链表)
             */
            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_EXACT:

        /*
         * 对于NGX_SLAB_EXACT，p & (ngx_pagesize - 1)获取的是待释放内存块相对于所在页的偏移量,
         * 再右移ngx_slab_exact_shift，则计算的是此块内存在所在页中的第几块内存块，也即在bitmap
         * 中的位置
         */
        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (ngx_pagesize - 1)) >> ngx_slab_exact_shift);
        size = ngx_slab_exact_size;

        /*内存块首地址对于该内存块大小而言是地址对齐的*/
        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        /*如果所在块在使用*/
        if (slab & m) {
            /*slab == NGX_SLAB_BUSY表明之前该页是全满页，现在释放了其中一块，说明需要加入半满页链表中*/
            if (slab == NGX_SLAB_BUSY) {
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = ngx_slab_exact_shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NGX_SLAB_EXACT;
            }

            /*对应bitmap位清零*/
            page->slab &= ~m;

            /*该页中还有其他内存块已分配*/
            if (page->slab) {
                goto done;
            }

            /*程序执行到这里表明该页已经退化为空闲页，需要加入到free链表中*/
            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_BIG:

        /*对于NGX_SLAB_BIG类型的内存块，其页管理结构中的slab的低四位用于表示对应内存块大小的位移*/
        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = 1 << shift;

        /*待释放内存首地址对于该内存块大小来说是对齐的*/
        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        /*
         * 我们知道，对于NGX_SLAB_BIG类型的页，其slab成员的高16位用于表示bitmap(有些不足16位的，
         * 就从低到高选择相应位作为bitmap),这一步计算出来m就是待释放内存块的在bitmap中的相应位
         * 其计算分解如下:
         *   1.p & (ngx_pagesize - 1)计算待释放内存块相对于所在页页首的偏移量，右移shift得该内存块在
         *     在该页中是第几个内存块，即在bitmap中对应的位的偏移量，在此基础上加NGX_SLAB_MAP_SHIFT，
         *     得到的就是在高16位中的偏移量，也就是真正bitmap中的偏移量
         */
        m = (uintptr_t) 1 << ((((uintptr_t) p & (ngx_pagesize - 1)) >> shift)
                              + NGX_SLAB_MAP_SHIFT);

        /*如果对应内存块目前确实已分配*/
        if (slab & m) {

            /*page->next == NULL表明该页之前是一个全满页，现在释放一块后需要加入到半满页中*/
            if (page->next == NULL) {
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NGX_SLAB_BIG;
            }

            /*对应bitmap位清零*/
            page->slab &= ~m;

            /*高16位表示的bitmap中仍有内存块已分配出去，不是空闲页*/
            if (page->slab & NGX_SLAB_MAP_MASK) {
                goto done;
            }

            /*程序执行到这里表明该页已经是空闲页了，需要加入到free链表中*/
            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_PAGE:
        
        /*判断地址对齐，页地址对页大小也是对齐的*/
        if ((uintptr_t) p & (ngx_pagesize - 1)) {
            goto wrong_chunk;
        }

        /*slab==NGX_SLAB_PAGE_FREE表明待释放的页其实已经释放过了*/
        if (slab == NGX_SLAB_PAGE_FREE) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): page is already free");
            goto fail;
        }

        /*
         * slab == NGX_SLAB_PAGE_BUSY,表明待释放的页并不是多个连续页的首页，不能直接释放，
         * 不许这几个page一起释放，因此p指针指向必须是首page，返回失败
         */
        if (slab == NGX_SLAB_PAGE_BUSY) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): pointer to wrong page");
            goto fail;
        }

        /*在这里n计算的是该待释放的页对于所有页的偏移量，即在pages数组中的下标*/
        n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
        size = slab & ~NGX_SLAB_PAGE_START;  //对于整个分配的页来说，其slab表示的是后面所跟的连续页的数量，包括自己

        ngx_slab_free_pages(pool, &pool->pages[n], size);

        ngx_slab_junk(p, size << ngx_pagesize_shift);

        return;
    }

    /* not reached */

    return;

done:

    ngx_slab_junk(p, size);

    return;

wrong_chunk:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): chunk is already free");

fail:

    return;
}


static ngx_slab_page_t *
ngx_slab_alloc_pages(ngx_slab_pool_t *pool, ngx_uint_t pages)
{
    ngx_slab_page_t  *page, *p;

    /*申请一页内存，需要从空闲页链表中申请而不是半满页链表*/
    /*如果page == &pool->free则说明已经没有空闲页可用于分配了*/
    for (page = pool->free.next; page != &pool->free; page = page->next) {

        /*page->slab表明后面有连续可用的页的数量，而不是用链表连接的*/
        if (page->slab >= pages) {

            /*连续可用的页的数量大于此次申请的页的数量*/
            if (page->slab > pages) {

                /*将剩余连续可用的页的最后一个页的prev指针指向剩余可用页首页地址*/
                page[page->slab - 1].prev = (uintptr_t) &page[pages];

                /*
                 * 1.计算剩下连续可用的页的数量
                 * 2.将剩余可用的页组成的块加入到free链表中
                 * 3.连续可用的页之间并不是通过链表结合在一起的
                 */
                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                /*将剩余可用连续页加入到free链表中*/
                p = (ngx_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {   /*连续可用页的数量刚好可以用于此次分配，将其脱离free链表*/
                p = (ngx_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            /*
             * 1.连续多个可用页的首页的slab除了需要存储页的数量外，还需要表明这个多个连续可用页的首页
             * 2.page页面不划分内存块(chunk)时候,即将整个页面分配给用户,pre的后两位为NGX_SLAB_PAGE
             * 3.连续多个可用页之间不是通过链表结合在一起的，因此需要next和prev为NULL，但由于prev指针还有
             *    另外一个作用，所以在这里需要将其置为NGX_SLAB_PAGE，将整个页面分配给用户
             */
            page->slab = pages | NGX_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = NGX_SLAB_PAGE;

            /*如果申请的页数是一个，则在此直接返回所申请的页的地址*/
            if (--pages == 0) {
                return page;
            }

            /*
             * 1.如果申请的页的数量超过一个，则除了首页之外，其余的页的slab需要置为NGX_SLAB_PAGE_BUSY,
             *   表明这个多个连续可用页的后续页
             * 2.连续多个可用页之间不是通过链表结合在一起的，因此需要next和prev为NULL，但由于prev指针还有
                 另外一个作用，所以在这里需要将其置为NGX_SLAB_PAGE，将整个页面分配给用户
             */
            for (p = page + 1; pages; pages--) {
                p->slab = NGX_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = NGX_SLAB_PAGE;
                p++;
            }

            return page;
        }
    }

    if (pool->log_nomem) {
        ngx_slab_error(pool, NGX_LOG_CRIT,
                       "ngx_slab_alloc() failed: no memory");
    }

    return NULL;
}

/*这个函数用于释放页面，加入到free链表中*/
static void
ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages)
{
    ngx_uint_t        type;
    ngx_slab_page_t  *prev, *join;

    /*计算待释放页后续有多少个连续的页，因为page->slab还包含了用于表示多个连续页的首页的标志，所以这里重新赋值*/ 
    /*这里pages--的目的是将计算后续连续也的数量，用于下面的清零操作*/
    page->slab = pages--;

    /*如果待释放的页是包含多个连续页的(pages > 1)*/
    if (pages) {
        /*将除首页外的所有后续连续页中的数据都清零，因为关于这些连续页的管理信息都在首页管理结构中可以获知*/
        ngx_memzero(&page[1], pages * sizeof(ngx_slab_page_t));
    }

    /*
     *将其脱离原来的半满页链表，因为待释放的这个页或者多个页之前可能用于存放的内存块类型有以下几种:
     *       #define NGX_SLAB_PAGE        0
     *       #define NGX_SLAB_BIG         1
     *       #define NGX_SLAB_EXACT       2
     *       #define NGX_SLAB_SMALL       3
     * 所以要用掩码获取prev指针真正指向的地址
     */
    if (page->next) {
        prev = (ngx_slab_page_t *) (page->prev & ~NGX_SLAB_PAGE_MASK);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    /*join指向的是待释放页(或多个页)的下一个页地址*/
    join = page + page->slab;

    /*如果这个页还在slab内存中可分配的所有页中，即至少指向的最后一个页*/
    if (join < pool->last) {
        //获取该页的内存块类型
        type = join->prev & NGX_SLAB_PAGE_MASK;

        //如果类型为NGX_SLAB_PAGE,表明该页尚未用于分配对应于具体大小的内存块，即该页未使用
        if (type == NGX_SLAB_PAGE) {

            //join->next != NULL表明该页已经在空闲链表中，则将其加入到待释放页(群)中，组成有更多连续页的大页群
            if (join->next != NULL) {
                pages += join->slab;
                page->slab += join->slab;

                prev = (ngx_slab_page_t *) (join->prev & ~NGX_SLAB_PAGE_MASK);
                prev->next = join->next;
                join->next->prev = join->prev;

                join->slab = NGX_SLAB_PAGE_FREE;
                join->next = NULL;
                join->prev = NGX_SLAB_PAGE;
            }
        }
    }

    /*如果该页不是所有页的首个页，即不是pages数组的首元素*/
    if (page > pool->pages) {
        /*获取该页的前一个页，上面的判断可以保证join不会越界*/
        join = page - 1;
        type = join->prev & NGX_SLAB_PAGE_MASK;  //获取该页的内存块类型

        //如果类型为NGX_SLAB_PAGE,表明该页尚未用于分配对应于具体大小的内存块，即该页未使用
        if (type == NGX_SLAB_PAGE) {

            /*slab==NGX_SLAB_PAGE_FREE表明待释放的页其实已经释放过了*/
            if (join->slab == NGX_SLAB_PAGE_FREE) {
                join = (ngx_slab_page_t *) (join->prev & ~NGX_SLAB_PAGE_MASK);
            }

            //join->next != NULL表明该页已经在空闲链表中，则将其加入到待释放页(群)中，组成有更多连续页的大页群
            if (join->next != NULL) {
                pages += join->slab;
                join->slab += page->slab;

                prev = (ngx_slab_page_t *) (join->prev & ~NGX_SLAB_PAGE_MASK);
                prev->next = join->next;
                join->next->prev = join->prev;

                page->slab = NGX_SLAB_PAGE_FREE;
                page->next = NULL;
                page->prev = NGX_SLAB_PAGE;

                page = join;
            }
        }
    }

    
    if (pages) {
        //page[pages]就是连续页的最后一个页，其prev指向连续页的首页
        page[pages].prev = (uintptr_t) page;
    }

    /*将释放的页(群)加入到加入到空闲链表中*/
    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
}


static void
ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level, char *text)
{
    ngx_log_error(level, ngx_cycle->log, 0, "%s%s", text, pool->log_ctx);
}
