
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RBTREE_H_INCLUDED_
#define _NGX_RBTREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_uint_t  ngx_rbtree_key_t;
typedef ngx_int_t   ngx_rbtree_key_int_t;


typedef struct ngx_rbtree_node_s  ngx_rbtree_node_t;

/* 红黑树节点对象类型 */
struct ngx_rbtree_node_s {
    ngx_rbtree_key_t       key;  /* 节点key值，用于在插入节点时排序之用 */
    ngx_rbtree_node_t     *left;  /* 节点的左子节点 */
    ngx_rbtree_node_t     *right;  /* 节点的右子节点 */
    ngx_rbtree_node_t     *parent;  /* 节点的父节点 */
    u_char                 color;  /* 节点颜色 */
    u_char                 data;  /* 节点包含的用户数据 */
};


typedef struct ngx_rbtree_s  ngx_rbtree_t;

/* 红黑树插入操作回调函数 */
typedef void (*ngx_rbtree_insert_pt) (ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

struct ngx_rbtree_s {
    ngx_rbtree_node_t     *root;  /* 红黑树根节点 */
    ngx_rbtree_node_t     *sentinel;  /* 红黑树哨兵节点 */
    ngx_rbtree_insert_pt   insert;  /* 插入操作回调函数 */
};

/* 初始化红黑树，也就是设置根节点、哨兵节点和注册插入操作回调函数 */
#define ngx_rbtree_init(tree, s, i)                                           \
    ngx_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i


void ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
void ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
void ngx_rbtree_insert_value(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
void ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);


#define ngx_rbt_red(node)               ((node)->color = 1)
#define ngx_rbt_black(node)             ((node)->color = 0)
#define ngx_rbt_is_red(node)            ((node)->color)
#define ngx_rbt_is_black(node)          (!ngx_rbt_is_red(node))
#define ngx_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */
/* 哨兵节点的颜色一定是黑色 */
#define ngx_rbtree_sentinel_init(node)  ngx_rbt_black(node)


/* 红黑树中最小的节点就是位置最靠左的叶子节点(哨兵节点的父节点) */
static ngx_inline ngx_rbtree_node_t *
ngx_rbtree_min(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    /* 循环访问节点的左子节点，直到某个节点的左子节点是哨兵节点，则返回该节点 */
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _NGX_RBTREE_H_INCLUDED_ */
