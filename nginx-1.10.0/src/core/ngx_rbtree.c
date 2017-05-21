
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */


static ngx_inline void ngx_rbtree_left_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);
static ngx_inline void ngx_rbtree_right_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);


void
ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */

    /* 获取红黑树的根节点和哨兵节点 */
    root = (ngx_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    /* 
     * 如果根节点就是哨兵节点，说明此时这棵树是一颗空树，那么就将待插入的节点
     * 作为根节点，染成黑色，并将其左右子节点设置为哨兵节点，根节点没有父节点
     */
    if (*root == sentinel) {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        ngx_rbt_black(node);
        *root = node;

        return;
    }

    /* 
     * 调用注册的insert回调，将值插入到红黑树中，此时仅仅将红黑树当作一颗普通的
     * 二叉查找树
     */
    tree->insert(*root, node, sentinel);

    /* re-balance tree */
    /* 红黑树的重平衡 */

    /* 当前节点不是根节点，并且其父节点是红色的 */
    while (node != *root && ngx_rbt_is_red(node->parent)) {

        /* 1. 当前节点(红色)的父节点是其祖父节点的左子节点 */
        if (node->parent == node->parent->parent->left) {
            
            /* 获取当前节点的叔叔节点(祖父节点的右子节点) */
            temp = node->parent->parent->right;

            /*
             * 如果当前节点的叔叔节点是红色的，那么将父节点和叔叔节点都染成黑色，
             * 将祖父节点染成红色，并设置为当前节点，下一轮会对其进行相似处理
             */
            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                /* 程序如果进入这里，说明其叔叔节点是黑色的 */
                
                /* 
                 * 如果当前节点是其父节点的右子节点，那么将其父节点设置为当前节点，
                 * 并对当前节点进行左旋操作，执行完之后"原当前节点"就变成了父节点，
                 * 而"原父节点"就变成了"原当前节点"的子节点
                 */
                if (node == node->parent->right) {
                    node = node->parent;
                    ngx_rbtree_left_rotate(root, sentinel, node);
                }

                /* 将当前节点的父节点染成黑色，这样父节点和叔叔节点又都是黑色的了 */
                ngx_rbt_black(node->parent);

                /* 将祖父节点设置为红色，并对祖父节点进行右旋操作 */
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_right_rotate(root, sentinel, node->parent->parent);
            }

        } else {
            /*
             * 程序执行流进入到这里说明当前节点的父节点是其祖父节点的右子节点
             */

            /* 获取当前节点的叔叔节点 */
            temp = node->parent->parent->left;

            /* 
             * 如果当前节点的叔叔节点是红色的，那么就将其父节点和叔叔节点都
             * 染成黑色，将其祖父节点染成红色，并设置为当前节点，下一次循环
             * 便会对其进行相似的处理
             */
            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                /* 程序执行流进入到这里说明当前节点的叔叔节点是黑色的 */

                /* 
                 * 如果当前节点是其父节点的左子节点，那么将其父节点设置为当前节点，
                 * 并对其进行右旋操作
                 */
                if (node == node->parent->left) {
                    node = node->parent;
                    ngx_rbtree_right_rotate(root, sentinel, node);
                }

                /* 将当前节点的父节点染成黑色，这样父节点和叔叔节点就均为黑色了 */
                ngx_rbt_black(node->parent);

                /* 将当前节点的祖父节点染成红色，并将其进行左旋操作 */
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }

    /* 将根节点染成黑色 */
    ngx_rbt_black(*root);
}

/* insert回调，实现普通二叉查找树的插入操作 */
void
ngx_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;

    for ( ;; ) {

        p = (node->key < temp->key) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    /* 每一个新插入的节点，都会作为新树的叶子节点(非哨兵节点)，并会被染成红色 */
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


/* 
 * ngx_rbtree_insert_timer_value()顾名思义该函数是用来管理定时器事件时使用的insert
 * 回调函数，此时的node节点是某个事件对象的成员，具体可以参考ngx_event_t结构体
 */
void
ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((ngx_rbtree_key_int_t) (node->key - temp->key) < 0)
            ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    /* 每一个新插入的节点，都会作为新树的叶子节点(非哨兵节点)，并会被染成红色 */
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


void
ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    ngx_uint_t           red;
    ngx_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

    /* a binary tree delete */

    root = (ngx_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    if (node->left == sentinel) {
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
        temp = node->left;
        subst = node;

    } else {
        subst = ngx_rbtree_min(node->right, sentinel);

        if (subst->left != sentinel) {
            temp = subst->left;
        } else {
            temp = subst->right;
        }
    }

    if (subst == *root) {
        *root = temp;
        ngx_rbt_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }

    red = ngx_rbt_is_red(subst);

    if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }

    if (subst == node) {

        temp->parent = subst->parent;

    } else {

        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }

        subst->left = node->left;
        subst->right = node->right;
        subst->parent = node->parent;
        ngx_rbt_copy_color(subst, node);

        if (node == *root) {
            *root = subst;

        } else {
            if (node == node->parent->left) {
                node->parent->left = subst;
            } else {
                node->parent->right = subst;
            }
        }

        if (subst->left != sentinel) {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel) {
            subst->right->parent = subst;
        }
    }

    /* DEBUG stuff */
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key = 0;

    if (red) {
        return;
    }

    /* a delete fixup */

    while (temp != *root && ngx_rbt_is_black(temp)) {

        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                if (ngx_rbt_is_black(w->right)) {
                    ngx_rbt_black(w->left);
                    ngx_rbt_red(w);
                    ngx_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->right);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
            w = temp->parent->left;

            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                if (ngx_rbt_is_black(w->left)) {
                    ngx_rbt_black(w->right);
                    ngx_rbt_red(w);
                    ngx_rbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->left);
                ngx_rbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    ngx_rbt_black(temp);
}

/*
 * 左旋操作，其中node节点即为需要进行左旋的节点。
 * 以下图为例:
 *        x                      z
 *       / \         -->        /
 *      y   z                  x
 *                            /
 *                           y
 * 对x进行左旋操作，意味着需要将"x的右子节点"设置为"x的父节点"，即x自身变成了
 * 其右子节点的左子节点，因此左旋中的"左"意味着待左旋节点会变成其右子节点的
 * 左子节点
 */
static ngx_inline void
ngx_rbtree_left_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  *temp;

    /* 获取待左旋节点的右子节点 */
    temp = node->right;

    /* 将右子节点的左子节点(待左旋节点的孙子节点)设置给待左旋节点作为其右子节点 */
    node->right = temp->left;

    /* 
     * 如果右子节点的左子节点(待左旋节点的孙子节点)并不是哨兵节点，
     * 即存放了数据的节点，那么需要将该节点的父节点设置为待左旋节点，
     * 因为上面的赋值操作将该节点设置给了待左旋节点作为其右子节点
     */
    if (temp->left != sentinel) {
        temp->left->parent = node;
    }

    /* 
     * 因为待左旋节点的右子节点要取代自己的位置，所以将自己的父节点设置给
     * 右子节点作为其父节点
     */
    temp->parent = node->parent;

    /*
     * 1. 如果待左旋的节点等于根节点，那么就把待左旋节点的右子节点设置为根节点
     * 2. 如果待左旋的节点是其父节点的左子节点，那么就把待左旋节点的右子节点
     *    设置给其父节点作为其左子节点。
     * 3. 如果待左旋的节点是其父节点的右子节点，那么就把待左旋节点的右子节点
     *    设置给其父节点作为其右子节点
     */
    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->left) {
        node->parent->left = temp;

    } else {
        node->parent->right = temp;
    }

    /* 
     * 对于需要进行左旋操作的节点，是要将该节点设置给其右子节点作为其左子节点，
     * 其右子节点也就变成了该节点的父节点 
     */
    temp->left = node;
    node->parent = temp;
}

/* 
 * 右旋操作，其中node节点即为需要进行右旋的节点
 * 以下图为例:
 *         x                        y
 *        / \          -->           \
 *       y   z                        x
 *                                     \
 *                                      z
 * 对x进行右旋操作，意味着需要将"x的左子节点"设置为"x的父节点"，其自身也就变成了
 * 其左子节点的右子节点，因此右旋中的"右"意味着待右旋节点会变成其左子节点的
 * 右子节点
 */
static ngx_inline void
ngx_rbtree_right_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  *temp;

    /* 获取待右旋节点的左子节点 */
    temp = node->left;

    /* 将左子节点的右子节点(待右旋节点的孙子节点)设置给待右旋节点作为其左子节点 */
    node->left = temp->right;

    /* 
     * 如果左子节点的右子节点(待右旋节点的孙子节点)并不是哨兵节点，
     * 即存放了数据的节点，那么需要将该节点的父节点设置为待右旋节点，
     * 因为上面的赋值操作将该节点设置给了待右旋节点作为其左子节点
     */
    if (temp->right != sentinel) {
        temp->right->parent = node;
    }

    /* 
     * 因为待右旋节点的左子节点要取代自己的位置，所以将自己的父节点设置给左子
     * 节点作为其父节点
     */
    temp->parent = node->parent;

    /*
     * 1. 如果待右旋节点是根节点，那么将待右旋节点的左子节点设置为根节点
     * 2. 如果待右旋节点是其父节点的右子节点，那么就把待右旋节点的左子节点设置给
     *    其父节点作为其右子节点
     * 3. 如果待右旋节点是其父节点的左子节点，那么就把待右旋节点的左子节点设置给
     *    其父节点作为其左子节点
     */
    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->right) {
        node->parent->right = temp;

    } else {
        node->parent->left = temp;
    }

    /* 
     * 对于需要进行右旋的节点，是要将其设置给其左子节点作为右子节点，
     * 所以其左子节点也就变成了待右旋节点的父节点
     */
    temp->right = node;
    node->parent = temp;
}
