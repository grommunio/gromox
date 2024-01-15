#pragma once
#include <cstddef>
#include <gromox/defs.h>

/* double list is composed by the base unit DOUBLE_LIST_NODE */
struct DOUBLE_LIST_NODE {
    void*    pdata;    /* pointer for recording the actual data */
	DOUBLE_LIST_NODE *pnext, *pprev;
};

/* this struct actually represent the double list object */
struct DOUBLE_LIST {
    DOUBLE_LIST_NODE *phead;    /* indicate the first node of the double list*/
    size_t    nodes_num;           /* indicate the current number of nodes */
};

extern GX_EXPORT void double_list_init(DOUBLE_LIST *);
extern GX_EXPORT void double_list_free(DOUBLE_LIST *);
/* insert a node into the double list and treat it as list head */
extern GX_EXPORT void double_list_insert_as_head(DOUBLE_LIST *, DOUBLE_LIST_NODE *);
/* append a node into the double list and treat it as list tail */
extern GX_EXPORT void double_list_append_as_tail(DOUBLE_LIST *, DOUBLE_LIST_NODE *);
/* inset a node before pbase_node */
extern GX_EXPORT void double_list_insert_before(DOUBLE_LIST *,
    DOUBLE_LIST_NODE *pbase_node, DOUBLE_LIST_NODE *pnode);
/* append a node after pbsae_node */
extern GX_EXPORT void double_list_append_after(DOUBLE_LIST *, DOUBLE_LIST_NODE *after_this,
    DOUBLE_LIST_NODE *pnode);
/* remove the node from the list */
extern GX_EXPORT void double_list_remove(DOUBLE_LIST *, DOUBLE_LIST_NODE *);
/* get head node and remove it from list */
extern GX_EXPORT DOUBLE_LIST_NODE *double_list_pop_front(DOUBLE_LIST *);
/* merge the plist into plist_des */
extern GX_EXPORT void double_list_append_list(DOUBLE_LIST *dst, DOUBLE_LIST *src);

/* 
get the previous node of pbase_node, if the pbase_node is the head node, NULL 
is returned. 
*/
extern GX_EXPORT DOUBLE_LIST_NODE *double_list_get_before(DOUBLE_LIST *,
    DOUBLE_LIST_NODE *pbase_node);
extern GX_EXPORT const DOUBLE_LIST_NODE *double_list_get_before(const DOUBLE_LIST *, const DOUBLE_LIST_NODE *);

/*
get the next node of pbase_node, if the pbase_node is the tail node, NULL is
returned.
*/
extern GX_EXPORT DOUBLE_LIST_NODE *double_list_get_after(DOUBLE_LIST *,
    DOUBLE_LIST_NODE *pbase_node);
extern GX_EXPORT const DOUBLE_LIST_NODE *double_list_get_after(const DOUBLE_LIST *, const DOUBLE_LIST_NODE *);

/* get the actual number of nodes in the double list */
extern GX_EXPORT size_t double_list_get_nodes_num(const DOUBLE_LIST *);

/* get head node and does not remove it from list */
extern GX_EXPORT DOUBLE_LIST_NODE* double_list_get_head(DOUBLE_LIST *);
extern GX_EXPORT const DOUBLE_LIST_NODE *double_list_get_head(const DOUBLE_LIST *);

/* get tail node and does not remove it from list */
extern GX_EXPORT DOUBLE_LIST_NODE *double_list_get_tail(DOUBLE_LIST *);
extern GX_EXPORT const DOUBLE_LIST_NODE *double_list_get_tail(const DOUBLE_LIST *);
