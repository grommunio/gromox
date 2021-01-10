#pragma once
#ifdef __cplusplus
#	include <cstddef>
#else
#	include <stddef.h>
#endif

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

#ifdef __cplusplus
extern "C" {
#endif

void double_list_init(DOUBLE_LIST* plist);

void double_list_free(DOUBLE_LIST* plist);

/* insert a node into the double list and treat it as list head */
void double_list_insert_as_head(DOUBLE_LIST *plist, DOUBLE_LIST_NODE *pnode);

/* append a node into the double list and treat it as list tail */
void double_list_append_as_tail(DOUBLE_LIST *plist, DOUBLE_LIST_NODE *pnode);

/* inset a node before pbase_node */
void double_list_insert_before(DOUBLE_LIST *plist, 
    DOUBLE_LIST_NODE *pbase_node, DOUBLE_LIST_NODE *pnode);

/* append a node after pbsae_node */
void double_list_append_after(DOUBLE_LIST *plist, DOUBLE_LIST_NODE *pbase_node,
    DOUBLE_LIST_NODE *pnode);

/* remove the node from the list */
void double_list_remove(DOUBLE_LIST *plist, DOUBLE_LIST_NODE *pnode);

/* get head node and remove it from list */
DOUBLE_LIST_NODE* double_list_get_from_head(DOUBLE_LIST *plist);

/* get tail node and remove it from list */
DOUBLE_LIST_NODE* double_list_get_from_tail(DOUBLE_LIST *plist);

/* merge the plist into plist_des */
void double_list_append_list(DOUBLE_LIST *plist_des, DOUBLE_LIST *plist);

/* 
get the previous node of pbase_node, if the pbase_node is the head node, NULL 
is returned. 
*/
DOUBLE_LIST_NODE* double_list_get_before(DOUBLE_LIST *plist, 
    DOUBLE_LIST_NODE *pbase_node);

/*
get the next node of pbase_node, if the pbase_node is the tail node, NULL is
returned.
*/
DOUBLE_LIST_NODE* double_list_get_after(DOUBLE_LIST *plist, 
    DOUBLE_LIST_NODE *pbase_node);

/*
get the nth node after the pbase_node, if tail is reached within the number, 
the atual number forwarded will be filled in "num"
*/
DOUBLE_LIST_NODE* double_list_forward(DOUBLE_LIST *plist, 
    DOUBLE_LIST_NODE *pbase_node, size_t *num);

/*
get the nth node before the pbase_node, if tail is reached within the number,
the atual number backwarded will be filled in "num"
*/
DOUBLE_LIST_NODE* double_list_backward(DOUBLE_LIST *plist, 
    DOUBLE_LIST_NODE *pbase_node, size_t *num);

/* get the actual number of nodes in the double list */
size_t double_list_get_nodes_num(DOUBLE_LIST *plist);

/* get head node and does not remove it from list */
DOUBLE_LIST_NODE* double_list_get_head(DOUBLE_LIST *plist);

/* get tail node and does not remove it from list */
DOUBLE_LIST_NODE* double_list_get_tail(DOUBLE_LIST *plist);

#ifdef __cplusplus
}
#endif
