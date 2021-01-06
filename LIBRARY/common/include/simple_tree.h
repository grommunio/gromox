#pragma once
#include "common_types.h"

enum {
	SIMPLE_TREE_INSERT_BEFORE,
	SIMPLE_TREE_INSERT_AFTER,
	SIMPLE_TREE_ADD_FIRST,
	SIMPLE_TREE_ADD_LAST
};

typedef struct _SIMPLE_TREE_NODE{
	struct _SIMPLE_TREE_NODE *pnode_sibling;
	struct _SIMPLE_TREE_NODE	*pnode_child;
	struct _SIMPLE_TREE_NODE	*pnode_parent;
	size_t						node_depth;
	size_t						node_children;
	void						*pdata;
} SIMPLE_TREE_NODE;

typedef struct _SIMPLE_TREE{
	SIMPLE_TREE_NODE *root;
	size_t	nodes_num;
} SIMPLE_TREE;

typedef void (*SIMPLE_TREE_ENUM)(SIMPLE_TREE_NODE*, void*);
typedef void (*SIMPLE_TREE_DELETE)(SIMPLE_TREE_NODE*);
typedef SIMPLE_TREE_NODE* (*SIMPLE_TREE_DUPLICATE)(SIMPLE_TREE_NODE*, void*);

#ifdef __cplusplus
extern "C" {
#endif

void simple_tree_init(SIMPLE_TREE *ptree);

SIMPLE_TREE_NODE* simple_tree_get_root(SIMPLE_TREE *ptree);

BOOL simple_tree_set_root(SIMPLE_TREE *ptree, SIMPLE_TREE_NODE *pnode);

size_t simple_tree_get_nodes_num(SIMPLE_TREE *ptree);

size_t simple_tree_node_get_children_num(SIMPLE_TREE_NODE *pnode);

size_t simple_tree_node_get_depth(SIMPLE_TREE_NODE *pnode);

SIMPLE_TREE_NODE* simple_tree_node_get_child(SIMPLE_TREE_NODE *pnode);

SIMPLE_TREE_NODE* simple_tree_node_get_parent(SIMPLE_TREE_NODE *pnode);
extern SIMPLE_TREE_NODE *simple_tree_node_get_sibling(SIMPLE_TREE_NODE *);
extern BOOL simple_tree_insert_sibling(SIMPLE_TREE *, SIMPLE_TREE_NODE *base, SIMPLE_TREE_NODE *pnode, int opt);
BOOL simple_tree_add_child(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode_base, SIMPLE_TREE_NODE *pnode, int opt);

void simple_tree_destroy_node(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, SIMPLE_TREE_DELETE del_func);
void simple_tree_enum_from_node(SIMPLE_TREE_NODE *pnode,
	SIMPLE_TREE_ENUM enum_func, void *param);

BOOL simple_tree_move_node_to_child(SIMPLE_TREE *ptree_dst, 
	SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE *ptree_src,
	SIMPLE_TREE_NODE *pnode_src, int opt);
extern BOOL simple_tree_move_node_to_sibling(SIMPLE_TREE *tdst, SIMPLE_TREE_NODE *ndst, SIMPLE_TREE *tsrc, SIMPLE_TREE_NODE *nsrc, int opt);
void simple_tree_free(SIMPLE_TREE *ptree);

#ifdef __cplusplus
}
#endif
