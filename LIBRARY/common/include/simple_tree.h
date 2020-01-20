#pragma once
#include "common_types.h"

enum {
	SIMPLE_TREE_INSERT_BEFORE,
	SIMPLE_TREE_INSERT_AFTER,
	SIMPLE_TREE_ADD_FIRST,
	SIMPLE_TREE_ADD_LAST
};

typedef struct _SIMPLE_TREE_NODE{
	struct _SIMPLE_TREE_NODE	*pnode_slibling;
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

SIMPLE_TREE_NODE* simple_tree_node_get_slibling(SIMPLE_TREE_NODE *pnode);

SIMPLE_TREE_NODE* simple_tree_get_node_horizontal(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode_base, unsigned int x, unsigned int y);

SIMPLE_TREE_NODE* simple_tree_get_node_vertical(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode_base, unsigned int x, unsigned int y);

BOOL simple_tree_insert_slibling(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode_base, SIMPLE_TREE_NODE *pnode, int opt);

BOOL simple_tree_add_child(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode_base, SIMPLE_TREE_NODE *pnode, int opt);

void simple_tree_destroy_node(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, SIMPLE_TREE_DELETE del_func);

void simple_tree_empty_children(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, SIMPLE_TREE_DELETE del_func);

void simple_tree_enum_from_node(SIMPLE_TREE_NODE *pnode,
	SIMPLE_TREE_ENUM enum_func, void *param);

BOOL simple_tree_move_node_to_child(SIMPLE_TREE *ptree_dst, 
	SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE *ptree_src,
	SIMPLE_TREE_NODE *pnode_src, int opt);

BOOL simple_tree_move_node_to_slibling(SIMPLE_TREE *ptree_dst, 
	SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE *ptree_src,
	SIMPLE_TREE_NODE *pnode_src, int opt);

BOOL simple_tree_move_children_to_child(SIMPLE_TREE *ptree_dst,
	SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE *ptree_src,
	SIMPLE_TREE_NODE *pnode_src, int opt);

BOOL simple_tree_move_children_to_slibling(SIMPLE_TREE *ptree_dst,
	SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE *ptree_src,
	SIMPLE_TREE_NODE *pnode_src, int opt);

BOOL simple_tree_copy_node_to_child(SIMPLE_TREE *ptree_dst,
    SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE_NODE *pnode_src,
	int opt, SIMPLE_TREE_DUPLICATE dup_func, void *param);

BOOL simple_tree_copy_node_to_slibling(SIMPLE_TREE *ptree_dst,
    SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE_NODE *pnode_src,
	int opt, SIMPLE_TREE_DUPLICATE dup_func, void *param);

BOOL simple_tree_copy_children_to_child(SIMPLE_TREE *ptree_dst,
    SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE_NODE *pnode_src,
	int opt, SIMPLE_TREE_DUPLICATE dup_func, void *param);

BOOL simple_tree_copy_children_to_slibling(SIMPLE_TREE *ptree_dst,
    SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE_NODE *pnode_src,
	int opt, SIMPLE_TREE_DUPLICATE dup_func, void *param);

BOOL simple_tree_dup(SIMPLE_TREE *ptree_src, SIMPLE_TREE *ptree_dst,
	SIMPLE_TREE_DUPLICATE dup_func, void *param);

void simple_tree_free(SIMPLE_TREE *ptree);

#ifdef __cplusplus
}
#endif
