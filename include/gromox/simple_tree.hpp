#pragma once
#include <gromox/common_types.hpp>

enum {
	SIMPLE_TREE_INSERT_BEFORE,
	SIMPLE_TREE_INSERT_AFTER,
	SIMPLE_TREE_ADD_FIRST,
	SIMPLE_TREE_ADD_LAST
};

struct SIMPLE_TREE_NODE {
	SIMPLE_TREE_NODE *pnode_sibling, *pnode_child, *pnode_parent;
	size_t						node_depth;
	size_t						node_children;
	void						*pdata;
};

struct SIMPLE_TREE {
	SIMPLE_TREE_NODE *root;
	size_t	nodes_num;
};

using SIMPLE_TREE_ENUM = void (*)(SIMPLE_TREE_NODE *, void *);
using SIMPLE_TREE_DELETE = void (*)(SIMPLE_TREE_NODE *);
using SIMPLE_TREE_DUPLICATE = SIMPLE_TREE_NODE *(*)(SIMPLE_TREE_NODE *, void *);

void simple_tree_init(SIMPLE_TREE *ptree);
SIMPLE_TREE_NODE* simple_tree_get_root(SIMPLE_TREE *ptree);
extern GX_EXPORT const SIMPLE_TREE_NODE *simple_tree_get_root(const SIMPLE_TREE *);
BOOL simple_tree_set_root(SIMPLE_TREE *ptree, SIMPLE_TREE_NODE *pnode);
extern GX_EXPORT size_t simple_tree_get_nodes_num(const SIMPLE_TREE *);
extern GX_EXPORT size_t simple_tree_node_get_children_num(const SIMPLE_TREE_NODE *);
extern GX_EXPORT size_t simple_tree_node_get_depth(const SIMPLE_TREE_NODE *);
SIMPLE_TREE_NODE* simple_tree_node_get_child(SIMPLE_TREE_NODE *pnode);
extern GX_EXPORT const SIMPLE_TREE_NODE *simple_tree_node_get_child(const SIMPLE_TREE_NODE *);
SIMPLE_TREE_NODE* simple_tree_node_get_parent(SIMPLE_TREE_NODE *pnode);
extern GX_EXPORT const SIMPLE_TREE_NODE *simple_tree_node_get_parent(const SIMPLE_TREE_NODE *);
extern SIMPLE_TREE_NODE *simple_tree_node_get_sibling(SIMPLE_TREE_NODE *);
extern GX_EXPORT const SIMPLE_TREE_NODE *simple_tree_node_get_sibling(const SIMPLE_TREE_NODE *);
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
