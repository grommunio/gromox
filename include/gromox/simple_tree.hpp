#pragma once
#include <gromox/common_types.hpp>

enum {
	SIMPLE_TREE_INSERT_BEFORE,
	SIMPLE_TREE_INSERT_AFTER,
	SIMPLE_TREE_ADD_FIRST,
	SIMPLE_TREE_ADD_LAST
};

struct GX_EXPORT tree_node {
	inline size_t get_children_num() const { return node_children; }
	inline size_t get_depth() const { return node_depth; }
	inline tree_node *get_child() { return pnode_child; }
	inline const tree_node *get_child() const { return pnode_child; }
	inline tree_node *get_parent() { return pnode_parent; }
	inline const tree_node *get_parent() const { return pnode_parent; }
	inline tree_node *get_sibling() { return pnode_sibling; }
	inline const tree_node *get_sibling() const { return pnode_sibling; }

	tree_node *pnode_sibling, *pnode_child, *pnode_parent;
	size_t						node_depth;
	size_t						node_children;
	void						*pdata;
};
using SIMPLE_TREE_NODE = tree_node;

struct GX_EXPORT tree {
	inline tree_node *get_root() { return root; }
	inline const tree_node *get_root() const { return root; }
	inline size_t get_nodes_num() const { return nodes_num; }
	void clear() { root = nullptr; nodes_num = 0; }

	SIMPLE_TREE_NODE *root;
	size_t	nodes_num;
};
using SIMPLE_TREE = tree;

using SIMPLE_TREE_ENUM = void (*)(SIMPLE_TREE_NODE *, void *);
using SIMPLE_TREE_DELETE = void (*)(SIMPLE_TREE_NODE *);
using SIMPLE_TREE_DUPLICATE = SIMPLE_TREE_NODE *(*)(SIMPLE_TREE_NODE *, void *);

void simple_tree_init(SIMPLE_TREE *ptree);
BOOL simple_tree_set_root(SIMPLE_TREE *ptree, SIMPLE_TREE_NODE *pnode);
extern BOOL simple_tree_insert_sibling(SIMPLE_TREE *, SIMPLE_TREE_NODE *base, SIMPLE_TREE_NODE *pnode, int opt);
BOOL simple_tree_add_child(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode_base, SIMPLE_TREE_NODE *pnode, int opt);
void simple_tree_destroy_node(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, SIMPLE_TREE_DELETE del_func);
template<typename C, typename F> void simple_tree_node_enum(C *n, F &&f)
{
	do {
		f(n);
		if (n->pnode_child != nullptr)
			simple_tree_node_enum(n->pnode_child, f);
		n = n->pnode_sibling;
	} while (n != nullptr);
}
template<typename C, typename F> void simple_tree_enum_from_node(C *n, F &&f)
{
	f(n);
	if (n->pnode_child != nullptr)
		simple_tree_node_enum(n->pnode_child, f);
}
BOOL simple_tree_move_node_to_child(SIMPLE_TREE *ptree_dst, 
	SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE *ptree_src,
	SIMPLE_TREE_NODE *pnode_src, int opt);
extern BOOL simple_tree_move_node_to_sibling(SIMPLE_TREE *tdst, SIMPLE_TREE_NODE *ndst, SIMPLE_TREE *tsrc, SIMPLE_TREE_NODE *nsrc, int opt);
