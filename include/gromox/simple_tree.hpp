#pragma once
#include <memory>
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

using SIMPLE_TREE_ENUM = void (*)(tree_node *, void *, unsigned int);
using SIMPLE_TREE_DELETE = void (*)(SIMPLE_TREE_NODE *);
using SIMPLE_TREE_DUPLICATE = SIMPLE_TREE_NODE *(*)(SIMPLE_TREE_NODE *, void *);

struct GX_EXPORT mtree {
	inline tree_node *get_root() { return root; }
	inline const tree_node *get_root() const { return root; }
	inline size_t get_nodes_num() const { return nodes_num; }
	void clear() { root = nullptr; nodes_num = 0; }
	BOOL set_root(tree_node *);
	BOOL insert_sibling(tree_node *base, tree_node *, int opt);
	BOOL add_child(tree_node *base, tree_node *, int opt);
	template<typename T> BOOL set_root(std::unique_ptr<T> &&p)
	{
		if (!set_root(&p.get()->node))
			return false;
		p.release();
		return TRUE;
	}
	template<typename T> BOOL insert_sibling(tree_node *b, std::unique_ptr<T> &&p, int opt)
	{
		if (!insert_sibling(b, &p.get()->node, opt))
			return false;
		p.release();
		return TRUE;
	}
	template<typename T> BOOL add_child(tree_node *b, std::unique_ptr<T> &&p, int opt)
	{
		if (!add_child(b, &p.get()->node, opt))
			return false;
		p.release();
		return TRUE;
	}
	void destroy_node(tree_node *, SIMPLE_TREE_DELETE);

	SIMPLE_TREE_NODE *root = nullptr;
	size_t nodes_num = 0;
};
using SIMPLE_TREE = mtree;

template<typename C, typename F> void simple_tree_node_enum(C *n, F &&f, unsigned int lvl = 0)
{
	do {
		f(n, lvl);
		if (n->pnode_child != nullptr)
			simple_tree_node_enum(n->pnode_child, f, lvl + 1);
		n = n->pnode_sibling;
	} while (n != nullptr);
}
template<typename C, typename F> void simple_tree_enum_from_node(C *n, F &&f, unsigned int lvl = 0)
{
	f(n, lvl);
	if (n->pnode_child != nullptr)
		simple_tree_node_enum(n->pnode_child, f, lvl + 1);
}
