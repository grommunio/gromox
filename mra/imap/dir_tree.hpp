#pragma once
#include <gromox/mem_file.hpp>
#include <gromox/simple_tree.hpp>

struct LIB_BUFFER;

struct DIR_NODE {
	SIMPLE_TREE_NODE node;
	BOOL b_loaded;
	char name[256];
	alloc_limiter<DIR_NODE> *ppool;
};

struct dir_tree {
	dir_tree(alloc_limiter<DIR_NODE> *);
	~dir_tree();
	void retrieve(MEM_FILE *);
	DIR_NODE *match(const char *path);
	static DIR_NODE *get_child(DIR_NODE *);

	SIMPLE_TREE tree{};
	alloc_limiter<DIR_NODE> *ppool = nullptr;
};
using DIR_TREE = dir_tree;
using DIR_TREE_ENUM = void (*)(DIR_NODE *, void*);
