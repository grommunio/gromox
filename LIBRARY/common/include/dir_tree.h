#pragma once
#include "simple_tree.h"
#include "lib_buffer.h"
#include "mem_file.h"


typedef struct _DIR_NODE {
	SIMPLE_TREE_NODE node;
	BOOL b_loaded;
	char name[256];
	LIB_BUFFER *ppool;
} DIR_NODE;

typedef struct _DIR_TREE {
	SIMPLE_TREE tree;
	LIB_BUFFER  *ppool;
} DIR_TREE;

typedef void (*DIR_TREE_ENUM)(DIR_NODE*, void*);

#ifdef __cplusplus
extern "C" {
#endif

LIB_BUFFER* dir_tree_allocator_init(size_t max_size, BOOL thread_safe);

void dir_tree_allocator_free(LIB_BUFFER *pallocator);

void dir_tree_init(DIR_TREE *ptree, LIB_BUFFER *pallocator);

void dir_tree_retrieve(DIR_TREE *ptree, MEM_FILE *pfile);

void dir_tree_clear(DIR_TREE *ptree);

DIR_NODE* dir_tree_match(DIR_TREE *ptree, const char *path);

BOOL dir_tree_pwd(DIR_TREE *ptree, DIR_NODE *pdir, char *path);

DIR_NODE* dir_tree_get_child(DIR_NODE* pdir);

DIR_NODE* dir_tree_get_parent(DIR_NODE* pdir);

DIR_NODE* dir_tree_get_slibling(DIR_NODE* pdir);

void dir_tree_enum_from_dir(DIR_NODE *pdir,
	DIR_TREE_ENUM enum_func, void *param);

DIR_NODE* dir_tree_add_dir(DIR_TREE *ptree, DIR_NODE *pdir, const char *name);

void dir_tree_delete_dir(DIR_TREE *ptree, DIR_NODE *pdir);

void dir_tree_add_path(DIR_TREE *ptree, const char *path);

void dir_tree_delete_path(DIR_TREE *ptree, const char *path);

BOOL dir_tree_check_dir(DIR_NODE *pdir);

void dir_tree_move_dir(DIR_TREE *ptree, DIR_NODE *psrc, DIR_NODE *pdst_parent);

void dir_tree_rename_dir(DIR_NODE *pdir, const char *new_name);

void dir_tree_free(DIR_TREE *ptree);


#ifdef __cplusplus
}
#endif
