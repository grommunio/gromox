// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstring>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/dir_tree.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/simple_tree.hpp>

static void dir_tree_enum_delete(SIMPLE_TREE_NODE *pnode)
{
	DIR_NODE *pdir;

	pdir = (DIR_NODE*)pnode->pdata;
	lib_buffer_put(pdir->ppool, pdir);
}

LIB_BUFFER* dir_tree_allocator_init(size_t max_size, BOOL thread_safe)
{
	return lib_buffer_init(sizeof(DIR_NODE), max_size, thread_safe);
}

void dir_tree_allocator_free(LIB_BUFFER *pallocator)
{
	lib_buffer_free(pallocator);
}

void dir_tree_init(DIR_TREE *ptree, LIB_BUFFER *pallocator)
{
	simple_tree_init(&ptree->tree);
	ptree->ppool = pallocator;
	
}

void dir_tree_retrieve(DIR_TREE *ptree, MEM_FILE *pfile)
{
	int len;
	DIR_NODE *pdir;
	char *ptr1, *ptr2;
	char temp_path[4096 + 1];
	SIMPLE_TREE_NODE *pnode, *proot, *pnode_parent;

	proot = simple_tree_get_root(&ptree->tree);
	if (NULL == proot) {
		pdir = static_cast<DIR_NODE *>(lib_buffer_get(ptree->ppool));
		pdir->node.pdata = pdir;
		pdir->name[0] = '\0';
		pdir->b_loaded = TRUE;
		pdir->ppool = ptree->ppool;
		simple_tree_set_root(&ptree->tree, &pdir->node);
		proot = &pdir->node;
	}

	
	mem_file_seek(pfile, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != (len = mem_file_readline(
		pfile, temp_path, 4096))) {
		pnode = proot;
		if ('/' != temp_path[len - 1]) {
			temp_path[len] = '/';
			len ++;
			temp_path[len] = '\0';
		}
		ptr1 = temp_path;
		while ((ptr2 = strchr(ptr1, '/')) != NULL) {
			*ptr2 = '\0';
			pnode_parent = pnode;
			pnode = simple_tree_node_get_child(pnode);
			if (NULL != pnode) {
				do {
					pdir = (DIR_NODE*)pnode->pdata;
					if (0 == strcmp(pdir->name, ptr1)) {
						break;
					}
				} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
			}

			if (NULL == pnode) {
				pdir = static_cast<DIR_NODE *>(lib_buffer_get(ptree->ppool));
				pdir->node.pdata = pdir;
				HX_strlcpy(pdir->name, ptr1, GX_ARRAY_SIZE(pdir->name));
				pdir->b_loaded = FALSE;
				pdir->ppool = ptree->ppool;
				pnode = &pdir->node;
				simple_tree_add_child(&ptree->tree, pnode_parent, pnode,
					SIMPLE_TREE_ADD_LAST);
			}
			ptr1 = ptr2 + 1;
		}

		((DIR_NODE*)(pnode->pdata))->b_loaded = TRUE;
		
	}

}

static void dir_tree_clear(DIR_TREE *ptree)
{
	SIMPLE_TREE_NODE *pnode;

	pnode = simple_tree_get_root(&ptree->tree);
	if (NULL != pnode) {
		simple_tree_destroy_node(&ptree->tree, pnode,
			dir_tree_enum_delete);
	}

}

DIR_NODE* dir_tree_match(DIR_TREE *ptree, const char *path)
{
	int len;
	DIR_NODE *pdir = nullptr;
	char *ptr1, *ptr2;
	char temp_path[4096 + 1];
	SIMPLE_TREE_NODE *pnode;

	pnode = simple_tree_get_root(&ptree->tree);
	if (NULL == pnode) {
		return NULL;
	}

	if ('\0' == path[0]) {
		return static_cast<DIR_NODE *>(pnode->pdata);
	}

	len = strlen(path);
	if (len >= 4096) {
		return NULL;
	}
	memcpy(temp_path, path, len);
	if ('/' != temp_path[len - 1]) {
		temp_path[len] = '/';
		len ++;
	}
	temp_path[len] = '\0';
	
	ptr1 = temp_path;
	while ((ptr2 = strchr(ptr1, '/')) != NULL) {
		*ptr2 = '\0';
		pnode = simple_tree_node_get_child(pnode);
		if (NULL == pnode) {
			return NULL;
		}
		do {
			pdir = (DIR_NODE*)pnode->pdata;
			if (0 == strcmp(pdir->name, ptr1)) {
				break;
			}
		} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);

		if (NULL == pnode) {
			return NULL;
		}

		ptr1 = ptr2 + 1;
	}

	return pdir;
}

DIR_NODE* dir_tree_get_child(DIR_NODE* pdir)
{
	SIMPLE_TREE_NODE *pnode;

	pnode = simple_tree_node_get_child(&pdir->node);
	if (NULL != pnode) {
		return static_cast<DIR_NODE *>(pnode->pdata);
	} else {
		return NULL;
	}
}

void dir_tree_free(DIR_TREE *ptree)
{
	dir_tree_clear(ptree);
	simple_tree_free(&ptree->tree);
	ptree->ppool = NULL;
}

