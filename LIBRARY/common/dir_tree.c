#include "dir_tree.h"


void dir_tree_enum_delete(SIMPLE_TREE_NODE *pnode)
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
		pdir = lib_buffer_get(ptree->ppool);
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
		while (ptr2 = strchr(ptr1, '/')) {
			*ptr2 = '\0';
			pnode_parent = pnode;
			pnode = simple_tree_node_get_child(pnode);
			if (NULL != pnode) {
				do {
					pdir = (DIR_NODE*)pnode->pdata;
					if (0 == strcmp(pdir->name, ptr1)) {
						break;
					}
				} while (pnode=simple_tree_node_get_slibling(pnode));
			}

			if (NULL == pnode) {
				pdir = lib_buffer_get(ptree->ppool);
				pdir->node.pdata = pdir;
				strncpy(pdir->name, ptr1, sizeof(pdir->name));
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

void dir_tree_clear(DIR_TREE *ptree)
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
	DIR_NODE *pdir;
	char *ptr1, *ptr2;
	char temp_path[4096 + 1];
	SIMPLE_TREE_NODE *pnode;

	pnode = simple_tree_get_root(&ptree->tree);
	if (NULL == pnode) {
		return NULL;
	}

	if ('\0' == path[0]) {
		return pnode->pdata;
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
	while (ptr2 = strchr(ptr1, '/')) {
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
		} while (pnode=simple_tree_node_get_slibling(pnode));

		if (NULL == pnode) {
			return NULL;
		}

		ptr1 = ptr2 + 1;
	}

	return pdir;
}

BOOL dir_tree_pwd(DIR_TREE *ptree, DIR_NODE *pdir, char *path)
{
	int len, len1;
	SIMPLE_TREE_NODE *pnode, *proot;

	proot = simple_tree_get_root(&ptree->tree);
	if (NULL == proot) {
		return FALSE;
	}
	pnode = &pdir->node;

	memset(path, 0, 4096);
	len = 0;
	while (TRUE) {
		len1 = strlen(((DIR_NODE*)(pnode->pdata))->name);
		len += len1;
		if (len >= 4096) {
			return FALSE;
		}
		memcpy(path + 4095 - len, ((DIR_NODE*)(pnode->pdata))->name, len1);
		pnode = simple_tree_node_get_parent(pnode);
		if (NULL == pnode) {
			return FALSE;
		}
		if (pnode == proot) {
			break;
		}
		len ++;
		*(path + 4095 - len) = '/';
	}
	memmove(path, path + 4095 - len, len);
	return TRUE;
}

DIR_NODE* dir_tree_get_child(DIR_NODE* pdir)
{
	SIMPLE_TREE_NODE *pnode;

	pnode = simple_tree_node_get_child(&pdir->node);
	if (NULL != pnode) {
		return pnode->pdata;
	} else {
		return NULL;
	}
}

DIR_NODE* dir_tree_get_parent(DIR_NODE* pdir)
{
	SIMPLE_TREE_NODE *pnode;

	pnode = simple_tree_node_get_parent(&pdir->node);
	if (NULL != pnode) {
		return pnode->pdata;
	} else {
		return NULL;
	}
}

DIR_NODE* dir_tree_get_slibling(DIR_NODE* pdir)
{
	SIMPLE_TREE_NODE *pnode;

	pnode = simple_tree_node_get_slibling(&pdir->node);
	if (NULL != pnode) {
		return pnode->pdata;
	} else {
		return NULL;
	}
}

void dir_tree_enum_from_dir(DIR_NODE *pdir,
	DIR_TREE_ENUM enum_func, void *param)
{
	simple_tree_enum_from_node(&pdir->node,
		(SIMPLE_TREE_ENUM)enum_func, param);
}

DIR_NODE* dir_tree_add_dir(DIR_TREE *ptree, DIR_NODE *pdir, const char *name)
{
	DIR_NODE *pret;
	
	pret = lib_buffer_get(ptree->ppool);
	pret->node.pdata = pret;
	strncpy(pret->name, name, sizeof(pret->name));
	pret->b_loaded = TRUE;
	pret->ppool = ptree->ppool;
	simple_tree_add_child(&ptree->tree, &pdir->node,
		&pret->node, SIMPLE_TREE_ADD_LAST);
	return pret;
}

void dir_tree_delete_dir(DIR_TREE *ptree, DIR_NODE *pdir)
{
	simple_tree_destroy_node(&ptree->tree, &pdir->node, dir_tree_enum_delete);
}

void dir_tree_add_path(DIR_TREE *ptree, const char *path)
{
	int len;
	DIR_NODE *pdir;
	char *ptr1, *ptr2;
	char temp_path[4096 + 1];
	SIMPLE_TREE_NODE *pnode, *pnode_parent;
	
	len = strlen(path);
	if (len >= 4096) {
		return;
	}
	pnode = simple_tree_get_root(&ptree->tree);
	if (NULL == pnode) {
		pdir = lib_buffer_get(ptree->ppool);
		pdir->node.pdata = pdir;
		pdir->name[0] = '\0';
		pdir->b_loaded = TRUE;
		pdir->ppool = ptree->ppool;
		simple_tree_set_root(&ptree->tree, &pdir->node);
		pnode = &pdir->node;
	}
	
	memcpy(temp_path, path, len);
	if ('/' != temp_path[len - 1]) {
		temp_path[len] = '/';
		len ++;
	}
	temp_path[len] = '\0';
	ptr1 = temp_path;
	while (ptr2 = strchr(ptr1, '/')) {
		*ptr2 = '\0';
		pnode_parent = pnode;
		pnode = simple_tree_node_get_child(pnode);
		if (NULL != pnode) {
			do {
				pdir = (DIR_NODE*)pnode->pdata;
				if (0 == strcmp(pdir->name, ptr1)) {
					break;
				}
			} while (pnode=simple_tree_node_get_slibling(pnode));
		}

		if (NULL == pnode) {
			pdir = lib_buffer_get(ptree->ppool);
			pdir->node.pdata = pdir;
			strncpy(pdir->name, ptr1, sizeof(pdir->name));
			pdir->b_loaded = TRUE;
			pdir->ppool = ptree->ppool;
			pnode = &pdir->node;
			simple_tree_add_child(&ptree->tree, pnode_parent, pnode,
				SIMPLE_TREE_ADD_LAST);
		}
		ptr1 = ptr2 + 1;
	}	
}

void dir_tree_delete_path(DIR_TREE *ptree, const char *path)
{
	DIR_NODE *pdir;
	
	pdir = dir_tree_match(ptree, path);
	if (NULL != pdir) {
		if (NULL != simple_tree_node_get_child(&pdir->node)) {
			pdir->b_loaded = FALSE;
		} else {
			simple_tree_destroy_node(&ptree->tree, &pdir->node,
				dir_tree_enum_delete);
		}
	}
}

BOOL dir_tree_check_dir(DIR_NODE *pdir)
{
	return pdir->b_loaded;
}

void dir_tree_move_dir(DIR_TREE *ptree, DIR_NODE *psrc, DIR_NODE *pdst_parent)
{
	simple_tree_move_node_to_child(&ptree->tree, &pdst_parent->node,
		&ptree->tree, &psrc->node, SIMPLE_TREE_ADD_LAST);
}

void dir_tree_rename_dir(DIR_NODE *pdir, const char *new_name)
{
	strncpy(pdir->name, new_name, sizeof(pdir->name));

}

void dir_tree_free(DIR_TREE *ptree)
{
	dir_tree_clear(ptree);
	simple_tree_free(&ptree->tree);
	ptree->ppool = NULL;
}

