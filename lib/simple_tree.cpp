// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/defs.h>
#include <gromox/util.hpp>
#include <gromox/simple_tree.hpp>
#include <cstring>

static void simple_tree_node_enum(SIMPLE_TREE_NODE *pnode, 
	SIMPLE_TREE_ENUM enum_func, void *param);

static void simple_tree_destroy_group(SIMPLE_TREE *ptree, 
	SIMPLE_TREE_NODE *pnode, SIMPLE_TREE_DELETE del_func);

static void simple_tree_strip_group(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode);

static void simple_tree_cohere_group(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode);

/*
 *	simple tree's construct function
 *	@param
 *		ptree [out]	pointer to tree object
 *		root [in]	root node of the tree
 */
void simple_tree_init(SIMPLE_TREE *ptree)
{
#ifdef _DEBUG_UMTA
	if (NULL == ptree) {
		debug_info("[simple_tree]: NULL pointer in simple_tree_init");
		return;
	}
#endif
	memset(ptree, 0, sizeof(SIMPLE_TREE));
}

BOOL simple_tree_set_root(SIMPLE_TREE *ptree, SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == ptree || NULL == pnode) {
		debug_info("[simple_tree]: NULL pointer in simple_tree_set_root");
		return FALSE;
	}
#endif
	if (NULL != ptree->root) {
		return FALSE;
	}
	pnode->pnode_sibling = nullptr;
	pnode->pnode_parent	  = NULL;
	pnode->pnode_child	  = NULL;
	pnode->node_children  = 0;
	pnode->node_depth	  = 0;

	ptree->root = pnode;
	ptree->nodes_num = 1;
	return TRUE;
}

/*
 *	get the root node of tree
 *	@param
 *		ptree [in]	indicate the tree object
 *	@return
 *		the pointer to root node
 */
SIMPLE_TREE_NODE* simple_tree_get_root(SIMPLE_TREE *ptree)
{
#ifdef _DEBUG_UMTA
	if (NULL == ptree) {
		debug_info("[simple_tree]: NULL pointer in simple_tree_get_root");
		return NULL;
	}
#endif
	return ptree->root;
}

/*
 *	add a sibling node after pnode_base
 *	@param
 *		ptree [in]		indicate the tree object
 *		pnode_base [in]	base node to be comparee with
 *		pnode [in]		node to be inserted
 *		opt				SIMPLE_TREE_INSERT_BEFORE
 *						SIMPLE_TREE_INSERT_AFTER
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
BOOL simple_tree_insert_sibling(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode_base, SIMPLE_TREE_NODE *pnode, int opt)
{
	SIMPLE_TREE_NODE *pnode_temp;

#ifdef _DEBUG_UMTA
	if (NULL == ptree || NULL == pnode || NULL == pnode_base) {
		debug_info("[simple_tree]: NULL pointer in simple_tree_add_sibling");
		return FALSE;
	}
#endif
	/* can not insert a sibling node into root node! */
	if (pnode_base == ptree->root) {
		return FALSE;
	}
	if (SIMPLE_TREE_INSERT_AFTER == opt) {
		pnode->pnode_sibling = pnode_base->pnode_sibling;
		pnode->pnode_parent	  = pnode_base->pnode_parent;
		pnode->pnode_child	  = NULL;
		pnode->node_depth	  = pnode_base->node_depth;
		pnode->node_children  = 0;
		pnode_base->pnode_sibling = pnode;
		pnode_base->pnode_parent->node_children ++;
		ptree->nodes_num ++;
		return TRUE;
	} else if (SIMPLE_TREE_INSERT_BEFORE == opt) {
		pnode_temp = pnode_base->pnode_parent->pnode_child;
		pnode_base->pnode_parent->node_children ++;
		ptree->nodes_num ++;
		pnode->pnode_child	  = NULL;
		pnode->node_depth	  = pnode_base->node_depth;
		pnode->node_children  = 0;
		pnode->pnode_parent	  = pnode_base->pnode_parent;
		pnode->pnode_sibling = pnode_base;
		if (pnode_temp == pnode_base) {
			pnode_base->pnode_parent->pnode_child = pnode;
			return TRUE;
		}
		while (pnode_temp->pnode_sibling != pnode_base)
			pnode_temp = pnode_temp->pnode_sibling;
		pnode_temp->pnode_sibling = pnode;
		return TRUE;
	}
	return FALSE;
}

/*
 *	add a child node to pbase_node 
 *	@param
 *		ptree [in]			indicate the tree object
 *		pnode_base [in]		indicate the base node to be compared with
 *		pnode [in]			node the be added
 *		opt					SIMPLE_TREE_ADD_FIRST
 *							SIMPLE_TREE_ADD_LAST
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 *
 */
BOOL simple_tree_add_child(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode_base, SIMPLE_TREE_NODE *pnode, int opt)
{
	SIMPLE_TREE_NODE *pnode_temp;
	SIMPLE_TREE_NODE *pnode_last;

#ifdef _DEBUG_UMTA
	if (NULL == ptree || NULL == pnode || NULL == pnode_base) {
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_add_child");
		return FALSE;
	}
#endif
	if (0 == pnode_base->node_children) {
		pnode->pnode_sibling = nullptr;
		pnode->pnode_parent		  = pnode_base;
		pnode->pnode_child		  = NULL;
		pnode->node_depth		  = pnode_base->node_depth + 1;
		pnode->node_children	  = 0;
		pnode_base->node_children = 1;
		pnode_base->pnode_child	  = pnode;
		ptree->nodes_num ++;
		return TRUE;
	}
	if (SIMPLE_TREE_ADD_FIRST == opt) {
		pnode->pnode_child		= NULL;
		pnode->node_depth		= pnode_base->node_depth + 1;
		pnode->node_children	= 0;
		pnode->pnode_parent		= pnode_base;
		pnode->pnode_sibling = pnode_base->pnode_child;
		pnode_base->pnode_child = pnode;
		pnode_base->node_children ++;
		ptree->nodes_num ++;
		return TRUE;
	} else if (SIMPLE_TREE_ADD_LAST == opt) {
		pnode_temp = pnode_base->pnode_child;
		pnode_last = pnode_temp;
		while ((pnode_temp = pnode_temp->pnode_sibling) != nullptr)
			pnode_last = pnode_temp;
		pnode->pnode_child		   = NULL;
		pnode->node_depth		   = pnode_base->node_depth + 1;
		pnode->node_children	   = 0;
		pnode->pnode_parent		   = pnode_base;
		pnode->pnode_sibling = nullptr;
		pnode_last->pnode_sibling = pnode;
		pnode_base->node_children ++;
		ptree->nodes_num ++;
		return TRUE;
	}
	return FALSE;

}

/*
 *	get the tree node's number
 *	@param
 *		ptree [in]		indicate the tree object
 *	@return
 *		all nodes number of tree
 */
size_t simple_tree_get_nodes_num(SIMPLE_TREE *ptree)
{
#ifdef _DEBUG_UMTA
	if (NULL == ptree) {
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_get_nodes_num");
		return 0;
	}
#endif
	return ptree->nodes_num;
}

/*
 *	get node's children node number
 *	@param
 *		pnode [in]	node object
 *	@return
 *		children nbumber
 */
size_t simple_tree_node_get_children_num(SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode) {
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_node_get_children_num");
		return 0;
	}
#endif
	return pnode->node_children;
}

/*
 *	get node's depth in the tree
 *	@param
 *		pnode [in]	node object
 *	@return
 *		depth of node in the tree
 */
size_t simple_tree_node_get_depth(SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode) {
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_node_get_depth");
		return 0;
	}
#endif
	return pnode->node_depth;
}

/*
 *	get the first child node of pnode
 *	@param
 *		pnode [in]		indicate the node object
 *	@return
 *		child node of pnode, NULL if there's no
 */
SIMPLE_TREE_NODE* simple_tree_node_get_child(SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode) {
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_node_get_child");
		return NULL;
	}
#endif
	return pnode->pnode_child;

}

/*
 *	get the parent node of pnode
 *	@param
 *		pnode [in]		indicate the node object
 *	@return
 *		parent node of pnode, NULL if the node is the root of tree
 */
SIMPLE_TREE_NODE* simple_tree_node_get_parent(SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode) {
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_node_get_parent");
		return NULL;
	}
#endif
	return pnode->pnode_parent;
}

/*
 *	get the sibling node of pnode
 *	@param
 *		pnode [in]		indicate the node object
 *	@return
 *		the sibling node of pnode, NULL if there's no sibling node
 */
SIMPLE_TREE_NODE *simple_tree_node_get_sibling(SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode) {
		debug_info("[simple_tree]: NULL pointer in simple_tree_node_get_sibling");
		return NULL;
	}
#endif
	return pnode->pnode_sibling;
}

/*
 *	remove and destroy the	node and its descendant nodes
 *	@param
 *		ptree [in]		indicate the tree object
 *		pnode [in]		node to be destroyed
 *		del_func		callback function to free held resouce
 */
void simple_tree_destroy_node(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, SIMPLE_TREE_DELETE del_func)
{
	SIMPLE_TREE_NODE *pnode_temp;
	SIMPLE_TREE_NODE *pnode_parent;

#ifdef _DEBUG_UMTA
	if (NULL == ptree || NULL == pnode || NULL == del_func) {	
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_destroy_node");
		return;
	}
#endif
	if (NULL != pnode->pnode_child) {
		simple_tree_destroy_group(ptree, pnode->pnode_child, del_func);
	}
	if (pnode == ptree->root) {
		pnode->pnode_child = NULL;
		pnode->node_children = 0;
		del_func(pnode);
		ptree->nodes_num --;
#ifdef _DEBUG_UMTA
		if (0 != ptree->nodes_num) {
			debug_info("[simple_tree]: fatal error "
					"in simple_tree_destroy_node");
		}
#endif
		ptree->root = NULL;
		return;
	}
	pnode_parent = pnode->pnode_parent;
	pnode_temp = pnode_parent->pnode_child;
	if (pnode_temp == pnode) {
		if (pnode_parent->node_children == 1) {
			pnode_parent->pnode_child = NULL;
		} else {
			pnode_parent->pnode_child = pnode->pnode_sibling;
		}
		pnode_parent->node_children --;
		pnode->pnode_parent	  = NULL;
		pnode->pnode_sibling = nullptr;
		pnode->pnode_child	  = NULL;
		pnode->node_depth	  = 0;
		pnode->node_children  = 0;
		del_func(pnode);
		ptree->nodes_num --;
		return;
	}
	/* find the prevoious node */
	while (pnode_temp->pnode_sibling != pnode)
		pnode_temp = pnode_temp->pnode_sibling;
	pnode_parent->node_children --;
	pnode_temp->pnode_sibling = pnode->pnode_sibling;
	pnode->pnode_child		   = NULL;
	pnode->pnode_parent		   = NULL;
	pnode->pnode_sibling = nullptr;
	pnode->node_depth		   = 0;
	pnode->node_children	   = 0;
	del_func(pnode);
	ptree->nodes_num --;
}

/*
 *	Destroy all descendant nodes of pnode, including pnode itself.
 *	@param
 *		ptree [in]		indicate the tree oject
 *		pnode [in]		indicate the node object, where we begin from
 *		del_func		when a node is about to be destroyed, this function 
 *						will be invoked to notify the function caller, this
 *						is for the caller to free resources held by node!
 *						do not operate any field except data pointer in
 *						del_func.
 */
static void simple_tree_destroy_group(SIMPLE_TREE *ptree, 
	SIMPLE_TREE_NODE *pnode, SIMPLE_TREE_DELETE del_func)
{
	SIMPLE_TREE_NODE *pnode_temp;

#ifdef _DEBUG_UMTA
	if (NULL == ptree || NULL == pnode || NULL == del_func) {	
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_destroy_group");
		return;
	}
#endif
	do {
		if (NULL != pnode->pnode_child) {
			simple_tree_destroy_group(ptree, pnode->pnode_child, del_func);
		}
		pnode->pnode_child = NULL;
		pnode_temp = pnode;
		pnode = pnode->pnode_sibling;
		pnode_temp->pnode_parent   = NULL;
		pnode_temp->pnode_sibling = nullptr;
		pnode_temp->pnode_child	   = NULL;
		pnode_temp->node_depth	   = 0;
		pnode_temp->node_children  = 0;
		del_func(pnode_temp);
		ptree->nodes_num --;
	} while (NULL != pnode);
}

/*
 *	enumerating the nodes in the tree, from pnode on
 *	@param
 *		pnode [in]		the node where we begin from
 *		enum_func		callback function
 *		param [in]		parameter pointer for callback function
 */
void simple_tree_enum_from_node(SIMPLE_TREE_NODE *pnode,
	SIMPLE_TREE_ENUM enum_func, void *param)
{
	SIMPLE_TREE_NODE *pnode_child;

#ifdef _DEBUG_UMTA
	if (NULL == pnode || NULL == enum_func) {	
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_enum_from_node");
		return;
	}
#endif
	enum_func(pnode, param);
	pnode_child = pnode->pnode_child;
	if (NULL != pnode_child) {
		simple_tree_node_enum(pnode_child, enum_func, param);
	}

}

static void simple_tree_node_enum(SIMPLE_TREE_NODE *pnode, 
	SIMPLE_TREE_ENUM enum_func, void *param)
{
#ifdef _DEBUG_UMTA
	if (NULL == pnode || NULL == enum_func) {	
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_node_enum");
		return;
	}
#endif
	do {
		enum_func(pnode, param);
		if (NULL != pnode->pnode_child) {
			simple_tree_node_enum(pnode->pnode_child, enum_func, param);
		}
		pnode = pnode->pnode_sibling;
	} while (NULL != pnode);
}

/*
 *	strip a group of nodes from the tree, but not destroy them
 *	@param
 *		ptree [in]		indicate the tree object
 *		pnode [in]		where we begin from
 */
static void simple_tree_strip_group(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == ptree || NULL == pnode) {	
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_strip_group");
		return;
	}
#endif
	do {
		if (NULL != pnode->pnode_child) {
			simple_tree_strip_group(ptree, pnode->pnode_child);
		}
		pnode->node_depth = 0;
		ptree->nodes_num --;
		pnode = pnode->pnode_sibling;
	} while (NULL != pnode);
}

/*
 *	cohere a group of nodes from the tree
 *	@param
 *		ptree [in]		indicate the tree object
 *		pnode [in]		where we begin from
 */
static void simple_tree_cohere_group(SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode)
{
#ifdef _DEBUG_UMTA
	if (NULL == ptree || NULL == pnode) {
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_cohere_group");
		return;
	}
#endif
	do {
		pnode->node_depth = pnode->pnode_parent->node_depth + 1;
		if (NULL != pnode->pnode_child) {
			simple_tree_cohere_group(ptree, pnode->pnode_child);
		}
		ptree->nodes_num ++;
		pnode = pnode->pnode_sibling;
	} while (NULL != pnode);
}

/*
 *	move node and its descendant to a none-child node as its descendant
 *	@param
 *		ptree_dst [in]		destination tree
 *		pnode_dst [in]		destination node where we begin from
 *		ptree_src [in]		source tree
 *		pnode_src [in]		source node
 *		opt					SIMPLE_TREE_ADD_FIRST
 *							SIMPLE_TREE_ADD_LAST
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
BOOL simple_tree_move_node_to_child(SIMPLE_TREE *ptree_dst,
	SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE *ptree_src,
	SIMPLE_TREE_NODE *pnode_src, int opt)
{
	SIMPLE_TREE_NODE *pnode_child;
	SIMPLE_TREE_NODE *pnode_parent;
	SIMPLE_TREE_NODE *pnode_temp;
	SIMPLE_TREE_NODE *pnode_last = nullptr;

#ifdef _DEBUG_UMTA
	if (NULL == ptree_dst || NULL == pnode_dst ||
		NULL == ptree_src || NULL == pnode_src) {
		debug_info("[simple_tree]: NULL pointer in "
					"simple_tree_move_node_to_child");
		return FALSE;
	}
#endif

	if (SIMPLE_TREE_ADD_FIRST != opt && SIMPLE_TREE_ADD_LAST != opt) {
		return FALSE;
	}
	/*
	 * check whether the destination node is same or descendant 
	 * of source node
	 */
	pnode_temp = pnode_dst;
	do {
		if (pnode_temp == pnode_src) {
			return FALSE;
		}
	} while ((pnode_temp = pnode_temp->pnode_parent) != NULL);
	/* first cut the relationship of source tree */
	pnode_child = pnode_src->pnode_child;
	if (NULL != pnode_child) {
		simple_tree_strip_group(ptree_src, pnode_child);
	}
	if (pnode_src != ptree_src->root) {
		pnode_parent = pnode_src->pnode_parent;
		pnode_temp = pnode_parent->pnode_child;
		if (pnode_temp == pnode_src) {
			if (pnode_parent->node_children == 1) {
				pnode_parent->pnode_child = NULL;
			} else {
				pnode_parent->pnode_child = pnode_src->pnode_sibling;
			}
		} else {
			while (pnode_temp->pnode_sibling != pnode_src)
				pnode_temp = pnode_temp->pnode_sibling;
			pnode_temp->pnode_sibling = pnode_src->pnode_sibling;
		}
		pnode_parent->node_children --;
	} else {
		ptree_src->root = NULL;
	}
	ptree_src->nodes_num --;
	pnode_src->pnode_parent	  = pnode_dst;
	pnode_src->node_depth	  = pnode_dst->node_depth + 1;
	pnode_dst->node_children ++;
	ptree_dst->nodes_num ++;
	if (NULL == pnode_dst->pnode_child) {	
		pnode_src->pnode_sibling = nullptr;
		pnode_dst->pnode_child	  = pnode_src;
		/* add the relationship to the destination */
		if (NULL != pnode_child) {
			simple_tree_cohere_group(ptree_dst, pnode_child);
		}
		return TRUE;
	}
	if (SIMPLE_TREE_ADD_FIRST == opt) {
		pnode_src->pnode_sibling = nullptr;
		pnode_temp = pnode_dst->pnode_child;
		pnode_dst->pnode_child = pnode_src;
		/* add the relationship to the destination */
		if (NULL != pnode_child) {
			simple_tree_cohere_group(ptree_dst, pnode_child);
		}
		pnode_src->pnode_sibling = pnode_temp;
	} else if (SIMPLE_TREE_ADD_LAST == opt) {
		pnode_temp = pnode_dst->pnode_child;
		while ((pnode_temp = pnode_temp->pnode_sibling) != nullptr)
			pnode_last = pnode_temp;
		pnode_src->pnode_sibling = nullptr;
		pnode_last->pnode_sibling = pnode_src;
		/* add the relationship to the destination */
		if (NULL != pnode_child) {
			simple_tree_cohere_group(ptree_dst, pnode_child);
		}
	}
	return TRUE;

}

/*
 *	move node and its descendant to a node as its sibling node
 *	@param
 *		ptree_dst [in]		destination tree
 *		pnode_dst [in]		destination node where we begin from
 *		ptree_src [in]		source tree
 *		pnode_src [in]		source node
 *		opt					SIMPLE_TREE_INSERT_BEFORE
 *							SIMPLE_TREE_INSERT_AFTER
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
BOOL simple_tree_move_node_to_sibling(SIMPLE_TREE *ptree_dst,
	SIMPLE_TREE_NODE *pnode_dst, SIMPLE_TREE *ptree_src,
	SIMPLE_TREE_NODE *pnode_src, int opt)
{
	SIMPLE_TREE_NODE *pnode_child;
	SIMPLE_TREE_NODE *pnode_parent;
	SIMPLE_TREE_NODE *pnode_temp;

#ifdef _DEBUG_UMTA
	if (NULL == ptree_dst || NULL == pnode_dst ||
		NULL == ptree_src || NULL == pnode_src) {
		debug_info("[simple_tree]: NULL pointer in simple_tree_move_node_to_sibling");
		return FALSE;
	}
#endif
	if (SIMPLE_TREE_INSERT_AFTER != opt && SIMPLE_TREE_INSERT_BEFORE != opt) {
		return FALSE;
	}
	/*
	 * check whether the destination node is same or descendant 
	 * of source node
	 */
	if (pnode_dst == pnode_src) {
		return TRUE;
	}
	pnode_temp = pnode_dst;
	while ((pnode_temp = pnode_temp->pnode_parent) != NULL) {
		if (pnode_temp == pnode_src) {
			return FALSE;
		}
	}
	if (pnode_dst == ptree_dst->root) {
		return FALSE;
	}

	/* first cut the relationship of source tree */
	pnode_child = pnode_src->pnode_child;
	if (NULL != pnode_child) {
		simple_tree_strip_group(ptree_src, pnode_child);
	}
	if (pnode_src != ptree_src->root) {
		pnode_parent = pnode_src->pnode_parent;
		pnode_temp = pnode_parent->pnode_child;
		if (pnode_temp == pnode_src) {
			if (pnode_parent->node_children == 1) {
				pnode_parent->pnode_child = NULL;
			} else {
				pnode_parent->pnode_child = pnode_src->pnode_sibling;
			}
		} else {
			while (pnode_temp->pnode_sibling != pnode_src)
				pnode_temp = pnode_temp->pnode_sibling;
			pnode_temp->pnode_sibling = pnode_src->pnode_sibling;
		}
		pnode_parent->node_children --;
	} else {
		ptree_src->root = NULL;
	}
	ptree_src->nodes_num --;

	pnode_dst->pnode_parent->node_children ++;
	ptree_dst->nodes_num ++;
	pnode_src->pnode_parent	  = pnode_dst->pnode_parent;
	pnode_src->node_depth	  = pnode_dst->node_depth;
	if (SIMPLE_TREE_INSERT_AFTER == opt) {
		pnode_src->pnode_sibling = pnode_dst->pnode_sibling;
		pnode_dst->pnode_sibling = pnode_src;
	} else if (SIMPLE_TREE_INSERT_BEFORE == opt) {
		pnode_temp = pnode_dst->pnode_parent->pnode_child;
		if (pnode_temp == pnode_dst) {
			pnode_dst->pnode_parent->pnode_child = pnode_src;
			pnode_src->pnode_sibling = pnode_dst;
		} else {
			while (pnode_temp->pnode_sibling != pnode_dst)
				pnode_temp = pnode_temp->pnode_sibling;
			pnode_temp->pnode_sibling = pnode_dst;
		}
	}
	/* add the relationship to the destination */
	if (NULL != pnode_child) {
		simple_tree_cohere_group(ptree_dst, pnode_child);
	}
	return TRUE;

}

/*
 *	tree object's destruct function
 *	@param
 *		ptree [in]	indicate the tree object
 */
void simple_tree_free(SIMPLE_TREE *ptree)
{
#ifdef _DEBUG_UMTA
	if (NULL == ptree) {
		debug_info("[simple_tree]: NULL pointer in simple_tree_free");
		return;
	}
#endif
	memset(ptree, 0, sizeof(SIMPLE_TREE));
}

