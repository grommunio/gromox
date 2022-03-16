// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstring>
#include <gromox/defs.h>
#include <gromox/simple_tree.hpp>
#include <gromox/util.hpp>

static void simple_tree_destroy_group(SIMPLE_TREE *ptree, 
	SIMPLE_TREE_NODE *pnode, SIMPLE_TREE_DELETE del_func);

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

BOOL tree::set_root(SIMPLE_TREE_NODE *pnode)
{
	auto ptree = this;
#ifdef _DEBUG_UMTA
	if (pnode == nullptr) {
		debug_info("[simple_tree]: NULL pointer in tree::set_root");
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
BOOL tree::insert_sibling(tree_node *pnode_base, tree_node *pnode, int opt)
{
	auto ptree = this;
	SIMPLE_TREE_NODE *pnode_temp;

#ifdef _DEBUG_UMTA
	if (pnode == nullptr || pnode_base == nullptr) {
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
BOOL tree::add_child(tree_node *pnode_base, tree_node *pnode, int opt)
{
	auto ptree = this;
	SIMPLE_TREE_NODE *pnode_temp;
	SIMPLE_TREE_NODE *pnode_last;

#ifdef _DEBUG_UMTA
	if (pnode == nullptr || pnode_base == nullptr) {
		debug_info("[simple_tree]: NULL pointer in tree::add_child");
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
 *	remove and destroy the	node and its descendant nodes
 *	@param
 *		ptree [in]		indicate the tree object
 *		pnode [in]		node to be destroyed
 *		del_func		callback function to free held resouce
 */
void tree::destroy_node(tree_node *pnode, SIMPLE_TREE_DELETE del_func)
{
	auto ptree = this;
	SIMPLE_TREE_NODE *pnode_temp;
	SIMPLE_TREE_NODE *pnode_parent;

#ifdef _DEBUG_UMTA
	if (pnode == nullptr || del_func == nullptr) {
		debug_info("[simple_tree]: NULL pointer in tree::destroy_node");
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
