// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*	
 *	double list's operating functions, including inserting, appending, pop,
 *	push ... Caution: double_list is not thread-safe, use mutex to control
 *	the visiting of double list.
 */
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#include <gromox/util.hpp>

using namespace gromox;

void double_list_init(DOUBLE_LIST* plist)
{
#ifdef _DEBUG_UMTA	  
	if (NULL == plist) {
		mlog(LV_DEBUG, "double_list: double_list_init, param NULL");
		return;
	}
#endif
	plist->phead = NULL;
	plist->nodes_num = 0;
}

void double_list_free(DOUBLE_LIST* plist)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist) {
		mlog(LV_DEBUG, "double_list: double_list_free, param NULL");
		return;
	}
#endif	  
	plist->phead = NULL;
	plist->nodes_num = 0;
}

/*
 *	  insert a node into a double list as it will be treated as the head
 *	  @param
 *		  plist [in]	indicate the list object
 *		  pnode [in]	node to insert	  
 */
void double_list_insert_as_head(DOUBLE_LIST *plist, DOUBLE_LIST_NODE *pnode)
{
	DOUBLE_LIST_NODE *phead, *ptail;
#ifdef _DEBUG_UMTA	  
	if (NULL == plist || NULL == pnode) {
		mlog(LV_DEBUG, "double_list: double_list_insert_as_head, param NULL");
		return;
	}
#endif	  
	if (NULL == plist->phead) {
		plist->phead = pnode;
		pnode->pprev = pnode;
		pnode->pnext = pnode;
		plist->nodes_num = 1;
		return;
	} else {
		phead = plist->phead;
		ptail = phead->pprev;
		pnode->pnext = phead;
		pnode->pprev = ptail;
		phead->pprev = pnode;
		if (phead->pnext == phead) {
			phead->pnext = pnode;
		} else {
			ptail->pnext = pnode;
		}
		plist->phead = pnode;
		plist->nodes_num ++;
	}
}

/*
 *	  append a node into the list and it will be treated as the tail of the list
 *	  @param
 *		  plist [in]	indicate the list object
 *		  pnode [in]	node to insert	  
 */
void double_list_append_as_tail(DOUBLE_LIST *plist, DOUBLE_LIST_NODE *pnode)
{
	DOUBLE_LIST_NODE *phead, *ptail;
#ifdef _DEBUG_UMTA	  
	if (NULL == plist || NULL == pnode) {
		mlog(LV_DEBUG, "double_list: double_list_append_as_tail, param NULL");
		return;
	}
#endif
	if (NULL == plist->phead) {
		plist->phead = pnode;
		pnode->pprev = pnode;
		pnode->pnext = pnode;
		plist->nodes_num = 1;
		return;
	} else {
		phead = plist->phead;
		ptail = phead->pprev;
		pnode->pnext = phead;
		pnode->pprev = ptail;
		phead->pprev = pnode;
		if (phead->pnext == phead) {
			phead->pnext = pnode;
		} else {
			ptail->pnext = pnode;
		}
		plist->nodes_num ++;
	}
}

/*
 *	  insert a node before the pbase_node
 *	  @param
 *		  plist [in]		indicate the list object
 *		  pbase_node [in]	the base node to be compared with
 *		  pnode [in]		the node te insert
 */
void double_list_insert_before(DOUBLE_LIST *plist, 
	DOUBLE_LIST_NODE *pbase_node, DOUBLE_LIST_NODE *pnode)
{	 
	DOUBLE_LIST_NODE *ptemp;
#ifdef _DEBUG_UMTA	  
	if (NULL == plist || NULL == pbase_node || pnode == NULL) {
		mlog(LV_DEBUG, "double_list: double_list_insert_before, param NULL");
		return;
	}
#endif
	if (pbase_node == plist->phead) {
		double_list_insert_as_head(plist, pnode);
		return;
	}
	ptemp = pbase_node->pprev;
	pbase_node->pprev = pnode;
	ptemp->pnext = pnode;
	pnode->pnext = pbase_node;
	pnode->pprev = ptemp; 
	plist->nodes_num ++;
}

/*
 *	  append a node after pbase_node 
 *	  @param
 *		  plist [in]		indicate the list object
 *		  pbase_node [in]	the base node to be compared with
 *		  pnode [in]		the node to insert
 */
void double_list_append_after(DOUBLE_LIST *plist, DOUBLE_LIST_NODE *pbase_node,
	DOUBLE_LIST_NODE *pnode)
{	 
	DOUBLE_LIST_NODE *ptemp;
#ifdef _DEBUG_UMTA
	if (NULL == plist || NULL == pbase_node || NULL == pnode) {
		mlog(LV_DEBUG, "double_list: double_list_append_after, param NULL");
		return ;
	}
#endif
	if (pbase_node == plist->phead->pprev) {
		double_list_append_as_tail(plist, pnode);
		return;
	}
	ptemp = pbase_node->pnext;
	pbase_node->pnext = pnode;
	ptemp->pprev = pnode;
	pnode->pnext = ptemp;
	pnode->pprev = pbase_node;
	plist->nodes_num ++;
}

/*
 *	  remove a node from list
 *	  @param
 *		  plist [in]		indicate the object
 *		  pnode [in]		the node to remove
 */
void double_list_remove(DOUBLE_LIST *plist, DOUBLE_LIST_NODE *pnode)
{
	DOUBLE_LIST_NODE *phead, *ptail;
#ifdef _DEBUG_UMTA	  
	if (NULL == plist || NULL == pnode) {
		mlog(LV_DEBUG, "double_list: double_list_remove, param NULL");
		return;
	}
#endif		  
	phead = plist->phead;
	ptail = phead->pprev;
	if (phead == pnode) {
		if (ptail == phead) {
			plist->phead = NULL;
			pnode->pprev = NULL;
			pnode->pnext = NULL;
			plist->nodes_num = 0;
			return;
		} else {
			if (ptail == phead->pnext) {
				ptail->pnext = ptail;
				ptail->pprev = ptail;
				plist->phead = ptail;
				pnode->pprev = NULL;
				pnode->pnext = NULL;
				plist->nodes_num --;
				return;   
			} else {
				phead->pnext->pprev = ptail;
				ptail->pnext = phead->pnext;
				plist->phead = phead->pnext;
				pnode->pnext = NULL;
				pnode->pprev = NULL;
				plist->nodes_num --;
				return;
			}
		}
	}
	
	pnode->pnext->pprev = pnode->pprev;
	pnode->pprev->pnext = pnode->pnext;
	pnode->pprev = NULL;
	pnode->pnext = NULL;
	plist->nodes_num --;
}

/*
 *	  popup a node from head
 *	  @param
 *		  plist [in]	indicate the list object
 *	  @return
 *		  the pointer to the poped node
 */
DOUBLE_LIST_NODE *double_list_pop_front(DOUBLE_LIST *plist)
{
	DOUBLE_LIST_NODE* pnode;
#ifdef _DEBUG_UMTA
	if (NULL == plist) {
		mlog(LV_DEBUG, "double_list: double_list_pop_front, param NULL");
		return NULL;
	}
#endif
	pnode = plist->phead;
	if (NULL == pnode) {
		return NULL;
	}
	double_list_remove(plist, pnode);
	return pnode;
}

/*
 *	  merge two lists into one
 *	  @param
 *		  plist_des [in,out]   indicate the destination list
 *		  plist	   [in]		   indicate the list to append
 */
void double_list_append_list(DOUBLE_LIST *plist_des, DOUBLE_LIST *plist)
{	 
	DOUBLE_LIST_NODE* phead_des;
	DOUBLE_LIST_NODE* ptail_des;
	DOUBLE_LIST_NODE* phead;
	DOUBLE_LIST_NODE* ptail;
#ifdef _DEBUG_UMTA
	if (NULL == plist_des || NULL == plist) {
		mlog(LV_DEBUG, "double_list: double_list_append_list, param NULL");
		return;
	}
#endif

	if(NULL == plist_des->phead) {
		plist_des->phead = plist->phead;
		plist_des->nodes_num = plist->nodes_num;
		return;
	}
	
	if(NULL == plist->phead) {
		return;
	}
	
	phead_des = plist_des->phead;
	ptail_des = plist_des->phead->pprev;
	phead = plist->phead;
	ptail = plist->phead->pprev;
	plist->phead = NULL;
	if(phead_des == ptail_des) {
		if(phead == ptail) {
			phead_des->pnext = phead;
			phead_des->pprev = phead;
			phead->pnext = phead_des;
			phead->pprev = phead_des;
			plist_des->nodes_num += plist->nodes_num;
			return;
		} else {
			phead_des->pnext = phead;
			phead_des->pprev = ptail;
			phead->pprev = phead_des;
			ptail->pnext = phead_des;
			plist_des->nodes_num += plist->nodes_num;
			return;
		}
	}
	if(phead == ptail) {
		phead_des->pprev = phead;
		ptail_des->pnext = phead;
		phead->pprev = ptail_des;
		phead->pnext = phead_des;
		plist_des->nodes_num += plist->nodes_num;
		return;
	}

	phead_des->pprev = ptail;
	ptail_des->pnext = phead;
	phead->pprev = ptail_des;
	ptail->pnext = phead_des;
	plist_des->nodes_num += plist->nodes_num;
}

/*
 *	  get the node before pbase_node
 *	  @param	
 *		  plist [in]		indicate the list object
 *		  pbase_node [in]	the node to be compared with
 *	  @return
 *		  the pointer to node got from list
 */
DOUBLE_LIST_NODE* double_list_get_before(DOUBLE_LIST *plist, 
	DOUBLE_LIST_NODE *pbase_node)
{
#ifdef _DEBUG_UMTA	  
	if (NULL == plist || NULL == pbase_node) {
		mlog(LV_DEBUG, "double_list: double_list_get_before, param NULL");
		return NULL;
	}
#endif
	if (NULL == plist->phead) {
		return NULL;
	}

	if (plist->phead == pbase_node) {
		return NULL;
	}
	return pbase_node->pprev;
}

/*
 *	  get the node after pbase_node
 *	  @param
 *		  plist [in]		indicate the list object
 *		  pbase_node [in]	the node to be compared with
 *	@return
 *		  the pointer to node got from list
 */
DOUBLE_LIST_NODE* double_list_get_after(DOUBLE_LIST *plist, 
	DOUBLE_LIST_NODE *pbase_node)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist || NULL == pbase_node) {
		mlog(LV_DEBUG, "double_list: double_list_get_after, param NULL");
		return NULL;
	}
#endif
	if (NULL == plist->phead) {
		return NULL;
	}
	if (pbase_node == plist->phead->pprev) {
		return NULL;
	}
	return pbase_node->pnext;
}

/*
 *	  get number of nodes in list
 *	  @param
 *		  plist [in]	indicate the list object
 *	  @return
 *		  the number of the nodes
 */
size_t double_list_get_nodes_num(const DOUBLE_LIST *plist)
{
#ifndef _DEBUG_UMTA
	if (NULL == plist) {
		mlog(LV_DEBUG, "double_list: double_list_get_nodes_num, param NULL");
		return 0;
	}
#endif
	return plist->nodes_num;
}

/*
 *	  get the head of list
 *	  @param
 *		  plist [in]	indicate the list object
 *	  @return
 *		  the pointer of head node
 */
DOUBLE_LIST_NODE* double_list_get_head(DOUBLE_LIST *plist)
{
#ifdef _DEBUG_UMTA	  
	if (NULL == plist) {
		mlog(LV_DEBUG, "double_list: double_list_get_head, param NULL");
		return NULL;
	}
#endif
	return plist->phead;
}

/*
 *	  get the head of list
 *	  @param
 *		  plist [in]  indicate the list object
 *	  @return
 *		  the pointer of head node
 */
DOUBLE_LIST_NODE* double_list_get_tail(DOUBLE_LIST *plist)
{	 
#ifdef _DEBUG_UMTA
	if(NULL == plist) {
		mlog(LV_DEBUG, "double_list: double_list_get_tail, param NULL");
		return NULL;
	}
#endif
	if (NULL == plist->phead) {
		return NULL;
	}
	return plist->phead->pprev;
}

const DOUBLE_LIST_NODE *double_list_get_before(const DOUBLE_LIST *l, const DOUBLE_LIST_NODE *n)
{
	return double_list_get_before(deconst(l), deconst(n));
}

const DOUBLE_LIST_NODE *double_list_get_after(const DOUBLE_LIST *l, const DOUBLE_LIST_NODE *n)
{
	return double_list_get_after(deconst(l), deconst(n));
}

const DOUBLE_LIST_NODE *double_list_get_head(const DOUBLE_LIST *l)
{
	return double_list_get_head(deconst(l));
}

const DOUBLE_LIST_NODE *double_list_get_tail(const DOUBLE_LIST *l)
{
	return double_list_get_tail(deconst(l));
}
