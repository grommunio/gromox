// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *	A simple single linked list skeleton that provide some fundamental 
 *	function of a list. The client should maintain the Mem of the List 
 *	node him of herself.
 *
 */
#include <gromox/single_list.hpp>
#include <gromox/util.hpp>

/*
 *	init a single linked list
 *
 *	@param
 *		plist [in]		the list object to init
 */
void single_list_init(SINGLE_LIST* plist)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist) {
		mlog(LV_DEBUG, "single_list: single_list_init, param NULL");
		return;
	}
#endif
	plist->list_head = NULL;
	plist->list_tail = NULL;
	plist->cur_size	 = 0;
}

/*
 *	append one node at the end of the list
 *
 *	@param
 *		plist [in]		the list to append 
 *						the node to
 *		node  [in]		the appended node
 *
 *	@return
 *		TRUE		success
 *		FALSE		fail
 */
BOOL single_list_append_as_tail(SINGLE_LIST* plist,
	SINGLE_LIST_NODE* node)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist || NULL == node) {
		mlog(LV_DEBUG, "single_list: single_list_append_as_tail, param NULL");
		return FALSE;
	}
#endif
	if (0 == plist->cur_size) {
		plist->list_head = node;
		plist->list_tail = node;
	} else {
		plist->list_tail->next	
						 = node;
		plist->list_tail = node;
	}
	plist->cur_size		+= 1;
	return TRUE;
}

/*
 *	insert the specified node at the end of the list
 *
 *	@param
 *		plist [in]		the list the insert the node
 *		node  [in]		the node that will be insert
 *
 *	@return
 *		TRUE		success
 *		FALSE		fail
 */
BOOL single_list_insert_as_head(SINGLE_LIST* plist, SINGLE_LIST_NODE* node)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist || NULL == node) {
		mlog(LV_DEBUG, "single_list: single_list_insert_as_head, param NULL");
		return FALSE;
	}
#endif
	if (0 == plist->cur_size) {
		plist->list_head = node;
		plist->list_tail = node;
	} else {
		node->next = plist->list_head;
		plist->list_head = node;
	}
	plist->cur_size += 1;
	return TRUE;
}

/*
 *	remove the front node from the specified list
 *
 *	@param	
 *		plist [in]	the specified list
 *
 *	@return
 *		the pointer pointer to the node at the 
 *		front of the list
 *		NULL if the list is empty
 */
SINGLE_LIST_NODE *single_list_pop_front(SINGLE_LIST *plist)
{
	SINGLE_LIST_NODE*  node = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == plist) {
		mlog(LV_DEBUG, "single_list: single_list_pop_front, param NULL");
		return NULL;
	}
#endif
	if (plist->cur_size <= 0) {
		return NULL;
	}
	node = plist->list_head;
	if (1 == plist->cur_size) {
		plist->list_head = NULL;
		plist->list_tail = NULL;
	} else {
		plist->list_head = 
			node->next;
	}
	plist->cur_size -= 1;
	return node;
}

/*
 *	get the front node at the specified list
 *
 *	@param
 *		plist [in]		the specified list
 *
 *	@return
 *		the pointer that point to the front
 *		node of the list
 *		NULL, if the list is empty
 */
SINGLE_LIST_NODE* single_list_get_head(SINGLE_LIST* plist)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist) {
		mlog(LV_DEBUG, "single_list: list_get_head, param NULL");
		return NULL;
	}
#endif
	if (plist->cur_size <= 0) {
		return NULL;
	}
	return plist->list_head;
}

/*
 *	get the last node from the specified list
 *
 *	@param
 *		plist [in]		the specified list
 *
 *	@return
 *		the pointer that point to the last
 *		node of the list
 *		NULL, if the list is empty
 */
SINGLE_LIST_NODE* single_list_get_tail(SINGLE_LIST* plist)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist) {
		mlog(LV_DEBUG, "single_list: list_get_tail, param NULL");
		return NULL;
	}
#endif
	if (plist->cur_size <= 0) {
		return NULL;
	}
	return plist->list_tail;
}

SINGLE_LIST_NODE* single_list_get_after(SINGLE_LIST* plist,
	SINGLE_LIST_NODE* base_node)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist || NULL == base_node) { 
		mlog(LV_DEBUG, "single_list: list_get_after, param NULL");
		return NULL;
	}
#endif
	if (base_node == plist->list_tail) {
		return NULL;
	}
	return base_node->next;
}

/*
 *	return the number of the node in the specified list
 *
 *	@param	
 *		plist [in]		the specified list
 *
 *	@return
 *		the number of nodes in the list
 */
size_t single_list_get_nodes_num(const SINGLE_LIST *plist)
{
#ifdef _DEBUG_UMTA
	if (NULL == plist) {
		mlog(LV_DEBUG, "single_list: single_list_get_nodes_num, param NULL");
		return 0;
	}
#endif
	return plist->cur_size;
}

const SINGLE_LIST_NODE *single_list_get_head(const SINGLE_LIST *l)
{
	return single_list_get_head(deconst(l));
}

const SINGLE_LIST_NODE *single_list_get_tail(const SINGLE_LIST *l)
{
	return single_list_get_tail(deconst(l));
}

const SINGLE_LIST_NODE *single_list_get_after(const SINGLE_LIST *l, const SINGLE_LIST_NODE *bn)
{
	return single_list_get_after(deconst(l), deconst(bn));
}
