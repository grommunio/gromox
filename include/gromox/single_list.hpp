#pragma once
#include <gromox/common_types.hpp>
#include <gromox/defs.h>

struct SINGLE_LIST_NODE {
    void*   pdata;
	SINGLE_LIST_NODE *next;
};

struct SINGLE_LIST {
    SINGLE_LIST_NODE  *list_head;
    SINGLE_LIST_NODE  *list_tail;
    size_t      cur_size;
};

void    single_list_init(SINGLE_LIST* plist);
BOOL    single_list_append_as_tail(SINGLE_LIST* plist, SINGLE_LIST_NODE* node);
BOOL    single_list_insert_as_head(SINGLE_LIST* plist, SINGLE_LIST_NODE* node);
extern SINGLE_LIST_NODE *single_list_pop_front(SINGLE_LIST *);
SINGLE_LIST_NODE*  single_list_get_head(SINGLE_LIST* plist);
extern GX_EXPORT const SINGLE_LIST_NODE *single_list_get_head(const SINGLE_LIST *);
SINGLE_LIST_NODE*  single_list_get_tail(SINGLE_LIST* plist);
extern GX_EXPORT const SINGLE_LIST_NODE *single_list_get_tail(const SINGLE_LIST *);
SINGLE_LIST_NODE*  single_list_get_after(SINGLE_LIST* plist, SINGLE_LIST_NODE* base_node);
extern GX_EXPORT const SINGLE_LIST_NODE *single_list_get_after(const SINGLE_LIST *, const SINGLE_LIST_NODE *);
extern GX_EXPORT size_t single_list_get_nodes_num(const SINGLE_LIST *);
