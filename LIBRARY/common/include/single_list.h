#pragma once
#include "common_types.h"

typedef struct _SINGLE_LIST_NODE {
    void*   pdata;
    struct _SINGLE_LIST_NODE* next;
} SINGLE_LIST_NODE;

typedef struct _LIST {
    SINGLE_LIST_NODE  *list_head;
    SINGLE_LIST_NODE  *list_tail;
    size_t      cur_size;
} SINGLE_LIST;

#ifdef __cplusplus
extern "C" {
#endif

void    single_list_init(SINGLE_LIST* plist);

void    single_list_free(SINGLE_LIST* plist);

BOOL    single_list_append_as_tail(SINGLE_LIST* plist, SINGLE_LIST_NODE* node);

BOOL    single_list_insert_as_head(SINGLE_LIST* plist, SINGLE_LIST_NODE* node);

BOOL    single_list_is_empty(SINGLE_LIST* plist);

SINGLE_LIST_NODE*  single_list_get_from_head(SINGLE_LIST* plist);

SINGLE_LIST_NODE*  single_list_get_from_tail(SINGLE_LIST* plist);

SINGLE_LIST_NODE*  single_list_get_head(SINGLE_LIST* plist);

SINGLE_LIST_NODE*  single_list_get_tail(SINGLE_LIST* plist);

SINGLE_LIST_NODE*  single_list_get_after(SINGLE_LIST* plist, SINGLE_LIST_NODE* base_node);

size_t  single_list_get_nodes_num(SINGLE_LIST* plist);

#ifdef __cplusplus
}
#endif
