#pragma once
#include "single_list.h"
#include "double_list.h"
#include "assoc_array.h"

typedef struct _LANG_NODE {
	SINGLE_LIST_NODE node;
	ASSOC_ARRAY *parray;
	char language[32];
} LANG_NODE;


typedef struct _LANG_RESOURCE {
	SINGLE_LIST resource_list;
	LANG_NODE *pdefault_lang;
} LANG_RESOURCE;

#ifdef __cplusplus
extern "C" {
#endif


LANG_RESOURCE* lang_resource_init(const char *path);

void lang_resource_free(LANG_RESOURCE *presource);

const char* lang_resource_get(LANG_RESOURCE *presource, const char *tag,
	const char *language);

#ifdef __cplusplus
}
#endif
