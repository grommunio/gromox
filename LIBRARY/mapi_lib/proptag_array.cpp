// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include "proptag_array.h"
#include <stdlib.h>
#include <string.h>

BOOL proptag_array_init_internal(PROPTAG_ARRAY *pproptags)
{
	
	pproptags->count = 0;
	pproptags->pproptag = static_cast<uint32_t *>(malloc(sizeof(uint32_t) * 100));
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	return TRUE;
}

PROPTAG_ARRAY* proptag_array_init()
{
	auto pproptags = static_cast<PROPTAG_ARRAY *>(malloc(sizeof(PROPTAG_ARRAY)));
	if (NULL == pproptags) {
		return NULL;
	}
	if (FALSE == proptag_array_init_internal(pproptags)) {
		free(pproptags);
		return NULL;
	}
	return pproptags;
}

void proptag_array_free_internal(PROPTAG_ARRAY *pproptags)
{
	free(pproptags->pproptag);
}

void proptag_array_free(PROPTAG_ARRAY *pproptags)
{
	proptag_array_free_internal(pproptags);
	free(pproptags);
}

void proptag_array_clear(PROPTAG_ARRAY *pproptags)
{
	pproptags->count = 0;
}

BOOL proptag_array_append(PROPTAG_ARRAY *pproptags, uint32_t proptag)
{
	int i;
	uint32_t count;
	uint32_t *pproptag;
	
	for (i=0; i<pproptags->count; i++) {
		if (pproptags->pproptag[i] == proptag) {
			return TRUE;
		}
	}
	count = (pproptags->count / 100 + 1) * 100;
	if (pproptags->count + 1 >= count) {
		count += 100;
		pproptag = static_cast<uint32_t *>(realloc(pproptags->pproptag, sizeof(uint32_t) * count));
		if (NULL == pproptag) {
			return FALSE;
		}
		pproptags->pproptag = pproptag;
	}
	pproptags->pproptag[pproptags->count] = proptag;
	pproptags->count ++;
	return TRUE;
}

void proptag_array_remove(PROPTAG_ARRAY *pproptags, uint32_t proptag)
{
	int i;
	
	for (i=0; i<pproptags->count; i++) {
		if (proptag == pproptags->pproptag[i]) {
			pproptags->count --;
			if (i < pproptags->count) {
				memmove(pproptags->pproptag + i, pproptags->pproptag + i + 1,
					(pproptags->count - i) * sizeof(uint32_t));
			}
			return;
		}
	}
}

BOOL proptag_array_check(const PROPTAG_ARRAY *pproptags, uint32_t proptag)
{
	int i;
	
	for (i=0; i<pproptags->count; i++) {
		if (proptag == pproptags->pproptag[i]) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL proptag_array_dup_internal(const PROPTAG_ARRAY *pproptags,
	PROPTAG_ARRAY *pproptags_dst)
{
	uint32_t count;
	
	count = (pproptags->count / 100 + 1) * 100;
	pproptags_dst->count = pproptags->count;
	pproptags_dst->pproptag = static_cast<uint32_t *>(malloc(sizeof(uint32_t) * count));
	if (NULL == pproptags_dst->pproptag) {
		return FALSE;
	}
	memcpy(pproptags_dst->pproptag, pproptags->pproptag,
				sizeof(uint32_t)*pproptags->count);
	return TRUE;
}

PROPTAG_ARRAY* proptag_array_dup(const PROPTAG_ARRAY *pproptags)
{
	auto pproptags1 = static_cast<PROPTAG_ARRAY *>(malloc(sizeof(PROPTAG_ARRAY)));
	if (NULL == pproptags1) {
		return NULL;
	}
	if (FALSE == proptag_array_dup_internal(pproptags, pproptags1)) {
		free(pproptags1);
		return NULL;
	}
	return pproptags1;
}

