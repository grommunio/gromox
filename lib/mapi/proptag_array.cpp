// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdlib>
#include <cstring>
#include <gromox/proptag_array.hpp>

using namespace gromox;

static bool proptag_array_init_internal(PROPTAG_ARRAY *pproptags)
{
	
	pproptags->count = 0;
	auto count = strange_roundup(pproptags->count, SR_GROW_PROPTAG_ARRAY);
	pproptags->pproptag = me_alloc<uint32_t>(count);
	return pproptags->pproptag != nullptr;
}

PROPTAG_ARRAY* proptag_array_init()
{
	auto pproptags = me_alloc<PROPTAG_ARRAY>();
	if (NULL == pproptags) {
		return NULL;
	}
	if (!proptag_array_init_internal(pproptags)) {
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

bool proptag_array_append(PROPTAG_ARRAY *pproptags, uint32_t proptag)
{
	for (size_t i = 0; i < pproptags->count; ++i)
		if (pproptags->pproptag[i] == proptag) {
			return true;
		}
	auto count = strange_roundup(pproptags->count, SR_GROW_PROPTAG_ARRAY);
	if (pproptags->count + 1U >= count) {
		count += SR_GROW_PROPTAG_ARRAY;
		auto pproptag = re_alloc<uint32_t>(pproptags->pproptag, count);
		if (NULL == pproptag) {
			return false;
		}
		pproptags->pproptag = pproptag;
	}
	pproptags->pproptag[pproptags->count++] = proptag;
	return true;
}

void proptag_array_remove(PROPTAG_ARRAY *pproptags, uint32_t proptag)
{
	for (unsigned int i = 0; i < pproptags->count; ++i) {
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

static bool proptag_array_dup_internal(const PROPTAG_ARRAY *pproptags,
    PROPTAG_ARRAY *pproptags_dst)
{
	auto count = strange_roundup(pproptags->count, SR_GROW_PROPTAG_ARRAY);
	pproptags_dst->count = pproptags->count;
	pproptags_dst->pproptag = me_alloc<uint32_t>(count);
	if (NULL == pproptags_dst->pproptag) {
		return false;
	}
	memcpy(pproptags_dst->pproptag, pproptags->pproptag,
				sizeof(uint32_t)*pproptags->count);
	return true;
}

PROPTAG_ARRAY* proptag_array_dup(const PROPTAG_ARRAY *pproptags)
{
	auto pproptags1 = me_alloc<PROPTAG_ARRAY>();
	if (NULL == pproptags1) {
		return NULL;
	}
	if (!proptag_array_dup_internal(pproptags, pproptags1)) {
		free(pproptags1);
		return NULL;
	}
	return pproptags1;
}

