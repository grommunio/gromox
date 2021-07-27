// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/tarray_set.hpp>
#include <gromox/tpropval_array.hpp>
#include <cstdlib>
#include <cstring>

TARRAY_SET* tarray_set_init()
{
	auto pset = static_cast<TARRAY_SET *>(malloc(sizeof(TARRAY_SET)));
	if (NULL == pset) {
		return NULL;
	}
	pset->count = 0;
	pset->pparray = static_cast<TPROPVAL_ARRAY **>(malloc(100 * sizeof(TPROPVAL_ARRAY *)));
	if (NULL == pset->pparray) {
		free(pset);
		return NULL;
	}
	return pset;
}

void tarray_set_free(TARRAY_SET *pset)
{
	for (size_t i = 0; i < pset->count; ++i)
		if (NULL != pset->pparray[i]) {
			tpropval_array_free(pset->pparray[i]);
		}
	free(pset->pparray);
	free(pset);
}

void tarray_set_remove(TARRAY_SET *pset, uint32_t index)
{
	TPROPVAL_ARRAY *parray;
	
	if (index >= pset->count) {
		return;
	}
	parray = pset->pparray[index];
	pset->count --;
	if (index != pset->count) {
		memmove(pset->pparray + index, pset->pparray +
			index + 1, sizeof(void*)*(pset->count - index));
	}
	tpropval_array_free(parray);
}

bool tarray_set_append_internal(TARRAY_SET *pset, TPROPVAL_ARRAY *pproplist)
{
	TPROPVAL_ARRAY **pparray;
	
	if (pset->count >= 0xFF00) {
		return false;
	}
	uint16_t count = strange_roundup(pset->count, 100);
	if (pset->count + 1 >= count) {
		count += 100;
		pparray = static_cast<TPROPVAL_ARRAY **>(realloc(pset->pparray, count * sizeof(TPROPVAL_ARRAY *)));
		if (NULL == pparray) {
			return false;
		}
		pset->pparray = pparray;
	}
	pset->pparray[pset->count] = pproplist;
	pset->count ++;
	return true;
}

TARRAY_SET* tarray_set_dup(TARRAY_SET *pset)
{
	TARRAY_SET *pset1;
	TPROPVAL_ARRAY *pproplist;
	
	pset1 = tarray_set_init();
	if (NULL == pset1) {
		return NULL;
	}
	for (size_t i = 0; i < pset->count; ++i) {
		pproplist = tpropval_array_dup(pset->pparray[i]);
		if (NULL == pproplist) {
			tarray_set_free(pset1);
			return NULL;
		}
		if (!tarray_set_append_internal(pset1, pproplist)) {
			tpropval_array_free(pproplist);
			tarray_set_free(pset1);
			return NULL;
		}
	}
	return pset1;
}
