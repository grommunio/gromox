// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/mapidefs.h>
#include <gromox/tpropval_array.hpp>
#include <gromox/util.hpp>
#include <gromox/propval.hpp>
#include <cstdlib>
#include <cstring>

static bool tpropval_array_append(TPROPVAL_ARRAY *parray,
	const TAGGED_PROPVAL *ppropval)
{
	TAGGED_PROPVAL *ppropvals;
	
	if (NULL == ppropval->pvalue) {
		debug_info("[tpropval_array]: pvalue is"
			" NULL in tpropval_array_append");
		return true;
	}
	auto count = strange_roundup(parray->count, SR_GROW_TAGGED_PROPVAL);
	if (parray->count + 1U >= count) {
		count += SR_GROW_TAGGED_PROPVAL;
		ppropvals = static_cast<TAGGED_PROPVAL *>(realloc(parray->ppropval, count * sizeof(TAGGED_PROPVAL)));
		if (NULL == ppropvals) {
			return false;
		}
		parray->ppropval = ppropvals;
	}
	parray->ppropval[parray->count].proptag = ppropval->proptag;
	parray->ppropval[parray->count].pvalue = propval_dup(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
	if (NULL == parray->ppropval[parray->count].pvalue) {
		return false;
	}
	parray->count ++;
	return true;
}

void *tpropval_array_get_propval(const TPROPVAL_ARRAY *parray, uint32_t proptag)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (proptag == parray->ppropval[i].proptag) {
			return parray->ppropval[i].pvalue;
		}
	}
	return NULL;
}

bool tpropval_array_set_propval(TPROPVAL_ARRAY *parray,
	const TAGGED_PROPVAL *ppropval)
{
	int i;
	void *pvalue;
	
	for (i=0; i<parray->count; i++) {
		if (ppropval->proptag == parray->ppropval[i].proptag) {
			pvalue = parray->ppropval[i].pvalue;
			parray->ppropval[i].pvalue = propval_dup(
				PROP_TYPE(ppropval->proptag), ppropval->pvalue);
			if (NULL == parray->ppropval[i].pvalue) {
				parray->ppropval[i].pvalue = pvalue;
				return false;
			}
			propval_free(PROP_TYPE(ppropval->proptag), pvalue);
			return true;
		}
	}
	return tpropval_array_append(parray, ppropval);
}

void tpropval_array_remove_propval(TPROPVAL_ARRAY *parray, uint32_t proptag)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (proptag == parray->ppropval[i].proptag) {
			propval_free(PROP_TYPE(proptag), parray->ppropval[i].pvalue);
			parray->count --;
			if (i < parray->count) {
				memmove(parray->ppropval + i, parray->ppropval + i + 1,
					(parray->count - i) * sizeof(TAGGED_PROPVAL));
			}
			return;
		}
	}
}

bool tpropval_array_init_internal(TPROPVAL_ARRAY *parray)
{
	parray->count = 0;
	auto count = strange_roundup(parray->count, SR_GROW_TAGGED_PROPVAL);
	parray->ppropval = static_cast<TAGGED_PROPVAL *>(malloc(sizeof(TAGGED_PROPVAL) * count));
	return parray->ppropval != nullptr;
}

TPROPVAL_ARRAY* tpropval_array_init()
{
	auto parray = static_cast<TPROPVAL_ARRAY *>(malloc(sizeof(TPROPVAL_ARRAY)));
	if (NULL == parray) {
		return NULL;
	}
	if (!tpropval_array_init_internal(parray)) {
		free(parray);
		return NULL;
	}
	return parray;
}

void tpropval_array_free_internal(TPROPVAL_ARRAY *parray)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		propval_free(PROP_TYPE(parray->ppropval[i].proptag),
			parray->ppropval[i].pvalue);
	}
	free(parray->ppropval);
}

void tpropval_array_free(TPROPVAL_ARRAY *parray)
{
	tpropval_array_free_internal(parray);
	free(parray);
}

TPROPVAL_ARRAY* tpropval_array_dup(TPROPVAL_ARRAY *parray)
{
	int i;
	TPROPVAL_ARRAY *parray1;
	
	parray1 = tpropval_array_init();
	if (NULL == parray1) {
		return NULL;
	}
	for (i=0; i<parray->count; i++) {
		if (!tpropval_array_append(parray1, &parray->ppropval[i])) {
			tpropval_array_free(parray1);
			return NULL;
		}
	}
	return parray1;
}
