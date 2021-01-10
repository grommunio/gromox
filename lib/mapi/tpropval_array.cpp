// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/mapidefs.h>
#include <gromox/tpropval_array.hpp>
#include <gromox/util.hpp>
#include <gromox/propval.hpp>
#include <cstdlib>
#include <cstring>

static BOOL tpropval_array_append(TPROPVAL_ARRAY *parray,
	const TAGGED_PROPVAL *ppropval)
{
	int count;
	TAGGED_PROPVAL *ppropvals;
	
	if (NULL == ppropval->pvalue) {
		debug_info("[tpropval_array]: pvalue is"
			" NULL in tpropval_array_append");
		return TRUE;
	}
	count = (parray->count/100 + 1) * 100;
	if (parray->count + 1 >= count) {
		count += 100;
		ppropvals = static_cast<TAGGED_PROPVAL *>(realloc(parray->ppropval, count * sizeof(TAGGED_PROPVAL)));
		if (NULL == ppropvals) {
			return FALSE;
		}
		parray->ppropval = ppropvals;
	}
	parray->ppropval[parray->count].proptag = ppropval->proptag;
	parray->ppropval[parray->count].pvalue = propval_dup(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
	if (NULL == parray->ppropval[parray->count].pvalue) {
		return FALSE;
	}
	parray->count ++;
	return TRUE;
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

BOOL tpropval_array_set_propval(TPROPVAL_ARRAY *parray,
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
				return FALSE;
			}
			propval_free(PROP_TYPE(ppropval->proptag), pvalue);
			return TRUE;
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

BOOL tpropval_array_init_internal(TPROPVAL_ARRAY *parray)
{
	parray->count = 0;
	parray->ppropval = static_cast<TAGGED_PROPVAL *>(malloc(100 * sizeof(TAGGED_PROPVAL)));
	if (NULL == parray->ppropval) {
		return FALSE;
	}
	return TRUE;
}

TPROPVAL_ARRAY* tpropval_array_init()
{
	auto parray = static_cast<TPROPVAL_ARRAY *>(malloc(sizeof(TPROPVAL_ARRAY)));
	if (NULL == parray) {
		return NULL;
	}
	if (FALSE == tpropval_array_init_internal(parray)) {
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
		if (FALSE == tpropval_array_append(
			parray1, parray->ppropval + i)) {
			tpropval_array_free(parray1);
			return NULL;
		}
	}
	return parray1;
}
