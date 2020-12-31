// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include "sortorder_set.h"
#include <string.h>
#include <stdlib.h>

void sortorder_set_free(SORTORDER_SET *pset)
{
	free(pset->psort);
	free(pset);
}

SORTORDER_SET* sortorder_set_dup(const SORTORDER_SET *pset)
{
	SORTORDER_SET *pset1;
	
	pset1 = malloc(sizeof(SORTORDER_SET));
	if (NULL == pset1) {
		return NULL;
	}
	pset1->count = pset->count;
	pset1->ccategories = pset->ccategories;
	pset1->cexpanded = pset->cexpanded;
	pset1->psort = malloc(sizeof(SORT_ORDER)*pset->count);
	if (NULL == pset1->psort) {
		free(pset1);
		return NULL;
	}
	memcpy(pset1->psort, pset->psort, sizeof(SORT_ORDER)*pset->count);
	return pset1;
}
