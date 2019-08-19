#include "tpropval_array.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "ics_state.h"
#include "rop_util.h"
#include "idset.h"
#include <stdlib.h>
#include <string.h>


static void ics_state_clear(ICS_STATE *pstate)
{
	if (NULL != pstate->pgiven) {
		idset_free(pstate->pgiven);
		pstate->pgiven = NULL;
	}
	if (NULL != pstate->pseen) {
		idset_free(pstate->pseen);
		pstate->pseen = NULL;
	}
	if (NULL != pstate->pseen_fai) {
		idset_free(pstate->pseen_fai);
		pstate->pseen_fai = NULL;
	}
	if (NULL != pstate->pread) {
		idset_free(pstate->pread);
		pstate->pread = NULL;
	}
}

static BOOL ics_state_init(ICS_STATE *pstate)
{
	pstate->pgiven = idset_init(TRUE, REPL_TYPE_ID);
	if (NULL == pstate->pgiven) {
		return FALSE;
	}
	pstate->pseen = idset_init(TRUE, REPL_TYPE_ID);
	if (NULL == pstate->pseen) {
		return FALSE;
	}
	if (ICS_TYPE_CONTENTS == pstate->type) {
		pstate->pseen_fai = idset_init(TRUE, REPL_TYPE_ID);
		if (NULL == pstate->pseen_fai) {
			return FALSE;
		}
		pstate->pread = idset_init(TRUE, REPL_TYPE_ID);
		if (NULL == pstate->pread) {
			return FALSE;
		}
	}
	return TRUE;
}

ICS_STATE* ics_state_create(uint8_t type)
{
	ICS_STATE *pstate;
	
	pstate = malloc(sizeof(ICS_STATE));
	if (NULL == pstate) {
		return NULL;
	}
	memset(pstate, 0, sizeof(ICS_STATE));
	pstate->type = type;
	if (FALSE == ics_state_init(pstate)) {
		ics_state_clear(pstate);
		free(pstate);
		return NULL;
	}
	return pstate;
}

void ics_state_free(ICS_STATE *pstate)
{
	ics_state_clear(pstate);
	free(pstate);
}

BINARY* ics_state_serialize(ICS_STATE *pstate)
{
	BINARY *pbin;
	EXT_PUSH ext_push;
	TAGGED_PROPVAL propval;
	TPROPVAL_ARRAY *pproplist;
	static BINARY fake_bin = {
		.cb = 8,
		.pb = "\0\0\0\0\0\0\0\0"
	};
	
	if (ICS_TYPE_CONTENTS == pstate->type) {
		if (TRUE == idset_check_empty(pstate->pgiven) &&
			TRUE == idset_check_empty(pstate->pseen) &&
			TRUE == idset_check_empty(pstate->pseen_fai) &&
			TRUE == idset_check_empty(pstate->pread)) {
			return &fake_bin;
		}
	} else {
		if (TRUE == idset_check_empty(pstate->pgiven) &&
			TRUE == idset_check_empty(pstate->pseen)) {
			return &fake_bin;	
		}
	}
	pproplist = tpropval_array_init();
	if (NULL == pproplist) {
		return NULL;
	}
	
	pbin = idset_serialize(pstate->pgiven);
	if (NULL == pbin) {
		tpropval_array_free(pproplist);
		return NULL;
	}
	propval.proptag = META_TAG_IDSETGIVEN1;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		rop_util_free_binary(pbin);
		tpropval_array_free(pproplist);
		return NULL;
	}
	rop_util_free_binary(pbin);
	
	pbin = idset_serialize(pstate->pseen);
	if (NULL == pbin) {
		tpropval_array_free(pproplist);
		return NULL;
	}
	propval.proptag = META_TAG_CNSETSEEN;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		rop_util_free_binary(pbin);
		tpropval_array_free(pproplist);
		return NULL;
	}
	rop_util_free_binary(pbin);
	
	if (ICS_TYPE_CONTENTS == pstate->type) {
		pbin = idset_serialize(pstate->pseen_fai);
		if (NULL == pbin) {
			tpropval_array_free(pproplist);
			return NULL;
		}
		propval.proptag = META_TAG_CNSETSEENFAI;
		propval.pvalue = pbin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			rop_util_free_binary(pbin);
			tpropval_array_free(pproplist);
			return NULL;
		}
		rop_util_free_binary(pbin);
	}
	
	if (ICS_TYPE_CONTENTS == pstate->type &&
		FALSE == idset_check_empty(pstate->pread)) {
		pbin = idset_serialize(pstate->pread);
		if (NULL == pbin) {
			tpropval_array_free(pproplist);
			return NULL;
		}
		propval.proptag = META_TAG_CNSETREAD;
		propval.pvalue = pbin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			rop_util_free_binary(pbin);
			tpropval_array_free(pproplist);
			return NULL;
		}
		rop_util_free_binary(pbin);
	}
	if (FALSE == ext_buffer_push_init(&ext_push, NULL, 0, 0)) {
		tpropval_array_free(pproplist);
		return NULL;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_tpropval_array(
		&ext_push, pproplist)) {
		tpropval_array_free(pproplist);
		return NULL;	
	}
	tpropval_array_free(pproplist);
	pbin = common_util_alloc(sizeof(BINARY));
	pbin->cb = ext_push.offset;
	pbin->pb = common_util_alloc(pbin->cb);
	if (NULL == pbin->pb) {
		ext_buffer_push_free(&ext_push);
		return NULL;
	}
	memcpy(pbin->pb, ext_push.data, pbin->cb);
	ext_buffer_push_free(&ext_push);
	return pbin;
}

BOOL ics_state_deserialize(ICS_STATE *pstate, const BINARY *pbin)
{
	int i;
	IDSET *pset;
	EXT_PULL ext_pull;
	TPROPVAL_ARRAY propvals;
	
	ics_state_clear(pstate);
	ics_state_init(pstate);
	if (pbin->cb <= 16) {
		return TRUE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb,
			pbin->cb, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tpropval_array(
		&ext_pull, &propvals)) {
		return FALSE;	
	}
	for (i=0; i<propvals.count; i++) {
		switch (propvals.ppropval[i].proptag) {
		case META_TAG_IDSETGIVEN1:
			pset = idset_init(FALSE, REPL_TYPE_ID);
			if (NULL == pset) {
				return FALSE;
			}
			if (FALSE == idset_deserialize(pset,
				propvals.ppropval[i].pvalue) ||
				FALSE == idset_convert(pset)) {
				idset_free(pset);
				return FALSE;
			}
			idset_free(pstate->pgiven);
			pstate->pgiven = pset;
			break;
		case META_TAG_CNSETSEEN:
			pset = idset_init(FALSE, REPL_TYPE_ID);
			if (NULL == pset) {
				return FALSE;
			}
			if (FALSE == idset_deserialize(pset,
				propvals.ppropval[i].pvalue) ||
				FALSE == idset_convert(pset)) {
				idset_free(pset);
				return FALSE;
			}
			idset_free(pstate->pseen);
			pstate->pseen = pset;
			break;
		case META_TAG_CNSETSEENFAI:
			if (ICS_TYPE_CONTENTS == pstate->type) {
				pset = idset_init(FALSE, REPL_TYPE_ID);
				if (NULL == pset) {
					return FALSE;
				}
				if (FALSE == idset_deserialize(pset,
					propvals.ppropval[i].pvalue) ||
					FALSE == idset_convert(pset)) {
					idset_free(pset);
					return FALSE;
				}
				idset_free(pstate->pseen_fai);
				pstate->pseen_fai = pset;
			}
			break;
		case META_TAG_CNSETREAD:
			if (ICS_TYPE_CONTENTS == pstate->type) {
				pset = idset_init(FALSE, REPL_TYPE_ID);
				if (NULL == pset) {
					return FALSE;
				}
				if (FALSE == idset_deserialize(pset,
					propvals.ppropval[i].pvalue) ||
					FALSE == idset_convert(pset)) {
					idset_free(pset);
					return FALSE;
				}
				idset_free(pstate->pread);
				pstate->pread = pset;
			}
			break;
		}
	}
	return TRUE;
}
