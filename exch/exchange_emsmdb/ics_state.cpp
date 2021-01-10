// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/tpropval_array.hpp>
#include "common_util.h"
#include "ics_state.h"
#include <gromox/rop_util.hpp>
#include <gromox/idset.hpp>
#include <cstdlib>
#include <cstring>

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

ICS_STATE* ics_state_create(LOGON_OBJECT *plogon, int type)
{
	BINARY tmp_bin;
	
	auto pstate = static_cast<ICS_STATE *>(malloc(sizeof(ICS_STATE)));
	if (NULL == pstate) {
		return NULL;
	}
	memset(pstate, 0, sizeof(ICS_STATE));
	tmp_bin.cb = sizeof(void*);
	tmp_bin.pv = &plogon;
	pstate->pseen = idset_init(TRUE, REPL_TYPE_GUID);
	if (NULL == pstate->pseen) {
		ics_state_clear(pstate);
		return NULL;
	}
	if (FALSE == idset_register_mapping(pstate->pseen,
		&tmp_bin, common_util_mapping_replica)) {
		ics_state_clear(pstate);
		return NULL;
	}
	switch (type) {
	case ICS_STATE_CONTENTS_DOWN:
		pstate->pgiven = idset_init(TRUE, REPL_TYPE_GUID);
		if (NULL == pstate->pgiven) {
			ics_state_clear(pstate);
			return NULL;
		}
		if (FALSE == idset_register_mapping(pstate->pgiven,
			&tmp_bin, common_util_mapping_replica)) {
			ics_state_clear(pstate);
			return NULL;
		}
		pstate->pseen_fai = idset_init(TRUE, REPL_TYPE_GUID);
		if (NULL == pstate->pseen_fai) {
			ics_state_clear(pstate);
			return NULL;
		}
		if (FALSE == idset_register_mapping(pstate->pseen_fai,
			&tmp_bin, common_util_mapping_replica)) {
			ics_state_clear(pstate);
			return NULL;
		}
		pstate->pread = idset_init(TRUE, REPL_TYPE_GUID);
		if (NULL == pstate->pread) {
			ics_state_clear(pstate);
			return NULL;
		}
		if (FALSE == idset_register_mapping(pstate->pread,
			&tmp_bin, common_util_mapping_replica)) {
			ics_state_clear(pstate);
			return NULL;
		}
		break;
	case ICS_STATE_HIERARCHY_DOWN:
		pstate->pgiven = idset_init(TRUE, REPL_TYPE_GUID);
		if (NULL == pstate->pgiven) {
			ics_state_clear(pstate);
			return NULL;
		}
		if (FALSE == idset_register_mapping(pstate->pgiven,
			&tmp_bin, common_util_mapping_replica)) {
			ics_state_clear(pstate);
			return NULL;
		}
		break;
	case ICS_STATE_CONTENTS_UP:
		pstate->pgiven = idset_init(TRUE, REPL_TYPE_GUID);
		if (NULL == pstate->pgiven) {
			ics_state_clear(pstate);
			return NULL;
		}
		if (FALSE == idset_register_mapping(pstate->pgiven,
			&tmp_bin, common_util_mapping_replica)) {
			ics_state_clear(pstate);
			return NULL;
		}
		pstate->pseen_fai = idset_init(TRUE, REPL_TYPE_GUID);
		if (NULL == pstate->pseen_fai) {
			ics_state_clear(pstate);
			return NULL;
		}
		if (FALSE == idset_register_mapping(pstate->pseen_fai,
			&tmp_bin, common_util_mapping_replica)) {
			ics_state_clear(pstate);
			return NULL;
		}
		pstate->pread = idset_init(TRUE, REPL_TYPE_GUID);
		if (NULL == pstate->pread) {
			ics_state_clear(pstate);
			return NULL;
		}
		if (FALSE == idset_register_mapping(pstate->pread,
			&tmp_bin, common_util_mapping_replica)) {
			ics_state_clear(pstate);
			return NULL;
		}
		break;
	case ICS_STATE_HIERARCHY_UP:
		break;
	}
	pstate->type = type;
	return pstate;
}

void ics_state_free(ICS_STATE *pstate)
{
	ics_state_clear(pstate);
	free(pstate);
}

BOOL ics_state_append_idset(ICS_STATE *pstate,
	uint32_t state_property, IDSET *pset)
{
	switch (state_property) {
	case META_TAG_IDSETGIVEN:
	case META_TAG_IDSETGIVEN1:
		if (NULL != pstate->pgiven) {
			idset_free(pstate->pgiven);
		}
		pstate->pgiven = pset;
		return TRUE;
	case META_TAG_CNSETSEEN:
		if (NULL != pstate->pseen) {
			if ((ICS_STATE_CONTENTS_UP == pstate->type ||
				ICS_STATE_HIERARCHY_UP == pstate->type) &&
				FALSE == idset_check_empty(pstate->pseen)) {
				if (FALSE == idset_concatenate(pset, pstate->pseen)) {
					return FALSE;
				}
			}
			idset_free(pstate->pseen);
		}
		pstate->pseen = pset;
		return TRUE;
	case META_TAG_CNSETSEENFAI:
		if (NULL != pstate->pseen_fai) {
			if (ICS_STATE_CONTENTS_UP == pstate->type &&
				FALSE == idset_check_empty(pstate->pseen_fai)) {
				if (FALSE == idset_concatenate(pset, pstate->pseen_fai)) {
					return FALSE;
				}
			}
			idset_free(pstate->pseen_fai);
		}
		pstate->pseen_fai = pset;
		return TRUE;
	case META_TAG_CNSETREAD:
		if (NULL != pstate->pread) {
			if (ICS_STATE_CONTENTS_UP == pstate->type &&
				FALSE == idset_check_empty(pstate->pread)) {
				if (FALSE == idset_concatenate(pset, pstate->pread)) {
					return FALSE;
				}
			}
			idset_free(pstate->pread);
		}
		pstate->pread = pset;
		return TRUE;
	}
	return FALSE;
}

TPROPVAL_ARRAY* ics_state_serialize(ICS_STATE *pstate)
{
	BINARY *pbin;
	TAGGED_PROPVAL propval;
	TPROPVAL_ARRAY *pproplist;
	
	
	pproplist = tpropval_array_init();
	if (NULL == pproplist) {
		return NULL;
	}
	
	if (ICS_STATE_CONTENTS_DOWN == pstate->type ||
		ICS_STATE_HIERARCHY_DOWN == pstate->type ||
		(ICS_STATE_CONTENTS_UP == pstate->type &&
		FALSE == idset_check_empty(pstate->pgiven))) {
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
	}
	
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
	
	if (ICS_STATE_CONTENTS_DOWN == pstate->type ||
		ICS_STATE_CONTENTS_UP == pstate->type) {
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
	
	if (ICS_STATE_CONTENTS_DOWN == pstate->type ||
		(ICS_STATE_CONTENTS_UP == pstate->type &&
		FALSE == idset_check_empty(pstate->pread))) {
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
	
	return pproplist;
}
