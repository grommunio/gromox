#include "icsdownctx_object.h"
#include "tpropval_array.h"
#include "proptag_array.h"
#include "zarafa_server.h"
#include "exmdb_client.h"
#include "restriction.h"
#include "ext_buffer.h"
#include "eid_array.h"
#include "rop_util.h"
#include "idset.h"
#include <stdlib.h>
#include <string.h>

ICSDOWNCTX_OBJECT* icsdownctx_object_create(
	FOLDER_OBJECT *pfolder, uint8_t sync_type)
{
	ICSDOWNCTX_OBJECT *pctx;
	
	pctx = malloc(sizeof(ICSDOWNCTX_OBJECT));
	if (NULL == pctx) {
		return NULL;
	}
	pctx->pstate = ics_state_create(sync_type);
	if (NULL == pctx->pstate) {
		free(pctx);
		return NULL;
	}
	pctx->pstore = folder_object_get_store(pfolder);
	pctx->folder_id = folder_object_get_id(pfolder);
	pctx->sync_type = sync_type;
	pctx->pgiven_eids = NULL;
	pctx->pchg_eids = NULL;
	pctx->pupdated_eids = NULL;
	pctx->pread_messags = NULL;
	pctx->punread_messags = NULL;
	pctx->pdeleted_eids = NULL;
	pctx->pnolonger_messages = NULL;
	pctx->b_started = FALSE;
	pctx->eid_pos = 0;
	return pctx;
}

uint8_t icsdownctx_object_get_type(ICSDOWNCTX_OBJECT *pctx)
{
	return pctx->sync_type;
}

BOOL icsdownctx_object_make_content(ICSDOWNCTX_OBJECT *pctx,
	const BINARY *pstate_bin, const RESTRICTION *prestriction,
	uint16_t sync_flags, BOOL *pb_changed, uint32_t *pmsg_count)
{
	int i;
	IDSET *pseen;
	IDSET *pread;
	BOOL b_ordered;
	IDSET *pseen_fai;
	USER_INFO *pinfo;
	uint32_t count_fai;
	uint64_t total_fai;
	const char *username;
	uint64_t total_normal;
	uint32_t count_normal;
	EID_ARRAY chg_messages;
	EID_ARRAY read_messags;
	EID_ARRAY given_messages;
	EID_ARRAY unread_messags;
	EID_ARRAY updated_messages;
	EID_ARRAY deleted_messages;
	EID_ARRAY nolonger_messages;
	
	*pb_changed = FALSE;
	if (SYNC_TYPE_CONTENTS != pctx->sync_type) {
		return FALSE;
	}
	if (FALSE == ics_state_deserialize(pctx->pstate, pstate_bin)) {
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	if (sync_flags & SYNC_FLAG_READSTATE) {
		pread = pctx->pstate->pread;
	} else {
		pread = NULL;
	}
	if (sync_flags & SYNC_FLAG_FAI) {
		pseen_fai = pctx->pstate->pseen_fai;
	} else {
		pseen_fai = NULL;
	}
	if (sync_flags & SYNC_FLAG_NORMAL) {
		pseen = pctx->pstate->pseen;
	} else {
		pseen = NULL;
	}
	if (FALSE == store_object_check_private(pctx->pstore)) {
		username = pinfo->username;
	} else {
		username = NULL;
	}
	if (FALSE == exmdb_client_get_content_sync(
		store_object_get_dir(pctx->pstore), pctx->folder_id,
		username, pctx->pstate->pgiven, pseen, pseen_fai,
		pread, pinfo->cpid, prestriction, TRUE, &count_fai,
		&total_fai, &count_normal, &total_normal,
		&updated_messages, &chg_messages, &pctx->last_changenum,
		&given_messages, &deleted_messages, &nolonger_messages,
		&read_messags, &unread_messags, &pctx->last_readcn)) {
		return FALSE;
	}
	if (NULL != pctx->pgiven_eids) {
		eid_array_free(pctx->pgiven_eids);
	}
	pctx->pgiven_eids = eid_array_dup(&given_messages);
	if (NULL == pctx->pgiven_eids) {
		return FALSE;
	}
	if ((sync_flags & SYNC_FLAG_FAI) ||
		(sync_flags & SYNC_FLAG_NORMAL)) {
		if (NULL != pctx->pchg_eids) {
			eid_array_free(pctx->pchg_eids);
		}
		pctx->pchg_eids = eid_array_dup(&chg_messages);
		if (NULL == pctx->pchg_eids) {
			return FALSE;
		}
		if (NULL != pctx->pupdated_eids) {
			eid_array_free(pctx->pupdated_eids);
		}
		pctx->pupdated_eids = eid_array_dup(&updated_messages);
		if (NULL == pctx->pupdated_eids) {
			return FALSE;
		}
		*pmsg_count = chg_messages.count;
		if (chg_messages.count > 0) {
			*pb_changed = TRUE;
		}
	} else {
		*pmsg_count = 0;
	}
	if (0 == (sync_flags & SYNC_FLAG_NODELETIONS)) {
		if (NULL != pctx->pdeleted_eids) {
			eid_array_free(pctx->pdeleted_eids);
		}
		pctx->pdeleted_eids = eid_array_dup(&deleted_messages);
		if (NULL == pctx->pdeleted_eids) {
			return FALSE;
		}
		if (NULL != pctx->pnolonger_messages) {
			eid_array_free(pctx->pnolonger_messages);
		}
		pctx->pnolonger_messages = eid_array_dup(&nolonger_messages);
		if (NULL == pctx->pnolonger_messages) {
			return FALSE;
		}
		if (deleted_messages.count > 0 || nolonger_messages.count > 0) {
			*pb_changed = TRUE;
		}
	}
	if (sync_flags & SYNC_FLAG_READSTATE) {
		if (NULL != pctx->pread_messags) {
			eid_array_free(pctx->pread_messags);
		}
		pctx->pread_messags = eid_array_dup(&read_messags);
		if (NULL == pctx->pread_messags) {
			return FALSE;
		}
		if (NULL != pctx->punread_messags) {
			eid_array_free(pctx->punread_messags);
		}
		pctx->punread_messags = eid_array_dup(&unread_messags);
		if (NULL == pctx->punread_messags) {
			return FALSE;
		}
		if (read_messags.count > 0 || unread_messags.count > 0) {
			*pb_changed = TRUE;
		}
	}
	return TRUE;
}

BOOL icsdownctx_object_make_hierarchy(ICSDOWNCTX_OBJECT *pctx,
	const BINARY *pstate, uint16_t sync_flags, BOOL *pb_changed,
	uint32_t *pfld_count)
{
	int i;
	void *pvalue;
	USER_INFO *pinfo;
	const char *username;
	FOLDER_CHANGES fldchgs;
	EID_ARRAY given_folders;
	EID_ARRAY deleted_folders;
	
	*pb_changed = FALSE;
	if (SYNC_TYPE_HIERARCHY != pctx->sync_type) {
		return FALSE;
	}
	if (FALSE == ics_state_deserialize(pctx->pstate, pstate)) {
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	if (TRUE == store_object_check_owner_mode(pctx->pstore)) {
		username = NULL;
	} else {
		username = pinfo->username;
	}
	if (FALSE == exmdb_client_get_hierarchy_sync(
		store_object_get_dir(pctx->pstore), pctx->folder_id,
		username, pctx->pstate->pgiven, pctx->pstate->pseen,
		&fldchgs, &pctx->last_changenum, &given_folders,
		&deleted_folders)) {
		return FALSE;
	}
	if (NULL != pctx->pgiven_eids) {
		eid_array_free(pctx->pgiven_eids);
	}
	pctx->pgiven_eids = eid_array_dup(&given_folders);
	if (NULL == pctx->pgiven_eids) {
		return FALSE;
	}
	if (0 == (sync_flags & SYNC_FLAG_NODELETIONS)) {
		if (NULL != pctx->pdeleted_eids) {
			eid_array_free(pctx->pdeleted_eids);
		}
		pctx->pdeleted_eids = eid_array_dup(&deleted_folders);
		if (NULL == pctx->pdeleted_eids) {
			return FALSE;
		}
		if (deleted_folders.count > 0) {
			*pb_changed = TRUE;
		}
	}
	pctx->pchg_eids = eid_array_init();
	if (NULL == pctx->pchg_eids) {
		return FALSE;
	}
	for (i=0; i<fldchgs.count; i++) {
		pvalue = common_util_get_propvals(
			fldchgs.pfldchgs + i, PROP_TAG_FOLDERID);
		if (NULL == pvalue) {
			return FALSE;
		}
		if (FALSE == eid_array_append(
			pctx->pchg_eids, *(uint64_t*)pvalue)) {
			return FALSE;	
		}
	}
	if (fldchgs.count > 0) {
		*pb_changed = TRUE;
	}
	*pfld_count = fldchgs.count;
	return TRUE;
}

BINARY* icsdownctx_object_get_state(ICSDOWNCTX_OBJECT *pctx)
{
	int i;
	
	if (NULL != pctx->pgiven_eids && NULL != pctx->pchg_eids
		&& pctx->eid_pos >= pctx->pchg_eids->count && NULL ==
		pctx->pdeleted_eids && NULL == pctx->pnolonger_messages) {
		idset_clear(pctx->pstate->pgiven);
		for (i=0; i<pctx->pgiven_eids->count; i++) {
			if (FALSE == idset_append(pctx->pstate->pgiven,
				pctx->pgiven_eids->pids[i])) {
				return FALSE;	
			}
		}
		idset_clear(pctx->pstate->pseen);
		if (0 != pctx->last_changenum) {
			if (FALSE == idset_append_range(pctx->pstate->pseen, 1,
				1, rop_util_get_gc_value(pctx->last_changenum))) {
				return FALSE;
			}
		}
		if (SYNC_TYPE_CONTENTS == pctx->sync_type) {
			idset_clear(pctx->pstate->pseen_fai);
			if (0 != pctx->last_changenum) {
				if (FALSE == idset_append_range(pctx->pstate->pseen_fai,
					1, 1, rop_util_get_gc_value(pctx->last_changenum))) {
					return FALSE;
				}
			}
		}
		pctx->last_changenum = 0;
		eid_array_free(pctx->pgiven_eids);
		pctx->pgiven_eids = NULL;
		eid_array_free(pctx->pchg_eids);
		pctx->pchg_eids = NULL;
		if (NULL != pctx->pupdated_eids) {
			eid_array_free(pctx->pupdated_eids);
			pctx->pupdated_eids = NULL;
		}
	}
	return ics_state_serialize(pctx->pstate);
}

void icsdownctx_object_free(ICSDOWNCTX_OBJECT *pctx)
{
	if (NULL != pctx->pgiven_eids) {
		eid_array_free(pctx->pgiven_eids);
	}
	if (NULL != pctx->pchg_eids) {
		eid_array_free(pctx->pchg_eids);
	}
	if (NULL != pctx->pupdated_eids) {
		eid_array_free(pctx->pupdated_eids);
	}
	if (NULL != pctx->pdeleted_eids) {
		eid_array_free(pctx->pdeleted_eids);
	}
	if (NULL != pctx->pnolonger_messages) {
		eid_array_free(pctx->pnolonger_messages);
	}
	if (NULL != pctx->pread_messags) {
		eid_array_free(pctx->pread_messags);
	}
	if (NULL != pctx->punread_messags) {
		eid_array_free(pctx->punread_messags);
	}
	if (NULL != pctx->pstate) {
		ics_state_free(pctx->pstate);
	}
	free(pctx);
}

BOOL icsdownctx_object_check_started(ICSDOWNCTX_OBJECT *pctx)
{
	return pctx->b_started;
}

BOOL icsdownctx_object_sync_message_change(ICSDOWNCTX_OBJECT *pctx,
	BOOL *pb_found, BOOL *pb_new, TPROPVAL_ARRAY *pproplist)
{
	void *pvalue;
	uint64_t message_id;
	
	if (SYNC_TYPE_CONTENTS != pctx->sync_type) {
		return FALSE;
	}
	if (NULL == pctx->pchg_eids || NULL == pctx->pupdated_eids) {
		*pb_found = FALSE;
		return TRUE;
	}
	do {
		if (pctx->eid_pos >= pctx->pchg_eids->count) {
			*pb_found = FALSE;
			return TRUE;
		}
		message_id = pctx->pchg_eids->pids[pctx->eid_pos];
		pctx->eid_pos ++;
		if (FALSE == exmdb_client_get_message_property(
			store_object_get_dir(pctx->pstore), NULL, 0,
			message_id, PROP_TAG_CHANGENUMBER, &pvalue)) {
			return FALSE;	
		}
	} while (NULL == pvalue);
	if (FALSE == eid_array_check(pctx->pupdated_eids, message_id)) {
		*pb_new = TRUE;	
	} else {
		*pb_new = FALSE;
	}
	pproplist->count = 2;
	pproplist->ppropval = common_util_alloc(
					2*sizeof(TAGGED_PROPVAL));
	if (NULL == pproplist->ppropval) {
		return FALSE;
	}
	pproplist->ppropval[0].proptag = PROP_TAG_SOURCEKEY;
	pproplist->ppropval[0].pvalue =
		common_util_calculate_message_sourcekey(
		pctx->pstore, message_id);
	if (NULL == pproplist->ppropval[0].pvalue) {
		return FALSE;
	}
	pproplist->ppropval[1].proptag = PROP_TAG_PARENTSOURCEKEY;
	pproplist->ppropval[1].pvalue =
		common_util_calculate_folder_sourcekey(
		pctx->pstore, pctx->folder_id);
	if (NULL == pproplist->ppropval[1].pvalue) {
		return FALSE;
	}
	*pb_found = TRUE;
	if (FALSE == idset_append(
		pctx->pstate->pgiven, message_id)
		|| FALSE == idset_append(
		pctx->pstate->pseen, *(uint64_t*)pvalue)
		|| FALSE == idset_append(
		pctx->pstate->pseen_fai, *(uint64_t*)pvalue)) {
		return FALSE;
	}
	return TRUE;
}

BOOL icsdownctx_object_sync_folder_change(ICSDOWNCTX_OBJECT *pctx,
	BOOL *pb_found, TPROPVAL_ARRAY *pproplist)
{
	void *pvalue;
	uint64_t folder_id;
	uint64_t parent_fid;
	uint64_t change_num;
	PROPTAG_ARRAY proptags;
	uint32_t proptag_buff[6];
	TPROPVAL_ARRAY tmp_propvals;
	static uint8_t fake_false = 0;
	
	if (SYNC_TYPE_HIERARCHY != pctx->sync_type) {
		return FALSE;
	}
	if (NULL == pctx->pchg_eids ||
		pctx->eid_pos >= pctx->pchg_eids->count) {
		*pb_found = FALSE;
		return TRUE;
	}
	folder_id = pctx->pchg_eids->pids[pctx->eid_pos];
	pctx->eid_pos ++;
	pproplist->count = 0;
	pproplist->ppropval = common_util_alloc(
					8*sizeof(TAGGED_PROPVAL));
	if (NULL == pproplist->ppropval) {
		return FALSE;
	}
	pproplist->ppropval[pproplist->count].proptag =
								PROP_TAG_SOURCEKEY;
	pvalue = common_util_calculate_folder_sourcekey(
							pctx->pstore, folder_id);
	if (NULL == pvalue) {
		return FALSE;
	}
	pproplist->ppropval[pproplist->count].pvalue = pvalue;
	pproplist->count ++;
	pproplist->ppropval[pproplist->count].proptag = PROP_TAG_ENTRYID;
	pvalue = common_util_to_folder_entryid(pctx->pstore, folder_id);
	if (NULL == pvalue) {
		return FALSE;
	}
	pproplist->ppropval[pproplist->count].pvalue = pvalue;
	pproplist->count ++;
	proptags.count = 6;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_PARENTFOLDERID;
	proptag_buff[1] = PROP_TAG_DISPLAYNAME;
	proptag_buff[2] = PROP_TAG_CONTAINERCLASS;
	proptag_buff[3] = PROP_TAG_ATTRIBUTEHIDDEN;
	proptag_buff[4] = PROP_TAG_EXTENDEDFOLDERFLAGS;
	proptag_buff[5] = PROP_TAG_CHANGENUMBER;
	if (FALSE == exmdb_client_get_folder_properties(
		store_object_get_dir(pctx->pstore), 0,
		folder_id, &proptags, &tmp_propvals)) {
		return FALSE;
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_CHANGENUMBER);
	if (NULL == pvalue) {
		*pb_found = FALSE;
		return TRUE;
	}
	change_num = *(uint64_t*)pvalue;
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_PARENTFOLDERID);
	if (NULL != pvalue) {
		parent_fid = *(uint64_t*)pvalue;
		pproplist->ppropval[pproplist->count].proptag =
								PROP_TAG_PARENTSOURCEKEY;
		pvalue = common_util_calculate_folder_sourcekey(
								pctx->pstore, parent_fid);
		if (NULL == pvalue) {
			return FALSE;
		}
		pproplist->ppropval[pproplist->count].pvalue = pvalue;
		pproplist->count ++;
		pproplist->ppropval[pproplist->count].proptag =
								PROP_TAG_PARENTENTRYID;
		pvalue = common_util_to_folder_entryid(
						pctx->pstore, parent_fid);
		if (NULL == pvalue) {
			return FALSE;
		}
		pproplist->ppropval[pproplist->count].pvalue = pvalue;
		pproplist->count ++;
	}
	pproplist->ppropval[pproplist->count].proptag =
								PROP_TAG_DISPLAYNAME;
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_DISPLAYNAME);
	if (NULL != pvalue) {
		pproplist->ppropval[pproplist->count].pvalue = pvalue;
		pproplist->count ++;
	}
	pproplist->ppropval[pproplist->count].proptag =
							PROP_TAG_CONTAINERCLASS;
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_CONTAINERCLASS);
	if (NULL != pvalue) {
		pproplist->ppropval[pproplist->count].pvalue = pvalue;
		pproplist->count ++;
	}
	pproplist->ppropval[pproplist->count].proptag =
							PROP_TAG_ATTRIBUTEHIDDEN;
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_ATTRIBUTEHIDDEN);
	if (NULL != pvalue) {
		pproplist->ppropval[pproplist->count].pvalue = pvalue;
		pproplist->count ++;
	} else {
		pproplist->ppropval[pproplist->count].pvalue = &fake_false;
		pproplist->count ++;
	}
	pproplist->ppropval[pproplist->count].proptag =
						PROP_TAG_EXTENDEDFOLDERFLAGS;
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_EXTENDEDFOLDERFLAGS);
	if (NULL != pvalue) {
		pproplist->ppropval[pproplist->count].pvalue = pvalue;
		pproplist->count ++;
	}
	*pb_found = TRUE;
	if (FALSE == idset_append(
		pctx->pstate->pgiven, folder_id)
		|| FALSE == idset_append(
		pctx->pstate->pseen, change_num)) {
		return FALSE;
	}
	return TRUE;
}

BOOL icsdownctx_object_sync_deletions(ICSDOWNCTX_OBJECT *pctx,
	uint32_t flags, BINARY_ARRAY *pbins)
{
	int i;
	BINARY *pbin;
	
	if (0 == (flags & SYNC_SOFT_DELETE)) {
		if (NULL == pctx->pdeleted_eids) {
			pbins->count = 0;
			pbins->pbin = NULL;
			return TRUE;
		}
		if (0 == pctx->pdeleted_eids->count) {
			pbins->count = 0;
			pbins->pbin = NULL;
			eid_array_free(pctx->pdeleted_eids);
			pctx->pdeleted_eids = NULL;
			return TRUE;
		}
		pbins->pbin = common_util_alloc(sizeof(
			BINARY)*pctx->pdeleted_eids->count);
		if (NULL == pbins->pbin) {
			return FALSE;
		}
		for (i=0; i<pctx->pdeleted_eids->count; i++) {
			if (SYNC_TYPE_CONTENTS == pctx->sync_type) {
				pbin = common_util_calculate_message_sourcekey(
					pctx->pstore, pctx->pdeleted_eids->pids[i]);
			} else {
				pbin = common_util_calculate_folder_sourcekey(
					pctx->pstore, pctx->pdeleted_eids->pids[i]);
			}
			if (NULL == pbin) {
				return FALSE;
			}
			pbins->pbin[i] = *pbin;
			idset_remove(pctx->pstate->pgiven,
				pctx->pdeleted_eids->pids[i]);
		}
		pbins->count = pctx->pdeleted_eids->count;
		eid_array_free(pctx->pdeleted_eids);
		pctx->pdeleted_eids = NULL;
	} else {
		if (SYNC_TYPE_HIERARCHY == pctx->sync_type
			|| NULL == pctx->pnolonger_messages) {
			pbins->count = 0;
			pbins->pbin = NULL;
			return TRUE;
		}
		if (0 == pctx->pnolonger_messages->count) {
			pbins->count = 0;
			pbins->pbin = NULL;
			eid_array_free(pctx->pnolonger_messages);
			pctx->pnolonger_messages = NULL;
			return TRUE;
		}
		pbins->pbin = common_util_alloc(sizeof(
			BINARY)*pctx->pnolonger_messages->count);
		if (NULL == pbins->pbin) {
			return FALSE;
		}
		for (i=0; i<pctx->pnolonger_messages->count; i++) {
			pbin = common_util_calculate_message_sourcekey(
				pctx->pstore, pctx->pnolonger_messages->pids[i]);
			if (NULL == pbin) {
				return FALSE;
			}
			pbins->pbin[i] = *pbin;
			idset_remove(pctx->pstate->pgiven,
				pctx->pnolonger_messages->pids[i]);
		}
		pbins->count = pctx->pnolonger_messages->count;
		eid_array_free(pctx->pnolonger_messages);
		pctx->pnolonger_messages = NULL;
	}
	return TRUE;
}

BOOL icsdownctx_object_sync_readstates(
	ICSDOWNCTX_OBJECT *pctx, STATE_ARRAY *pstates)
{
	int i;
	BINARY *pbin;
	STORE_OBJECT *pstore;
	
	if (SYNC_TYPE_CONTENTS != pctx->sync_type) {
		return FALSE;
	}
	if (NULL == pctx->pread_messags ||
		NULL == pctx->punread_messags) {
		pstates->count = 0;
		pstates->pstate = NULL;
		return TRUE;
	}
	pstates->count = pctx->pread_messags->count
				+ pctx->punread_messags->count;
	if (0 == pstates->count) {
		pstates->count = 0;
		pstates->pstate = NULL;
	} else {
		pstates->pstate = common_util_alloc(
			pstates->count*sizeof(MESSAGE_STATE));
		if (NULL == pstates->pstate) {
			return FALSE;
		}
		pstates->count = 0;
		for (i=0; i<pctx->pread_messags->count; i++) {
			pbin = common_util_calculate_message_sourcekey(
				pctx->pstore, pctx->pread_messags->pids[i]);
			if (NULL == pbin) {
				return FALSE;
			}
			pstates->pstate[pstates->count].source_key = *pbin;
			pstates->pstate[pstates->count].message_flags =
											MESSAGE_FLAG_READ;
			pstates->count ++;
		}
		for (i=0; i<pctx->punread_messags->count; i++) {
			pbin = common_util_calculate_message_sourcekey(
				pctx->pstore, pctx->punread_messags->pids[i]);
			if (NULL == pbin) {
				return FALSE;
			}
			pstates->pstate[pstates->count].source_key = *pbin;
			pstates->pstate[pstates->count].message_flags = 0;
			pstates->count ++;
		}
	}
	eid_array_free(pctx->pread_messags);
	pctx->pread_messags = NULL;
	eid_array_free(pctx->punread_messags);
	pctx->punread_messags = NULL;
	idset_clear(pctx->pstate->pread);
	if (0 != pctx->last_readcn) {
		if (FALSE == idset_append_range(pctx->pstate->pread,
			1, 1, rop_util_get_gc_value(pctx->last_readcn))) {
			return FALSE;
		}
		pctx->last_readcn = 0;
	}
	return TRUE;
}
