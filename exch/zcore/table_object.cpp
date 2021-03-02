// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <cstdint>
#include <gromox/mapidefs.h>
#include <gromox/tarray_set.hpp>
#include "object_tree.h"
#include <gromox/restriction.hpp>
#include "exmdb_client.h"
#include "table_object.h"
#include <gromox/sortorder_set.hpp>
#include "folder_object.h"
#include <gromox/proptag_array.hpp>
#include "zarafa_server.h"
#include "message_object.h"
#include "container_object.h"
#include <gromox/propval.hpp>
#include <cstdlib>
#include <cstring>
#include "common_util.h"

struct BOOKMARK_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t index;
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	uint32_t position;
};

static void table_object_set_table_id(
	TABLE_OBJECT *ptable, uint32_t table_id)
{
	if (0 != ptable->table_id) {
		exmdb_client_unload_table(
			store_object_get_dir(ptable->pstore),
			ptable->table_id);
	}
	ptable->table_id = table_id;
}

BOOL table_object_check_loaded(TABLE_OBJECT *ptable)
{
	if (RECIPIENT_TABLE == ptable->table_type ||
		ATTACHMENT_TABLE == ptable->table_type ||
		CONTAINER_TABLE == ptable->table_type ||
		USER_TABLE == ptable->table_type ||
		STORE_TABLE == ptable->table_type) {
		return TRUE;
	}
	if (0 == ptable->table_id) {
		return FALSE;
	} else {
		return TRUE;
	}
}

BOOL table_object_check_to_load(TABLE_OBJECT *ptable)
{
	USER_INFO *pinfo;
	uint32_t row_num;
	uint32_t table_id;
	uint32_t permission;
	const char *username;
	uint32_t table_flags;
	
	if (ATTACHMENT_TABLE == ptable->table_type ||
		RECIPIENT_TABLE == ptable->table_type ||
		CONTAINER_TABLE == ptable->table_type ||
		STORE_TABLE == ptable->table_type) {
		return TRUE;
	} else if (USER_TABLE == ptable->table_type) {
		return container_object_load_user_table(
		       static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj),
		       ptable->prestriction);
	}
	if (0 != ptable->table_id) {
		return TRUE;
	}
	switch (ptable->table_type) {
	case HIERARCHY_TABLE:
		pinfo = zarafa_server_get_info();
		if (TRUE == store_object_check_owner_mode(ptable->pstore)) {
			username = NULL;
		} else {
			username = pinfo->username;
		}
		table_flags = TABLE_FLAG_NONOTIFICATIONS;
		if (ptable->table_flags & FLAG_SOFT_DELETE) {
			table_flags |= TABLE_FLAG_SOFTDELETES;
		}
		if (ptable->table_flags & FLAG_CONVENIENT_DEPTH) {
			table_flags |= TABLE_FLAG_DEPTH;
		}
		if (FALSE == exmdb_client_load_hierarchy_table(
			store_object_get_dir(ptable->pstore),
		    folder_object_get_id(static_cast<FOLDER_OBJECT *>(ptable->pparent_obj)),
			username, table_flags, ptable->prestriction,
			&table_id, &row_num)) {
			return FALSE;
		}
		break;
	case CONTENT_TABLE:
		pinfo = zarafa_server_get_info();
		username = NULL;
		if (TRUE != store_object_check_owner_mode(ptable->pstore)) {
			if (FALSE == store_object_check_private(ptable->pstore)) {
				username = pinfo->username;
			} else {
				if (FALSE == exmdb_client_check_folder_permission(
					store_object_get_dir(ptable->pstore),
				    folder_object_get_id(static_cast<FOLDER_OBJECT *>(ptable->pparent_obj)),
					pinfo->username, &permission)) {
					return FALSE;	
				}
				if (0 == (permission & PERMISSION_READANY) &&
					0 == (permission & PERMISSION_FOLDEROWNER)) {
					username = pinfo->username;
				}
			}
		}
		table_flags = TABLE_FLAG_NONOTIFICATIONS;
		if (ptable->table_flags & FLAG_SOFT_DELETE) {
			table_flags |= TABLE_FLAG_SOFTDELETES;
		}
		if (ptable->table_flags & FLAG_ASSOCIATED) {
			table_flags |= TABLE_FLAG_ASSOCIATED;
		}
		if (FALSE == exmdb_client_load_content_table(
			store_object_get_dir(ptable->pstore), pinfo->cpid,
		    folder_object_get_id(static_cast<FOLDER_OBJECT *>(ptable->pparent_obj)),
			username, table_flags, ptable->prestriction,
			ptable->psorts, &table_id, &row_num)) {
			return FALSE;
		}
		break;
	case RULE_TABLE:
		if (FALSE == exmdb_client_load_rule_table(
			store_object_get_dir(ptable->pstore),
			*(uint64_t*)ptable->pparent_obj, 0,
			ptable->prestriction,
			&table_id, &row_num)) {
			return FALSE;
		}
		break;
	}
	table_object_set_table_id(ptable, table_id);
	return TRUE;
}

void table_object_unload(TABLE_OBJECT *ptable)
{
	if (USER_TABLE == ptable->table_type) {
		container_object_clear(static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj));
	} else {
		table_object_set_table_id(ptable, 0);
	}
}
static BOOL table_object_get_store_table_all_proptags(
	PROPTAG_ARRAY *pproptags)
{
	int i;
	USER_INFO *pinfo;
	PROPTAG_ARRAY tmp_proptags1;
	PROPTAG_ARRAY tmp_proptags2;
	static const uint32_t proptag_buff[] = {
		PROP_TAG_STOREPROVIDER,
		PROP_TAG_MESSAGESIZE,
		PROP_TAG_ASSOCMESSAGESIZE,
		PROP_TAG_NORMALMESSAGESIZE,
		PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE,
		PROP_TAG_DEFAULTSTORE,
		PROP_TAG_DISPLAYNAME,
		PROP_TAG_EMAILADDRESS,
		PROP_TAG_EXTENDEDRULESIZELIMIT,
		PROP_TAG_MAILBOXOWNERENTRYID,
		PROP_TAG_MAILBOXOWNERNAME,
		PROP_TAG_MAXIMUMSUBMITMESSAGESIZE,
		PROP_TAG_OBJECTTYPE,
		PROP_TAG_PROVIDERDISPLAY,
		PROP_TAG_RESOURCEFLAGS,
		PROP_TAG_RESOURCETYPE,
		PROP_TAG_RECORDKEY,
		PROP_TAG_INSTANCEKEY,
		PROP_TAG_ENTRYID,
		PROP_TAG_STOREENTRYID,
		PROP_TAG_USERENTRYID
	};
	
	pinfo = zarafa_server_get_info();
	if (FALSE == exmdb_client_get_store_all_proptags(
		pinfo->maildir, &tmp_proptags1) ||
		FALSE == exmdb_client_get_store_all_proptags(
		pinfo->homedir, &tmp_proptags2)) {
		return FALSE;
	}
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags1.count + tmp_proptags2.count + 25);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags1.pproptag,
				sizeof(uint32_t)*tmp_proptags1.count);
	pproptags->count = tmp_proptags1.count;
	for (i=0; i<tmp_proptags2.count; i++) {
		if (common_util_index_proptags(&tmp_proptags1,
			tmp_proptags2.pproptag[i]) >= 0) {
			continue;	
		}
		pproptags->pproptag[pproptags->count] =
					tmp_proptags2.pproptag[i];
		pproptags->count ++;
	}
	for (i=0; i<sizeof(proptag_buff)/sizeof(uint32_t); i++) {
		if (common_util_index_proptags(&tmp_proptags1,
			proptag_buff[i]) >= 0 ||
			common_util_index_proptags(&tmp_proptags2,
			proptag_buff[i]) >= 0) {
			continue;	
		}
		pproptags->pproptag[pproptags->count] = proptag_buff[i];
		pproptags->count ++;
	}
	return TRUE;
}

static BOOL table_object_get_all_columns(TABLE_OBJECT *ptable,
	PROPTAG_ARRAY *pcolumns)
{
	if (ATTACHMENT_TABLE == ptable->table_type) {
		return message_object_get_attachment_table_all_proptags(
		       static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj), pcolumns);
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		return message_object_get_recipient_all_proptags(
		       static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj), pcolumns);
	} else if (CONTAINER_TABLE == ptable->table_type) {
		container_object_get_container_table_all_proptags(pcolumns);
		return TRUE;
	} else if (USER_TABLE == ptable->table_type) {
		container_object_get_user_table_all_proptags(pcolumns);
		return TRUE;
	} else if (STORE_TABLE == ptable->table_type) {
		return table_object_get_store_table_all_proptags(pcolumns);
	}
	return exmdb_client_get_table_all_proptags(
			store_object_get_dir(ptable->pstore),
			ptable->table_id, pcolumns);
}

static uint32_t table_object_get_folder_tag_access(
	STORE_OBJECT *pstore, uint64_t folder_id, const char *username)
{
	uint32_t tag_access;
	uint32_t permission;
	
	if (TRUE == store_object_check_owner_mode(pstore)) {
		tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
				TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
				TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
	} else {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore), folder_id, username,
			&permission)) {
			return 0;
		}
		tag_access = TAG_ACCESS_READ;
		if (permission & PERMISSION_FOLDEROWNER) {
			tag_access = TAG_ACCESS_MODIFY |TAG_ACCESS_DELETE |
				TAG_ACCESS_HIERARCHY | TAG_ACCESS_CONTENTS |
				TAG_ACCESS_FAI_CONTENTS;
		} else {
			if (permission & PERMISSION_CREATE) {
				tag_access |= TAG_ACCESS_CONTENTS |
							TAG_ACCESS_FAI_CONTENTS;
			}
			if (permission & PERMISSION_CREATESUBFOLDER) {
				tag_access |= TAG_ACCESS_HIERARCHY;
			}
		}
	}
	return tag_access;
}

static uint32_t table_object_get_folder_permission_rights(
	STORE_OBJECT *pstore, uint64_t folder_id, const char *username)
{
	uint32_t permission;
	
	if (TRUE == store_object_check_owner_mode(pstore)) {
		permission = PERMISSION_READANY|PERMISSION_CREATE|
				PERMISSION_EDITOWNED|PERMISSION_DELETEOWNED|
				PERMISSION_EDITANY|PERMISSION_DELETEANY|
				PERMISSION_CREATESUBFOLDER|PERMISSION_FOLDEROWNER|
				PERMISSION_FOLDERCONTACT|PERMISSION_FOLDERVISIBLE;
	} else {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore), folder_id, username,
			&permission)) {
			return 0;
		}
	}
	return permission;
}

BOOL table_object_query_rows(TABLE_OBJECT *ptable, BOOL b_forward,
	const PROPTAG_ARRAY *pcolumns, uint32_t row_count, TARRAY_SET *pset)
{
	int i, j;
	void *pvalue;
	uint32_t handle;
	uint32_t row_num;
	uint32_t end_pos;
	USER_INFO *pinfo;
	BINARY *pentryid;
	uint64_t tmp_eid;
	uint8_t mapi_type;
	int32_t row_needed;
	int idx, idx1, idx2;
	TARRAY_SET rcpt_set;
	TARRAY_SET temp_set;
	const char *username;
	STORE_OBJECT *pstore;
	uint32_t *ppermission;
	uint32_t *ptag_access;
	TPROPVAL_ARRAY *ppropvals;
	PROPTAG_ARRAY tmp_columns;
	
	if (NULL == pcolumns) {
		if (NULL != ptable->pcolumns) {
			pcolumns = ptable->pcolumns;
		} else {
			if (FALSE == table_object_get_all_columns(
				ptable, &tmp_columns)) {
				return FALSE;	
			}
			pcolumns = &tmp_columns;
		}
	}
	pinfo = zarafa_server_get_info();
	if (NULL == pinfo) {
		return FALSE;
	}
	if (0 == ptable->position && FALSE == b_forward) {
		pset->count = 0;
		return TRUE;
	}
	row_num = table_object_get_total(ptable);
	if (ptable->position >= row_num && TRUE == b_forward) {
		pset->count = 0;
		return TRUE;
	}
	if (row_count > row_num) {
		row_count = row_num;
	}
	if (TRUE == b_forward) {
		row_needed = row_count;
	} else {
		row_needed = -1 * row_count;
	}
	if (ATTACHMENT_TABLE == ptable->table_type) {
		return message_object_query_attachment_table(
		       static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj),
		       pcolumns, ptable->position, row_needed, pset);
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		if (!message_object_read_recipients(static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj),
		    0, 0xFFFF, &rcpt_set))
			return FALSE;	
		if (TRUE == b_forward) {
			if (ptable->position + row_needed > rcpt_set.count) {
				end_pos = rcpt_set.count;
			} else {
				end_pos = ptable->position + row_needed;
			}
			pset->count = 0;
			pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(end_pos - ptable->position);
			if (NULL == pset->pparray) {
				return FALSE;
			}
			for (i=ptable->position; i<end_pos; i++) {
				pset->pparray[pset->count] = rcpt_set.pparray[i];
				pset->count ++;
			}
		} else {
			if (ptable->position <= row_needed) {
				end_pos = 0;
			} else {
				end_pos = ptable->position - row_needed + 1;
			}
			pset->count = 0;
			pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(ptable->position - end_pos + 1);
			if (NULL == pset->pparray) {
				return FALSE;
			}
			for (i=ptable->position; i>=end_pos; i--) {
				pset->pparray[pset->count] = rcpt_set.pparray[i];
				pset->count ++;
			}
		}
		if (common_util_index_proptags(pcolumns, PROP_TAG_ENTRYID) < 0) {
			return TRUE;	
		}
		for (i=0; i<pset->count; i++) {
			if (NULL != common_util_get_propvals(
				pset->pparray[i], PROP_TAG_ENTRYID)) {
				continue;
			}
			pvalue = common_util_get_propvals(
				pset->pparray[i], PROP_TAG_ADDRESSTYPE);
			if (pvalue == nullptr ||
			    strcasecmp(static_cast<char *>(pvalue), "EX") != 0)
				continue;
			pvalue = common_util_get_propvals(
				pset->pparray[i], PROP_TAG_EMAILADDRESS);
			if (NULL == pvalue) {
				continue;
			}
			pentryid = cu_alloc<BINARY>();
			if (NULL == pentryid) {
				return FALSE;
			}
			if (!common_util_essdn_to_entryid(static_cast<char *>(pvalue), pentryid))
				return FALSE;	
			pvalue = cu_alloc<TAGGED_PROPVAL>(pset->pparray[i]->count + 1);
			if (NULL == pvalue) {
				return FALSE;
			}
			memcpy(pvalue, pset->pparray[i]->ppropval,
				sizeof(TAGGED_PROPVAL)*pset->pparray[i]->count);
			pset->pparray[i]->ppropval = static_cast<TAGGED_PROPVAL *>(pvalue);
			pset->pparray[i]->ppropval[pset->pparray[i]->count].proptag =
														PROP_TAG_ENTRYID;
			pset->pparray[i]->ppropval[pset->pparray[i]->count].pvalue =
																pentryid;
			pset->pparray[i]->count ++;
		}
		return TRUE;
	} else if (CONTAINER_TABLE == ptable->table_type) {
		if (ptable->table_flags & FLAG_CONVENIENT_DEPTH) {
			return container_object_query_container_table(
			       static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj),
			       pcolumns, true, ptable->position, row_needed, pset);
		} else {
			return container_object_query_container_table(
			       static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj),
			       pcolumns, false, ptable->position, row_needed, pset);
		}
	} else if (USER_TABLE == ptable->table_type) {
		return container_object_query_user_table(
		       static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj),
		       pcolumns, ptable->position, row_needed, pset);
	} else if (RULE_TABLE == ptable->table_type) {
		if (FALSE == exmdb_client_query_table(
			store_object_get_dir(ptable->pstore),
			NULL, pinfo->cpid, ptable->table_id,
			pcolumns, ptable->position, row_needed,
			pset)) {
			return FALSE;
		}
		for (i=0; i<pset->count; i++) {
			if (FALSE == common_util_convert_to_zrule_data(
				ptable->pstore, pset->pparray[i])) {
				return FALSE;	
			}
		}
		return TRUE;
	} else if (STORE_TABLE == ptable->table_type) {
		if (TRUE == b_forward) {
			end_pos = ptable->position + row_needed;
			if (end_pos >= 2) {
				end_pos = 1;
			}
			pset->count = 0;
			pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(end_pos - ptable->position + 1);
			if (NULL == pset->pparray) {
				return FALSE;
			}
			for (i=ptable->position; i<=end_pos; i++) {
				if (0 != i && 1 != i) {
					continue;
				}
				pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
				if (NULL == pset->pparray[pset->count]) {
					return FALSE;
				}
				if (0 == i) {
					handle = object_tree_get_store_handle(
						pinfo->ptree, TRUE, pinfo->user_id);
				} else {
					handle = object_tree_get_store_handle(
						pinfo->ptree, FALSE, pinfo->domain_id);
				}
				pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
				         pinfo->ptree, handle, &mapi_type));
				if (NULL == pstore || MAPI_STORE != mapi_type) {
					return FALSE;
				}
				if (FALSE == store_object_get_properties(pstore,
					pcolumns, pset->pparray[pset->count])) {
					return FALSE;	
				}
				pset->count ++;
			}
		} else {
			end_pos = ptable->position - row_needed;
			if (end_pos < 0) {
				end_pos = 0;
			}
			pset->count = 0;
			pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(ptable->position - end_pos + 1);
			if (NULL == pset->pparray) {
				return FALSE;
			}
			for (i=ptable->position; i>=end_pos; i--) {
				if (0 != i && 1 != i) {
					continue;
				}
				pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
				if (NULL == pset->pparray[pset->count]) {
					return FALSE;
				}
				if (0 == i) {
					handle = object_tree_get_store_handle(
						pinfo->ptree, TRUE, pinfo->user_id);
				} else {
					handle = object_tree_get_store_handle(
						pinfo->ptree, FALSE, pinfo->domain_id);
					break;
				}
				pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
				         pinfo->ptree, handle, &mapi_type));
				if (NULL == pstore || MAPI_STORE != mapi_type) {
					return FALSE;
				}
				if (FALSE == store_object_get_properties(pstore,
					pcolumns, pset->pparray[pset->count])) {
					return FALSE;	
				}
				pset->count ++;
			}
		}
		return TRUE;
	}
	if (FALSE == store_object_check_private(ptable->pstore)) {
		username = pinfo->username;
	} else {
		username = NULL;
	}
	if ((CONTENT_TABLE == ptable->table_type ||
		HIERARCHY_TABLE == ptable->table_type)) {
		idx = common_util_index_proptags(
			pcolumns, PROP_TAG_SOURCEKEY);
		if (HIERARCHY_TABLE == ptable->table_type) {
			idx1 = common_util_index_proptags(
					pcolumns, PROP_TAG_ACCESS);
			idx2 = common_util_index_proptags(
					pcolumns, PROP_TAG_RIGHTS);
		} else {
			idx1 = -1;
			idx2 = -1;
		}
		if (idx >= 0 || idx1 >= 0 || idx2 >= 0) {
			tmp_columns.pproptag = cu_alloc<uint32_t>(pcolumns->count);
			if (NULL == tmp_columns.pproptag) {
				return FALSE;
			}
			tmp_columns.count = pcolumns->count;
			memcpy(tmp_columns.pproptag, pcolumns->pproptag,
						sizeof(uint32_t)*pcolumns->count);
			if (idx >= 0) {
				if (CONTENT_TABLE == ptable->table_type) {
					tmp_columns.pproptag[idx] = PROP_TAG_MID;
				} else {
					tmp_columns.pproptag[idx] = PROP_TAG_FOLDERID;
				}
			}
			if (idx1 >= 0) {
				tmp_columns.pproptag[idx1] = PROP_TAG_FOLDERID;
			}
			if (idx2 >= 0) {
				tmp_columns.pproptag[idx2] = PROP_TAG_FOLDERID;
			}
			if (FALSE == exmdb_client_query_table(
				store_object_get_dir(ptable->pstore), username,
				pinfo->cpid, ptable->table_id, &tmp_columns,
				ptable->position, row_needed, &temp_set)) {
				return FALSE;	
			}
			if (CONTENT_TABLE == ptable->table_type) {
				for (i=0; i<temp_set.count; i++) {
					for (j=0; j<temp_set.pparray[i]->count; j++) {
						if (PROP_TAG_MID == 
							temp_set.pparray[i]->ppropval[j].proptag) {
							tmp_eid = *(uint64_t*)
								temp_set.pparray[i]->ppropval[j].pvalue;
							temp_set.pparray[i]->ppropval[j].pvalue =
								common_util_calculate_message_sourcekey(
								ptable->pstore, tmp_eid);
							if (NULL ==
								temp_set.pparray[i]->ppropval[j].pvalue) {
								return FALSE;
							}
							temp_set.pparray[i]->ppropval[j].proptag =
													PROP_TAG_SOURCEKEY;
							break;
						}	
					}
				}
			} else {
				if (idx >= 0) {
					for (i=0; i<temp_set.count; i++) {
						for (j=0; j<temp_set.pparray[i]->count; j++) {
							if (PROP_TAG_FOLDERID == 
								temp_set.pparray[i]->ppropval[j].proptag) {
								tmp_eid = *(uint64_t*)
									temp_set.pparray[i]->ppropval[j].pvalue;
								temp_set.pparray[i]->ppropval[j].pvalue =
									common_util_calculate_folder_sourcekey(
									ptable->pstore, tmp_eid);
								if (NULL ==
									temp_set.pparray[i]->ppropval[j].pvalue) {
									return FALSE;
								}
								temp_set.pparray[i]->ppropval[j].proptag =
														PROP_TAG_SOURCEKEY;
								break;
							}	
						}
					}
				}
				if (idx1 >= 0) {
					for (i=0; i<temp_set.count; i++) {
						for (j=0; j<temp_set.pparray[i]->count; j++) {
							if (PROP_TAG_FOLDERID == 
								temp_set.pparray[i]->ppropval[j].proptag) {
								tmp_eid = *(uint64_t*)
									temp_set.pparray[i]->ppropval[j].pvalue;
								ptag_access = cu_alloc<uint32_t>();
								if (NULL == ptag_access) {
									return FALSE;
								}
								*ptag_access =
									table_object_get_folder_tag_access(
									ptable->pstore, tmp_eid, pinfo->username);
								temp_set.pparray[i]->ppropval[j].proptag =
															PROP_TAG_ACCESS;
								temp_set.pparray[i]->ppropval[j].pvalue =
															ptag_access;
								break;
							}	
						}
					}
				}
				if (idx2 >= 0) {
					for (i=0; i<temp_set.count; i++) {
						for (j=0; j<temp_set.pparray[i]->count; j++) {
							if (PROP_TAG_FOLDERID == 
								temp_set.pparray[i]->ppropval[j].proptag) {
								tmp_eid = *(uint64_t*)
									temp_set.pparray[i]->ppropval[j].pvalue;
								ppermission = cu_alloc<uint32_t>();
								if (NULL == ppermission) {
									return FALSE;
								}
								*ppermission =
									table_object_get_folder_permission_rights(
									ptable->pstore, tmp_eid, pinfo->username);
								temp_set.pparray[i]->ppropval[j].proptag =
															PROP_TAG_RIGHTS;
								temp_set.pparray[i]->ppropval[j].pvalue =
																ppermission;
								break;
							}	
						}
					}
				}
			}
		} else {
			if (FALSE == exmdb_client_query_table(
				store_object_get_dir(ptable->pstore),
				username, pinfo->cpid, ptable->table_id,
				pcolumns, ptable->position, row_needed,
				&temp_set)) {
				return FALSE;	
			}
		}
		if (common_util_index_proptags(pcolumns,
			PROP_TAG_STOREENTRYID) >= 0) {
			pentryid = common_util_to_store_entryid(ptable->pstore);
			if (NULL == pentryid) {
				return FALSE;
			}
			for (i=0; i<temp_set.count; i++) {
				ppropvals = cu_alloc<TPROPVAL_ARRAY>();
				if (NULL == ppropvals) {
					return FALSE;
				}
				ppropvals->count = temp_set.pparray[i]->count + 1;
				ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
				if (NULL == ppropvals->ppropval) {
					return FALSE;
				}
				memcpy(ppropvals->ppropval, temp_set.pparray[i]->ppropval,
					sizeof(TAGGED_PROPVAL)*temp_set.pparray[i]->count);
				ppropvals->ppropval[temp_set.pparray[i]->count].proptag =
													PROP_TAG_STOREENTRYID;
				ppropvals->ppropval[temp_set.pparray[i]->count].pvalue =
																pentryid;
				temp_set.pparray[i] = ppropvals;
			}
		}
		*pset = temp_set;
		return TRUE;
	}
	return exmdb_client_query_table(
		store_object_get_dir(ptable->pstore),
		username, pinfo->cpid, ptable->table_id,
		pcolumns, ptable->position, row_needed, pset);
}

void table_object_seek_current(TABLE_OBJECT *ptable,
	BOOL b_forward, uint32_t row_count)
{
	uint32_t total_rows;
	
	if (TRUE == b_forward) {
		ptable->position += row_count;
		total_rows = table_object_get_total(ptable);
		if (ptable->position > total_rows) {
			ptable->position = total_rows;
		}
	} else {
		if (ptable->position < row_count) {
			ptable->position = 0;
			return;
		}
		ptable->position -= row_count;
	}
}

uint8_t table_object_get_table_type(TABLE_OBJECT *ptable)
{
	return ptable->table_type;
}

uint32_t table_object_get_table_id(TABLE_OBJECT *ptable)
{
	return ptable->table_id;
}

const PROPTAG_ARRAY* table_object_get_columns(TABLE_OBJECT *ptable)
{
	return ptable->pcolumns;
}

BOOL table_object_set_columns(TABLE_OBJECT *ptable,
	const PROPTAG_ARRAY *pcolumns)
{
	if (NULL != ptable->pcolumns) {
		proptag_array_free(ptable->pcolumns);
	}
	if (NULL == pcolumns) {
		ptable->pcolumns = NULL;
		return TRUE;
	}
	ptable->pcolumns = proptag_array_dup(pcolumns);
	if (NULL == ptable->pcolumns) {
		return FALSE;
	}
	return TRUE;
}

BOOL table_object_set_sorts(TABLE_OBJECT *ptable,
	const SORTORDER_SET *psorts)
{
	if (NULL != ptable->psorts) {
		sortorder_set_free(ptable->psorts);
	}
	if (NULL == psorts) {
		ptable->psorts = NULL;
		return TRUE;
	}
	ptable->psorts = sortorder_set_dup(psorts);
	if (NULL == ptable->psorts) {
		return FALSE;
	}
	return TRUE;
}

BOOL table_object_set_restriction(TABLE_OBJECT *ptable,
	const RESTRICTION *prestriction)
{
	if (NULL != ptable->prestriction) {
		restriction_free(ptable->prestriction);
	}
	if (NULL == prestriction) {
		ptable->prestriction = NULL;
		return TRUE;
	}
	ptable->prestriction = restriction_dup(prestriction);
	if (NULL == ptable->prestriction) {
		return FALSE;
	}
	return TRUE;
}

uint32_t table_object_get_position(TABLE_OBJECT *ptable)
{
	return ptable->position;
}

void table_object_set_position(TABLE_OBJECT *ptable, uint32_t position)
{
	uint32_t total_rows;
	
	total_rows = table_object_get_total(ptable);
	if (position > total_rows) {
		position = total_rows;
	}
	ptable->position = position;
}

void table_object_clear_position(TABLE_OBJECT *ptable)
{
	ptable->position = 0;
}

uint32_t table_object_get_total(TABLE_OBJECT *ptable)
{
	uint16_t num;
	uint32_t num1;
	uint32_t total_rows;
	
	if (ATTACHMENT_TABLE == ptable->table_type) {
		num = 0;
		message_object_get_attachments_num(static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj), &num);
		return num;
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		num = 0;
		message_object_get_recipient_num(static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj), &num);
		return num;
	} else if (CONTAINER_TABLE == ptable->table_type) {
		num1 = 0;
		if (ptable->table_flags & FLAG_CONVENIENT_DEPTH) {
			container_object_get_container_table_num(
				static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj),
				true, &num1);
		} else {
			container_object_get_container_table_num(
				static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj),
				false, &num1);
		}
		return num1;
	} else if (USER_TABLE == ptable->table_type) {
		num1 = 0;
		container_object_get_user_table_num(static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj), &num1);
		return num1;
	} else if (STORE_TABLE == ptable->table_type) {
		return 2;
	}
	exmdb_client_sum_table(
		store_object_get_dir(ptable->pstore),
		ptable->table_id, &total_rows);
	return total_rows;
}

TABLE_OBJECT* table_object_create(STORE_OBJECT *pstore,
	void *pparent_obj, uint8_t table_type, uint32_t table_flags)
{
	auto ptable = me_alloc<TABLE_OBJECT>();
	if (NULL == ptable) {
		return NULL;
	}
	ptable->pstore = pstore;
	if (RULE_TABLE == table_type) {
		ptable->pparent_obj = me_alloc<uint64_t>();
		if (NULL == ptable->pparent_obj) {
			free(ptable);
			return NULL;
		}
		*(uint64_t*)ptable->pparent_obj = *(uint64_t*)pparent_obj;
	} else {
		ptable->pparent_obj = pparent_obj;
	}
	ptable->table_type = table_type;
	ptable->table_flags = table_flags;
	ptable->pcolumns = NULL;
	ptable->psorts = NULL;
	ptable->prestriction = NULL;
	ptable->position = 0;
	ptable->table_id = 0;
	ptable->bookmark_index = 0x100;
	double_list_init(&ptable->bookmark_list);
	return ptable;
}

void table_object_free(TABLE_OBJECT *ptable)
{
	table_object_reset(ptable);
	double_list_free(&ptable->bookmark_list);
	if (RULE_TABLE == ptable->table_type) {
		free(ptable->pparent_obj);
	}
	free(ptable);
}

BOOL table_object_create_bookmark(TABLE_OBJECT *ptable, uint32_t *pindex)
{
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	if (FALSE == exmdb_client_mark_table(
		store_object_get_dir(ptable->pstore),
		ptable->table_id, ptable->position,
		&inst_id, &inst_num, &row_type)) {
		return FALSE;
	}
	auto pbookmark = me_alloc<BOOKMARK_NODE>();
	if (NULL == pbookmark) {
		return FALSE;
	}
	pbookmark->node.pdata = pbookmark;
	pbookmark->index = ptable->bookmark_index;
	ptable->bookmark_index ++;
	pbookmark->inst_id = inst_id;
	pbookmark->row_type = row_type;
	pbookmark->inst_num = inst_num;
	pbookmark->position = ptable->position;
	double_list_append_as_tail(&ptable->bookmark_list, &pbookmark->node);
	*pindex = pbookmark->index;
	return TRUE;
}

BOOL table_object_retrieve_bookmark(TABLE_OBJECT *ptable,
	uint32_t index, BOOL *pb_exist)
{
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	uint32_t position;
	uint32_t tmp_type;
	uint32_t total_rows;
	int32_t tmp_position;
	DOUBLE_LIST_NODE *pnode;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	for (pnode=double_list_get_head(&ptable->bookmark_list); NULL!=pnode;
		pnode=double_list_get_after(&ptable->bookmark_list, pnode)) {
		auto bn = static_cast<BOOKMARK_NODE *>(pnode->pdata);
		if (index == bn->index) {
			inst_id = bn->inst_id;
			row_type = bn->row_type;
			inst_num = bn->inst_num;
			position = bn->position;
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	if (FALSE == exmdb_client_locate_table(
		store_object_get_dir(ptable->pstore),
		ptable->table_id, inst_id, inst_num,
		&tmp_position, &tmp_type)) {
		return FALSE;
	}
	*pb_exist = FALSE;
	if (tmp_position >= 0) {
		if (tmp_type == row_type) {
			*pb_exist = TRUE;
		}
		ptable->position = tmp_position;
	} else {
		ptable->position = position;
	}
	total_rows = table_object_get_total(ptable);
	if (ptable->position > total_rows) {
		ptable->position = total_rows;
	}
	return TRUE;
}

void table_object_remove_bookmark(TABLE_OBJECT *ptable, uint32_t index)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&ptable->bookmark_list); NULL!=pnode;
		pnode=double_list_get_after(&ptable->bookmark_list, pnode)) {
		if (index == ((BOOKMARK_NODE*)pnode->pdata)->index) {
			double_list_remove(&ptable->bookmark_list, pnode);
			free(pnode->pdata);
			break;
		}
	}
}

void table_object_clear_bookmarks(TABLE_OBJECT *ptable)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&ptable->bookmark_list)) != nullptr)
		free(pnode->pdata);
}

void table_object_reset(TABLE_OBJECT *ptable)
{
	if (NULL != ptable->pcolumns) {
		proptag_array_free(ptable->pcolumns);
		ptable->pcolumns = NULL;
	}
	if (NULL != ptable->psorts) {
		sortorder_set_free(ptable->psorts);
		ptable->psorts = NULL;
	}
	if (NULL != ptable->prestriction) {
		restriction_free(ptable->prestriction);
		ptable->prestriction = NULL;
	}
	ptable->position = 0;
	table_object_set_table_id(ptable, 0);
	table_object_clear_bookmarks(ptable);
}

static BOOL table_object_evaluate_restriction(
	const TPROPVAL_ARRAY *ppropvals, const RESTRICTION *pres)
{
	int i;
	int len;
	void *pvalue;
	void *pvalue1;
	uint32_t val_size;
	
	switch (pres->rt) {
	case RES_OR:
		for (i = 0; i < pres->andor->count; ++i)
			if (table_object_evaluate_restriction(ppropvals,
			    &pres->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_AND:
		for (i = 0; i < pres->andor->count; ++i)
			if (!table_object_evaluate_restriction(ppropvals,
			    &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_NOT:
		if (table_object_evaluate_restriction(ppropvals, &pres->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		pvalue = common_util_get_propvals(ppropvals, rcon->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strcmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
				return FALSE;
			} else {
				if (strstr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
			}
			return FALSE;
		case FL_PREFIX:
			len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strncasecmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue),
				    len) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strncmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue),
				    len) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		pvalue = common_util_get_propvals(ppropvals, rprop->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		if (rprop->proptag == PROP_TAG_ANR) {
			if (PROP_TYPE(rprop->propval.proptag) != PT_UNICODE)
				return FALSE;
			if (strcasestr(static_cast<char *>(rprop->propval.pvalue),
			    static_cast<char *>(pvalue)) != nullptr)
				return TRUE;
			return FALSE;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (PROP_TYPE(rprop->proptag1) != PROP_TYPE(rprop->proptag2))
			return FALSE;
		pvalue = common_util_get_propvals(ppropvals, rprop->proptag1);
		if (NULL == pvalue) {
			return FALSE;
		}
		pvalue1 = common_util_get_propvals(ppropvals, rprop->proptag2);
		if (NULL == pvalue1) {
			return FALSE;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		pvalue = common_util_get_propvals(ppropvals, rbm->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			if ((*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0)
				return TRUE;
			break;
		case BMR_NEZ:
			if (*static_cast<uint32_t *>(pvalue) & rbm->mask)
				return TRUE;
			break;
		}	
		return FALSE;
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		pvalue = common_util_get_propvals(ppropvals, rsize->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		val_size = propval_size(rsize->proptag, pvalue);
		return propval_compare_relop(rsize->relop, PT_LONG,
		       &val_size, &rsize->size);
	}
	case RES_EXIST:
		pvalue = common_util_get_propvals(ppropvals, pres->exist->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		return TRUE;
	case RES_COMMENT:
		if (pres->comment->pres == nullptr)
			return TRUE;
		return table_object_evaluate_restriction(ppropvals, pres->comment->pres);
	default:
		return FALSE;
	}	
	return FALSE;
}

BOOL table_object_filter_rows(TABLE_OBJECT *ptable,
	uint32_t count, const RESTRICTION *pres,
	const PROPTAG_ARRAY *pcolumns, TARRAY_SET *pset)
{
	int i;
	TARRAY_SET tmp_set;
	uint32_t tmp_proptag;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY tmp_proptags;
	
	switch (ptable->table_type) {
	case ATTACHMENT_TABLE:
		if (!message_object_get_attachment_table_all_proptags(
		    static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj), &proptags))
			return FALSE;	
		tmp_proptag = PROP_TAG_ATTACHDATABINARY;
		tmp_proptags.count = 1;
		tmp_proptags.pproptag = &tmp_proptag;
		common_util_reduce_proptags(&proptags, &tmp_proptags);
		if (!message_object_query_attachment_table(
		    static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj),
		    &proptags, ptable->position, 0x7FFFFFFF, &tmp_set))
			return FALSE;	
		break;
	case RECIPIENT_TABLE:
		if (!message_object_read_recipients(
		    static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj),
		    0, 0xFFFF, &tmp_set))
			return FALSE;	
		break;
	case USER_TABLE:
		container_object_get_user_table_all_proptags(&proptags);
		if (!container_object_query_user_table(
		    static_cast<CONTAINER_OBJECT *>(ptable->pparent_obj),
		    &proptags, ptable->position, 0x7FFFFFFF, &tmp_set))
			return FALSE;	
		break;
	default:
		return FALSE;	
	}
	pset->count = 0;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(tmp_set.count);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	for (i=0; i<tmp_set.count&&pset->count<count; i++) {
		if (FALSE == table_object_evaluate_restriction(
			tmp_set.pparray[i], pres)) {
			continue;	
		}
		pset->pparray[pset->count] = tmp_set.pparray[i];
		pset->count ++;
	}
	return TRUE;
}

BOOL table_object_match_row(TABLE_OBJECT *ptable,
	BOOL b_forward, const RESTRICTION *pres,
	int32_t *pposition)
{
	USER_INFO *pinfo;
	const char *username;
	PROPTAG_ARRAY proptags;
	uint32_t proptag_buff[2];
	TPROPVAL_ARRAY tmp_propvals;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	if (FALSE == store_object_check_private(ptable->pstore)) {
		username = pinfo->username;
	} else {
		username = NULL;
	}
	proptags.count = 2;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_INSTID;
	proptag_buff[1] = PROP_TAG_INSTANCENUM;
	return exmdb_client_match_table(
		store_object_get_dir(ptable->pstore), username,
		pinfo->cpid, ptable->table_id, b_forward,
		ptable->position, pres, &proptags, pposition,
		&tmp_propvals);
}

BOOL table_object_read_row(TABLE_OBJECT *ptable,
	uint64_t inst_id, uint32_t inst_num,
	TPROPVAL_ARRAY *ppropvals)
{
	USER_INFO *pinfo;
	const char *username;
	
	if (NULL == ptable->pcolumns || 0 == ptable->table_id) {
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	if (FALSE == store_object_check_private(ptable->pstore)) {
		username = pinfo->username;
	} else {
		username = NULL;
	}
	return exmdb_client_read_table_row(
		store_object_get_dir(ptable->pstore),
		username, pinfo->cpid, ptable->table_id,
		ptable->pcolumns, inst_id, inst_num,
		ppropvals);
}

BOOL table_object_expand(TABLE_OBJECT *ptable, uint64_t inst_id,
	BOOL *pb_found, int32_t *pposition, uint32_t *prow_count)
{
	if (0 == ptable->table_id) {
		return FALSE;
	}
	return exmdb_client_expand_table(
			store_object_get_dir(ptable->pstore),
			ptable->table_id, inst_id, pb_found,
			pposition, prow_count);
}

BOOL table_object_collapse(TABLE_OBJECT *ptable, uint64_t inst_id,
	BOOL *pb_found, int32_t *pposition, uint32_t *prow_count)
{
	if (0 == ptable->table_id) {
		return FALSE;
	}
	return exmdb_client_collapse_table(
			store_object_get_dir(ptable->pstore),
			ptable->table_id, inst_id, pb_found,
			pposition, prow_count);
}

BOOL table_object_store_state(TABLE_OBJECT *ptable,
	uint64_t inst_id, uint32_t inst_num, uint32_t *pstate_id)
{
	if (0 == ptable->table_id) {
		return FALSE;
	}
	return exmdb_client_store_table_state(
			store_object_get_dir(ptable->pstore),
			ptable->table_id, inst_id, inst_num, pstate_id);
}

BOOL table_object_restore_state(TABLE_OBJECT *ptable,
	uint32_t state_id, uint32_t *pindex)
{
	int32_t position;
	uint64_t inst_id;
	uint32_t inst_num;
	uint32_t tmp_type;
	uint32_t new_position;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	if (FALSE == exmdb_client_mark_table(
		store_object_get_dir(ptable->pstore),
		ptable->table_id, ptable->position,
		&inst_id, &inst_num, &tmp_type)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_restore_table_state(
		store_object_get_dir(ptable->pstore),
		ptable->table_id, state_id, &position)) {
		return FALSE;	
	}
	if (FALSE == exmdb_client_locate_table(
		store_object_get_dir(ptable->pstore),
		ptable->table_id, inst_id, inst_num,
	    reinterpret_cast<int32_t *>(&new_position), &tmp_type)) {
		return FALSE;
	}
	if (position < 0) {
		/* assign an invalid bookmark index */
		*pindex = ptable->bookmark_index;
		ptable->bookmark_index ++;
		return TRUE;
	}
	ptable->position = position;
	if (FALSE == table_object_create_bookmark(ptable, pindex)) {
		ptable->position = new_position;
		return FALSE;
	}
	ptable->position = new_position;
	return TRUE;
}
