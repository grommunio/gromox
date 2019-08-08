#include "tarray_set.h"
#include "object_tree.h"
#include "restriction.h"
#include "exmdb_client.h"
#include "table_object.h"
#include "rules_object.h"
#include "sortorder_set.h"
#include "folder_object.h"
#include "sortorder_set.h"
#include "proptag_array.h"
#include "zarafa_server.h"
#include "message_object.h"
#include "container_object.h"
#include <stdlib.h>
#include <string.h>

typedef struct _BOOKMARK_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t index;
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	uint32_t position;
} BOOKMARK_NODE;

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
		return container_object_restrict_user_table(
			ptable->pparent_obj, ptable->prestriction);
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
			folder_object_get_id(ptable->pparent_obj),
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
					folder_object_get_id(ptable->pparent_obj),
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
			table_flags != TABLE_FLAG_ASSOCIATED;
		}
		if (FALSE == exmdb_client_load_content_table(
			store_object_get_dir(ptable->pstore), pinfo->cpid,
			folder_object_get_id(ptable->pparent_obj),
			username, table_flags, ptable->prestriction,
			ptable->psorts, &table_id, &row_num)) {
			return FALSE;
		}
		break;
	case RULE_TABLE:
		if (FALSE == exmdb_client_load_rule_table(
			store_object_get_dir(ptable->pstore),
			rules_object_get_folder_id(ptable->pparent_obj),
			0, ptable->prestriction,
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
		container_object_clear_restriction(
						ptable->pparent_obj);
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
	static uint32_t proptag_buff[] = {
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
	pproptags->pproptag = common_util_alloc(sizeof(uint32_t)*
			(tmp_proptags1.count + tmp_proptags2.count + 25));
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
								ptable->pparent_obj, pcolumns);
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		return message_object_get_recipient_all_proptags(
							ptable->pparent_obj, pcolumns);
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
	uint64_t fid_val;
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
	uint64_t fid_val;
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
	const PROPTAG_ARRAY *pcolumns, uint16_t row_count, TARRAY_SET *pset)
{
	int i, j;
	uint32_t handle;
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
	if (ptable->position >= table_object_get_total(
		ptable) && TRUE == b_forward) {
		pset->count = 0;
		return TRUE;
	}
	if (TRUE == b_forward) {
		row_needed = row_count;
	} else {
		row_needed = -1 * row_count;
	}
	if (ATTACHMENT_TABLE == ptable->table_type) {
		return message_object_query_attachment_table(
			ptable->pparent_obj, pcolumns,
			ptable->position, row_needed, pset);
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		if (FALSE == message_object_read_recipients(
			ptable->pparent_obj, 0, 0xFFFF, &rcpt_set)) {
			return FALSE;	
		}
		if (TRUE == b_forward) {
			if (ptable->position + row_needed > rcpt_set.count) {
				end_pos = rcpt_set.count - 1;
			} else {
				end_pos = ptable->position + row_needed - 1;
			}
			pset->count = 0;
			pset->pparray = common_util_alloc(sizeof(void*)
						*(end_pos - ptable->position + 1));
			if (NULL == pset->pparray) {
				return FALSE;
			}
			for (i=ptable->position; i<=end_pos; i++) {
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
			pset->pparray = common_util_alloc(sizeof(void*)
						*(ptable->position - end_pos + 1));
			if (NULL == pset->pparray) {
				return FALSE;
			}
			for (i=ptable->position; i>=end_pos; i--) {
				pset->pparray[pset->count] = rcpt_set.pparray[i];
				pset->count ++;
			}
		}
		return TRUE;
	} else if (CONTAINER_TABLE == ptable->table_type) {
		if (ptable->table_flags & FLAG_CONVENIENT_DEPTH) {
			return container_object_query_container_table(
					ptable->pparent_obj, pcolumns, TRUE,
					ptable->position, row_needed, pset);
		} else {
			return container_object_query_container_table(
					ptable->pparent_obj, pcolumns, FALSE,
					ptable->position, row_needed, pset);
		}
	} else if (USER_TABLE == ptable->table_type) {
		return container_object_query_user_table(
			ptable->pparent_obj, pcolumns,
			ptable->position, row_needed, pset);
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
			pset->pparray = common_util_alloc(sizeof(void*)
						*(end_pos - ptable->position + 1));
			if (NULL == pset->pparray) {
				return FALSE;
			}
			for (i=ptable->position; i<=end_pos; i++) {
				if (0 != i && 1 != i) {
					continue;
				}
				pset->pparray[pset->count] =
					common_util_alloc(sizeof(TPROPVAL_ARRAY));
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
				pstore = object_tree_get_object(
					pinfo->ptree, handle, &mapi_type);
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
			pset->pparray = common_util_alloc(sizeof(void*)
						*(ptable->position - end_pos + 1));
			if (NULL == pset->pparray) {
				return FALSE;
			}
			for (i=ptable->position; i>=end_pos; i--) {
				if (0 != i && 1 != i) {
					continue;
				}
				pset->pparray[pset->count] =
					common_util_alloc(sizeof(TPROPVAL_ARRAY));
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
				pstore = object_tree_get_object(
					pinfo->ptree, handle, &mapi_type);
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
			tmp_columns.pproptag = common_util_alloc(
					sizeof(uint32_t)*pcolumns->count);
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
								ptag_access = common_util_alloc(
												sizeof(uint32_t));
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
								ppermission = common_util_alloc(
												sizeof(uint32_t));
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
				ppropvals = common_util_alloc(sizeof(TPROPVAL_ARRAY));
				if (NULL == ppropvals) {
					return FALSE;
				}
				ppropvals->count = temp_set.pparray[i]->count + 1;
				ppropvals->ppropval = common_util_alloc(
					sizeof(TAGGED_PROPVAL)*ppropvals->count);
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
		message_object_get_attachments_num(ptable->pparent_obj, &num);
		return num;
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		num = 0;
		message_object_get_recipient_num(ptable->pparent_obj, &num);
		return num;
	} else if (CONTAINER_TABLE == ptable->table_type) {
		num1 = 0;
		if (ptable->table_flags & FLAG_CONVENIENT_DEPTH) {
			container_object_get_container_table_num(
					ptable->pparent_obj, TRUE, &num1);
		} else {
			container_object_get_container_table_num(
					ptable->pparent_obj, FALSE, &num1);
		}
		return num1;
	} else if (USER_TABLE == ptable->table_type) {
		num1 = 0;
		container_object_get_user_table_num(
				ptable->pparent_obj, &num1);
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
	TARRAY_SET rcpt_set;
	TABLE_OBJECT *ptable;
	
	ptable = malloc(sizeof(TABLE_OBJECT));
	if (NULL == ptable) {
		return NULL;
	}
	ptable->pstore = pstore;
	ptable->pparent_obj = pparent_obj;
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
	free(ptable);
}

BOOL table_object_create_bookmark(TABLE_OBJECT *ptable, uint32_t *pindex)
{
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	DOUBLE_LIST_NODE *pnode;
	BOOKMARK_NODE *pbookmark;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	if (FALSE == exmdb_client_mark_table(
		store_object_get_dir(ptable->pstore),
		ptable->table_id, ptable->position,
		&inst_id, &inst_num, &row_type)) {
		return FALSE;
	}
	pbookmark = malloc(sizeof(BOOKMARK_NODE));
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
		if (index == ((BOOKMARK_NODE*)pnode->pdata)->index) {
			inst_id = ((BOOKMARK_NODE*)pnode->pdata)->inst_id;
			row_type = ((BOOKMARK_NODE*)pnode->pdata)->row_type;
			inst_num = ((BOOKMARK_NODE*)pnode->pdata)->inst_num;
			position = ((BOOKMARK_NODE*)pnode->pdata)->position;
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
	
	while (pnode=double_list_get_from_head(&ptable->bookmark_list)) {
		free(pnode->pdata);
	}
}

void table_object_reset(TABLE_OBJECT *ptable)
{
	DOUBLE_LIST_NODE *pnode;
	
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
		&new_position, &tmp_type)) {
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
