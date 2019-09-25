#include "attachment_object.h"
#include "system_services.h"
#include "message_object.h"
#include "tpropval_array.h"
#include "zarafa_server.h"
#include "proptag_array.h"
#include "store_object.h"
#include "exmdb_client.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "rop_util.h"
#include "idset.h"
#include "guid.h"
#include "util.h"
#include "pcl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BOOL message_object_set_properties_internal(
	MESSAGE_OBJECT *pmessage, BOOL b_check,
	const TPROPVAL_ARRAY *ppropvals);

BOOL message_object_get_recipient_all_proptags(
	MESSAGE_OBJECT *pmessage, PROPTAG_ARRAY *pproptags)
{
	return exmdb_client_get_message_instance_rcpts_all_proptags(
						store_object_get_dir(pmessage->pstore),
						pmessage->instance_id, pproptags);
}

MESSAGE_OBJECT* message_object_create(STORE_OBJECT *pstore,
	BOOL b_new, uint32_t cpid, uint64_t message_id,
	void *pparent, uint32_t tag_access, BOOL b_writable,
	ICS_STATE *pstate)
{
	USER_INFO *pinfo;
	uint64_t *pchange_num;
	MESSAGE_OBJECT *pmessage;
	
	pmessage = malloc(sizeof(MESSAGE_OBJECT));
	if (NULL == pmessage) {
		return NULL;
	}
	memset(pmessage, 0, sizeof(MESSAGE_OBJECT));
	pmessage->pstore = pstore;
	pmessage->b_new = b_new;
	pmessage->b_touched = FALSE;
	pmessage->cpid = cpid;
	pmessage->message_id = message_id;
	pmessage->tag_access = tag_access;
	pmessage->b_writable = b_writable;
	pmessage->pstate = pstate;
	pmessage->change_num = 0;
	pmessage->pchanged_proptags = NULL;
	pmessage->premoved_proptags = NULL;
	if (0 == message_id) {
		pmessage->pembedding = pparent;
		if (FALSE == exmdb_client_load_embedded_instance(
			store_object_get_dir(pstore), b_new,
			((ATTACHMENT_OBJECT*)pparent)->instance_id,
			&pmessage->instance_id)) {
			free(pmessage);
			return NULL;
		}
		/* cannot find embedded message in attachment, return
			immediately to caller and the caller check the
			result by calling message_object_get_instance_id */
		if (FALSE == b_new && 0 == pmessage->instance_id) {
			return pmessage;
		}
	} else {
		pmessage->folder_id = *(uint64_t*)pparent;
		if (TRUE == store_object_check_private(pmessage->pstore)) {
			if (FALSE == exmdb_client_load_message_instance(
				store_object_get_dir(pstore), NULL, cpid,
				b_new, pmessage->folder_id, message_id,
				&pmessage->instance_id)) {
				free(pmessage);
				return NULL;
			}
		} else {
			pinfo = zarafa_server_get_info();
			if (FALSE == exmdb_client_load_message_instance(
				store_object_get_dir(pstore), pinfo->username,
				cpid, b_new, pmessage->folder_id, message_id,
				&pmessage->instance_id)) {
				free(pmessage);
				return NULL;
			}
		}
	}
	if (0 == pmessage->instance_id) {
		free(pmessage);
		return NULL;
	}
	pmessage->pchanged_proptags = proptag_array_init();
	if (NULL == pmessage->pchanged_proptags) {
		message_object_free(pmessage);
		return NULL;
	}
	pmessage->premoved_proptags = proptag_array_init();
	if (NULL == pmessage->premoved_proptags) {
		message_object_free(pmessage);
		return NULL;
	}
	if (FALSE == b_new) {
		if (FALSE == exmdb_client_get_instance_property(
			store_object_get_dir(pstore), pmessage->instance_id,
			PROP_TAG_CHANGENUMBER, (void**)&pchange_num)) {
			message_object_free(pmessage);
			return NULL;
		}
		if (NULL != pchange_num) {
			pmessage->change_num = *pchange_num;
		}
	}
	return pmessage;
}

BOOL message_object_check_importing(MESSAGE_OBJECT *pmessage)
{
	if (0 != pmessage->message_id && NULL != pmessage->pstate) {
		return TRUE;
	}
	return FALSE;
}

BOOL message_object_check_writable(MESSAGE_OBJECT *pmessage)
{
	return pmessage->b_writable;
}

uint32_t message_object_get_instance_id(MESSAGE_OBJECT *pmessage)
{
	return pmessage->instance_id;
}

BOOL message_object_check_orignal_touched(
	MESSAGE_OBJECT *pmessage, BOOL *pb_touched)
{
	uint64_t *pchange_num;
	
	if (TRUE == pmessage->b_new) {
		*pb_touched = FALSE;
		return TRUE;
	}
	if (0 != pmessage->message_id) {
		if (FALSE == exmdb_client_get_message_property(
			store_object_get_dir(pmessage->pstore), NULL,
			0, pmessage->message_id, PROP_TAG_CHANGENUMBER,
			(void**)&pchange_num)) {
			return FALSE;
		}
	} else {
		if (FALSE == exmdb_client_get_embeded_cn(
			store_object_get_dir(pmessage->pstore),
			pmessage->instance_id, &pchange_num)) {
			return FALSE;	
		}
	}
	if (NULL == pchange_num) {
		/* if cannot find PROP_TAG_CHANGENUMBER, it
			means message does not exist any more */
		*pb_touched = TRUE;
	} else {
		if (*pchange_num == pmessage->change_num) {
			*pb_touched = FALSE;
		} else {
			*pb_touched = TRUE;
		}
	}
	return TRUE;
}

void message_object_free(MESSAGE_OBJECT *pmessage)
{	
	if (0 != pmessage->instance_id) { 
		exmdb_client_unload_instance(
			store_object_get_dir(pmessage->pstore),
			pmessage->instance_id);
	}
	if (NULL != pmessage->pchanged_proptags) {
		proptag_array_free(pmessage->pchanged_proptags);
	}
	if (NULL != pmessage->premoved_proptags) {
		proptag_array_free(pmessage->premoved_proptags);
	}
	free(pmessage);
}

BOOL message_object_init_message(MESSAGE_OBJECT *pmessage,
	BOOL b_fai, uint32_t cpid)
{
	void *pvalue;
	GUID tmp_guid;
	USER_INFO *pinfo;
	EXT_PUSH ext_push;
	char id_string[256];
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	
	
	if (FALSE == pmessage->b_new) {
		return FALSE;
	}
	propvals.count = 0;
	propvals.ppropval = common_util_alloc(
				sizeof(TAGGED_PROPVAL)*20);
	if (NULL == propvals.ppropval) {
		return FALSE;
	}
	
	propvals.ppropval[propvals.count].proptag =
						PROP_TAG_MESSAGECODEPAGE;
	pvalue = common_util_alloc(sizeof(uint32_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint32_t*)pvalue = cpid;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_IMPORTANCE;
	pvalue = common_util_alloc(sizeof(uint32_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint32_t*)pvalue = 1;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_MESSAGECLASS;
	propvals.ppropval[propvals.count].pvalue = "IPM.Note";
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_SENSITIVITY;
	pvalue = common_util_alloc(sizeof(uint32_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint32_t*)pvalue = 0;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
					PROP_TAG_ORIGINALDISPLAYBCC;
	propvals.ppropval[propvals.count].pvalue = "";
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
					PROP_TAG_ORIGINALDISPLAYCC;
	propvals.ppropval[propvals.count].pvalue = "";
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
					PROP_TAG_ORIGINALDISPLAYTO;
	propvals.ppropval[propvals.count].pvalue = "";
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_MESSAGEFLAGS;
	pvalue = common_util_alloc(sizeof(uint32_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint32_t*)pvalue = MESSAGE_FLAG_UNSENT
					| MESSAGE_FLAG_UNMODIFIED;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
								PROP_TAG_READ;
	pvalue = common_util_alloc(sizeof(uint8_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint8_t*)pvalue = 1;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_ASSOCIATED;
	pvalue = common_util_alloc(sizeof(uint8_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	if (FALSE == b_fai) {
		*(uint8_t*)pvalue = 0;
	} else {
		*(uint8_t*)pvalue = 1;
	}
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_TRUSTSENDER;
	pvalue = common_util_alloc(sizeof(uint32_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint32_t*)pvalue = 1;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_CREATIONTIME;
	pvalue = common_util_alloc(sizeof(uint64_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint64_t*)pvalue = rop_util_current_nttime();
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_SEARCHKEY;
	pvalue = common_util_alloc(sizeof(BINARY));
	if (NULL == pvalue) {
		return FALSE;
	}
	
	pvalue = common_util_guid_to_binary(guid_random_new());
	if (NULL == pvalue) {
		return FALSE;
	}
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
						PROP_TAG_MESSAGELOCALEID;
	pvalue = common_util_alloc(sizeof(uint32_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint32_t*)pvalue = 0x0409;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_LOCALEID;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_CREATORNAME;
	pvalue = common_util_alloc(1024);
	if (NULL == pvalue) {
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	if (FALSE == system_services_get_user_displayname(
		pinfo->username, pvalue) ||
		'\0' == ((char*)pvalue)[0]) {
		strcpy(pvalue, pinfo->username);
	}
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
						PROP_TAG_CREATORENTRYID;
	pvalue = common_util_username_to_addressbook_entryid(
										pinfo->username);
	if (NULL == pvalue) {
		return FALSE;
	}
	propvals.ppropval[propvals.count].pvalue = pvalue;	
	propvals.count ++;
	
	tmp_guid = guid_random_new();
	ext_buffer_push_init(&ext_push, id_string, 256, 0);
	ext_buffer_push_guid(&ext_push, &tmp_guid);
	encode_hex_binary(id_string, 16, id_string + 16, 64);
	id_string[0] = '<';
	memmove(id_string + 1, id_string + 16, 32);
	snprintf(id_string + 33, 128, "@%s>", common_util_get_hostname());
	propvals.ppropval[propvals.count].proptag =
					PROP_TAG_INTERNETMESSAGEID;
	propvals.ppropval[propvals.count].pvalue = id_string;
	propvals.count ++;
	
	if (FALSE == exmdb_client_set_instance_properties(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, &propvals, &problems)) {
		return FALSE;	
	}
	pmessage->b_touched = TRUE;
	return TRUE;
}

uint64_t message_object_get_id(MESSAGE_OBJECT *pmessage)
{
	return pmessage->message_id;
}

uint32_t message_object_get_cpid(MESSAGE_OBJECT *pmessage)
{
	return pmessage->cpid;
}

uint32_t message_object_get_tag_access(MESSAGE_OBJECT *pmessage)
{
	return pmessage->tag_access;
}

STORE_OBJECT* message_object_get_store(MESSAGE_OBJECT *pmessage)
{
	return pmessage->pstore;
}

BOOL message_object_save(MESSAGE_OBJECT *pmessage)
{
	int i;
	BOOL b_new;
	BOOL b_fai;
	XID tmp_xid;
	void *pvalue;
	BOOL b_result;
	const char *dir;
	uint32_t result;
	USER_INFO *pinfo;
	BINARY *pbin_pcl;
	BINARY *pbin_pcl1;
	uint32_t tmp_index;
	uint32_t *pgroup_id;
	uint32_t tmp_status;
	INDEX_ARRAY *pindices;
	BINARY *pbin_changekey;
	INDEX_ARRAY tmp_indices;
	MESSAGE_CONTENT *pmsgctnt;
	PROBLEM_ARRAY tmp_problems;
	TAGGED_PROPVAL tmp_propval;
	TPROPVAL_ARRAY tmp_propvals;
	PROPERTY_GROUPINFO *pgpinfo;
	PROPTAG_ARRAY *pungroup_proptags;
	
	
	if (FALSE == pmessage->b_new &&
		FALSE == pmessage->b_touched) {
		return TRUE;	
	}
	dir = store_object_get_dir(pmessage->pstore);
	pinfo = zarafa_server_get_info();
	if (FALSE == exmdb_client_allocate_cn(
		dir, &pmessage->change_num)) {
		return FALSE;
	}
	
	if (FALSE == exmdb_client_get_instance_property(
		dir, pmessage->instance_id, PROP_TAG_ASSOCIATED,
		&pvalue)) {
		return FALSE;	
	}
	if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
		b_fai = FALSE;
	} else {
		b_fai = TRUE;
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = common_util_alloc(sizeof(TAGGED_PROPVAL)*8);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
								PROP_TAG_LOCALCOMMITTIME;
	pvalue = common_util_alloc(sizeof(uint64_t));
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint64_t*)pvalue = rop_util_current_nttime();
	tmp_propvals.ppropval[tmp_propvals.count].pvalue = pvalue;
	tmp_propvals.count ++;
	
	if (FALSE == proptag_array_check(pmessage->pchanged_proptags,
		PROP_TAG_LASTMODIFICATIONTIME)) {
		tmp_propvals.ppropval[tmp_propvals.count].proptag =
								PROP_TAG_LASTMODIFICATIONTIME;
		tmp_propvals.ppropval[tmp_propvals.count].pvalue = pvalue;
		tmp_propvals.count ++;
	}
	
	if (FALSE == proptag_array_check(pmessage->pchanged_proptags,
		PROP_TAG_LASTMODIFIERNAME)) {
		tmp_propvals.ppropval[tmp_propvals.count].proptag =
									PROP_TAG_LASTMODIFIERNAME;
		pvalue = common_util_alloc(1024);
		if (NULL == pvalue) {
			return FALSE;
		}
		if (FALSE == system_services_get_user_displayname(
			pinfo->username, pvalue) || '\0' == ((char*)pvalue)[0]) {
			strcpy(pvalue, pinfo->username);
		}
		tmp_propvals.ppropval[tmp_propvals.count].pvalue = pvalue;
		tmp_propvals.count ++;
	}
	
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
							PROP_TAG_LASTMODIFIERENTRYID;
	pvalue = common_util_username_to_addressbook_entryid(
										pinfo->username);
	if (NULL == pvalue) {
		return FALSE;
	}
	tmp_propvals.ppropval[tmp_propvals.count].pvalue = pvalue;
	tmp_propvals.count ++;
	
	if (0 != pmessage->message_id) {
		if (FALSE == exmdb_client_get_instance_property(dir,
			pmessage->instance_id, PROP_TAG_PREDECESSORCHANGELIST,
			(void**)&pbin_pcl)) {
			return FALSE;
		}
		if (FALSE == pmessage->b_new && NULL == pbin_pcl) {
			return FALSE;
		}
		if (TRUE == store_object_check_private(pmessage->pstore)) {
			tmp_xid.guid = rop_util_make_user_guid(
				store_object_get_account_id(pmessage->pstore));
		} else {
			tmp_xid.guid = rop_util_make_domain_guid(
				store_object_get_account_id(pmessage->pstore));
		}
		rop_util_get_gc_array(pmessage->change_num, tmp_xid.local_id);
		tmp_propvals.ppropval[tmp_propvals.count].proptag =
										PROP_TAG_CHANGEKEY;
		pbin_changekey = common_util_xid_to_binary(22, &tmp_xid);
		if (NULL == pbin_changekey) {
			return FALSE;
		}
		tmp_propvals.ppropval[tmp_propvals.count].pvalue =
											pbin_changekey;
		tmp_propvals.count ++;
		
		pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
		if (NULL == pbin_pcl) {
			return FALSE;
		}
		tmp_propvals.ppropval[tmp_propvals.count].proptag =
							PROP_TAG_PREDECESSORCHANGELIST;
		tmp_propvals.ppropval[tmp_propvals.count].pvalue = pbin_pcl;	
		tmp_propvals.count ++;
	}
	
	if (FALSE == message_object_set_properties_internal(
		pmessage, FALSE, &tmp_propvals)) {
		return FALSE;	
	}
	
	/* change number of embedding message is used for message
		modification's check when the rop_savechangesmessage
		is called, it is useless for ICS!
	*/
	tmp_propval.proptag = PROP_TAG_CHANGENUMBER;
	tmp_propval.pvalue = &pmessage->change_num;
	if (FALSE == exmdb_client_set_instance_property(dir,
		pmessage->instance_id, &tmp_propval, &result)) {
		return FALSE;	
	}
	
	if (FALSE == exmdb_client_flush_instance(
		dir, pmessage->instance_id,
		store_object_get_account(pmessage->pstore),
		&b_result) || FALSE == b_result) {
		return FALSE;	
	}
	b_new = pmessage->b_new;
	pmessage->b_new = FALSE;
	pmessage->b_touched = FALSE;
	if (0 == pmessage->message_id) {
		pmessage->pembedding->b_touched = TRUE;
		return TRUE;
	}
	
	if (NULL != pmessage->pstate) {
		idset_append(pmessage->pstate->pgiven,
						pmessage->message_id);
		if (FALSE == b_fai) {
			idset_append(pmessage->pstate->pseen,
							pmessage->change_num);
		} else {
			idset_append(pmessage->pstate->pseen_fai,
								pmessage->change_num);
		}
	}
	
	if (0 == pmessage->message_id || TRUE == b_fai) {
		proptag_array_clear(pmessage->pchanged_proptags);
		proptag_array_clear(pmessage->premoved_proptags);
		return TRUE;
	}
	
	if (TRUE == b_new) {
		goto SAVE_FULL_CHANGE;
	}
	if (FALSE == exmdb_client_get_message_group_id(
		dir, pmessage->message_id, &pgroup_id)) {
		return FALSE;	
	}
	if (NULL == pgroup_id) {
		pgpinfo = store_object_get_last_property_groupinfo(
											pmessage->pstore);
		if (NULL == pgpinfo) {
			return FALSE;
		}
		if (FALSE == exmdb_client_set_message_group_id(
			dir, pmessage->message_id, pgpinfo->group_id)) {
			return FALSE;	
		}
	}  else {
		pgpinfo = store_object_get_property_groupinfo(
						pmessage->pstore, *pgroup_id);
		if (NULL == pgpinfo) {
			return FALSE;
		}
	}
	
	if (FALSE == exmdb_client_mark_modified(
		dir, pmessage->message_id)) {
		return FALSE;	
	}
	
	pindices = proptag_array_init();
	if (NULL == pindices) {
		return FALSE;
	}
	pungroup_proptags = proptag_array_init();
	if (NULL == pungroup_proptags) {
		proptag_array_free(pindices);
		return FALSE;
	}
	/* always mark PROP_TAG_MESSAGEFLAGS as changed */
	if (FALSE == proptag_array_append(
		pmessage->pchanged_proptags, PROP_TAG_MESSAGEFLAGS)) {
		proptag_array_free(pindices);
		proptag_array_free(pungroup_proptags);
		return FALSE;
	}
	for (i=0; i<pmessage->pchanged_proptags->count; i++) {
		if (FALSE == property_groupinfo_get_partial_index(pgpinfo,
			pmessage->pchanged_proptags->pproptag[i], &tmp_index)) {
			if (FALSE == proptag_array_append(pungroup_proptags,
				pmessage->pchanged_proptags->pproptag[i])) {
				proptag_array_free(pindices);
				proptag_array_free(pungroup_proptags);
				return FALSE;
			}
		} else {
			if (FALSE == proptag_array_append(pindices, tmp_index)) {
				proptag_array_free(pindices);
				proptag_array_free(pungroup_proptags);
				return FALSE;
			}
		}
	}
	for (i=0; i<pmessage->premoved_proptags->count; i++) {
		if (FALSE == property_groupinfo_get_partial_index(pgpinfo,
			pmessage->premoved_proptags->pproptag[i], &tmp_index)) {
			proptag_array_free(pindices);
			proptag_array_free(pungroup_proptags);
			goto SAVE_FULL_CHANGE;
		} else {
			if (FALSE == proptag_array_append(pindices, tmp_index)) {
				proptag_array_free(pindices);
				proptag_array_free(pungroup_proptags);
				return FALSE;
			}
		}
	}
	if (FALSE == exmdb_client_save_change_indices(
		dir, pmessage->message_id, pmessage->change_num,
		pindices, pungroup_proptags)) {
		proptag_array_free(pindices);
		proptag_array_free(pungroup_proptags);
		return FALSE;
	}
	proptag_array_free(pindices);
	proptag_array_free(pungroup_proptags);
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	/* trigger the rule evaluation under public mode 
		when the message is first saved to the folder */
	if (TRUE == b_new && FALSE == b_fai && 0 != pmessage->message_id
		&& FALSE == store_object_check_private(pmessage->pstore)) {
		exmdb_client_rule_new_message(dir, pinfo->username,
			store_object_get_account(pmessage->pstore),
			pmessage->cpid, pmessage->folder_id,
			pmessage->message_id);
	}
	return TRUE;
	
SAVE_FULL_CHANGE:
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	tmp_indices.count = 0;
	tmp_indices.pproptag = NULL;
	if (FALSE == exmdb_client_save_change_indices(
		dir, pmessage->message_id, pmessage->change_num,
		&tmp_indices, (PROPTAG_ARRAY*)&tmp_indices)) {
		return FALSE;	
	}
	/* trigger the rule evaluation under public mode 
		when the message is first saved to the folder */
	if (TRUE == b_new && FALSE == b_fai && 0 != pmessage->message_id
		&& FALSE == store_object_check_private(pmessage->pstore)) {
		exmdb_client_rule_new_message(dir, pinfo->username,
			store_object_get_account(pmessage->pstore),
			pmessage->cpid, pmessage->folder_id,
			pmessage->message_id);
	}
	return TRUE;
}

BOOL message_object_reload(MESSAGE_OBJECT *pmessage)
{
	BOOL b_result;
	uint64_t *pchange_num;
	
	if (TRUE == pmessage->b_new) {
		return TRUE;
	}
	if (FALSE == exmdb_client_reload_message_instance(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, &b_result) ||
		FALSE == b_result) {
		return FALSE;	
	}
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	pmessage->b_touched = FALSE;
	pmessage->change_num = 0;
	if (FALSE == pmessage->b_new) {
		if (FALSE == exmdb_client_get_instance_property(
			store_object_get_dir(pmessage->pstore),
			pmessage->instance_id, PROP_TAG_CHANGENUMBER,
			(void**)&pchange_num) || NULL == pchange_num) {
			return FALSE;
		}
		pmessage->change_num = *pchange_num;
	}
	return TRUE;
}

BOOL message_object_write_message(MESSAGE_OBJECT *pmessage,
	const MESSAGE_CONTENT *pmsgctnt)
{
	PROPTAG_ARRAY proptags;
	MESSAGE_CONTENT msgctnt;
	PROBLEM_ARRAY tmp_problems;
	
	msgctnt = *pmsgctnt;
	msgctnt.proplist.ppropval = common_util_alloc(
		sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
	if (NULL == msgctnt.proplist.ppropval) {
		return FALSE;
	}
	memcpy(msgctnt.proplist.ppropval, pmsgctnt->proplist.ppropval,
				sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_MID);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_DISPLAYTO);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_DISPLAYCC);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_DISPLAYBCC);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_MESSAGESIZE);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_HASATTACHMENTS);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_CHANGEKEY);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_CHANGENUMBER);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_PREDECESSORCHANGELIST);
	if (FALSE == exmdb_client_clear_message_instance(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_write_message_instance(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, &msgctnt,
		TRUE, &proptags, &tmp_problems)) {
		return FALSE;	
	}
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	pmessage->b_new = TRUE;
	pmessage->b_touched = TRUE;
	return TRUE;
}

BOOL message_object_read_recipients(MESSAGE_OBJECT *pmessage,
	uint32_t row_id, uint16_t need_count, TARRAY_SET *pset)
{
	return exmdb_client_get_message_instance_rcpts(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, row_id, need_count, pset);
}

BOOL message_object_get_rowid_begin(
	MESSAGE_OBJECT *pmessage, uint32_t *pbegin_id)
{
	int i;
	int last_rowid;
	int32_t *prow_id;
	TARRAY_SET tmp_set;
	
	if (FALSE == exmdb_client_get_message_instance_rcpts(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, 0, 0xFFFF, &tmp_set)) {
		return FALSE;	
	}
	last_rowid = -1;
	for (i=0; i<tmp_set.count; i++) {
		prow_id = common_util_get_propvals(
			tmp_set.pparray[i], PROP_TAG_ROWID);
		if (NULL != prow_id && *prow_id > last_rowid) {
			last_rowid = *prow_id;
		}
	}
	*pbegin_id = last_rowid + 1;
	return TRUE;
}

BOOL message_object_get_recipient_num(
	MESSAGE_OBJECT *pmessage, uint16_t *pnum)
{
	return exmdb_client_get_message_instance_rcpts_num(
			store_object_get_dir(pmessage->pstore),
			pmessage->instance_id, pnum);
}

BOOL message_object_empty_rcpts(MESSAGE_OBJECT *pmessage)
{
	if (FALSE == exmdb_client_empty_message_instance_rcpts(
		store_object_get_dir(pmessage->pstore), pmessage->instance_id)) {
		return FALSE;	
	}
	pmessage->b_touched = TRUE;
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	proptag_array_append(pmessage->pchanged_proptags,
						PROP_TAG_MESSAGERECIPIENTS);
	return TRUE;
}

BOOL message_object_set_rcpts(MESSAGE_OBJECT *pmessage,
	const TARRAY_SET *pset)
{
	int i;
	
	if (FALSE == exmdb_client_update_message_instance_rcpts(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, pset)) {
		return FALSE;	
	}
	pmessage->b_touched = TRUE;
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	proptag_array_append(pmessage->pchanged_proptags,
						PROP_TAG_MESSAGERECIPIENTS);
	return TRUE;
}

BOOL message_object_get_attachments_num(
	MESSAGE_OBJECT *pmessage, uint16_t *pnum)
{
	return exmdb_client_get_message_instance_attachments_num(
						store_object_get_dir(pmessage->pstore),
						pmessage->instance_id, pnum);
}

BOOL message_object_delele_attachment(MESSAGE_OBJECT *pmessage,
	uint32_t attachment_num)
{
	if (FALSE == exmdb_client_delete_message_instance_attachment(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, attachment_num)) {
		return FALSE;
	}
	pmessage->b_touched = TRUE;
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	proptag_array_append(pmessage->pchanged_proptags,
						PROP_TAG_MESSAGEATTACHMENTS);
	return TRUE;
}

BOOL message_object_get_attachment_table_all_proptags(
	MESSAGE_OBJECT *pmessage, PROPTAG_ARRAY *pproptags)
{
	return exmdb_client_get_message_instance_attachment_table_all_proptags(
			store_object_get_dir(pmessage->pstore),
			pmessage->instance_id, pproptags);
}

BOOL message_object_query_attachment_table(
	MESSAGE_OBJECT *pmessage, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	return exmdb_client_query_message_instance_attachment_table(
						store_object_get_dir(pmessage->pstore),
						pmessage->instance_id, pproptags,
						start_pos, row_needed, pset);
}

BOOL message_object_clear_unsent(MESSAGE_OBJECT *pmessage)
{
	uint32_t result;
	uint32_t *pmessage_flags;
	TAGGED_PROPVAL tmp_propval;
	
	if (0 == pmessage->message_id) {
		return FALSE;
	}
	if (FALSE == exmdb_client_get_instance_property(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, PROP_TAG_MESSAGEFLAGS,
		(void**)&pmessage_flags)) {
		return FALSE;	
	}
	if (NULL == pmessage_flags) {
		return TRUE;
	}
	*pmessage_flags &= ~MESSAGE_FLAG_UNSENT;
	tmp_propval.proptag = PROP_TAG_MESSAGEFLAGS;
	tmp_propval.pvalue = pmessage_flags;
	return exmdb_client_set_instance_property(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, &tmp_propval, &result);
}

BOOL message_object_get_all_proptags(MESSAGE_OBJECT *pmessage,
	PROPTAG_ARRAY *pproptags)
{
	int i;
	PROPTAG_ARRAY tmp_proptags;
	
	if (FALSE == exmdb_client_get_instance_all_proptags(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, &tmp_proptags)) {
		return FALSE;	
	}
	pproptags->count = 0;
	pproptags->pproptag = common_util_alloc(
		sizeof(uint32_t)*(tmp_proptags.count + 15));
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	for (i=0; i<tmp_proptags.count; i++) {
		switch (tmp_proptags.pproptag[i]) {
		case PROP_TAG_MID:
		case PROP_TAG_ASSOCIATED:
		case PROP_TAG_CHANGENUMBER:
			continue;
		default:
			pproptags->pproptag[pproptags->count] =
							tmp_proptags.pproptag[i];
			pproptags->count ++;
			break;
		}
	}
	pproptags->pproptag[pproptags->count] = PROP_TAG_ACCESS;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_ENTRYID;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_ACCESSLEVEL;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_OBJECTTYPE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_PARENTENTRYID;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_PARENTSOURCEKEY;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_RECORDKEY;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_STORERECORDKEY;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_MAPPINGSIGNATURE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_STOREENTRYID;
	pproptags->count ++;
	if (NULL == pmessage->pembedding && common_util_index_proptags(
		pproptags, PROP_TAG_SOURCEKEY) < 0) {
		pproptags->pproptag[pproptags->count] = PROP_TAG_SOURCEKEY;
		pproptags->count ++;
	}
	if (common_util_index_proptags(pproptags,
		PROP_TAG_MESSAGELOCALEID) < 0) {
		pproptags->pproptag[pproptags->count] = PROP_TAG_MESSAGELOCALEID;
		pproptags->count ++;
	}
	if (common_util_index_proptags(pproptags,
		PROP_TAG_MESSAGECODEPAGE) < 0) {
		pproptags->pproptag[pproptags->count] = PROP_TAG_MESSAGECODEPAGE;
		pproptags->count ++;
	}
	return TRUE;
}

BOOL message_object_check_readonly_property(
	MESSAGE_OBJECT *pmessage, uint32_t proptag)
{
	if (PROPVAL_TYPE_OBJECT == (proptag & 0xFFFF)) {
		return TRUE;
	}
	switch (proptag) {
	case PROP_TAG_ACCESS:
	case PROP_TAG_ACCESSLEVEL:
	case PROP_TAG_ASSOCIATED:
	case PROP_TAG_CHANGENUMBER:
	case PROP_TAG_CONVERSATIONID:
	case PROP_TAG_CREATORNAME:
	case PROP_TAG_CREATORENTRYID:
	case PROP_TAG_DISPLAYBCC:
	case PROP_TAG_DISPLAYCC:
	case PROP_TAG_DISPLAYTO:
	case PROP_TAG_ENTRYID:
	case PROP_TAG_FOLDERID:
	case PROP_TAG_HASATTACHMENTS:
	case PROP_TAG_HASNAMEDPROPERTIES:
	case PROP_TAG_LASTMODIFIERENTRYID:
	case PROP_TAG_MID:
	case PROP_TAG_MIMESKELETON:
	case PROP_TAG_NATIVEBODY:
	case PROP_TAG_OBJECTTYPE:
	case PROP_TAG_PARENTENTRYID:
	case PROP_TAG_PARENTSOURCEKEY:
	case PROP_TAG_STOREENTRYID:
	case PROP_TAG_STORERECORDKEY:
	case PROP_TAG_RECORDKEY:
	case PROP_TAG_MESSAGESIZE:
	case PROP_TAG_MESSAGESTATUS:
	case PROP_TAG_TRANSPORTMESSAGEHEADERS:
		return TRUE;
	case PROP_TAG_CHANGEKEY:
	case PROP_TAG_CREATIONTIME:
	case PROP_TAG_LASTMODIFICATIONTIME:
	case PROP_TAG_PREDECESSORCHANGELIST:
	case PROP_TAG_SOURCEKEY:
		if (TRUE == pmessage->b_new) {
			return FALSE;
		}
		return TRUE;
	case PROP_TAG_READ:
		if (NULL == pmessage->pembedding) {
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static BOOL message_object_get_calculated_property(
	MESSAGE_OBJECT *pmessage, uint32_t proptag, void **ppvalue)
{
	switch (proptag) {
	case PROP_TAG_ACCESS:
		*ppvalue = &pmessage->tag_access;
		return TRUE;
	case PROP_TAG_ACCESSLEVEL:
		*ppvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (TRUE == pmessage->b_writable) {
			*(uint32_t*)(*ppvalue) = ACCESS_LEVEL_MODIFY;
		} else {
			*(uint32_t*)(*ppvalue) = ACCESS_LEVEL_READ_ONLY;
		}
		return TRUE;
	case PROP_TAG_ENTRYID:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = common_util_to_message_entryid(pmessage->pstore,
						pmessage->folder_id, pmessage->message_id);
		return TRUE;
	case PROP_TAG_SOURCEKEY:
		if (NULL == pmessage->pembedding) {
			*ppvalue = common_util_calculate_message_sourcekey(
						pmessage->pstore, pmessage->message_id);
			return TRUE;
		}
		return FALSE;
	case PROP_TAG_OBJECTTYPE:
		*ppvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = OBJECT_MESSAGE;
		return TRUE;
	case PROP_TAG_PARENTENTRYID:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = common_util_to_folder_entryid(
			pmessage->pstore, pmessage->folder_id);
		return TRUE;
	case PROP_TAG_FOLDERID:
	case PROP_TAG_PARENTFOLDERID:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = &pmessage->folder_id;
		return TRUE;
	case PROP_TAG_PARENTSOURCEKEY:
		*ppvalue = common_util_calculate_folder_sourcekey(
					pmessage->pstore, pmessage->folder_id);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		return TRUE;
	case PROP_TAG_MID:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = &pmessage->message_id;
		return TRUE;
	case PROP_TAG_RECORDKEY:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = common_util_to_folder_entryid(
			pmessage->pstore, pmessage->message_id);
		return TRUE;
	case PROP_TAG_STORERECORDKEY:
	case PROP_TAG_MAPPINGSIGNATURE:
		*ppvalue = common_util_guid_to_binary(
				store_object_get_mailbox_guid(
				pmessage->pstore));
		return TRUE;
	case PROP_TAG_STOREENTRYID:
		*ppvalue = common_util_to_store_entryid(pmessage->pstore);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

BOOL message_object_get_properties(MESSAGE_OBJECT *pmessage,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static uint32_t lcid_default = 0x0409;
	
	ppropvals->ppropval = common_util_alloc(
		sizeof(TAGGED_PROPVAL)*pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = common_util_alloc(
			sizeof(uint32_t)*pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	ppropvals->count = 0;
	for (i=0; i<pproptags->count; i++) {
		if (TRUE == message_object_get_calculated_property(
			pmessage, pproptags->pproptag[i], &pvalue)) {
			if (NULL == pvalue) {
				return FALSE;
			}
			ppropvals->ppropval[ppropvals->count].proptag =
										pproptags->pproptag[i];
			ppropvals->ppropval[ppropvals->count].pvalue = pvalue;
			ppropvals->count ++;
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count] =
							pproptags->pproptag[i];
		tmp_proptags.count ++;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (FALSE == exmdb_client_get_instance_properties(
		store_object_get_dir(pmessage->pstore),
		pmessage->cpid, pmessage->instance_id,
		&tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
	if (tmp_propvals.count > 0) {
		memcpy(ppropvals->ppropval +
			ppropvals->count, tmp_propvals.ppropval,
			sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
		ppropvals->count += tmp_propvals.count;
	}
	if (common_util_index_proptags(pproptags,
		PROP_TAG_MESSAGELOCALEID) >= 0 &&
		NULL == common_util_get_propvals(
		ppropvals, PROP_TAG_MESSAGELOCALEID)) {
		ppropvals->ppropval[ppropvals->count].proptag =
								PROP_TAG_MESSAGELOCALEID;
		ppropvals->ppropval[ppropvals->count].pvalue =
										&lcid_default;
		ppropvals->count ++;
	}
	if (common_util_index_proptags(pproptags,
		PROP_TAG_MESSAGECODEPAGE) >= 0 &&
		NULL == common_util_get_propvals(
		ppropvals, PROP_TAG_MESSAGECODEPAGE)) {
		ppropvals->ppropval[ppropvals->count].proptag =
								PROP_TAG_MESSAGECODEPAGE;
		ppropvals->ppropval[ppropvals->count].pvalue =
										&pmessage->cpid;
		ppropvals->count ++;
	}
	return TRUE;	
}

static BOOL message_object_set_properties_internal(
	MESSAGE_OBJECT *pmessage, BOOL b_check,
	const TPROPVAL_ARRAY *ppropvals)
{
	int i, j;
	void *pvalue;
	uint32_t proptag;
	uint8_t tmp_bytes[3];
	PROBLEM_ARRAY problems;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	uint16_t *poriginal_indices;
	TPROPVAL_ARRAY tmp_propvals1;
	TAGGED_PROPVAL propval_buff[3];
	
	if (FALSE == pmessage->b_writable) {
		return FALSE;
	}
	problems.count = 0;
	problems.pproblem = common_util_alloc(
		sizeof(PROPERTY_PROBLEM)*ppropvals->count);
	if (NULL == problems.pproblem) {
		return FALSE;
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = common_util_alloc(
		sizeof(TAGGED_PROPVAL)*ppropvals->count);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	poriginal_indices = common_util_alloc(
		sizeof(uint16_t)*ppropvals->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	for (i=0; i<ppropvals->count; i++) {
		if (TRUE == b_check) {
			if (TRUE == message_object_check_readonly_property(
				pmessage, ppropvals->ppropval[i].proptag)) {
				problems.pproblem[problems.count].index = i;
				problems.count ++;
				continue;
			} else if (PROP_TAG_EXTENDEDRULEMESSAGECONDITION
				== ppropvals->ppropval[i].proptag) {
				if (FALSE == exmdb_client_get_instance_property(
					store_object_get_dir(pmessage->pstore),
					pmessage->instance_id, PROP_TAG_ASSOCIATED,
					&pvalue)) {
					return FALSE;	
				}
				if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
					problems.pproblem[problems.count].index = i;
					problems.count ++;
					continue;
				}
				if (((BINARY*)ppropvals->ppropval[i].pvalue)->cb
					> common_util_get_param(
					COMMON_UTIL_MAX_EXTRULE_LENGTH)) {
					problems.pproblem[problems.count].index = i;
					problems.count ++;
					continue;
				}
			} else if (PROP_TAG_MESSAGEFLAGS ==
				ppropvals->ppropval[i].proptag) {
				tmp_propvals1.count = 3;
				tmp_propvals1.ppropval = propval_buff;
				propval_buff[0].proptag = PROP_TAG_READ;
				propval_buff[0].pvalue = &tmp_bytes[0];
				propval_buff[1].proptag = PROP_TAG_READRECEIPTREQUESTED;
				propval_buff[1].pvalue = &tmp_bytes[1];
				propval_buff[2].proptag =
					PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED;
				propval_buff[2].pvalue = &tmp_bytes[2];
				if (0 == ((*(uint32_t*)ppropvals->ppropval[i].pvalue)
					& MESSAGE_FLAG_READ)) {
					tmp_bytes[0] = 0;	
				} else {
					tmp_bytes[0] = 1;
				}
				if (0 == ((*(uint32_t*)ppropvals->ppropval[i].pvalue)
					& MESSAGE_FLAG_NOTIFYREAD)) {
					tmp_bytes[1] = 0;	
				} else {
					tmp_bytes[1] = 1;
				}
				if (0 == ((*(uint32_t*)ppropvals->ppropval[i].pvalue)
					& MESSAGE_FLAG_NOTIFYUNREAD)) {
					tmp_bytes[2] = 0;	
				} else {
					tmp_bytes[2] = 1;
				}
				if (FALSE == exmdb_client_set_instance_properties(
					store_object_get_dir(pmessage->pstore),
					pmessage->instance_id, &tmp_propvals1,
					&tmp_problems)) {
					return FALSE;	
				}
			}
		}
		tmp_propvals.ppropval[tmp_propvals.count] =
							ppropvals->ppropval[i];
		poriginal_indices[tmp_propvals.count] = i;
		tmp_propvals.count ++;
	}
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	if (FALSE == exmdb_client_set_instance_properties(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, &tmp_propvals,
		&tmp_problems)) {
		return FALSE;	
	}
	if (tmp_problems.count > 0) {
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index =
				poriginal_indices[tmp_problems.pproblem[i].index];
		}
		memcpy(problems.pproblem + problems.count,
			tmp_problems.pproblem, tmp_problems.count
			*sizeof(PROPERTY_PROBLEM));
		problems.count += tmp_problems.count;
	}
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	for (i=0; i<ppropvals->count; i++) {
		for (j=0; j<problems.count; j++) {
			if (i == problems.pproblem[j].index) {
				break;
			}
		}
		if (j < problems.count) {
			continue;
		}
		pmessage->b_touched = TRUE;
		proptag = ppropvals->ppropval[i].proptag;
		proptag_array_remove(
			pmessage->premoved_proptags, proptag);
		if (FALSE == proptag_array_append(
			pmessage->pchanged_proptags, proptag)) {
			return FALSE;	
		}
	}
	return TRUE;
}

BOOL message_object_set_properties(MESSAGE_OBJECT *pmessage,
	const TPROPVAL_ARRAY *ppropvals)
{
	char *psubject;
	char *pnormalized_subject;
	
	/* seems some php-mapi users do not understand well
		the relationship between PROP_TAG_SUBJECT and
		PROP_TAG_NORMALIZEDSUBJECT, we try to resolve
		the conflict when there exist both of them */
	psubject = common_util_get_propvals(
			ppropvals, PROP_TAG_SUBJECT);
	if (NULL == psubject) {
		psubject = common_util_get_propvals(
			ppropvals, PROP_TAG_SUBJECT_STRING8);
	}
	if (NULL != psubject) {
		pnormalized_subject = common_util_get_propvals(
				ppropvals, PROP_TAG_NORMALIZEDSUBJECT);
		if (NULL == pnormalized_subject) {
			pnormalized_subject = common_util_get_propvals(
				ppropvals, PROP_TAG_NORMALIZEDSUBJECT_STRING8);
		}
		if (NULL != pnormalized_subject) {
			if ('\0' == pnormalized_subject[0] && '\0' != psubject[0]) {
				common_util_remove_propvals((TPROPVAL_ARRAY*)
					ppropvals, PROP_TAG_NORMALIZEDSUBJECT);
				common_util_remove_propvals((TPROPVAL_ARRAY*)
					ppropvals, PROP_TAG_NORMALIZEDSUBJECT_STRING8);
			}
		}
	}
	return message_object_set_properties_internal(
						pmessage, TRUE, ppropvals);
}

BOOL message_object_remove_properties(MESSAGE_OBJECT *pmessage,
	const PROPTAG_ARRAY *pproptags)
{
	int i, j;
	uint32_t proptag;
	PROBLEM_ARRAY problems;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	uint16_t *poriginal_indices;
	
	if (FALSE == pmessage->b_writable) {
		return FALSE;
	}
	problems.count = 0;
	problems.pproblem = common_util_alloc(
		sizeof(PROPERTY_PROBLEM)*pproptags->count);
	if (NULL == problems.pproblem) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = common_util_alloc(
		sizeof(uint32_t)*pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	poriginal_indices = common_util_alloc(
		sizeof(uint16_t)*pproptags->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		if (TRUE == message_object_check_readonly_property(
			pmessage, pproptags->pproptag[i])) {
			problems.pproblem[problems.count].index = i;
			problems.count ++;
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count] =
							pproptags->pproptag[i];
		poriginal_indices[tmp_proptags.count] = i;
		tmp_proptags.count ++;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (FALSE == exmdb_client_remove_instance_properties(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, &tmp_proptags,
		&tmp_problems)) {
		return FALSE;	
	}
	if (tmp_problems.count > 0) {
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index =
				poriginal_indices[tmp_problems.pproblem[i].index];
		}
		memcpy(problems.pproblem + problems.count,
			tmp_problems.pproblem, tmp_problems.count*
			sizeof(PROPERTY_PROBLEM));
		problems.count += tmp_problems.count;
	}
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	for (i=0; i<pproptags->count; i++) {
		for (j=0; j<problems.count; j++) {
			if (i == problems.pproblem[j].index) {
				break;
			}
		}
		if (j < problems.count) {
			continue;
		}
		pmessage->b_touched = TRUE;
		proptag = pproptags->pproptag[i];
		proptag_array_remove(
			pmessage->pchanged_proptags, proptag);
		if (FALSE == proptag_array_append(
			pmessage->premoved_proptags, proptag)) {
			return FALSE;	
		}
	}
	return TRUE;
}

BOOL message_object_copy_to(
	MESSAGE_OBJECT *pmessage, MESSAGE_OBJECT *pmessage_src,
	const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force,
	BOOL *pb_cycle)
{
	int i;
	PROPTAG_ARRAY proptags;
	MESSAGE_CONTENT msgctnt;
	PROBLEM_ARRAY tmp_problems;
	
	if (FALSE == exmdb_client_check_instance_cycle(
		store_object_get_dir(pmessage->pstore),
		pmessage_src->instance_id, pmessage->instance_id,
		pb_cycle)) {
		return FALSE;	
	}
	if (TRUE == *pb_cycle) {
		return TRUE;
	}
	if (FALSE == exmdb_client_read_message_instance(
		store_object_get_dir(pmessage_src->pstore),
		pmessage_src->instance_id, &msgctnt)) {
		return FALSE;
	}
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_MID);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_DISPLAYTO);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_DISPLAYCC);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_DISPLAYBCC);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_MESSAGESIZE);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_HASATTACHMENTS);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_CHANGEKEY);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_CHANGENUMBER);
	common_util_remove_propvals(
		&msgctnt.proplist, PROP_TAG_PREDECESSORCHANGELIST);
	i = 0;
	while (i < msgctnt.proplist.count) {
		if (common_util_index_proptags(pexcluded_proptags,
			msgctnt.proplist.ppropval[i].proptag) >= 0) {
			common_util_remove_propvals(&msgctnt.proplist,
					msgctnt.proplist.ppropval[i].proptag);
			continue;
		}
		i ++;
	}
	if (common_util_index_proptags(pexcluded_proptags,
		PROP_TAG_MESSAGERECIPIENTS) >= 0) {				
		msgctnt.children.prcpts = NULL;
	}
	if (common_util_index_proptags(pexcluded_proptags,
		PROP_TAG_MESSAGEATTACHMENTS) >= 0) {
		msgctnt.children.pattachments = NULL;
	}
	if (FALSE == exmdb_client_write_message_instance(
		store_object_get_dir(pmessage->pstore),
		pmessage->instance_id, &msgctnt,
		b_force, &proptags, &tmp_problems)) {
		return FALSE;	
	}
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	for (i=0; i<proptags.count; i++) {
		proptag_array_append(pmessage->pchanged_proptags,
			proptags.pproptag[i]);
	}
	return TRUE;
}

BOOL message_object_copy_rcpts(MESSAGE_OBJECT *pmessage,
	MESSAGE_OBJECT *pmessage_src, BOOL b_force, BOOL *pb_result)
{
	if (FALSE == exmdb_client_copy_instance_rcpts(
		store_object_get_dir(pmessage->pstore), b_force,
		pmessage_src->instance_id, pmessage->instance_id,
		pb_result)) {
		return FALSE;	
	}
	if (TRUE == *pb_result) {
		proptag_array_append(pmessage->pchanged_proptags,
							PROP_TAG_MESSAGEATTACHMENTS);
	}
	return TRUE;
}
	
BOOL message_object_copy_attachments(MESSAGE_OBJECT *pmessage,
	MESSAGE_OBJECT *pmessage_src, BOOL b_force, BOOL *pb_result)
{
	if (FALSE == exmdb_client_copy_instance_attachments(
		store_object_get_dir(pmessage->pstore), b_force,
		pmessage_src->instance_id, pmessage->instance_id,
		pb_result)) {
		return FALSE;	
	}
	if (TRUE == *pb_result) {
		proptag_array_append(pmessage->pchanged_proptags,
							PROP_TAG_MESSAGERECIPIENTS);
	}
	return TRUE;
}

BOOL message_object_set_readflag(MESSAGE_OBJECT *pmessage,
	uint8_t read_flag, BOOL *pb_changed)
{
	void *pvalue;
	BOOL b_notify;
	const char *dir;
	uint32_t result;
	uint64_t read_cn;
	uint8_t tmp_byte;
	USER_INFO *pinfo;
	const char *username;
	PROBLEM_ARRAY problems;
	TAGGED_PROPVAL propval;
	MESSAGE_CONTENT *pbrief;
	TPROPVAL_ARRAY propvals;
	static uint8_t fake_false = 0;
	TAGGED_PROPVAL propval_buff[2];
	
	read_flag &= MSG_READ_FLAG_SUPPRESS_RECEIPT|
				MSG_READ_FLAG_CLEAR_READ_FLAG|
				MSG_READ_FLAG_GENERATE_RECEIPT_ONLY|
				MSG_READ_FLAG_CLEAR_NOTIFY_READ|
				MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD;
	if (TRUE == store_object_check_private(pmessage->pstore)) {
		username = NULL;
	} else {
		pinfo = zarafa_server_get_info();
		username = pinfo->username;
	}
	b_notify = FALSE;
	*pb_changed = FALSE;
	dir = store_object_get_dir(pmessage->pstore);
	switch (read_flag) {
	case MSG_READ_FLAG_DEFAULT:
	case MSG_READ_FLAG_SUPPRESS_RECEIPT:
		if (FALSE == exmdb_client_get_instance_property(
			dir, pmessage->instance_id, PROP_TAG_READ,
			&pvalue)) {
			return FALSE;	
		}
		if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
			tmp_byte = 1;
			*pb_changed = TRUE;
			if (MSG_READ_FLAG_DEFAULT == read_flag) {
				if (FALSE == exmdb_client_get_instance_property(
					dir, pmessage->instance_id,
					PROP_TAG_READRECEIPTREQUESTED, &pvalue)) {
					return FALSE;
				}
				if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
					b_notify = TRUE;
				}
			}
		}
		break;
	case MSG_READ_FLAG_CLEAR_READ_FLAG:
		if (FALSE == exmdb_client_get_instance_property(
			dir, pmessage->instance_id, PROP_TAG_READ,
			&pvalue)) {
			return FALSE;	
		}
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			tmp_byte = 0;
			*pb_changed = TRUE;
		}
		break;
	case MSG_READ_FLAG_GENERATE_RECEIPT_ONLY:
		if (FALSE == exmdb_client_get_instance_property(
			dir, pmessage->instance_id,
			PROP_TAG_READRECEIPTREQUESTED, &pvalue)) {
			return FALSE;
		}
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			b_notify = TRUE;
		}
		break;
	case MSG_READ_FLAG_CLEAR_NOTIFY_READ:
	case MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD:
	case MSG_READ_FLAG_CLEAR_NOTIFY_READ |
		MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD:
		if (read_flag & MSG_READ_FLAG_CLEAR_NOTIFY_READ) {
			if (FALSE == exmdb_client_remove_instance_property(
				dir, pmessage->instance_id,
				PROP_TAG_READRECEIPTREQUESTED, &result)) {
				return FALSE;	
			}
			if (TRUE == exmdb_client_get_message_property(
				dir, username, 0, pmessage->message_id,
				PROP_TAG_READRECEIPTREQUESTED, &pvalue) &&
				NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				if (FALSE == exmdb_client_remove_message_property(
					dir, pmessage->cpid, pmessage->message_id,
					PROP_TAG_READRECEIPTREQUESTED)) {
					return FALSE;	
				}
			}
		}
		if (read_flag & MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD) {
			if (FALSE == exmdb_client_remove_instance_property(
				dir, pmessage->instance_id,
				PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED, &result)) {
				return FALSE;	
			}
			if (TRUE == exmdb_client_get_message_property(
				dir, username, 0, pmessage->message_id,
				PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED, &pvalue)
				&& NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				if (FALSE == exmdb_client_remove_message_property(
					dir, pmessage->cpid, pmessage->message_id,
					PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED)) {
					return FALSE;	
				}
			}
		}
		if (FALSE == exmdb_client_get_instance_property(
			dir, pmessage->instance_id, PROP_TAG_MESSAGEFLAGS,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		if (*(uint32_t*)pvalue & MESSAGE_FLAG_UNMODIFIED) {
			*(uint32_t*)pvalue &= ~MESSAGE_FLAG_UNMODIFIED;
			propval.proptag = PROP_TAG_MESSAGEFLAGS;
			propval.pvalue = pvalue;
			if (FALSE == exmdb_client_set_instance_property(
				dir, pmessage->instance_id, &propval, &result)) {
				return FALSE;
			}
			if (FALSE == exmdb_client_mark_modified(
				dir, pmessage->message_id)) {
				return FALSE;
			}
		}
		return TRUE;
	default:
		return TRUE;
	}
	if (TRUE == *pb_changed) {
		if (FALSE == exmdb_client_set_message_read_state(
			dir, username, pmessage->message_id, tmp_byte,
			&read_cn)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_READ;
		propval.pvalue = &tmp_byte;
		if (FALSE == exmdb_client_set_instance_property(
			dir, pmessage->instance_id, &propval, &result)) {
			return FALSE;	
		}
		if (0 != result) {
			return TRUE;
		}
	}
	if (TRUE == b_notify) {
		if (FALSE == exmdb_client_get_message_brief(
			dir, pmessage->cpid, pmessage->message_id,
			&pbrief)) {
			return FALSE;	
		}
		if (NULL != pbrief) {
			common_util_notify_receipt(store_object_get_account(
				pmessage->pstore), NOTIFY_RECEIPT_READ, pbrief);
		}
		propvals.count = 2;
		propvals.ppropval = propval_buff;
		propval_buff[0].proptag = PROP_TAG_READRECEIPTREQUESTED;
		propval_buff[0].pvalue = &fake_false;
		propval_buff[1].proptag = PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED;
		propval_buff[1].pvalue = &fake_false;
		exmdb_client_set_instance_properties(dir,
			pmessage->instance_id, &propvals, &problems);
		exmdb_client_set_message_properties(dir, username,
			0, pmessage->message_id, &propvals, &problems);
	}
	return TRUE;
}
