// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include "attachment_object.h"
#include "emsmdb_interface.h"
#include "message_object.h"
#include <gromox/tpropval_array.hpp>
#include <gromox/proptag_array.hpp>
#include "ics_state.h"
#include "logon_object.h"
#include "stream_object.h"
#include "exmdb_client.h"
#include "common_util.h"
#include <gromox/proc_common.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/idset.hpp>
#include <gromox/guid.hpp>
#include <gromox/util.hpp>
#include <gromox/pcl.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static BOOL message_object_set_properties_internal(message_object *, BOOL check, const TPROPVAL_ARRAY *, PROBLEM_ARRAY *);

static BOOL message_object_get_recipient_all_proptags(message_object *pmessage,
    PROPTAG_ARRAY *pproptags)
{
	int i;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client_get_message_instance_rcpts_all_proptags(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &tmp_proptags))
		return FALSE;
	pproptags->count = 0;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	for (i=0; i<tmp_proptags.count; i++) {
		switch (tmp_proptags.pproptag[i]) {
		case PROP_TAG_RESPONSIBILITY:
		case PROP_TAG_ADDRESSTYPE:
		case PR_DISPLAY_NAME:
		case PR_DISPLAY_NAME_A:
		case PR_EMAIL_ADDRESS:
		case PR_EMAIL_ADDRESS_A:
		case PR_ENTRYID:
		case PROP_TAG_INSTANCEKEY:
		case PROP_TAG_RECIPIENTTYPE:
		case PROP_TAG_ROWID:
		case PROP_TAG_SEARCHKEY:
		case PROP_TAG_SENDRICHINFO:
		case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
		case PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8:
			continue;
		default:
			pproptags->pproptag[pproptags->count++] = tmp_proptags.pproptag[i];
			break;
		}
	}
	return TRUE;
}

static uint32_t message_object_rectify_proptag(uint32_t proptag)
{
	switch (PROP_TYPE(proptag)) {
	case PT_STRING8:
		proptag = CHANGE_PROP_TYPE(proptag, PT_UNICODE);
		break;
	case PT_MV_STRING8:
		proptag = CHANGE_PROP_TYPE(proptag, PT_MV_UNICODE);
		break;
	case PT_UNSPECIFIED:
		proptag = CHANGE_PROP_TYPE(proptag, PT_UNICODE);
		break;
	}
	return proptag;
}

std::unique_ptr<message_object> message_object::create(logon_object *plogon,
	BOOL b_new, uint32_t cpid, uint64_t message_id, void *pparent,
	uint32_t tag_access, uint8_t open_flags, ICS_STATE *pstate)
{
	uint64_t *pchange_num;
	PROPTAG_ARRAY tmp_columns;
	std::unique_ptr<message_object> pmessage;
	
	try {
		pmessage.reset(new message_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pmessage->plogon = plogon;
	pmessage->b_new = b_new;
	pmessage->cpid = cpid;
	pmessage->message_id = message_id;
	pmessage->tag_access = tag_access;
	pmessage->open_flags = open_flags;
	pmessage->pstate = pstate;
	double_list_init(&pmessage->stream_list);
	if (0 == message_id) {
		pmessage->pembedding = static_cast<attachment_object *>(pparent);
		if (!exmdb_client_load_embedded_instance(plogon->get_dir(),
		    b_new, static_cast<attachment_object *>(pparent)->instance_id,
		    &pmessage->instance_id))
			return NULL;
		/* cannot find embedded message in attachment, return
			immediately to caller and the caller check the
			result by calling message_object_get_instance_id */
		if (FALSE == b_new && 0 == pmessage->instance_id) {
			return pmessage;
		}
	} else {
		pmessage->folder_id = *(uint64_t*)pparent;
		if (pmessage->plogon->check_private()) {
			if (!exmdb_client_load_message_instance(plogon->get_dir(),
			    nullptr, cpid, b_new, pmessage->folder_id, message_id,
			    &pmessage->instance_id))
				return NULL;
		} else {
			auto rpc_info = get_rpc_info();
			if (!exmdb_client_load_message_instance(plogon->get_dir(),
			    rpc_info.username, cpid, b_new, pmessage->folder_id,
			    message_id, &pmessage->instance_id))
				return NULL;
		}
	}
	if (0 == pmessage->instance_id) {
		return NULL;
	}
	pmessage->pchanged_proptags = proptag_array_init();
	if (NULL == pmessage->pchanged_proptags) {
		return NULL;
	}
	pmessage->premoved_proptags = proptag_array_init();
	if (NULL == pmessage->premoved_proptags) {
		return NULL;
	}
	if (FALSE == b_new) {
		if (!exmdb_client_get_instance_property(plogon->get_dir(),
		    pmessage->instance_id, PROP_TAG_CHANGENUMBER,
		    reinterpret_cast<void **>(&pchange_num)))
			return NULL;
		if (NULL != pchange_num) {
			pmessage->change_num = *pchange_num;
		}
	}
	if (!message_object_get_recipient_all_proptags(pmessage.get(), &tmp_columns))
		return NULL;
	pmessage->precipient_columns = proptag_array_dup(&tmp_columns);
	if (NULL == pmessage->precipient_columns) {
		return NULL;
	}
	return pmessage;
}

BOOL message_object::check_importing() const
{
	auto pmessage = this;
	if (0 != pmessage->message_id && NULL != pmessage->pstate) {
		return TRUE;
	}
	return FALSE;
}

BOOL message_object::check_orignal_touched(BOOL *pb_touched)
{
	auto pmessage = this;
	uint64_t *pchange_num;
	
	if (TRUE == pmessage->b_new) {
		*pb_touched = FALSE;
		return TRUE;
	}
	if (0 != pmessage->message_id) {
		if (!exmdb_client_get_message_property(pmessage->plogon->get_dir(),
		    nullptr, 0, pmessage->message_id, PROP_TAG_CHANGENUMBER,
		    reinterpret_cast<void **>(&pchange_num)))
			return FALSE;
	} else {
		if (!exmdb_client_get_embedded_cn(pmessage->plogon->get_dir(),
		    pmessage->instance_id, &pchange_num))
			return FALSE;	
	}
	/* if it cannot find PROP_TAG_CHANGENUMBER, it means message does not exist any more */
	*pb_touched = pchange_num == nullptr || *pchange_num != pmessage->change_num ? TRUE : false;
	return TRUE;
}

message_object::~message_object()
{
	auto pmessage = this;
	DOUBLE_LIST_NODE *pnode;
	
	if (0 != pmessage->instance_id) { 
		exmdb_client_unload_instance(pmessage->plogon->get_dir(),
			pmessage->instance_id);
	}
	if (NULL != pmessage->precipient_columns) {
		proptag_array_free(pmessage->precipient_columns);
	}
	if (NULL != pmessage->pchanged_proptags) {
		proptag_array_free(pmessage->pchanged_proptags);
	}
	if (NULL != pmessage->premoved_proptags) {
		proptag_array_free(pmessage->premoved_proptags);
	}
	while ((pnode = double_list_pop_front(&pmessage->stream_list)) != nullptr)
		free(pnode);
	double_list_free(&pmessage->stream_list);
}

BOOL message_object::init_message(BOOL b_fai, uint32_t new_cpid)
{
	auto pmessage = this;
	GUID tmp_guid;
	EXT_PUSH ext_push;
	char id_string[256];
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	
	
	if (FALSE == pmessage->b_new) {
		return FALSE;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return FALSE;
	}
	auto rpc_info = get_rpc_info();
	propvals.count = 0;
	propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(20);
	if (NULL == propvals.ppropval) {
		return FALSE;
	}
	
	propvals.ppropval[propvals.count].proptag = PR_MESSAGE_CODEPAGE;
	void *pvalue = cu_alloc<uint32_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*static_cast<uint32_t *>(pvalue) = new_cpid;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PR_IMPORTANCE;
	pvalue = cu_alloc<uint32_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*static_cast<uint32_t *>(pvalue) = IMPORTANCE_NORMAL;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PR_DEF_POST_MSGCLASS;
	propvals.ppropval[propvals.count++].pvalue  = deconst("IPM.Note");
	
	propvals.ppropval[propvals.count].proptag = PR_SENSITIVITY;
	pvalue = cu_alloc<uint32_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*static_cast<uint32_t *>(pvalue) = SENSITIVITY_NONE;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_ORIGINALDISPLAYBCC;
	propvals.ppropval[propvals.count++].pvalue  = deconst("");
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_ORIGINALDISPLAYCC;
	propvals.ppropval[propvals.count++].pvalue  = deconst("");
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_ORIGINALDISPLAYTO;
	propvals.ppropval[propvals.count++].pvalue  = deconst("");
	
	propvals.ppropval[propvals.count].proptag = PR_MESSAGE_FLAGS;
	pvalue = cu_alloc<uint32_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*static_cast<uint32_t *>(pvalue) = MSGFLAG_UNSENT | MSGFLAG_UNMODIFIED;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PR_READ;
	pvalue = cu_alloc<uint8_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint8_t*)pvalue = 0;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PR_ASSOCIATED;
	pvalue = cu_alloc<uint8_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*static_cast<uint8_t *>(pvalue) = !!b_fai;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_TRUSTSENDER;
	pvalue = cu_alloc<uint32_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint32_t*)pvalue = 1;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PR_CREATION_TIME;
	pvalue = cu_alloc<uint64_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint64_t*)pvalue = rop_util_current_nttime();
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_SEARCHKEY;
	pvalue = cu_alloc<BINARY>();
	if (NULL == pvalue) {
		return FALSE;
	}
	
	pvalue = common_util_guid_to_binary(guid_random_new());
	if (NULL == pvalue) {
		return FALSE;
	}
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PR_MESSAGE_LOCALE_ID;
	pvalue = cu_alloc<uint32_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint32_t*)pvalue = pinfo->lcid_string;
	if (0 == *(uint32_t*)pvalue) {
		*(uint32_t*)pvalue = 0x0409;
	}
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	propvals.ppropval[propvals.count].proptag = PR_LOCALE_ID;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_CREATORNAME;
	pvalue = common_util_alloc(1024);
	if (NULL == pvalue) {
		return FALSE;
	}
	if (!common_util_get_user_displayname(rpc_info.username,
	    static_cast<char *>(pvalue)) || *static_cast<char *>(pvalue) == '\0')
		strcpy(static_cast<char *>(pvalue), rpc_info.username);
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_CREATORENTRYID;
	pvalue = common_util_username_to_addressbook_entryid(rpc_info.username);
	if (NULL == pvalue) {
		return FALSE;
	}
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	
	tmp_guid = guid_random_new();
	if (!ext_push.init(id_string, 256, 0) ||
	    ext_push.p_guid(&tmp_guid) != EXT_ERR_SUCCESS)
		return false;
	encode_hex_binary(id_string, 16, id_string + 16, 64);
	id_string[0] = '<';
	memmove(id_string + 1, id_string + 16, 32);
	snprintf(id_string + 33, 128, "@%s>", get_host_ID());
	propvals.ppropval[propvals.count].proptag = PROP_TAG_INTERNETMESSAGEID;
	propvals.ppropval[propvals.count++].pvalue = id_string;
	
	if (!exmdb_client_set_instance_properties(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &propvals, &problems))
		return FALSE;	
	pmessage->b_touched = TRUE;
	return TRUE;
}

void message_object::set_open_flags(uint8_t f)
{
	open_flags = f;
}

gxerr_t message_object::save()
{
	auto pmessage = this;
	int i;
	void *pvalue;
	uint32_t result;
	BINARY *pbin_pcl;
	BINARY *pbin_pcl1;
	uint32_t tmp_index;
	uint32_t *pgroup_id;
	uint32_t tmp_status;
	INDEX_ARRAY *pindices;
	INDEX_ARRAY tmp_indices;
	MESSAGE_CONTENT *pmsgctnt;
	PROBLEM_ARRAY tmp_problems;
	TAGGED_PROPVAL tmp_propval;
	TPROPVAL_ARRAY tmp_propvals;
	PROPERTY_GROUPINFO *pgpinfo;
	PROPTAG_ARRAY *pungroup_proptags;
	
	
	if (FALSE == pmessage->b_new &&
		FALSE == pmessage->b_touched) {
		return GXERR_SUCCESS;
	}
	auto rpc_info = get_rpc_info();
	if (!exmdb_client_allocate_cn(pmessage->plogon->get_dir(), &pmessage->change_num))
		return GXERR_CALL_FAILED;
	if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
	    pmessage->instance_id, PR_ASSOCIATED, &pvalue))
		return GXERR_CALL_FAILED;

	BOOL b_fai = pvalue == nullptr || *static_cast<uint8_t *>(pvalue) == 0 ? false : TRUE;
	if (NULL != pmessage->pstate) {
		if (FALSE == pmessage->b_new) {
			if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
			    pmessage->instance_id, PR_PREDECESSOR_CHANGE_LIST,
			    reinterpret_cast<void **>(&pbin_pcl)) ||
			    pbin_pcl == nullptr)
				return GXERR_CALL_FAILED;
			if (!exmdb_client_get_message_property(pmessage->plogon->get_dir(),
			    nullptr, 0, pmessage->message_id, PR_PREDECESSOR_CHANGE_LIST,
			    reinterpret_cast<void **>(&pbin_pcl1)) ||
			    pbin_pcl1 == nullptr)
				return GXERR_CALL_FAILED;
			if (FALSE == common_util_pcl_compare(
				pbin_pcl, pbin_pcl1, &result)) {
				return GXERR_CALL_FAILED;
			}
			if (PCL_CONFLICT == result) {
				if (!exmdb_client_get_folder_property(pmessage->plogon->get_dir(),
				    0, pmessage->folder_id, PROP_TAG_RESOLVEMETHOD, &pvalue))
					return GXERR_CALL_FAILED;
				uint32_t resolve_method = pvalue == nullptr ? RESOLVE_METHOD_DEFAULT :
				                          *static_cast<uint32_t *>(pvalue);
				if (FALSE == b_fai &&
					RESOLVE_METHOD_DEFAULT == resolve_method) {
					if (pmessage->plogon->check_private()) {
						if (!exmdb_client_read_message(pmessage->plogon->get_dir(),
						    nullptr, pmessage->cpid,
						    pmessage->message_id, &pmsgctnt))
							return GXERR_CALL_FAILED;
					} else if (!exmdb_client_read_message(pmessage->plogon->get_dir(),
					    rpc_info.username, pmessage->cpid,
					    pmessage->message_id, &pmsgctnt)) {
						return GXERR_CALL_FAILED;
					}
					if (NULL != pmsgctnt) {
						pvalue = common_util_get_propvals(
							&pmsgctnt->proplist, PROP_TAG_MESSAGESTATUS);
						if (NULL == pvalue) {
							return GXERR_CALL_FAILED;
						}
						tmp_status = *(uint32_t*)pvalue;
						if (!exmdb_client_set_message_instance_conflict(
						    pmessage->plogon->get_dir(),
						    pmessage->instance_id, pmsgctnt))
							return GXERR_CALL_FAILED;
						tmp_propvals.count = 1;
						tmp_propvals.ppropval = &tmp_propval;
						tmp_propval.proptag = PROP_TAG_MESSAGESTATUS;
						tmp_propval.pvalue = &tmp_status;
						tmp_status |= MESSAGE_STATUS_IN_CONFLICT;
						if (FALSE == message_object_set_properties_internal(
							pmessage, FALSE, &tmp_propvals, &tmp_problems)) {
							return GXERR_CALL_FAILED;
						}
					}
				}
				pbin_pcl = common_util_pcl_merge(pbin_pcl, pbin_pcl1);
				if (NULL == pbin_pcl) {
					return GXERR_CALL_FAILED;
				}
				tmp_propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
				tmp_propval.pvalue = pbin_pcl;
				if (FALSE == message_object_set_properties_internal(
					pmessage, FALSE, &tmp_propvals, &tmp_problems)) {
					return GXERR_CALL_FAILED;
				}
			}
		}
	} else if (0 != pmessage->message_id) {
		if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, PR_PREDECESSOR_CHANGE_LIST,
		    reinterpret_cast<void **>(&pbin_pcl)))
			return GXERR_CALL_FAILED;
		if (FALSE == pmessage->b_new && NULL == pbin_pcl) {
			return GXERR_CALL_FAILED;
		}
	}
	
	if (!flush_streams())
		return GXERR_CALL_FAILED;
	
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(8);
	if (NULL == tmp_propvals.ppropval) {
		return GXERR_CALL_FAILED;
	}
	
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
								PROP_TAG_LOCALCOMMITTIME;
	pvalue = cu_alloc<uint64_t>();
	if (NULL == pvalue) {
		return GXERR_CALL_FAILED;
	}
	*(uint64_t*)pvalue = rop_util_current_nttime();
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pvalue;
	
	if (!proptag_array_check(pmessage->pchanged_proptags,
	    PR_LAST_MODIFICATION_TIME)) {
		tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_LAST_MODIFICATION_TIME;
		tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pvalue;
	}
	
	if (!proptag_array_check(pmessage->pchanged_proptags,
	    PROP_TAG_LASTMODIFIERNAME)) {
		tmp_propvals.ppropval[tmp_propvals.count].proptag =
									PROP_TAG_LASTMODIFIERNAME;
		pvalue = common_util_alloc(1024);
		if (NULL == pvalue) {
			return GXERR_CALL_FAILED;
		}
		if (!common_util_get_user_displayname(rpc_info.username,
		    static_cast<char *>(pvalue)) || *static_cast<char *>(pvalue) == '\0')
			strcpy(static_cast<char *>(pvalue), rpc_info.username);
		tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pvalue;
	}
	
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
							PROP_TAG_LASTMODIFIERENTRYID;
	pvalue = common_util_username_to_addressbook_entryid(rpc_info.username);
	if (NULL == pvalue) {
		return GXERR_CALL_FAILED;
	}
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pvalue;
	
	if (0 != pmessage->message_id && NULL == pmessage->pstate) {
		tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_CHANGE_KEY;
		auto pbin_changekey = cu_xid_to_bin({pmessage->plogon->guid(), pmessage->change_num});
		if (NULL == pbin_changekey) {
			return GXERR_CALL_FAILED;
		}
		tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pbin_changekey;
		
		pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
		if (NULL == pbin_pcl) {
			return GXERR_CALL_FAILED;
		}
		tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_PREDECESSOR_CHANGE_LIST;
		tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pbin_pcl;
	}
	
	if (FALSE == message_object_set_properties_internal(
		pmessage, FALSE, &tmp_propvals, &tmp_problems)) {
		return GXERR_CALL_FAILED;
	}
	
	/* change number of embedding message is used for message
		modification's check when the  rop_savechangesmessage
		is called, it is useless for ICS!
	*/
	tmp_propval.proptag = PROP_TAG_CHANGENUMBER;
	tmp_propval.pvalue = &pmessage->change_num;
	if (!exmdb_client_set_instance_property(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &tmp_propval, &result))
		return GXERR_CALL_FAILED;
	
	gxerr_t e_result = GXERR_CALL_FAILED;
	if (!exmdb_client_flush_instance(pmessage->plogon->get_dir(),
	    pmessage->instance_id, pmessage->plogon->get_account(),
	    &e_result) || e_result != GXERR_SUCCESS)
		return e_result;
	auto is_new = pmessage->b_new;
	pmessage->b_new = FALSE;
	pmessage->b_touched = FALSE;
	if (0 == pmessage->message_id) {
		pmessage->pembedding->b_touched = TRUE;
		return GXERR_SUCCESS;
	}
	
	if (NULL != pmessage->pstate) {
		auto &x = pmessage->pstate;
		idset_append(b_fai ? x->pseen_fai : x->pseen, pmessage->change_num);
	}
	
	if (0 == pmessage->message_id || TRUE == b_fai) {
		proptag_array_clear(pmessage->pchanged_proptags);
		proptag_array_clear(pmessage->premoved_proptags);
		return GXERR_SUCCESS;
	}
	
	if (is_new || pmessage->pstate != nullptr)
		goto SAVE_FULL_CHANGE;
	if (!exmdb_client_get_message_group_id(pmessage->plogon->get_dir(),
	    pmessage->message_id, &pgroup_id))
		return GXERR_CALL_FAILED;
	if (NULL == pgroup_id) {
		pgpinfo = pmessage->plogon->get_last_property_groupinfo();
		if (NULL == pgpinfo) {
			return GXERR_CALL_FAILED;
		}
		if (!exmdb_client_set_message_group_id(pmessage->plogon->get_dir(),
		    pmessage->message_id, pgpinfo->group_id))
			return GXERR_CALL_FAILED;
	}  else {
		pgpinfo = pmessage->plogon->get_property_groupinfo(*pgroup_id);
		if (NULL == pgpinfo) {
			return GXERR_CALL_FAILED;
		}
	}
	
	if (!exmdb_client_mark_modified(pmessage->plogon->get_dir(),
	    pmessage->message_id))
		return GXERR_CALL_FAILED;
	
	pindices = proptag_array_init();
	if (NULL == pindices) {
		return GXERR_CALL_FAILED;
	}
	pungroup_proptags = proptag_array_init();
	if (NULL == pungroup_proptags) {
		proptag_array_free(pindices);
		return GXERR_CALL_FAILED;
	}
	/* always mark PR_MESSAGE_FLAGS as changed */
	if (!proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_FLAGS)) {
		proptag_array_free(pindices);
		proptag_array_free(pungroup_proptags);
		return GXERR_CALL_FAILED;
	}
	for (i=0; i<pmessage->pchanged_proptags->count; i++) {
		if (FALSE == property_groupinfo_get_partial_index(pgpinfo,
			pmessage->pchanged_proptags->pproptag[i], &tmp_index)) {
			if (!proptag_array_append(pungroup_proptags,
			    pmessage->pchanged_proptags->pproptag[i])) {
				proptag_array_free(pindices);
				proptag_array_free(pungroup_proptags);
				return GXERR_CALL_FAILED;
			}
		} else {
			if (!proptag_array_append(pindices, tmp_index)) {
				proptag_array_free(pindices);
				proptag_array_free(pungroup_proptags);
				return GXERR_CALL_FAILED;
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
			if (!proptag_array_append(pindices, tmp_index)) {
				proptag_array_free(pindices);
				proptag_array_free(pungroup_proptags);
				return GXERR_CALL_FAILED;
			}
		}
	}
	if (!exmdb_client_save_change_indices(pmessage->plogon->get_dir(),
	    pmessage->message_id, pmessage->change_num, pindices, pungroup_proptags)) {
		proptag_array_free(pindices);
		proptag_array_free(pungroup_proptags);
		return GXERR_CALL_FAILED;
	}
	proptag_array_free(pindices);
	proptag_array_free(pungroup_proptags);
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	return GXERR_SUCCESS;
	
 SAVE_FULL_CHANGE:
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	tmp_indices.count = 0;
	tmp_indices.pproptag = NULL;
	if (!exmdb_client_save_change_indices(pmessage->plogon->get_dir(),
	    pmessage->message_id, pmessage->change_num, &tmp_indices,
	    static_cast<PROPTAG_ARRAY *>(&tmp_indices)))
		return GXERR_CALL_FAILED;
	/* trigger the rule evaluation under public mode 
		when the message is first saved to the folder */
	if (is_new && !b_fai && pmessage->message_id != 0 &&
	    !pmessage->plogon->check_private())
		exmdb_client_rule_new_message(pmessage->plogon->get_dir(),
			rpc_info.username, pmessage->plogon->get_account(),
			pmessage->cpid, pmessage->folder_id,
			pmessage->message_id);
	return GXERR_SUCCESS;
}

BOOL message_object::reload()
{
	auto pmessage = this;
	BOOL b_result;
	uint64_t *pchange_num;
	PROPTAG_ARRAY *pcolumns;
	DOUBLE_LIST_NODE *pnode;
	PROPTAG_ARRAY tmp_columns;
	
	if (TRUE == pmessage->b_new) {
		return TRUE;
	}
	if (!exmdb_client_reload_message_instance(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &b_result))
		return FALSE;	
	if (FALSE == b_result) {
		return FALSE;
	}
	if (FALSE == message_object_get_recipient_all_proptags(
		pmessage, &tmp_columns)) {
		return FALSE;
	}
	pcolumns = proptag_array_dup(&tmp_columns);
	if (NULL == pcolumns) {
		return FALSE;
	}
	proptag_array_free(pmessage->precipient_columns);
	pmessage->precipient_columns = pcolumns;
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	pmessage->b_touched = FALSE;
	while ((pnode = double_list_pop_front(&pmessage->stream_list)) != nullptr)
		free(pnode);
	pmessage->change_num = 0;
	if (FALSE == pmessage->b_new) {
		if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, PROP_TAG_CHANGENUMBER,
		    reinterpret_cast<void **>(&pchange_num)) ||
		    pchange_num == nullptr)
			return FALSE;
		pmessage->change_num = *pchange_num;
	}
	return TRUE;
}

BOOL message_object::read_recipients(uint32_t row_id, uint16_t need_count, TARRAY_SET *pset)
{
	auto pmessage = this;
	return exmdb_client_get_message_instance_rcpts(pmessage->plogon->get_dir(),
	       pmessage->instance_id, row_id, need_count, pset);
}

BOOL message_object::get_recipient_num(uint16_t *pnum)
{
	auto pmessage = this;
	return exmdb_client_get_message_instance_rcpts_num(pmessage->plogon->get_dir(),
	       pmessage->instance_id, pnum);
}

BOOL message_object::empty_rcpts()
{
	auto pmessage = this;
	if (!exmdb_client_empty_message_instance_rcpts(pmessage->plogon->get_dir(),
	    pmessage->instance_id))
		return FALSE;	
	pmessage->b_touched = TRUE;
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_RECIPIENTS);
	return TRUE;
}

BOOL message_object::set_rcpts(const TARRAY_SET *pset)
{
	auto pmessage = this;
	if (!exmdb_client_update_message_instance_rcpts(pmessage->plogon->get_dir(),
	    pmessage->instance_id, pset))
		return FALSE;	
	for (size_t i = 0; i < pset->count; ++i) {
		for (size_t j = 0; j < pset->pparray[i]->count; ++j) {
			switch (pset->pparray[i]->ppropval[j].proptag) {
			case PROP_TAG_RESPONSIBILITY:
			case PROP_TAG_ADDRESSTYPE:
			case PR_DISPLAY_NAME:
			case PR_DISPLAY_NAME_A:
			case PR_EMAIL_ADDRESS:
			case PR_EMAIL_ADDRESS_A:
			case PR_ENTRYID:
			case PROP_TAG_INSTANCEKEY:
			case PROP_TAG_RECIPIENTTYPE:
			case PROP_TAG_ROWID:
			case PROP_TAG_SEARCHKEY:
			case PROP_TAG_SENDRICHINFO:
			case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
			case PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8:
				continue;
			}
			proptag_array_append(pmessage->precipient_columns,
				pset->pparray[i]->ppropval[j].proptag);
		}
	}
	pmessage->b_touched = TRUE;
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_RECIPIENTS);
	return TRUE;
}

BOOL message_object::get_attachments_num(uint16_t *pnum)
{
	auto pmessage = this;
	return exmdb_client_get_message_instance_attachments_num(
	       pmessage->plogon->get_dir(), pmessage->instance_id, pnum);
}

BOOL message_object::delete_attachment(uint32_t attachment_num)
{
	auto pmessage = this;
	if (!exmdb_client_delete_message_instance_attachment(
	    pmessage->plogon->get_dir(), pmessage->instance_id, attachment_num))
		return FALSE;
	pmessage->b_touched = TRUE;
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_ATTACHMENTS);
	return TRUE;
}

BOOL message_object::get_attachment_table_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pmessage = this;
	return exmdb_client_get_message_instance_attachment_table_all_proptags(
	       pmessage->plogon->get_dir(), pmessage->instance_id, pproptags);
}

BOOL message_object::query_attachment_table(const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	auto pmessage = this;
	return exmdb_client_query_message_instance_attachment_table(
	       pmessage->plogon->get_dir(), pmessage->instance_id, pproptags,
	       start_pos, row_needed, pset);
}

BOOL message_object::append_stream_object(stream_object *pstream)
{
	auto pmessage = this;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pmessage->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pmessage->stream_list, pnode)) {
		if (pnode->pdata == pstream) {
			return TRUE;
		}
	}
	if (FALSE == pmessage->b_new && 0 != pmessage->message_id) {
		auto proptag = message_object_rectify_proptag(pstream->get_proptag());
		if (!proptag_array_append(pmessage->pchanged_proptags, proptag))
			return FALSE;
		proptag_array_remove(
			pmessage->premoved_proptags, proptag);
	}
	pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (NULL == pnode) {
		return FALSE;
	}
	pnode->pdata = pstream;
	double_list_append_as_tail(&pmessage->stream_list, pnode);
	pmessage->b_touched = TRUE;
	return TRUE;
}

/* called when stream object is released */
BOOL message_object::commit_stream_object(stream_object *pstream)
{
	auto pmessage = this;
	uint32_t result;
	DOUBLE_LIST_NODE *pnode;
	TAGGED_PROPVAL tmp_propval;
	
	for (pnode=double_list_get_head(&pmessage->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pmessage->stream_list, pnode)) {
		if (pnode->pdata == pstream) {
			double_list_remove(&pmessage->stream_list, pnode);
			free(pnode);
			tmp_propval.proptag = pstream->get_proptag();
			tmp_propval.pvalue = pstream->get_content();
			if (!exmdb_client_set_instance_property(pmessage->plogon->get_dir(),
			    pmessage->instance_id, &tmp_propval, &result))
				return FALSE;
			return TRUE;
		}
	}
	return TRUE;
}

BOOL message_object::flush_streams()
{
	auto pmessage = this;
	uint32_t result;
	DOUBLE_LIST_NODE *pnode;
	TAGGED_PROPVAL tmp_propval;
	
	while ((pnode = double_list_pop_front(&pmessage->stream_list)) != nullptr) {
		auto pstream = static_cast<stream_object *>(pnode->pdata);
		tmp_propval.proptag = pstream->get_proptag();
		tmp_propval.pvalue = pstream->get_content();
		if (!exmdb_client_set_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, &tmp_propval, &result)) {
			double_list_insert_as_head(&pmessage->stream_list, pnode);
			return FALSE;
		}
		free(pnode);
	}
	return TRUE;
}

BOOL message_object::clear_unsent()
{
	auto pmessage = this;
	uint32_t result;
	uint32_t *pmessage_flags;
	TAGGED_PROPVAL tmp_propval;
	
	if (0 == pmessage->message_id) {
		return FALSE;
	}
	if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
	    pmessage->instance_id, PR_MESSAGE_FLAGS, reinterpret_cast<void **>(&pmessage_flags)))
		return FALSE;	
	if (NULL == pmessage_flags) {
		return TRUE;
	}
	*pmessage_flags &= ~MSGFLAG_UNSENT;
	tmp_propval.proptag = PR_MESSAGE_FLAGS;
	tmp_propval.pvalue = pmessage_flags;
	return exmdb_client_set_instance_property(pmessage->plogon->get_dir(),
	       pmessage->instance_id, &tmp_propval, &result);
}

BOOL message_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pmessage = this;
	int i;
	int nodes_num;
	DOUBLE_LIST_NODE *pnode;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client_get_instance_all_proptags(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &tmp_proptags))
		return FALSE;	
	nodes_num = double_list_get_nodes_num(&pmessage->stream_list);
	nodes_num += 10;
	pproptags->count = 0;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + nodes_num);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	for (i=0; i<tmp_proptags.count; i++) {
		switch (tmp_proptags.pproptag[i]) {
		case PROP_TAG_MID:
		case PR_SUBJECT:
		case PR_ASSOCIATED:
		case PROP_TAG_CHANGENUMBER:
		case PR_SUBJECT_PREFIX:
		case PR_NORMALIZED_SUBJECT:
			continue;
		default:
			pproptags->pproptag[pproptags->count++] = tmp_proptags.pproptag[i];
			break;
		}
	}
	for (pnode=double_list_get_head(&pmessage->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pmessage->stream_list, pnode)) {
		auto proptag = static_cast<stream_object *>(pnode->pdata)->get_proptag();
		if (common_util_index_proptags(pproptags, proptag) < 0) {
			pproptags->pproptag[pproptags->count++] = proptag;
		}
	}
	pproptags->pproptag[pproptags->count++] = PR_ACCESS;
	pproptags->pproptag[pproptags->count++] = PR_ACCESS_LEVEL;
	pproptags->pproptag[pproptags->count++] = PROP_TAG_FOLDERID;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_SOURCE_KEY;
	if (pmessage->pembedding == nullptr &&
	    common_util_index_proptags(pproptags, PR_SOURCE_KEY) < 0)
		pproptags->pproptag[pproptags->count++] = PR_SOURCE_KEY;
	if (common_util_index_proptags(pproptags, PR_MESSAGE_LOCALE_ID) < 0)
		pproptags->pproptag[pproptags->count++] = PR_MESSAGE_LOCALE_ID;
	if (common_util_index_proptags(pproptags, PR_MESSAGE_CODEPAGE) < 0)
		pproptags->pproptag[pproptags->count++] = PR_MESSAGE_CODEPAGE;
	return TRUE;
}

BOOL message_object::check_readonly_property(uint32_t proptag) const
{
	auto pmessage = this;
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return TRUE;
	switch (proptag) {
	case PR_ACCESS:
	case PR_ACCESS_LEVEL:
	case PR_ASSOCIATED:
	case PROP_TAG_CHANGENUMBER:
	case PROP_TAG_CONVERSATIONID:
	case PROP_TAG_CREATORNAME:
	case PROP_TAG_CREATORENTRYID:
	case PR_DISPLAY_BCC:
	case PR_DISPLAY_CC:
	case PR_DISPLAY_TO:
	case PR_ENTRYID:
	case PROP_TAG_FOLDERID:
	case PR_HASATTACH:
	case PROP_TAG_HASNAMEDPROPERTIES:
	case PROP_TAG_LASTMODIFIERENTRYID:
	case PROP_TAG_MID:
	case PROP_TAG_MIMESKELETON:
	case PROP_TAG_NATIVEBODY:
	case PR_OBJECT_TYPE:
	case PR_PARENT_ENTRYID:
	case PR_PARENT_SOURCE_KEY:
	case PR_STORE_ENTRYID:
	case PR_STORE_RECORD_KEY:
	case PR_RECORD_KEY:
	case PR_MESSAGE_SIZE:
	case PROP_TAG_MESSAGESTATUS:
	case PROP_TAG_TRANSPORTMESSAGEHEADERS:
	case PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
		return TRUE;
	case PR_CHANGE_KEY:
	case PR_CREATION_TIME:
	case PR_LAST_MODIFICATION_TIME:
	case PR_PREDECESSOR_CHANGE_LIST:
	case PR_SOURCE_KEY:
		if (TRUE == pmessage->b_new || NULL != pmessage->pstate) {
			return FALSE;
		}
		return TRUE;
	case PR_READ:
		if (NULL == pmessage->pembedding) {
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static BOOL message_object_get_calculated_property(message_object *pmessage,
    uint32_t proptag, void **ppvalue)
{	
	switch (proptag) {
	case PR_ACCESS:
		*ppvalue = &pmessage->tag_access;
		return TRUE;
	case PR_ACCESS_LEVEL:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*static_cast<uint32_t *>(*ppvalue) = (pmessage->open_flags & OPEN_MODE_FLAG_READWRITE) ?
			ACCESS_LEVEL_MODIFY : ACCESS_LEVEL_READ_ONLY;
		return TRUE;
	case PR_ENTRYID:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = common_util_to_message_entryid(pmessage->plogon,
						pmessage->folder_id, pmessage->message_id);
		return TRUE;
	case PR_OBJECT_TYPE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*static_cast<uint32_t *>(*ppvalue) = MAPI_MESSAGE;
		return TRUE;
	case PR_PARENT_ENTRYID:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = common_util_to_folder_entryid(
			pmessage->plogon, pmessage->folder_id);
		return TRUE;
	case PROP_TAG_FOLDERID:
	case PROP_TAG_PARENTFOLDERID:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = &pmessage->folder_id;
		return TRUE;
	case PR_PARENT_SOURCE_KEY:
		if (!exmdb_client_get_folder_property(pmessage->plogon->get_dir(),
		    0, pmessage->folder_id, PR_SOURCE_KEY, ppvalue))
			return FALSE;	
		if (NULL == *ppvalue) {
			*ppvalue = common_util_calculate_folder_sourcekey(
						pmessage->plogon, pmessage->folder_id);
			if (NULL == *ppvalue) {
				return FALSE;
			}
		}
		return TRUE;
	case PROP_TAG_MID:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = &pmessage->message_id;
		return TRUE;
	case PR_RECORD_KEY:
		if (0 == pmessage->message_id) {
			return FALSE;
		}
		*ppvalue = common_util_to_folder_entryid(
			pmessage->plogon, pmessage->message_id);
		return TRUE;
	case PR_STORE_RECORD_KEY:
	case PR_MAPPING_SIGNATURE:
		*ppvalue = common_util_guid_to_binary(pmessage->plogon->mailbox_guid);
		return TRUE;
	}
	return FALSE;
}

static void* message_object_get_stream_property_value(message_object *pmessage,
    uint32_t proptag)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pmessage->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pmessage->stream_list, pnode)) {
		auto so = static_cast<stream_object *>(pnode->pdata);
		if (so->get_proptag() == proptag)
			return so->get_content();
	}
	return NULL;
}

BOOL message_object::get_properties(uint32_t size_limit,
    const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	auto pmessage = this;
	int i;
	void *pvalue;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint32_t err_code = ecError;
	static const uint32_t lcid_default = 0x0409;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	ppropvals->count = 0;
	for (i=0; i<pproptags->count; i++) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		if (TRUE == message_object_get_calculated_property(
			pmessage, pproptags->pproptag[i], &pvalue)) {
			if (NULL != pvalue) {
				pv.proptag = pproptags->pproptag[i];
				pv.pvalue = pvalue;
			} else {
				pv.proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_ERROR);
				pv.pvalue = deconst(&err_code);
			}
			ppropvals->count ++;
			continue;
		}
		pvalue = message_object_get_stream_property_value(
							pmessage, pproptags->pproptag[i]);
		if (NULL != pvalue) {
			pv.proptag = pproptags->pproptag[i];
			pv.pvalue = pvalue;
			ppropvals->count ++;
			continue;
		}	
		tmp_proptags.pproptag[tmp_proptags.count++] = pproptags->pproptag[i];
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client_get_instance_properties(pmessage->plogon->get_dir(),
	    size_limit, pmessage->instance_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	
	if (tmp_propvals.count > 0) {
		memcpy(ppropvals->ppropval +
			ppropvals->count, tmp_propvals.ppropval,
			sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
		ppropvals->count += tmp_propvals.count;
	}
	if (pmessage->pembedding == nullptr &&
	    common_util_index_proptags(pproptags, PR_SOURCE_KEY) >= 0 &&
	    common_util_get_propvals(ppropvals, PR_SOURCE_KEY) == nullptr) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		pv.proptag = PR_SOURCE_KEY;
		pv.pvalue = common_util_calculate_message_sourcekey(pmessage->plogon, pmessage->message_id);
		if (pv.pvalue == nullptr)
			return FALSE;
		ppropvals->count ++;
	}
	if (common_util_index_proptags(pproptags, PR_MESSAGE_LOCALE_ID) >= 0 &&
	    common_util_get_propvals(ppropvals, PR_MESSAGE_LOCALE_ID) == nullptr) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		pv.proptag = PR_MESSAGE_LOCALE_ID;
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, PR_INTERNET_CPID, &pvalue) &&
		    pvalue != nullptr && pinfo->cpid == *static_cast<uint32_t *>(pvalue))
			pv.pvalue = &pinfo->lcid_string;
		else
			pv.pvalue = deconst(&lcid_default);
		ppropvals->count ++;
	}
	if (common_util_index_proptags(pproptags, PR_MESSAGE_CODEPAGE) >= 0 &&
	    common_util_get_propvals(ppropvals, PR_MESSAGE_CODEPAGE) == nullptr) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		pv.proptag = PR_MESSAGE_CODEPAGE;
		pv.pvalue = &pmessage->cpid;
		ppropvals->count ++;
	}
	return TRUE;	
}

static BOOL message_object_check_stream_property(message_object *pmessage,
    uint32_t proptag)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pmessage->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pmessage->stream_list, pnode)) {
		if (static_cast<stream_object *>(pnode->pdata)->get_proptag() == proptag)
			return TRUE;
	}
	return FALSE;
}

static BOOL message_object_set_properties_internal(message_object *pmessage,
	BOOL b_check, const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems)
{
	int i, j;
	void *pvalue;
	uint32_t proptag;
	uint8_t tmp_bytes[3];
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	uint16_t *poriginal_indices;
	TPROPVAL_ARRAY tmp_propvals1;
	TAGGED_PROPVAL propval_buff[3];
	
	if (0 == (pmessage->open_flags & OPEN_MODE_FLAG_READWRITE)) {
		return FALSE;
	}
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	poriginal_indices = cu_alloc<uint16_t>(ppropvals->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	
	for (i=0; i<ppropvals->count; i++) {
		/* if property is being open as stream object, can not be modified */
		if (TRUE == b_check) {
			if (pmessage->check_readonly_property(ppropvals->ppropval[i].proptag) ||
				TRUE == message_object_check_stream_property(
				pmessage, ppropvals->ppropval[i].proptag)) {
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
				pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
				continue;
			} else if (PROP_TAG_EXTENDEDRULEMESSAGECONDITION
				==  ppropvals->ppropval[i].proptag) {
				if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
				    pmessage->instance_id, PR_ASSOCIATED, &pvalue))
					return FALSE;	
				if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
					continue;
				}
				if (static_cast<BINARY *>(ppropvals->ppropval[i].pvalue)->cb >
				    common_util_get_param(COMMON_UTIL_MAX_EXTRULE_LENGTH)) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
									ppropvals->ppropval[i].proptag;
					pproblems->pproblem[pproblems->count++].err = ecMAPIOOM;
					continue;
				}
			} else if (ppropvals->ppropval[i].proptag == PR_MESSAGE_FLAGS) {
				tmp_propvals1.count = 3;
				tmp_propvals1.ppropval = propval_buff;
				propval_buff[0].proptag = PR_READ;
				propval_buff[0].pvalue = &tmp_bytes[0];
				propval_buff[1].proptag = PR_READ_RECEIPT_REQUESTED;
				propval_buff[1].pvalue = &tmp_bytes[1];
				propval_buff[2].proptag = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
				propval_buff[2].pvalue = &tmp_bytes[2];
				tmp_bytes[0] = !!(*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) & MSGFLAG_READ);
				tmp_bytes[1] = !!(*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) & MSGFLAG_RN_PENDING);
				tmp_bytes[2] = !!(*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) & MSGFLAG_NRN_PENDING);
				if (!exmdb_client_set_instance_properties(
				    pmessage->plogon->get_dir(),
				    pmessage->instance_id, &tmp_propvals1,
				    &tmp_problems))
					return FALSE;	
			}
		}
		tmp_propvals.ppropval[tmp_propvals.count] =
							ppropvals->ppropval[i];
		poriginal_indices[tmp_propvals.count++] = i;
	}
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	if (!exmdb_client_set_instance_properties(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count > 0) {
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index =
				poriginal_indices[tmp_problems.pproblem[i].index];
		}
		memcpy(pproblems->pproblem + pproblems->count,
			tmp_problems.pproblem, tmp_problems.count*
			sizeof(PROPERTY_PROBLEM));
		pproblems->count += tmp_problems.count;
		qsort(pproblems->pproblem, pproblems->count,
			sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
	}
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	for (i=0; i<ppropvals->count; i++) {
		for (j=0; j<pproblems->count; j++) {
			if (i == pproblems->pproblem[j].index) {
				break;
			}
		}
		if (j < pproblems->count) {
			continue;
		}
		pmessage->b_touched = TRUE;
		proptag = message_object_rectify_proptag(
				ppropvals->ppropval[i].proptag);
		proptag_array_remove(pmessage->premoved_proptags, proptag);
		if (!proptag_array_append(pmessage->pchanged_proptags, proptag))
			return FALSE;	
	}
	return TRUE;
}

BOOL message_object::set_properties(const TPROPVAL_ARRAY *ppropvals,
    PROBLEM_ARRAY *pproblems)
{
	auto pmessage = this;
	return message_object_set_properties_internal(
			pmessage, TRUE, ppropvals, pproblems);
}

BOOL message_object::remove_properties(const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems)
{
	auto pmessage = this;
	int i, j;
	uint32_t proptag;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	uint16_t *poriginal_indices;
	
	if (0 == (pmessage->open_flags & OPEN_MODE_FLAG_READWRITE)) {
		return FALSE;
	}
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	poriginal_indices = cu_alloc<uint16_t>(pproptags->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	/* if property is being open as stream object, can not be removed */
	for (i=0; i<pproptags->count; i++) {
		if (check_readonly_property(pproptags->pproptag[i]) ||
			TRUE == message_object_check_stream_property(
			pmessage, pproptags->pproptag[i])) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
									pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count] =
								pproptags->pproptag[i];
		poriginal_indices[tmp_proptags.count++] = i;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client_remove_instance_properties(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &tmp_proptags, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count > 0) {
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index =
				poriginal_indices[tmp_problems.pproblem[i].index];
		}
		memcpy(pproblems->pproblem + pproblems->count,
			tmp_problems.pproblem, tmp_problems.count*
			sizeof(PROPERTY_PROBLEM));
		pproblems->count += tmp_problems.count;
		qsort(pproblems->pproblem, pproblems->count,
			sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
	}
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	for (i=0; i<pproptags->count; i++) {
		for (j=0; j<pproblems->count; j++) {
			if (i == pproblems->pproblem[j].index) {
				break;
			}
		}
		if (j < pproblems->count) {
			continue;
		}
		pmessage->b_touched = TRUE;
		proptag = message_object_rectify_proptag(
						pproptags->pproptag[i]);
		proptag_array_remove(pmessage->pchanged_proptags, proptag);
		if (!proptag_array_append(pmessage->premoved_proptags, proptag))
			return FALSE;	
	}
	return TRUE;
}

BOOL message_object::copy_to(message_object *pmessage_src,
     const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force, BOOL *pb_cycle,
     PROBLEM_ARRAY *pproblems)
{
	auto pmessage = this;
	int i;
	uint32_t proptag;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY *pcolumns;
	MESSAGE_CONTENT msgctnt;
	
	if (!exmdb_client_check_instance_cycle(pmessage->plogon->get_dir(),
	    pmessage_src->instance_id, pmessage->instance_id, pb_cycle))
		return FALSE;	
	if (TRUE == *pb_cycle) {
		return TRUE;
	}
	if (!pmessage_src->flush_streams())
		return FALSE;
	if (!exmdb_client_read_message_instance(pmessage_src->plogon->get_dir(),
	    pmessage_src->instance_id, &msgctnt))
		return FALSE;
	static constexpr uint32_t tags[] = {
		PROP_TAG_MID, PR_DISPLAY_TO, PR_DISPLAY_TO_A,
		PR_DISPLAY_CC, PR_DISPLAY_CC_A, PR_DISPLAY_BCC,
		PR_DISPLAY_BCC_A, PR_MESSAGE_SIZE,
		PR_HASATTACH, PR_CHANGE_KEY, PROP_TAG_CHANGENUMBER,
		PR_PREDECESSOR_CHANGE_LIST,
	};
	for (auto t : tags)
		common_util_remove_propvals(&msgctnt.proplist, t);
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
	if (common_util_index_proptags(pexcluded_proptags, PR_MESSAGE_RECIPIENTS) >= 0)
		msgctnt.children.prcpts = NULL;
	if (common_util_index_proptags(pexcluded_proptags, PR_MESSAGE_ATTACHMENTS) >= 0)
		msgctnt.children.pattachments = NULL;
	if (!exmdb_client_write_message_instance(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &msgctnt, b_force, &proptags, pproblems))
		return FALSE;	
	pcolumns = proptag_array_dup(pmessage_src->precipient_columns);
	if (NULL != pcolumns) {
		proptag_array_free(pmessage->precipient_columns);
		pmessage->precipient_columns = pcolumns;
	}
	if (TRUE == pmessage->b_new || 0 == pmessage->message_id) {
		return TRUE;
	}
	for (i=0; i<proptags.count; i++) {
		proptag = message_object_rectify_proptag(proptags.pproptag[i]);
		proptag_array_append(pmessage->pchanged_proptags, proptag);
	}
	return TRUE;
}

BOOL message_object::copy_rcpts(message_object *pmessage_src,
    BOOL b_force, BOOL *pb_result)
{
	auto pmessage = this;
	if (!exmdb_client_copy_instance_rcpts(pmessage->plogon->get_dir(),
	    b_force, pmessage_src->instance_id, pmessage->instance_id, pb_result))
		return FALSE;	
	if (TRUE == *pb_result) {
		proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_ATTACHMENTS);
	}
	return TRUE;
}
	
BOOL message_object::copy_attachments(message_object *pmessage_src,
    BOOL b_force, BOOL *pb_result)
{
	auto pmessage = this;
	if (!exmdb_client_copy_instance_attachments(pmessage->plogon->get_dir(),
	    b_force, pmessage_src->instance_id, pmessage->instance_id, pb_result))
		return FALSE;	
	if (TRUE == *pb_result) {
		proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_RECIPIENTS);
	}
	return TRUE;
}

BOOL message_object::set_readflag(uint8_t read_flag, BOOL *pb_changed)
{
	auto pmessage = this;
	void *pvalue;
	BOOL b_notify;
	uint32_t result;
	uint64_t read_cn;
	uint8_t tmp_byte;
	PROBLEM_ARRAY problems;
	TAGGED_PROPVAL propval;
	MESSAGE_CONTENT *pbrief;
	TPROPVAL_ARRAY propvals;
	static constexpr uint8_t fake_false = 0;
	TAGGED_PROPVAL propval_buff[2];
	
	auto rpc_info = get_rpc_info();
	auto username = pmessage->plogon->check_private() ? nullptr : rpc_info.username;
	b_notify = FALSE;
	*pb_changed = FALSE;
	switch (read_flag) {
	case MSG_READ_FLAG_DEFAULT:
	case MSG_READ_FLAG_SUPPRESS_RECEIPT:
		if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, PR_READ, &pvalue))
			return FALSE;	
		if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
			tmp_byte = 1;
			*pb_changed = TRUE;
			if (MSG_READ_FLAG_DEFAULT == read_flag) {
				if (!exmdb_client_get_instance_property(
				    pmessage->plogon->get_dir(), pmessage->instance_id,
				    PR_READ_RECEIPT_REQUESTED, &pvalue))
					return FALSE;
				if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
					b_notify = TRUE;
				}
			}
		}
		break;
	case MSG_READ_FLAG_CLEAR_READ_FLAG:
		if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, PR_READ, &pvalue))
			return FALSE;	
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			tmp_byte = 0;
			*pb_changed = TRUE;
		}
		break;
	case MSG_READ_FLAG_GENERATE_RECEIPT_ONLY:
		if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, PR_READ_RECEIPT_REQUESTED, &pvalue))
			return FALSE;
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			b_notify = TRUE;
		}
		break;
	case MSG_READ_FLAG_CLEAR_NOTIFY_READ:
	case MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD:
	case MSG_READ_FLAG_CLEAR_NOTIFY_READ |
		MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD:
		if (read_flag & MSG_READ_FLAG_CLEAR_NOTIFY_READ) {
			if (!exmdb_client_remove_instance_property(pmessage->plogon->get_dir(),
			    pmessage->instance_id, PR_READ_RECEIPT_REQUESTED, &result))
				return FALSE;	
			if (exmdb_client_get_message_property(pmessage->plogon->get_dir(),
			    username, 0, pmessage->message_id,
			    PR_READ_RECEIPT_REQUESTED, &pvalue) &&
			    pvalue != nullptr && *static_cast<uint8_t *>(pvalue) != 0 &&
			    !exmdb_client_remove_message_property(pmessage->plogon->get_dir(),
			    pmessage->cpid, pmessage->message_id, PR_READ_RECEIPT_REQUESTED))
				return FALSE;
		}
		if (read_flag & MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD) {
			if (!exmdb_client_remove_instance_property(pmessage->plogon->get_dir(),
			    pmessage->instance_id, PR_NON_RECEIPT_NOTIFICATION_REQUESTED,
			    &result))
				return FALSE;	
			if (exmdb_client_get_message_property(pmessage->plogon->get_dir(),
			    username, 0, pmessage->message_id,
			    PR_NON_RECEIPT_NOTIFICATION_REQUESTED, &pvalue) &&
			    pvalue != nullptr && *static_cast<uint8_t *>(pvalue) != 0 &&
			    !exmdb_client_remove_message_property(pmessage->plogon->get_dir(),
			    pmessage->cpid, pmessage->message_id,
			    PR_NON_RECEIPT_NOTIFICATION_REQUESTED))
					return FALSE;	
		}
		if (!exmdb_client_get_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, PR_MESSAGE_FLAGS, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		if (*static_cast<uint32_t *>(pvalue) & MSGFLAG_UNMODIFIED) {
			*static_cast<uint32_t *>(pvalue) &= ~MSGFLAG_UNMODIFIED;
			propval.proptag = PR_MESSAGE_FLAGS;
			propval.pvalue = pvalue;
			if (!exmdb_client_set_instance_property(pmessage->plogon->get_dir(),
			    pmessage->instance_id, &propval, &result))
				return FALSE;
			if (!exmdb_client_mark_modified(pmessage->plogon->get_dir(),
			    pmessage->message_id))
				return FALSE;
		}
		return TRUE;
	default:
		return TRUE;
	}
	if (TRUE == *pb_changed) {
		if (!exmdb_client_set_message_read_state(pmessage->plogon->get_dir(),
		    username, pmessage->message_id, tmp_byte, &read_cn))
			return FALSE;
		propval.proptag = PR_READ;
		propval.pvalue = &tmp_byte;
		if (!exmdb_client_set_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, &propval, &result))
			return FALSE;	
		if (0 != result) {
			return TRUE;
		}
	}
	if (TRUE == b_notify) {
		if (!exmdb_client_get_message_brief(pmessage->plogon->get_dir(),
		    pmessage->cpid, pmessage->message_id, &pbrief))
			return FALSE;	
		if (NULL != pbrief) {
			common_util_notify_receipt(pmessage->plogon->get_account(),
				NOTIFY_RECEIPT_READ, pbrief);
		}
		propvals.count = 2;
		propvals.ppropval = propval_buff;
		propval_buff[0].proptag = PR_READ_RECEIPT_REQUESTED;
		propval_buff[0].pvalue  = deconst(&fake_false);
		propval_buff[1].proptag = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
		propval_buff[1].pvalue  = deconst(&fake_false);
		exmdb_client_set_instance_properties(pmessage->plogon->get_dir(),
			pmessage->instance_id, &propvals, &problems);
		exmdb_client_set_message_properties(pmessage->plogon->get_dir(),
			username, 0, pmessage->message_id, &propvals, &problems);
	}
	return TRUE;
}
