// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/pcl.hpp>
#include <gromox/proc_common.h>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "attachment_object.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "ics_state.h"
#include "logon_object.h"
#include "message_object.h"
#include "stream_object.h"

using namespace gromox;

static BOOL message_object_set_properties_internal(message_object *, BOOL check, const TPROPVAL_ARRAY *, PROBLEM_ARRAY *);

static BOOL message_object_get_recipient_all_proptags(message_object *pmessage,
    PROPTAG_ARRAY *pproptags)
{
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_message_instance_rcpts_all_proptags(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &tmp_proptags))
		return FALSE;
	pproptags->count = 0;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < tmp_proptags.count; ++i) {
		switch (tmp_proptags.pproptag[i]) {
		case PR_RESPONSIBILITY:
		case PR_ADDRTYPE:
		case PR_DISPLAY_NAME:
		case PR_DISPLAY_NAME_A:
		case PR_EMAIL_ADDRESS:
		case PR_EMAIL_ADDRESS_A:
		case PR_ENTRYID:
		case PR_INSTANCE_KEY:
		case PR_RECIPIENT_TYPE:
		case PR_ROWID:
		case PR_SEARCH_KEY:
		case PR_SEND_RICH_INFO:
		case PR_TRANSMITABLE_DISPLAY_NAME:
		case PR_TRANSMITABLE_DISPLAY_NAME_A:
			continue;
		default:
			pproptags->emplace_back(tmp_proptags.pproptag[i]);
			break;
		}
	}
	return TRUE;
}

static uint32_t message_object_rectify_proptag(uint32_t proptag)
{
	switch (PROP_TYPE(proptag)) {
	case PT_STRING8:     return CHANGE_PROP_TYPE(proptag, PT_UNICODE);
	case PT_MV_STRING8:  return CHANGE_PROP_TYPE(proptag, PT_MV_UNICODE);
	case PT_UNSPECIFIED: return CHANGE_PROP_TYPE(proptag, PT_UNICODE);
	default:             return proptag;
	}
}

std::unique_ptr<message_object> message_object::create(logon_object *plogon,
    BOOL b_new, cpid_t cpid, uint64_t message_id, void *pparent,
    uint32_t tag_access, uint8_t open_flags, std::shared_ptr<ICS_STATE> pstate)
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
	pmessage->pstate = std::move(pstate);
	auto dir = plogon->get_dir();
	if (0 == message_id) {
		pmessage->pembedding = static_cast<attachment_object *>(pparent);
		if (!exmdb_client::load_embedded_instance(dir,
		    b_new, static_cast<attachment_object *>(pparent)->instance_id,
		    &pmessage->instance_id))
			return NULL;
		/* cannot find embedded message in attachment, return
			immediately to caller and the caller check the
			result by calling message_object_get_instance_id */
		if (!b_new && pmessage->instance_id == 0)
			return pmessage;
	} else {
		pmessage->folder_id = *static_cast<uint64_t *>(pparent);
		if (pmessage->plogon->is_private()) {
			if (!exmdb_client::load_message_instance(dir,
			    nullptr, cpid, b_new, pmessage->folder_id, message_id,
			    &pmessage->instance_id))
				return NULL;
		} else {
			auto rpc_info = get_rpc_info();
			if (!exmdb_client::load_message_instance(dir,
			    rpc_info.username, cpid, b_new, pmessage->folder_id,
			    message_id, &pmessage->instance_id))
				return NULL;
		}
	}
	if (pmessage->instance_id == 0)
		return NULL;
	pmessage->pchanged_proptags = proptag_array_init();
	if (pmessage->pchanged_proptags == nullptr)
		return NULL;
	pmessage->premoved_proptags = proptag_array_init();
	if (pmessage->premoved_proptags == nullptr)
		return NULL;
	if (!b_new) {
		if (!exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PidTagChangeNumber,
		    reinterpret_cast<void **>(&pchange_num)))
			return NULL;
		if (pchange_num != nullptr)
			pmessage->change_num = *pchange_num;
	}
	if (!message_object_get_recipient_all_proptags(pmessage.get(), &tmp_columns))
		return NULL;
	pmessage->precipient_columns = proptag_array_dup(&tmp_columns);
	if (pmessage->precipient_columns == nullptr)
		return NULL;
	return pmessage;
}

ec_error_t message_object::check_original_touched() const
{
	auto pmessage = this;
	uint64_t *pchange_num;
	
	if (pmessage->b_new)
		return ecSuccess; /* not touched */
	if (0 != pmessage->message_id) {
		if (!exmdb_client::get_message_property(pmessage->plogon->get_dir(),
		    nullptr, CP_ACP, pmessage->message_id, PidTagChangeNumber,
		    reinterpret_cast<void **>(&pchange_num)))
			return ecError;
	} else {
		if (!exmdb_client::get_embedded_cn(pmessage->plogon->get_dir(),
		    pmessage->instance_id, &pchange_num))
			return ecError;
	}
	if (pchange_num == nullptr)
		/* OXCFXICS v24 §3.3.4.3.3.2.2.1; message does not exist anymore */
		return ecObjectDeleted;
	if (*pchange_num != pmessage->change_num)
		return ecObjectModified;
	return ecSuccess;
}

message_object::~message_object()
{
	auto pmessage = this;
	
	if (pmessage->instance_id != 0)
		exmdb_client::unload_instance(pmessage->plogon->get_dir(),
			pmessage->instance_id);
	if (pmessage->precipient_columns != nullptr)
		proptag_array_free(pmessage->precipient_columns);
	if (pmessage->pchanged_proptags != nullptr)
		proptag_array_free(pmessage->pchanged_proptags);
	if (pmessage->premoved_proptags != nullptr)
		proptag_array_free(pmessage->premoved_proptags);
}

errno_t message_object::init_message(bool fai, cpid_t new_cpid)
{
	auto pmessage = this;
	EXT_PUSH ext_push;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	
	if (!pmessage->b_new)
		return EINVAL;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return ESRCH;
	auto rpc_info = get_rpc_info();
	propvals.count = 0;
	propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(20);
	if (propvals.ppropval == nullptr)
		return ENOMEM;
	
	auto msgcpid = cu_alloc<uint32_t>();
	if (msgcpid == nullptr)
		return ENOMEM;
	*msgcpid = static_cast<uint32_t>(new_cpid);
	propvals.emplace_back(PR_MESSAGE_CODEPAGE, msgcpid);
	
	auto importance = cu_alloc<uint32_t>();
	if (importance == nullptr)
		return ENOMEM;
	*importance = IMPORTANCE_NORMAL;
	propvals.emplace_back(PR_IMPORTANCE, importance);
	propvals.emplace_back(PR_DEF_POST_MSGCLASS, "IPM.Note");
	
	auto sens = cu_alloc<uint32_t>();
	if (sens == nullptr)
		return ENOMEM;
	*sens = SENSITIVITY_NONE;
	propvals.emplace_back(PR_SENSITIVITY, sens);
	for (auto t : {PR_ORIGINAL_DISPLAY_TO, PR_ORIGINAL_DISPLAY_CC, PR_ORIGINAL_DISPLAY_BCC})
		propvals.emplace_back(t, "");
	
	auto msgflags = cu_alloc<uint32_t>();
	if (msgflags == nullptr)
		return ENOMEM;
	*msgflags = MSGFLAG_UNSENT | MSGFLAG_UNMODIFIED;
	propvals.emplace_back(PR_MESSAGE_FLAGS, msgflags);
	
	auto readflag = cu_alloc<uint8_t>();
	if (readflag == nullptr)
		return ENOMEM;
	*readflag = 0;
	propvals.emplace_back(PR_READ, readflag);
	
	auto assocflag = cu_alloc<uint8_t>();
	if (assocflag == nullptr)
		return ENOMEM;
	*assocflag = fai;
	propvals.emplace_back(PR_ASSOCIATED, assocflag);
	
	auto trustsender = cu_alloc<uint32_t>();
	if (trustsender == nullptr)
		return ENOMEM;
	*trustsender = 1;
	propvals.emplace_back(PR_TRUST_SENDER, trustsender);
	
	auto modtime = cu_alloc<uint64_t>();
	if (modtime == nullptr)
		return ENOMEM;
	*modtime = rop_util_current_nttime();
	propvals.emplace_back(PR_CREATION_TIME, modtime);
	
	auto search_key = common_util_guid_to_binary(GUID::random_new());
	if (search_key == nullptr)
		return ENOMEM;
	propvals.emplace_back(PR_SEARCH_KEY, search_key);
	
	propvals.ppropval[propvals.count].proptag = PR_MESSAGE_LOCALE_ID;
	auto msglcid = cu_alloc<uint32_t>();
	if (msglcid == nullptr)
		return ENOMEM;
	*msglcid = pinfo->lcid_string;
	if (*msglcid == 0)
		*msglcid = 0x0409;
	propvals.emplace_back(PR_MESSAGE_LOCALE_ID, msglcid);
	propvals.emplace_back(PR_LOCALE_ID, msglcid);
	
	static constexpr size_t dispnamesize = 1024;
	auto dispname = cu_alloc<char>(1024);
	if (dispname == nullptr)
		return ENOMEM;
	if (!common_util_get_user_displayname(rpc_info.username,
	    dispname, dispnamesize) || *dispname == '\0')
		gx_strlcpy(dispname, rpc_info.username, dispnamesize);
	propvals.emplace_back(PR_CREATOR_NAME, dispname);
	
	auto abk_eid = common_util_username_to_addressbook_entryid(rpc_info.username);
	if (abk_eid == nullptr)
		return ENOMEM;
	propvals.emplace_back(PR_CREATOR_ENTRYID, abk_eid);

	char id_string[UADDR_SIZE+2];
	auto ret = make_inet_msgid(id_string, std::size(id_string), 0x4554);
	if (ret != 0)
		return ret;
	propvals.emplace_back(PR_INTERNET_MESSAGE_ID, id_string);
	
	if (!exmdb_client::set_instance_properties(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &propvals, &problems))
		return EIO;
	pmessage->b_touched = TRUE;
	return 0;
}

void message_object::set_open_flags(uint8_t f)
{
	open_flags = f;
}

static ec_error_t message_object_save2(message_object *pmessage, bool b_fai,
    BINARY *&pbin_pcl, const char *rpc_user)
{
	BINARY *pbin_pcl1 = nullptr;
	auto dir = pmessage->plogon->get_dir();

	if (!exmdb_client::get_instance_property(dir,
	    pmessage->instance_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)) ||
	    pbin_pcl == nullptr)
		return ecRpcFailed;
	if (!exmdb_client::get_message_property(dir,
	    nullptr, CP_ACP, pmessage->message_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl1)) ||
	    pbin_pcl1 == nullptr)
		return ecRpcFailed;

	uint32_t result = 0;
	if (!common_util_pcl_compare(pbin_pcl, pbin_pcl1, &result))
		return ecRpcFailed;
	if (result != PCL_CONFLICT)
		return ecSuccess;

	void *rv;
	if (!exmdb_client::get_folder_property(dir,
	    CP_ACP, pmessage->folder_id, PR_RESOLVE_METHOD, &rv))
		return ecRpcFailed;
	uint32_t resolve_method = rv == nullptr ? RESOLVE_METHOD_DEFAULT :
	                          *static_cast<uint32_t *>(rv);
	if (!b_fai && resolve_method == RESOLVE_METHOD_DEFAULT) {
		MESSAGE_CONTENT *pmsgctnt = nullptr;
		if (pmessage->plogon->is_private()) {
			if (!exmdb_client::read_message(dir,
			    nullptr, pmessage->cpid,
			    pmessage->message_id, &pmsgctnt))
				return ecRpcFailed;
		} else if (!exmdb_client::read_message(dir,
		    rpc_user, pmessage->cpid,
		    pmessage->message_id, &pmsgctnt)) {
			return ecRpcFailed;
		}
		if (NULL != pmsgctnt) {
			auto mstatus = pmsgctnt->proplist.get<const uint32_t>(PR_MSG_STATUS);
			if (mstatus == nullptr)
				return ecRpcFailed;
			if (!exmdb_client::set_message_instance_conflict(dir,
			    pmessage->instance_id, pmsgctnt))
				return ecRpcFailed;
			auto tmp_status = *mstatus | MSGSTATUS_IN_CONFLICT;
			TAGGED_PROPVAL tmp_propval;
			TPROPVAL_ARRAY tmp_propvals;
			PROBLEM_ARRAY tmp_problems;
			tmp_propval.proptag = PR_MSG_STATUS;
			tmp_propval.pvalue = &tmp_status;
			tmp_propvals.count = 1;
			tmp_propvals.ppropval = &tmp_propval;
			if (!message_object_set_properties_internal(pmessage,
			    false, &tmp_propvals, &tmp_problems))
				return ecRpcFailed;
		}
	}
	pbin_pcl = common_util_pcl_merge(pbin_pcl, pbin_pcl1);
	if (pbin_pcl == nullptr)
		return ecRpcFailed;
	TAGGED_PROPVAL tmp_propval;
	TPROPVAL_ARRAY tmp_propvals;
	PROBLEM_ARRAY tmp_problems;
	tmp_propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
	tmp_propval.pvalue = pbin_pcl;
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = &tmp_propval;
	if (!message_object_set_properties_internal(pmessage,
	    false, &tmp_propvals, &tmp_problems))
		return ecRpcFailed;
	return ecSuccess;
}

ec_error_t message_object::save()
{
	auto pmessage = this;
	uint32_t result;
	BINARY *pbin_pcl = nullptr;
	uint32_t tmp_index;
	uint32_t *pgroup_id;
	
	if (!pmessage->b_new && !pmessage->b_touched)
		return ecSuccess;
	auto rpc_info = get_rpc_info();
	auto dir = plogon->get_dir();
	if (!exmdb_client::allocate_cn(dir, &pmessage->change_num))
		return ecRpcFailed;
	void *assoc;
	if (!exmdb_client::get_instance_property(dir,
	    pmessage->instance_id, PR_ASSOCIATED, &assoc))
		return ecRpcFailed;

	BOOL b_fai = pvb_disabled(assoc) ? false : TRUE;
	if (NULL != pmessage->pstate) {
		if (!pmessage->b_new) {
			auto ret = message_object_save2(pmessage, b_fai,
			           pbin_pcl, rpc_info.username);
			if (ret != 0)
				return ret;
		}
	} else if (0 != pmessage->message_id) {
		if (!exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PR_PREDECESSOR_CHANGE_LIST,
		    reinterpret_cast<void **>(&pbin_pcl)))
			return ecRpcFailed;
		if (!pmessage->b_new && pbin_pcl == nullptr)
			return ecRpcFailed;
	}
	
	if (!flush_streams())
		return ecRpcFailed;
	
	TPROPVAL_ARRAY tmp_propvals;
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(8);
	if (tmp_propvals.ppropval == nullptr)
		return ecServerOOM;
	
	auto modtime = cu_alloc<uint64_t>();
	if (modtime == nullptr)
		return ecServerOOM;
	*modtime = rop_util_current_nttime();
	tmp_propvals.emplace_back(PR_LOCAL_COMMIT_TIME, modtime);
	if (!pmessage->pchanged_proptags->has(PR_LAST_MODIFICATION_TIME))
		tmp_propvals.emplace_back(PR_LAST_MODIFICATION_TIME, modtime);
	
	if (!pmessage->pchanged_proptags->has(PR_LAST_MODIFIER_NAME)) {
		static constexpr size_t dsize = 1024;
		auto dispname = cu_alloc<char>(1024);
		if (dispname == nullptr)
			return ecServerOOM;
		if (!common_util_get_user_displayname(rpc_info.username,
		    dispname, dsize) || *dispname == '\0')
			gx_strlcpy(dispname, rpc_info.username, dsize);
		tmp_propvals.emplace_back(PR_LAST_MODIFIER_NAME, dispname);
	}
	
	auto abk_eid = common_util_username_to_addressbook_entryid(rpc_info.username);
	if (abk_eid == nullptr)
		return ecRpcFailed;
	tmp_propvals.emplace_back(PR_LAST_MODIFIER_ENTRYID, abk_eid);
	
	if (0 != pmessage->message_id && NULL == pmessage->pstate) {
		auto pbin_changekey = cu_xid_to_bin({pmessage->plogon->guid(), pmessage->change_num});
		if (pbin_changekey == nullptr)
			return ecRpcFailed;
		tmp_propvals.emplace_back(PR_CHANGE_KEY, pbin_changekey);
		
		pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
		if (pbin_pcl == nullptr)
			return ecRpcFailed;
		tmp_propvals.emplace_back(PR_PREDECESSOR_CHANGE_LIST, pbin_pcl);
	}
	
	PROBLEM_ARRAY tmp_problems;
	if (!message_object_set_properties_internal(pmessage,
	    false, &tmp_propvals, &tmp_problems))
		return ecRpcFailed;
	
	/* change number of embedding message is used for message
		modification's check when the  rop_savechangesmessage
		is called, it is not used by ICS.
	*/
	TAGGED_PROPVAL tmp_propval;
	tmp_propval.proptag = PidTagChangeNumber;
	tmp_propval.pvalue = &pmessage->change_num;
	if (!exmdb_client::set_instance_property(dir,
	    pmessage->instance_id, &tmp_propval, &result))
		return ecRpcFailed;
	
	ec_error_t e_result = ecRpcFailed;
	if (!exmdb_client::flush_instance(dir,
	    pmessage->instance_id, pmessage->plogon->get_account(),
	    &e_result) || e_result != ecSuccess)
		return e_result;
	auto is_new = pmessage->b_new;
	pmessage->b_new = FALSE;
	pmessage->b_touched = FALSE;
	if (pmessage->pembedding != nullptr)
		pmessage->pembedding->b_touched = TRUE;
	if (pmessage->message_id == 0)
		return ecSuccess;
	
	if (NULL != pmessage->pstate) {
		auto s = b_fai ? pmessage->pstate->pseen_fai.get() : pmessage->pstate->pseen.get();
		s->append(pmessage->change_num);
	}
	if (pmessage->message_id == 0 || b_fai) {
		proptag_array_clear(pmessage->pchanged_proptags);
		proptag_array_clear(pmessage->premoved_proptags);
		return ecSuccess;
	}
	
	const property_groupinfo *pgpinfo = nullptr;
	if (is_new || pmessage->pstate != nullptr)
		goto SAVE_FULL_CHANGE;
	if (!exmdb_client::get_message_group_id(dir,
	    pmessage->message_id, &pgroup_id))
		return ecRpcFailed;
	if (NULL == pgroup_id) {
		pgpinfo = pmessage->plogon->get_last_property_groupinfo();
		if (pgpinfo == nullptr)
			return ecRpcFailed;
		if (!exmdb_client::set_message_group_id(dir,
		    pmessage->message_id, pgpinfo->group_id))
			return ecRpcFailed;
	}  else {
		pgpinfo = pmessage->plogon->get_property_groupinfo(*pgroup_id);
		if (pgpinfo == nullptr)
			return ecRpcFailed;
	}
	
	if (!exmdb_client::mark_modified(dir,
	    pmessage->message_id))
		return ecRpcFailed;
	
	{
	std::unique_ptr<INDEX_ARRAY, pta_delete> pindices(proptag_array_init());
	if (pindices == nullptr)
		return ecServerOOM;
	std::unique_ptr<PROPTAG_ARRAY, pta_delete> pungroup_proptags(proptag_array_init());
	if (pungroup_proptags == nullptr)
		return ecServerOOM;
	/* always mark PR_MESSAGE_FLAGS as changed */
	if (!proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_FLAGS))
		return ecRpcFailed;
	for (size_t i = 0; i < pmessage->pchanged_proptags->count; ++i) {
		if (!pgpinfo->get_partial_index(pmessage->pchanged_proptags->pproptag[i], &tmp_index)) {
			if (!proptag_array_append(pungroup_proptags.get(),
			    pmessage->pchanged_proptags->pproptag[i]))
				return ecRpcFailed;
		} else {
			if (!proptag_array_append(pindices.get(), tmp_index))
				return ecRpcFailed;
		}
	}
	for (size_t i = 0; i < pmessage->premoved_proptags->count; ++i) {
		if (!pgpinfo->get_partial_index(pmessage->premoved_proptags->pproptag[i], &tmp_index))
			goto SAVE_FULL_CHANGE;
		else if (!proptag_array_append(pindices.get(), tmp_index))
			return ecRpcFailed;
	}
	if (!exmdb_client::save_change_indices(dir,
	    pmessage->message_id, pmessage->change_num, pindices.get(), pungroup_proptags.get()))
		return ecRpcFailed;
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	return ecSuccess;
	}
	
 SAVE_FULL_CHANGE:
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	INDEX_ARRAY tmp_indices;
	tmp_indices.count = 0;
	tmp_indices.pproptag = NULL;
	if (!exmdb_client::save_change_indices(dir,
	    pmessage->message_id, pmessage->change_num, &tmp_indices,
	    static_cast<PROPTAG_ARRAY *>(&tmp_indices)))
		return ecRpcFailed;
	/* trigger the rule evaluation under public mode 
		when the message is first saved to the folder */
	if (is_new && !b_fai && pmessage->message_id != 0 &&
	    !pmessage->plogon->is_private())
		exmdb_client::rule_new_message(dir,
			rpc_info.username, pmessage->plogon->get_account(),
			pmessage->cpid, pmessage->folder_id,
			pmessage->message_id);
	return ecSuccess;
}

BOOL message_object::reload()
{
	auto pmessage = this;
	BOOL b_result;
	uint64_t *pchange_num;
	PROPTAG_ARRAY *pcolumns;
	PROPTAG_ARRAY tmp_columns;
	
	if (pmessage->b_new)
		return TRUE;
	auto dir = plogon->get_dir();
	if (!exmdb_client::reload_message_instance(dir,
	    pmessage->instance_id, &b_result))
		return FALSE;	
	if (!b_result)
		return FALSE;
	if (!message_object_get_recipient_all_proptags(pmessage, &tmp_columns))
		return FALSE;
	pcolumns = proptag_array_dup(&tmp_columns);
	if (pcolumns == nullptr)
		return FALSE;
	proptag_array_free(pmessage->precipient_columns);
	pmessage->precipient_columns = pcolumns;
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	pmessage->b_touched = FALSE;
	stream_list.clear();
	pmessage->change_num = 0;
	if (!pmessage->b_new) {
		if (!exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PidTagChangeNumber,
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
	return exmdb_client::get_message_instance_rcpts(pmessage->plogon->get_dir(),
	       pmessage->instance_id, row_id, need_count, pset);
}

BOOL message_object::get_recipient_num(uint16_t *pnum)
{
	auto pmessage = this;
	return exmdb_client::get_message_instance_rcpts_num(pmessage->plogon->get_dir(),
	       pmessage->instance_id, pnum);
}

BOOL message_object::empty_rcpts()
{
	auto pmessage = this;
	if (!exmdb_client::empty_message_instance_rcpts(pmessage->plogon->get_dir(),
	    pmessage->instance_id))
		return FALSE;	
	pmessage->b_touched = TRUE;
	if (pmessage->b_new || pmessage->message_id == 0)
		return TRUE;
	proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_RECIPIENTS);
	return TRUE;
}

BOOL message_object::set_rcpts(const TARRAY_SET *pset)
{
	auto pmessage = this;
	if (!exmdb_client::update_message_instance_rcpts(pmessage->plogon->get_dir(),
	    pmessage->instance_id, pset))
		return FALSE;	
	for (size_t i = 0; i < pset->count; ++i) {
		for (size_t j = 0; j < pset->pparray[i]->count; ++j) {
			switch (pset->pparray[i]->ppropval[j].proptag) {
			case PR_RESPONSIBILITY:
			case PR_ADDRTYPE:
			case PR_DISPLAY_NAME:
			case PR_DISPLAY_NAME_A:
			case PR_EMAIL_ADDRESS:
			case PR_EMAIL_ADDRESS_A:
			case PR_ENTRYID:
			case PR_INSTANCE_KEY:
			case PR_RECIPIENT_TYPE:
			case PR_ROWID:
			case PR_SEARCH_KEY:
			case PR_SEND_RICH_INFO:
			case PR_TRANSMITABLE_DISPLAY_NAME:
			case PR_TRANSMITABLE_DISPLAY_NAME_A:
				continue;
			}
			proptag_array_append(pmessage->precipient_columns,
				pset->pparray[i]->ppropval[j].proptag);
		}
	}
	pmessage->b_touched = TRUE;
	if (pmessage->b_new || pmessage->message_id == 0)
		return TRUE;
	proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_RECIPIENTS);
	return TRUE;
}

BOOL message_object::get_attachments_num(uint16_t *pnum)
{
	auto pmessage = this;
	return exmdb_client::get_message_instance_attachments_num(
	       pmessage->plogon->get_dir(), pmessage->instance_id, pnum);
}

BOOL message_object::delete_attachment(uint32_t attachment_num)
{
	auto pmessage = this;
	if (!exmdb_client::delete_message_instance_attachment(
	    pmessage->plogon->get_dir(), pmessage->instance_id, attachment_num))
		return FALSE;
	pmessage->b_touched = TRUE;
	if (pmessage->b_new || pmessage->message_id == 0)
		return TRUE;
	proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_ATTACHMENTS);
	return TRUE;
}

BOOL message_object::get_attachment_table_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pmessage = this;
	return exmdb_client::get_message_instance_attachment_table_all_proptags(
	       pmessage->plogon->get_dir(), pmessage->instance_id, pproptags);
}

BOOL message_object::query_attachment_table(const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	auto pmessage = this;
	return exmdb_client::query_message_instance_attachment_table(
	       pmessage->plogon->get_dir(), pmessage->instance_id, pproptags,
	       start_pos, row_needed, pset);
}

BOOL message_object::append_stream_object(stream_object *pstream) try
{
	auto pmessage = this;
	
	for (auto so : stream_list)
		if (so == pstream)
			return TRUE;
	if (!pmessage->b_new && pmessage->message_id != 0) {
		auto u_tag = message_object_rectify_proptag(pstream->get_proptag());
		if (!proptag_array_append(pmessage->pchanged_proptags, u_tag))
			return FALSE;
		proptag_array_remove(pmessage->premoved_proptags, u_tag);
	}
	stream_list.push_back(pstream);
	pmessage->b_touched = TRUE;
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

/* called when stream object is released */
BOOL message_object::commit_stream_object(stream_object *pstream)
{
	auto pmessage = this;
	uint32_t result;
	TAGGED_PROPVAL tmp_propval;

	for (auto it = stream_list.begin(); it != stream_list.end(); ) {
		if (*it != pstream) {
			++it;
			continue;
		}
		it = stream_list.erase(it);
		tmp_propval.proptag = pstream->get_proptag();
		tmp_propval.pvalue = pstream->get_content();
		if (!exmdb_client::set_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, &tmp_propval, &result))
			return FALSE;
		return TRUE;
	}
	return TRUE;
}

BOOL message_object::flush_streams()
{
	auto pmessage = this;
	uint32_t result;
	TAGGED_PROPVAL tmp_propval;
	
	while (stream_list.size() > 0) {
		auto pstream = stream_list.front();
		tmp_propval.proptag = pstream->get_proptag();
		tmp_propval.pvalue = pstream->get_content();
		if (!exmdb_client::set_instance_property(pmessage->plogon->get_dir(),
		    pmessage->instance_id, &tmp_propval, &result))
			return FALSE;
		stream_list.erase(stream_list.begin());
	}
	return TRUE;
}

BOOL message_object::clear_unsent()
{
	auto pmessage = this;
	uint32_t result;
	uint32_t *pmessage_flags;
	TAGGED_PROPVAL tmp_propval;
	
	if (pmessage->message_id == 0)
		return FALSE;
	auto dir = plogon->get_dir();
	if (!exmdb_client::get_instance_property(dir,
	    pmessage->instance_id, PR_MESSAGE_FLAGS, reinterpret_cast<void **>(&pmessage_flags)))
		return FALSE;	
	if (pmessage_flags == nullptr)
		return TRUE;
	*pmessage_flags &= ~MSGFLAG_UNSENT;
	tmp_propval.proptag = PR_MESSAGE_FLAGS;
	tmp_propval.pvalue = pmessage_flags;
	return exmdb_client::set_instance_property(dir,
	       pmessage->instance_id, &tmp_propval, &result);
}

BOOL message_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pmessage = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_instance_all_proptags(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &tmp_proptags))
		return FALSE;	
	auto nodes_num = stream_list.size();
	nodes_num += 10;
	pproptags->count = 0;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + nodes_num);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < tmp_proptags.count; ++i) {
		switch (tmp_proptags.pproptag[i]) {
		case PidTagMid:
		case PR_SUBJECT:
		case PR_ASSOCIATED:
		case PidTagChangeNumber:
		case PR_SUBJECT_PREFIX:
		case PR_NORMALIZED_SUBJECT:
			continue;
		default:
			pproptags->emplace_back(tmp_proptags.pproptag[i]);
			break;
		}
	}
	for (auto so : stream_list) {
		auto proptag = so->get_proptag();
		if (!pproptags->has(proptag))
			pproptags->emplace_back(proptag);
	}
	for (auto t : {PR_ACCESS, PR_ACCESS_LEVEL, PidTagFolderId, PR_PARENT_SOURCE_KEY})
		pproptags->emplace_back(t);
	if (pmessage->pembedding == nullptr && !pproptags->has(PR_SOURCE_KEY))
		pproptags->emplace_back(PR_SOURCE_KEY);
	for (auto t : {PR_MESSAGE_LOCALE_ID, PR_MESSAGE_CODEPAGE})
		if (!pproptags->has(t))
			pproptags->emplace_back(t);
	return TRUE;
}

bool message_object::is_readonly_prop(uint32_t proptag) const
{
	auto pmessage = this;
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return true;
	switch (proptag) {
	case PR_ACCESS:
	case PR_ACCESS_LEVEL:
	case PR_ASSOCIATED:
	case PidTagChangeNumber:
	case PR_CONVERSATION_ID:
	case PR_CREATOR_NAME:
	case PR_CREATOR_ENTRYID:
	case PR_DISPLAY_BCC:
	case PR_DISPLAY_CC:
	case PR_DISPLAY_TO:
	case PR_ENTRYID:
	case PidTagFolderId:
	case PR_HASATTACH:
	case PR_HAS_NAMED_PROPERTIES:
	case PR_LAST_MODIFIER_ENTRYID:
	case PidTagMid:
	case PidTagMimeSkeleton:
	case PR_NATIVE_BODY_INFO:
	case PR_OBJECT_TYPE:
	case PR_PARENT_ENTRYID:
	case PR_PARENT_SOURCE_KEY:
	case PR_STORE_ENTRYID:
	case PR_STORE_RECORD_KEY:
	case PR_RECORD_KEY:
	case PR_MESSAGE_SIZE:
	case PR_MSG_STATUS:
		return true;
	case PR_CHANGE_KEY:
	case PR_CREATION_TIME:
	case PR_LAST_MODIFICATION_TIME:
	case PR_PREDECESSOR_CHANGE_LIST:
	case PR_SOURCE_KEY:
		return !pmessage->b_new && pmessage->pstate == nullptr;
	case PR_READ:
		return pmessage->pembedding != nullptr;
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
	case PR_ACCESS_LEVEL: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		*v = (pmessage->open_flags & MAPI_MODIFY) ?
			ACCESS_LEVEL_MODIFY : ACCESS_LEVEL_READ_ONLY;
		return TRUE;
	}
	case PR_ENTRYID:
		if (pmessage->message_id == 0)
			return FALSE;
		*ppvalue = cu_mid_to_entryid(pmessage->plogon,
						pmessage->folder_id, pmessage->message_id);
		return TRUE;
	case PR_OBJECT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = static_cast<uint32_t>(MAPI_MESSAGE);
		return TRUE;
	}
	case PR_PARENT_ENTRYID:
		if (pmessage->message_id == 0)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pmessage->plogon, pmessage->folder_id);
		return TRUE;
	case PidTagFolderId:
	case PidTagParentFolderId:
		if (pmessage->message_id == 0)
			return FALSE;
		*ppvalue = &pmessage->folder_id;
		return TRUE;
	case PR_PARENT_SOURCE_KEY:
		if (!exmdb_client::get_folder_property(pmessage->plogon->get_dir(),
		    CP_ACP, pmessage->folder_id, PR_SOURCE_KEY, ppvalue))
			return FALSE;	
		if (*ppvalue != nullptr)
			return TRUE;
		*ppvalue = cu_fid_to_sk(pmessage->plogon, pmessage->folder_id);
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	case PidTagMid:
		if (pmessage->message_id == 0)
			return FALSE;
		*ppvalue = &pmessage->message_id;
		return TRUE;
	case PR_RECORD_KEY:
		if (pmessage->message_id == 0)
			return FALSE;
		*ppvalue = cu_fid_to_entryid(pmessage->plogon, pmessage->message_id);
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
	for (auto so : pmessage->stream_list)
		if (so->get_proptag() == proptag)
			return so->get_content();
	return NULL;
}

BOOL message_object::get_properties(uint32_t size_limit,
    const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	auto pmessage = this;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint32_t err_code = ecError;
	static const uint32_t lcid_default = 0x0409;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	ppropvals->count = 0;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (message_object_get_calculated_property(pmessage, tag, &pvalue)) {
			if (pvalue != nullptr)
				ppropvals->emplace_back(tag, pvalue);
			else
				ppropvals->emplace_back(CHANGE_PROP_TYPE(tag, PT_ERROR), &err_code);
			continue;
		}
		pvalue = message_object_get_stream_property_value(pmessage, tag);
		if (NULL != pvalue) {
			ppropvals->emplace_back(tag, pvalue);
			continue;
		}	
		tmp_proptags.emplace_back(tag);
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	auto dir = plogon->get_dir();
	if (!exmdb_client::get_instance_properties(dir,
	    size_limit, pmessage->instance_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	
	if (tmp_propvals.count > 0) {
		memcpy(ppropvals->ppropval +
			ppropvals->count, tmp_propvals.ppropval,
			sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
		ppropvals->count += tmp_propvals.count;
	}
	if (pmessage->pembedding == nullptr && pproptags->has(PR_SOURCE_KEY) &&
	    !ppropvals->has(PR_SOURCE_KEY)) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		pv.proptag = PR_SOURCE_KEY;
		pv.pvalue = cu_mid_to_sk(pmessage->plogon, pmessage->message_id);
		if (pv.pvalue == nullptr)
			return FALSE;
		ppropvals->count ++;
	}
	if (pproptags->has(PR_MESSAGE_LOCALE_ID) &&
	    !ppropvals->has(PR_MESSAGE_LOCALE_ID)) {
		void *pvalue = nullptr;
		auto &pv = ppropvals->ppropval[ppropvals->count];
		pv.proptag = PR_MESSAGE_LOCALE_ID;
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PR_INTERNET_CPID, &pvalue) &&
		    pvalue != nullptr && pinfo->cpid == *static_cast<uint32_t *>(pvalue))
			pv.pvalue = &pinfo->lcid_string;
		else
			pv.pvalue = deconst(&lcid_default);
		ppropvals->count ++;
	}
	if (pproptags->has(PR_MESSAGE_CODEPAGE) &&
	    !ppropvals->has(PR_MESSAGE_CODEPAGE)) {
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
	for (auto so : pmessage->stream_list)
		if (so->get_proptag() == proptag)
			return TRUE;
	return FALSE;
}

static BOOL message_object_set_properties_internal(message_object *pmessage,
	BOOL b_check, const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems)
{
	uint8_t tmp_bytes[3];
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	TPROPVAL_ARRAY tmp_propvals1;
	TAGGED_PROPVAL propval_buff[3];
	
	if (!(pmessage->open_flags & MAPI_MODIFY))
		return FALSE;
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
	if (tmp_propvals.ppropval == nullptr)
		return FALSE;
	auto poriginal_indices = cu_alloc<uint16_t>(ppropvals->count);
	if (poriginal_indices == nullptr)
		return FALSE;
	
	auto dir = pmessage->plogon->get_dir();
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		/* if property is being open as stream object, can not be modified */
		const auto &pv = ppropvals->ppropval[i];
		if (b_check) {
			if (pmessage->is_readonly_prop(pv.proptag) ||
			    message_object_check_stream_property(pmessage, pv.proptag)) {
				pproblems->emplace_back(i, pv.proptag, ecAccessDenied);
				continue;
			} else if (pv.proptag == PR_EXTENDED_RULE_MSG_CONDITION) {
				void *pvalue = nullptr;
				if (!exmdb_client::get_instance_property(dir,
				    pmessage->instance_id, PR_ASSOCIATED, &pvalue))
					return FALSE;	
				if (pvb_disabled(pvalue)) {
					pproblems->emplace_back(i, pv.proptag, ecAccessDenied);
					continue;
				}
				if (static_cast<BINARY *>(pv.pvalue)->cb > g_max_extrule_len) {
					pproblems->emplace_back(i, pv.proptag, ecMAPIOOM);
					continue;
				}
			} else if (pv.proptag == PR_MESSAGE_FLAGS) {
				tmp_propvals1.count = 3;
				tmp_propvals1.ppropval = propval_buff;
				propval_buff[0].proptag = PR_READ;
				propval_buff[0].pvalue = &tmp_bytes[0];
				propval_buff[1].proptag = PR_READ_RECEIPT_REQUESTED;
				propval_buff[1].pvalue = &tmp_bytes[1];
				propval_buff[2].proptag = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
				propval_buff[2].pvalue = &tmp_bytes[2];
				tmp_bytes[0] = !!(*static_cast<uint32_t *>(pv.pvalue) & MSGFLAG_READ);
				tmp_bytes[1] = !!(*static_cast<uint32_t *>(pv.pvalue) & MSGFLAG_RN_PENDING);
				tmp_bytes[2] = !!(*static_cast<uint32_t *>(pv.pvalue) & MSGFLAG_NRN_PENDING);
				if (!exmdb_client::set_instance_properties(dir,
				    pmessage->instance_id, &tmp_propvals1,
				    &tmp_problems))
					return FALSE;	
			}
		}
		tmp_propvals.ppropval[tmp_propvals.count] = pv;
		poriginal_indices[tmp_propvals.count++] = i;
	}
	if (tmp_propvals.count == 0)
		return TRUE;
	if (!exmdb_client::set_instance_properties(dir,
	    pmessage->instance_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count > 0) {
		tmp_problems.transform(poriginal_indices);
		*pproblems += std::move(tmp_problems);
	}
	if (pmessage->b_new || pmessage->message_id == 0) {
		pmessage->b_touched = TRUE;
		return TRUE;
	}
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		unsigned int j;
		for (j=0; j<pproblems->count; ++j)
			if (i == pproblems->pproblem[j].index)
				break;
		if (j < pproblems->count)
			continue;
		pmessage->b_touched = TRUE;
		auto u_tag = message_object_rectify_proptag(ppropvals->ppropval[i].proptag);
		proptag_array_remove(pmessage->premoved_proptags, u_tag);
		if (!proptag_array_append(pmessage->pchanged_proptags, u_tag))
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
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!(pmessage->open_flags & MAPI_MODIFY))
		return FALSE;
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	auto poriginal_indices = cu_alloc<uint16_t>(pproptags->count);
	if (poriginal_indices == nullptr)
		return FALSE;
	/* if property is being open as stream object, can not be removed */
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (is_readonly_prop(tag) ||
		    message_object_check_stream_property(pmessage, tag)) {
			pproblems->emplace_back(i, tag, ecAccessDenied);
			continue;
		}
		poriginal_indices[tmp_proptags.count] = i;
		tmp_proptags.emplace_back(tag);
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	if (!exmdb_client::remove_instance_properties(pmessage->plogon->get_dir(),
	    pmessage->instance_id, &tmp_proptags, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count > 0) {
		tmp_problems.transform(poriginal_indices);
		*pproblems += std::move(tmp_problems);
	}
	if (pmessage->b_new || pmessage->message_id == 0) {
		pmessage->b_touched = TRUE;
		return TRUE;
	}
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		unsigned int j;
		for (j = 0; j < pproblems->count; ++j)
			if (i == pproblems->pproblem[j].index)
				break;
		if (j < pproblems->count)
			continue;
		pmessage->b_touched = TRUE;
		auto u_tag = message_object_rectify_proptag(pproptags->pproptag[i]);
		proptag_array_remove(pmessage->pchanged_proptags, u_tag);
		if (!proptag_array_append(pmessage->premoved_proptags, u_tag))
			return FALSE;	
	}
	return TRUE;
}

BOOL message_object::copy_to(message_object *pmessage_src,
     const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force, BOOL *pb_cycle,
     PROBLEM_ARRAY *pproblems)
{
	auto pmessage = this;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY *pcolumns;
	MESSAGE_CONTENT msgctnt;
	auto dstdir = plogon->get_dir();
	
	if (!exmdb_client::check_instance_cycle(dstdir,
	    pmessage_src->instance_id, pmessage->instance_id, pb_cycle))
		return FALSE;	
	if (*pb_cycle)
		return TRUE;
	if (!pmessage_src->flush_streams())
		return FALSE;
	if (!exmdb_client::read_message_instance(pmessage_src->plogon->get_dir(),
	    pmessage_src->instance_id, &msgctnt))
		return FALSE;
	static constexpr uint32_t tags[] = {
		PidTagMid, PR_DISPLAY_TO, PR_DISPLAY_TO_A,
		PR_DISPLAY_CC, PR_DISPLAY_CC_A, PR_DISPLAY_BCC,
		PR_DISPLAY_BCC_A, PR_MESSAGE_SIZE,
		PR_HASATTACH, PR_CHANGE_KEY, PidTagChangeNumber,
		PR_PREDECESSOR_CHANGE_LIST,
	};
	for (auto t : tags)
		common_util_remove_propvals(&msgctnt.proplist, t);
	for (unsigned int i = 0; i < msgctnt.proplist.count; ) {
		if (pexcluded_proptags->has(msgctnt.proplist.ppropval[i].proptag)) {
			common_util_remove_propvals(&msgctnt.proplist,
					msgctnt.proplist.ppropval[i].proptag);
			continue;
		}
		i ++;
	}
	if (pexcluded_proptags->has(PR_MESSAGE_RECIPIENTS))
		msgctnt.children.prcpts = NULL;
	if (pexcluded_proptags->has(PR_MESSAGE_ATTACHMENTS))
		msgctnt.children.pattachments = NULL;
	if (!exmdb_client::write_message_instance(dstdir,
	    pmessage->instance_id, &msgctnt, b_force, &proptags, pproblems))
		return FALSE;	
	pcolumns = proptag_array_dup(pmessage_src->precipient_columns);
	if (NULL != pcolumns) {
		proptag_array_free(pmessage->precipient_columns);
		pmessage->precipient_columns = pcolumns;
	}
	if (pmessage->b_new || pmessage->message_id == 0)
		return TRUE;
	for (unsigned int i = 0; i < proptags.count; ++i) {
		auto u_tag = message_object_rectify_proptag(proptags.pproptag[i]);
		proptag_array_append(pmessage->pchanged_proptags, u_tag);
	}
	return TRUE;
}

BOOL message_object::copy_rcpts(message_object *pmessage_src,
    BOOL b_force, BOOL *pb_result)
{
	auto pmessage = this;
	if (!exmdb_client::copy_instance_rcpts(pmessage->plogon->get_dir(),
	    b_force, pmessage_src->instance_id, pmessage->instance_id, pb_result))
		return FALSE;	
	if (*pb_result)
		proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_ATTACHMENTS);
	return TRUE;
}
	
BOOL message_object::copy_attachments(message_object *pmessage_src,
    BOOL b_force, BOOL *pb_result)
{
	auto pmessage = this;
	if (!exmdb_client::copy_instance_attachments(pmessage->plogon->get_dir(),
	    b_force, pmessage_src->instance_id, pmessage->instance_id, pb_result))
		return FALSE;	
	if (*pb_result)
		proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_RECIPIENTS);
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
	auto username = pmessage->plogon->is_private() ? nullptr : rpc_info.username;
	b_notify = FALSE;
	*pb_changed = FALSE;
	auto dir = pmessage->plogon->get_dir();

	read_flag &= ~rfReserved;
	switch (read_flag) {
	case rfDefault:
	case rfSuppressReceipt:
		if (!exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PR_READ, &pvalue))
			return FALSE;	
		if (pvb_enabled(pvalue))
			break;
		tmp_byte = 1;
		*pb_changed = TRUE;
		if (read_flag != rfDefault)
			break;
		if (!exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PR_READ_RECEIPT_REQUESTED, &pvalue))
			return FALSE;
		if (pvb_enabled(pvalue))
			b_notify = TRUE;
		break;
	case rfClearReadFlag:
	case rfClearReadFlag | rfSuppressReceipt:
		if (!exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PR_READ, &pvalue))
			return FALSE;
		if (pvb_disabled(pvalue))
			break;
		tmp_byte = 0;
		*pb_changed = TRUE;
		break;
	case rfGenerateReceiptOnly:
		if (!exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PR_READ_RECEIPT_REQUESTED, &pvalue))
			return FALSE;
		if (pvb_enabled(pvalue))
			b_notify = TRUE;
		break;
	case rfClearNotifyRead:
	case rfClearNotifyUnread:
	case rfClearNotifyRead | rfClearNotifyUnread: {
		if (read_flag & rfClearNotifyRead) {
			if (!exmdb_client::remove_instance_property(dir,
			    pmessage->instance_id, PR_READ_RECEIPT_REQUESTED, &result))
				return FALSE;	
			if (exmdb_client::get_message_property(dir,
			    username, CP_ACP, pmessage->message_id,
			    PR_READ_RECEIPT_REQUESTED, &pvalue) &&
			    pvb_enabled(pvalue) &&
			    !exmdb_client::remove_message_property(dir,
			    pmessage->cpid, pmessage->message_id, PR_READ_RECEIPT_REQUESTED))
				return FALSE;
		}
		if (read_flag & rfClearNotifyUnread) {
			if (!exmdb_client::remove_instance_property(dir,
			    pmessage->instance_id, PR_NON_RECEIPT_NOTIFICATION_REQUESTED,
			    &result))
				return FALSE;	
			if (exmdb_client::get_message_property(dir,
			    username, CP_ACP, pmessage->message_id,
			    PR_NON_RECEIPT_NOTIFICATION_REQUESTED, &pvalue) &&
			    pvb_enabled(pvalue) &&
			    !exmdb_client::remove_message_property(dir,
			    pmessage->cpid, pmessage->message_id,
			    PR_NON_RECEIPT_NOTIFICATION_REQUESTED))
					return FALSE;	
		}
		if (!exmdb_client::get_instance_property(dir,
		    pmessage->instance_id, PR_MESSAGE_FLAGS, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		auto v = static_cast<uint32_t *>(pvalue);
		if (!(*v & MSGFLAG_UNMODIFIED))
			return TRUE;
		*v &= ~MSGFLAG_UNMODIFIED;
		propval.proptag = PR_MESSAGE_FLAGS;
		propval.pvalue = v;
		if (!exmdb_client::set_instance_property(dir,
		    pmessage->instance_id, &propval, &result))
			return FALSE;
		if (!exmdb_client::mark_modified(dir, pmessage->message_id))
			return FALSE;
		return TRUE;
	}
	default:
		return TRUE;
	}
	if (*pb_changed) {
		if (!exmdb_client::set_message_read_state(dir,
		    username, pmessage->message_id, tmp_byte, &read_cn))
			return FALSE;
		propval.proptag = PR_READ;
		propval.pvalue = &tmp_byte;
		if (!exmdb_client::set_instance_property(dir,
		    pmessage->instance_id, &propval, &result))
			return FALSE;	
		if (result != 0)
			return TRUE;
	}
	if (!b_notify)
		return TRUE;
	if (!exmdb_client::get_message_brief(dir,
	    pmessage->cpid, pmessage->message_id, &pbrief))
		return FALSE;
	if (pbrief != nullptr)
		common_util_notify_receipt(pmessage->plogon->get_account(),
			NOTIFY_RECEIPT_READ, pbrief);
	propvals.count = 2;
	propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PR_READ_RECEIPT_REQUESTED;
	propval_buff[0].pvalue  = deconst(&fake_false);
	propval_buff[1].proptag = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
	propval_buff[1].pvalue  = deconst(&fake_false);
	exmdb_client::set_instance_properties(dir,
		pmessage->instance_id, &propvals, &problems);
	exmdb_client::set_message_properties(dir,
		username, CP_ACP, pmessage->message_id, &propvals, &problems);
	return TRUE;
}
