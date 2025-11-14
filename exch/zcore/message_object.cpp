// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/pcl.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "ics_state.hpp"
#include "objects.hpp"
#include "store_object.hpp"
#include "system_services.hpp"
#include "zserver.hpp"

using namespace gromox;

static BOOL message_object_set_properties_internal(message_object *, BOOL check, const TPROPVAL_ARRAY *);

BOOL message_object::get_recipient_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pmessage = this;
	return exmdb_client->get_message_instance_rcpts_all_proptags(
	       pmessage->pstore->get_dir(), pmessage->instance_id, pproptags);
}

std::unique_ptr<message_object> message_object::create(store_object *pstore,
    BOOL b_new, cpid_t cpid, uint64_t message_id, void *pparent,
    uint32_t tag_access, BOOL b_writable, std::shared_ptr<ics_state> pstate)
{
	uint64_t *pchange_num;
	std::unique_ptr<message_object> pmessage;
	try {
		pmessage.reset(new message_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pmessage->pstore = pstore;
	pmessage->b_new = b_new;
	pmessage->cpid = cpid;
	pmessage->message_id = eid_t{message_id};
	pmessage->tag_access = tag_access;
	pmessage->b_writable = b_writable;
	pmessage->pstate = std::move(pstate);
	if (0 == message_id) {
		pmessage->pembedding = static_cast<attachment_object *>(pparent);
		if (!exmdb_client->load_embedded_instance(pstore->get_dir(),
		    b_new, static_cast<attachment_object *>(pparent)->instance_id,
		    &pmessage->instance_id))
			return NULL;
		/* cannot find embedded message in attachment, return
			immediately to caller and the caller check the
			result by calling message_object_get_instance_id */
		if (!b_new && pmessage->instance_id == 0)
			return pmessage;
	} else {
		pmessage->folder_id = *static_cast<eid_t *>(pparent);
		if (pmessage->pstore->b_private) {
			if (!exmdb_client->load_message_instance(pstore->get_dir(),
			    nullptr, cpid, b_new, pmessage->folder_id, message_id,
			    &pmessage->instance_id))
				return NULL;
		} else {
			auto pinfo = zs_get_info();
			if (!exmdb_client->load_message_instance(pstore->get_dir(),
			    pinfo->get_username(), cpid, b_new, pmessage->folder_id,
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
		if (!exmdb_client_get_instance_property(pstore->get_dir(),
		    pmessage->instance_id, PidTagChangeNumber,
		    reinterpret_cast<void **>(&pchange_num)))
			return NULL;
		if (pchange_num != nullptr)
			pmessage->change_num = *pchange_num;
	}
	return pmessage;
}

BOOL message_object::check_original_touched(BOOL *pb_touched)
{
	auto pmessage = this;
	uint64_t *pchange_num;
	
	if (pmessage->b_new) {
		*pb_touched = FALSE;
		return TRUE;
	}
	if (0 != pmessage->message_id) {
		if (!exmdb_client_get_message_property(pmessage->pstore->get_dir(),
		    nullptr, CP_ACP, pmessage->message_id, PidTagChangeNumber,
		    reinterpret_cast<void **>(&pchange_num)))
			return FALSE;
	} else {
		if (!exmdb_client->get_embedded_cn(pmessage->pstore->get_dir(),
		    pmessage->instance_id, &pchange_num))
			return FALSE;	
	}
	/* if it cannot find PidTagChangeNumber, it means message does not exist any more */
	*pb_touched = pchange_num == nullptr || *pchange_num != pmessage->change_num ? TRUE : false;
	return TRUE;
}

message_object::~message_object()
{	
	auto pmessage = this;
	if (pmessage->instance_id != 0)
		exmdb_client->unload_instance(pmessage->pstore->get_dir(),
			pmessage->instance_id);
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
	propvals.count = 0;
	propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(20);
	if (propvals.ppropval == nullptr)
		return ENOMEM;
	
	auto msgcpid = cu_alloc<uint32_t>();
	if (msgcpid == nullptr)
		return ENOMEM;
	*msgcpid = new_cpid;
	propvals.emplace_back(PR_MESSAGE_CODEPAGE, msgcpid);

	auto importance = cu_alloc<uint32_t>();
	if (importance == nullptr)
		return ENOMEM;
	*importance = IMPORTANCE_NORMAL;
	propvals.emplace_back(PR_IMPORTANCE, importance);
	propvals.emplace_back(PR_MESSAGE_CLASS, "IPM.Note");

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
	*msgflags = MSGFLAG_READ | MSGFLAG_UNSENT | MSGFLAG_EVERREAD | MSGFLAG_UNMODIFIED;
	propvals.emplace_back(PR_MESSAGE_FLAGS, msgflags);

	auto readflag = cu_alloc<uint8_t>();
	if (readflag == nullptr)
		return ENOMEM;
	*readflag = 1;
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

	auto crtime = cu_alloc<uint64_t>();
	if (crtime == nullptr)
		return ENOMEM;
	*crtime = rop_util_current_nttime();
	propvals.emplace_back(PR_CREATION_TIME, crtime);

	auto search_key = common_util_guid_to_binary(GUID::random_new());
	if (search_key == nullptr)
		return ENOMEM;
	propvals.emplace_back(PR_SEARCH_KEY, search_key);

	auto msglcid = cu_alloc<uint32_t>();
	if (msglcid == nullptr)
		return ENOMEM;
	*msglcid = 0x409; /* en-US */
	propvals.emplace_back(PR_MESSAGE_LOCALE_ID, msglcid);
	propvals.emplace_back(PR_LOCALE_ID, msglcid);

	auto pinfo = zs_get_info();
	std::string dispname;
	auto dnptr = mysql_adaptor_get_user_displayname(pinfo->get_username(), dispname) &&
	             !dispname.empty() ? common_util_dup(dispname) :
	             common_util_dup(pinfo->get_username());
	if (dnptr == nullptr)
		return ENOMEM;
	propvals.emplace_back(PR_CREATOR_NAME, std::move(dnptr));

	auto abk_eid = common_util_username_to_addressbook_entryid(pinfo->get_username());
	if (abk_eid == nullptr)
		return ENOMEM;
	propvals.emplace_back(PR_CREATOR_ENTRYID, abk_eid);

	char id_string[UADDR_SIZE+2];
	auto ret = make_inet_msgid(id_string, std::size(id_string), 0x5a54);
	if (ret != 0)
		return ret;
	propvals.emplace_back(PR_INTERNET_MESSAGE_ID, id_string);

	if (!exmdb_client->set_instance_properties(pmessage->pstore->get_dir(),
	    pmessage->instance_id, &propvals, &problems))
		return EIO;
	pmessage->b_touched = TRUE;
	return 0;
}

ec_error_t message_object::save() try
{
	auto pmessage = this;
	uint32_t result;
	BINARY *pbin_pcl;
	TAGGED_PROPVAL tmp_propval;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (!pmessage->b_new && !pmessage->b_touched)
		return ecSuccess;
	auto dir = pmessage->pstore->get_dir();
	auto pinfo = zs_get_info();
	if (!exmdb_client->allocate_cn(dir, &pmessage->change_num))
		return ecError;
	void *assoc = nullptr;
	if (!exmdb_client_get_instance_property(dir, pmessage->instance_id,
	    PR_ASSOCIATED, &assoc))
		return ecError;
	BOOL b_fai = pvb_disabled(assoc) ? false : TRUE;
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
		const char *u = pinfo->get_username();
		std::string dispname;
		auto v = mysql_adaptor_get_user_displayname(u, dispname) && !dispname.empty() ?
		         common_util_dup(dispname) : common_util_dup(u);
		if (v == nullptr)
			return ecServerOOM;
		tmp_propvals.emplace_back(PR_LAST_MODIFIER_NAME, std::move(v));
	}
	
	auto abk_eid = common_util_username_to_addressbook_entryid(pinfo->get_username());
	if (abk_eid == nullptr)
		return ecError;
	tmp_propvals.emplace_back(PR_LAST_MODIFIER_ENTRYID, abk_eid);

	if (0 != pmessage->message_id) {
		if (!exmdb_client_get_instance_property(dir,
		    pmessage->instance_id, PR_PREDECESSOR_CHANGE_LIST,
		    reinterpret_cast<void **>(&pbin_pcl)))
			return ecError;
		if (!pmessage->b_new && pbin_pcl == nullptr)
			return ecError;

		auto pbin_changekey = cu_xid_to_bin({pmessage->pstore->guid(), pmessage->change_num});
		if (pbin_changekey == nullptr)
			return ecError;
		tmp_propvals.emplace_back(PR_CHANGE_KEY, pbin_changekey);

		pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
		if (pbin_pcl == nullptr)
			return ecError;
		tmp_propvals.emplace_back(PR_PREDECESSOR_CHANGE_LIST, pbin_pcl);
	}
	
	if (!message_object_set_properties_internal(pmessage, false, &tmp_propvals))
		return ecError;
	
	/* change number of embedding message is used for message
		modification's check when the rop_savechangesmessage
		is called, it is useless for ICS!
	*/
	tmp_propval.proptag = PidTagChangeNumber;
	tmp_propval.pvalue = &pmessage->change_num;
	if (!exmdb_client_set_instance_property(dir,
	    pmessage->instance_id, &tmp_propval, &result))
		return ecServerOOM;
	
	ec_error_t e_result = ecError;
	if (!exmdb_client->flush_instance(dir, pmessage->instance_id,
	    &e_result) || e_result != ecSuccess)
		return e_result;

	auto is_new = pmessage->b_new;
	pmessage->b_new = FALSE;
	pmessage->b_touched = FALSE;
	if (0 == pmessage->message_id) {
		pmessage->pembedding->b_touched = TRUE;
		return ecSuccess;
	}
	
	if (NULL != pmessage->pstate) {
		pmessage->pstate->pgiven->append(pmessage->message_id);
		if (!b_fai)
			pmessage->pstate->pseen->append(pmessage->change_num);
		else
			pmessage->pstate->pseen_fai->append(pmessage->change_num);
	}
	
	if (pmessage->message_id == 0 || b_fai) {
		proptag_array_clear(pmessage->pchanged_proptags);
		proptag_array_clear(pmessage->premoved_proptags);
		return ecSuccess;
	}
	if (is_new)
		goto SAVE_FULL_CHANGE;
	if (!exmdb_client->mark_modified(dir, pmessage->message_id))
		return ecError;
 SAVE_FULL_CHANGE:
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	/* trigger the rule evaluation under public mode 
		when the message is first saved to the folder */
	if (is_new && !b_fai && pmessage->message_id != 0 &&
	    !pmessage->pstore->b_private)
		exmdb_client->rule_new_message(dir, pinfo->get_username(),
			pmessage->cpid, pmessage->folder_id, pmessage->message_id);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return ecServerOOM;
}

BOOL message_object::reload()
{
	auto pmessage = this;
	BOOL b_result;
	uint64_t *pchange_num;
	
	if (pmessage->b_new)
		return TRUE;
	if (!exmdb_client->reload_message_instance(pmessage->pstore->get_dir(),
	    pmessage->instance_id, &b_result) || !b_result)
		return FALSE;	
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	pmessage->b_touched = FALSE;
	pmessage->change_num = 0;
	if (pmessage->b_new)
		return TRUE;
	if (!exmdb_client_get_instance_property(pmessage->pstore->get_dir(),
	    pmessage->instance_id, PidTagChangeNumber,
	    reinterpret_cast<void **>(&pchange_num)) ||
	    pchange_num == nullptr)
		return FALSE;
	pmessage->change_num = *pchange_num;
	return TRUE;
}

static constexpr proptag_t trimtags[] = {
	PidTagMid, PR_DISPLAY_TO, PR_DISPLAY_CC,
	PR_DISPLAY_BCC, PR_MESSAGE_SIZE, PR_HASATTACH,
	PR_CHANGE_KEY, PidTagChangeNumber,
	PR_PREDECESSOR_CHANGE_LIST,
};

BOOL message_object::write_message(const MESSAGE_CONTENT *pmsgctnt)
{
	auto pmessage = this;
	PROPTAG_ARRAY proptags;
	MESSAGE_CONTENT msgctnt;
	PROBLEM_ARRAY tmp_problems;
	
	msgctnt = *pmsgctnt;
	msgctnt.proplist.ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count);
	if (msgctnt.proplist.ppropval == nullptr)
		return FALSE;
	memcpy(msgctnt.proplist.ppropval, pmsgctnt->proplist.ppropval,
				sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
	for (auto t : trimtags)
		common_util_remove_propvals(&msgctnt.proplist, t);
	if (!exmdb_client->clear_message_instance(pmessage->pstore->get_dir(),
	    pmessage->instance_id))
		return FALSE;
	if (!exmdb_client->write_message_instance(pmessage->pstore->get_dir(),
	    pmessage->instance_id, &msgctnt, TRUE, &proptags, &tmp_problems))
		return FALSE;	
	proptag_array_clear(pmessage->pchanged_proptags);
	proptag_array_clear(pmessage->premoved_proptags);
	pmessage->b_new = TRUE;
	pmessage->b_touched = TRUE;
	return TRUE;
}

BOOL message_object::read_recipients(uint32_t row_id, uint16_t need_count,
    TARRAY_SET *pset)
{
	auto pmessage = this;
	return exmdb_client->get_message_instance_rcpts(pmessage->pstore->get_dir(),
		pmessage->instance_id, row_id, need_count, pset);
}

BOOL message_object::get_rowid_begin(uint32_t *pbegin_id)
{
	auto pmessage = this;
	int last_rowid;
	TARRAY_SET tmp_set;
	
	if (!exmdb_client->get_message_instance_rcpts(pmessage->pstore->get_dir(),
	    pmessage->instance_id, 0, 0xFFFF, &tmp_set))
		return FALSE;	
	last_rowid = -1;
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto prow_id = tmp_set.pparray[i]->get<int32_t>(PR_ROWID);
		if (prow_id != nullptr && *prow_id > last_rowid)
			last_rowid = *prow_id;
	}
	*pbegin_id = last_rowid + 1;
	return TRUE;
}

BOOL message_object::get_recipient_num(uint16_t *pnum)
{
	auto pmessage = this;
	return exmdb_client->get_message_instance_rcpts_num(pmessage->pstore->get_dir(),
			pmessage->instance_id, pnum);
}

BOOL message_object::empty_rcpts()
{
	auto pmessage = this;
	if (!exmdb_client->empty_message_instance_rcpts(pmessage->pstore->get_dir(),
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
	if (!exmdb_client->update_message_instance_rcpts(pmessage->pstore->get_dir(),
	    pmessage->instance_id, pset))
		return FALSE;	
	pmessage->b_touched = TRUE;
	if (pmessage->b_new || pmessage->message_id == 0)
		return TRUE;
	proptag_array_append(pmessage->pchanged_proptags, PR_MESSAGE_RECIPIENTS);
	return TRUE;
}

BOOL message_object::get_attachments_num(uint16_t *pnum)
{
	auto pmessage = this;
	return exmdb_client->get_message_instance_attachments_num(pmessage->pstore->get_dir(),
	       pmessage->instance_id, pnum);
}

BOOL message_object::delete_attachment(uint32_t attachment_num)
{
	auto pmessage = this;
	if (!exmdb_client->delete_message_instance_attachment(pmessage->pstore->get_dir(),
	    pmessage->instance_id, attachment_num))
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
	return exmdb_client->get_message_instance_attachment_table_all_proptags(
	       pmessage->pstore->get_dir(), pmessage->instance_id, pproptags);
}

bool message_object::query_attachment_table(proptag_cspan pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	auto pmessage = this;
	const PROPTAG_ARRAY pta = {static_cast<uint16_t>(pproptags.size()), deconst(pproptags.data())};
	return exmdb_client->query_message_instance_attachment_table(
	       pmessage->pstore->get_dir(), pmessage->instance_id, &pta,
	       start_pos, row_needed, pset);
}

BOOL message_object::clear_unsent()
{
	auto pmessage = this;
	uint32_t result;
	uint32_t *pmessage_flags;
	TAGGED_PROPVAL tmp_propval;
	
	if (pmessage->message_id == 0)
		return FALSE;
	if (!exmdb_client_get_instance_property(pmessage->pstore->get_dir(),
	    pmessage->instance_id, PR_MESSAGE_FLAGS, reinterpret_cast<void **>(&pmessage_flags)))
		return FALSE;	
	if (pmessage_flags == nullptr)
		return TRUE;
	*pmessage_flags &= ~MSGFLAG_UNSENT;
	tmp_propval.proptag = PR_MESSAGE_FLAGS;
	tmp_propval.pvalue = pmessage_flags;
	return exmdb_client_set_instance_property(pmessage->pstore->get_dir(),
		pmessage->instance_id, &tmp_propval, &result);
}

BOOL message_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pmessage = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client->get_instance_all_proptags(pmessage->pstore->get_dir(),
	    pmessage->instance_id, &tmp_proptags))
		return FALSE;	
	pproptags->count = 0;
	pproptags->pproptag = cu_alloc<proptag_t>(tmp_proptags.count + 15);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < tmp_proptags.count; ++i) {
		const auto tag = tmp_proptags.pproptag[i];
		switch (tag) {
		case PidTagMid:
		case PR_ASSOCIATED:
		case PidTagChangeNumber:
			continue;
		default:
			pproptags->emplace_back(tag);
			break;
		}
	}
	static constexpr proptag_t tags1[] = {
		PR_ACCESS, PR_ENTRYID, PR_ACCESS_LEVEL, PR_OBJECT_TYPE,
		PR_PARENT_ENTRYID, PR_PARENT_SOURCE_KEY, PR_RECORD_KEY,
		PR_STORE_RECORD_KEY, PR_MAPPING_SIGNATURE, PR_STORE_ENTRYID,
		PR_MESSAGE_LOCALE_ID, PR_MESSAGE_CODEPAGE,
	};
	for (auto t : tags1)
		pproptags->emplace_back(t);
	if (pmessage->pembedding == nullptr)
		pproptags->emplace_back(PR_SOURCE_KEY);
	std::sort(pproptags->begin(), pproptags->end());
	pproptags->count = std::unique(pproptags->begin(), pproptags->end()) - pproptags->begin();
	return TRUE;
}

static BOOL msgo_is_readonly_prop(const message_object *pmessage,
   proptag_t proptag)
{ 
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return TRUE;
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
		return TRUE;
	case PR_CHANGE_KEY:
	case PR_CREATION_TIME:
	case PR_LAST_MODIFICATION_TIME:
	case PR_PREDECESSOR_CHANGE_LIST:
	case PR_SOURCE_KEY:
		if (pmessage->b_new)
			return FALSE;
		return TRUE;
	case PR_READ:
		return pmessage->pembedding != nullptr ? TRUE : false;
	}
	return FALSE;
}

static BOOL message_object_get_calculated_property(message_object *pmessage,
    proptag_t proptag, void **ppvalue)
{
	switch (proptag) {
	case PR_ACCESS:
		*ppvalue = &pmessage->tag_access;
		return TRUE;
	case PR_ACCESS_LEVEL:
		*ppvalue = cu_alloc<uint32_t>();
		if (*ppvalue == nullptr)
			return FALSE;
		*static_cast<uint32_t *>(*ppvalue) = pmessage->b_writable ? MAPI_MODIFY : 0;
		return TRUE;
	case PR_ENTRYID:
		if (pmessage->message_id == 0)
			return FALSE;
		*ppvalue = cu_mid_to_entryid(*pmessage->pstore,
						pmessage->folder_id, pmessage->message_id);
		return TRUE;
	case PR_SOURCE_KEY:
		if (pmessage->pembedding != nullptr)
			return false;
		*ppvalue = cu_mid_to_sk(*pmessage->pstore, pmessage->message_id);
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
		*ppvalue = cu_fid_to_entryid(*pmessage->pstore, pmessage->folder_id);
		return TRUE;
	case PidTagFolderId:
	case PidTagParentFolderId:
		if (pmessage->message_id == 0)
			return FALSE;
		*ppvalue = &pmessage->folder_id;
		return TRUE;
	case PR_PARENT_SOURCE_KEY:
		*ppvalue = cu_fid_to_sk(*pmessage->pstore, pmessage->folder_id);
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
		*ppvalue = cu_fid_to_entryid(*pmessage->pstore, pmessage->message_id);
		return TRUE;
	case PR_STORE_RECORD_KEY:
		*ppvalue = common_util_guid_to_binary(pmessage->pstore->mailbox_guid);
		return TRUE;
	case PR_MAPPING_SIGNATURE:
		*ppvalue = common_util_guid_to_binary(pmessage->pstore->mapping_signature);
		return TRUE;
	case PR_STORE_ENTRYID:
		*ppvalue = cu_to_store_entryid(*pmessage->pstore);
		return *ppvalue != nullptr ? TRUE : false;
	}
	return FALSE;
}

bool message_object::get_properties(proptag_cspan pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	auto pmessage = this;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint32_t lcid_default = 0x409; /* en-US */
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags.size());
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<proptag_t>(pproptags.size());
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	ppropvals->count = 0;
	for (const auto tag : pproptags) {
		void *pvalue = nullptr;
		if (!message_object_get_calculated_property(pmessage, tag, &pvalue))
			tmp_proptags.emplace_back(tag);
		else if (pvalue != nullptr)
			ppropvals->emplace_back(tag, pvalue);
		else
			return false;
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	if (!exmdb_client->get_instance_properties(pmessage->pstore->get_dir(),
	    pmessage->cpid, pmessage->instance_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (tmp_propvals.count > 0) {
		memcpy(ppropvals->ppropval +
			ppropvals->count, tmp_propvals.ppropval,
			sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
		ppropvals->count += tmp_propvals.count;
	}
	if (pproptags.has(PR_MESSAGE_LOCALE_ID) &&
	    !ppropvals->has(PR_MESSAGE_LOCALE_ID))
		ppropvals->emplace_back(PR_MESSAGE_LOCALE_ID, &lcid_default);
	if (pproptags.has(PR_MESSAGE_CODEPAGE) &&
	    !ppropvals->has(PR_MESSAGE_CODEPAGE))
		ppropvals->emplace_back(PR_MESSAGE_CODEPAGE, &pmessage->cpid);
	return TRUE;	
}

static BOOL message_object_set_properties_internal(message_object *pmessage,
    BOOL b_check, const TPROPVAL_ARRAY *ppropvals) try
{
	uint8_t tmp_bytes[3];
	PROBLEM_ARRAY problems;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	TPROPVAL_ARRAY tmp_propvals1;
	TAGGED_PROPVAL propval_buff[3];
	
	if (!pmessage->b_writable)
		return FALSE;
	problems.count = 0;
	problems.pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (problems.pproblem == nullptr)
		return FALSE;
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
	if (tmp_propvals.ppropval == nullptr)
		return FALSE;
	std::vector<uint16_t> poriginal_indices;
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		const auto &pv = ppropvals->ppropval[i];
		if (b_check) {
			if (msgo_is_readonly_prop(pmessage, pv.proptag)) {
				problems.pproblem[problems.count++].index = i;
				continue;
			} else if (pv.proptag == PR_EXTENDED_RULE_MSG_CONDITION) {
				void *pvalue = nullptr;
				if (!exmdb_client_get_instance_property(pmessage->pstore->get_dir(),
				    pmessage->instance_id, PR_ASSOCIATED, &pvalue))
					return FALSE;	
				if (pvb_disabled(pvalue)) {
					problems.pproblem[problems.count++].index = i;
					continue;
				}
				if (static_cast<BINARY *>(pv.pvalue)->cb > g_max_extrule_len) {
					problems.pproblem[problems.count++].index = i;
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
				if (!exmdb_client->set_instance_properties(pmessage->pstore->get_dir(),
				    pmessage->instance_id, &tmp_propvals1, &tmp_problems))
					return FALSE;	
			}
		}
		tmp_propvals.ppropval[tmp_propvals.count++] = pv;
		poriginal_indices.push_back(i);
	}
	if (tmp_propvals.count == 0)
		return TRUE;
	if (!exmdb_client->set_instance_properties(pmessage->pstore->get_dir(),
	    pmessage->instance_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count > 0) {
		tmp_problems.transform(poriginal_indices);
		problems += std::move(tmp_problems);
	}
	if (pmessage->b_new || pmessage->message_id == 0)
		return TRUE;
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		if (problems.have_index(i))
			continue;
		pmessage->b_touched = TRUE;
		const auto proptag = ppropvals->ppropval[i].proptag;
		proptag_array_remove(
			pmessage->premoved_proptags, proptag);
		if (!proptag_array_append(pmessage->pchanged_proptags, proptag))
			return FALSE;	
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

BOOL message_object::set_properties(TPROPVAL_ARRAY *ppropvals)
{
	auto pmessage = this;
	return message_object_set_properties_internal(
						pmessage, TRUE, ppropvals);
}

bool message_object::remove_properties(proptag_cspan pproptags) try
{
	auto pmessage = this;
	PROBLEM_ARRAY problems;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!pmessage->b_writable)
		return FALSE;
	problems.count = 0;
	problems.pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags.size());
	if (problems.pproblem == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<proptag_t>(pproptags.size());
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	std::vector<uint16_t> poriginal_indices;
	for (unsigned int i = 0; i < pproptags.size(); ++i) {
		const auto tag = pproptags[i];
		if (msgo_is_readonly_prop(pmessage, tag)) {
			problems.pproblem[problems.count++].index = i;
			continue;
		}
		tmp_proptags.emplace_back(tag);
		poriginal_indices.push_back(i);
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	if (!exmdb_client->remove_instance_properties(pmessage->pstore->get_dir(),
	    pmessage->instance_id, &tmp_proptags, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count > 0) {
		tmp_problems.transform(poriginal_indices);
		problems += std::move(tmp_problems);
	}
	if (pmessage->b_new || pmessage->message_id == 0)
		return TRUE;
	for (unsigned int i = 0; i < pproptags.size(); ++i) {
		if (problems.have_index(i))
			continue;
		pmessage->b_touched = TRUE;
		const auto proptag = pproptags[i];
		proptag_array_remove(
			pmessage->pchanged_proptags, proptag);
		if (!proptag_array_append(pmessage->premoved_proptags, proptag))
			return FALSE;	
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

bool message_object::copy_to(message_object *pmessage_src,
    proptag_cspan pexcluded_proptags, BOOL b_force, BOOL *pb_cycle)
{
	auto pmessage = this;
	PROPTAG_ARRAY proptags;
	MESSAGE_CONTENT msgctnt;
	PROBLEM_ARRAY tmp_problems;
	
	*pb_cycle = false;
	if (strcmp(pstore->get_dir(), pmessage_src->pstore->get_dir()) == 0 &&
	    !exmdb_client->is_descendant_instance(pmessage->pstore->get_dir(),
	    pmessage_src->instance_id, pmessage->instance_id, pb_cycle))
		return FALSE;	
	if (*pb_cycle)
		return TRUE;
	if (!exmdb_client->read_message_instance(pmessage_src->pstore->get_dir(),
	    pmessage_src->instance_id, &msgctnt))
		return FALSE;
	for (auto t : trimtags)
		common_util_remove_propvals(&msgctnt.proplist, t);
	for (unsigned int i = 0; i < msgctnt.proplist.count; ) {
		if (pexcluded_proptags.has(msgctnt.proplist.ppropval[i].proptag)) {
			common_util_remove_propvals(&msgctnt.proplist,
					msgctnt.proplist.ppropval[i].proptag);
			continue;
		}
		i ++;
	}
	if (pexcluded_proptags.has(PR_MESSAGE_RECIPIENTS))
		msgctnt.children.prcpts = NULL;
	if (pexcluded_proptags.has(PR_MESSAGE_ATTACHMENTS))
		msgctnt.children.pattachments = NULL;
	if (!exmdb_client->write_message_instance(pmessage->pstore->get_dir(),
	    pmessage->instance_id, &msgctnt, b_force, &proptags, &tmp_problems))
		return FALSE;	
	if (pmessage->b_new || pmessage->message_id == 0)
		return TRUE;
	for (unsigned int i = 0; i < proptags.count; ++i)
		proptag_array_append(pmessage->pchanged_proptags,
			proptags.pproptag[i]);
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
	static const uint8_t fake_false = false;
	TAGGED_PROPVAL propval_buff[2];
	
	read_flag &= ~rfReserved;
	const char *username = nullptr;
	if (!pmessage->pstore->b_private) {
		auto pinfo = zs_get_info();
		username = pinfo->get_username();
	}
	b_notify = FALSE;
	*pb_changed = FALSE;
	auto dir = pmessage->pstore->get_dir();
	switch (read_flag) {
	case rfDefault:
	case rfSuppressReceipt:
		if (!exmdb_client_get_instance_property(dir,
		    pmessage->instance_id, PR_READ, &pvalue))
			return FALSE;	
		if (pvb_enabled(pvalue))
			break;
		tmp_byte = 1;
		*pb_changed = TRUE;
		if (read_flag != rfDefault)
			break;
		if (!exmdb_client_get_instance_property(dir,
		    pmessage->instance_id,
		    PR_READ_RECEIPT_REQUESTED, &pvalue))
			return FALSE;
		if (pvb_enabled(pvalue))
			b_notify = TRUE;
		break;
	case rfClearReadFlag:
	case rfClearReadFlag | rfSuppressReceipt:
		if (!exmdb_client_get_instance_property(dir,
		    pmessage->instance_id, PR_READ, &pvalue))
			return FALSE;
		if (!pvb_enabled(pvalue))
			break;
		tmp_byte = 0;
		*pb_changed = TRUE;
		break;
	case rfGenerateReceiptOnly:
		if (!exmdb_client_get_instance_property(dir,
		    pmessage->instance_id, PR_READ_RECEIPT_REQUESTED,
		    &pvalue))
			return FALSE;
		if (pvb_enabled(pvalue))
			b_notify = TRUE;
		break;
	case rfClearNotifyRead:
	case rfClearNotifyUnread:
	case rfClearNotifyRead | rfClearNotifyUnread: {
		if (read_flag & rfClearNotifyRead) {
			if (!exmdb_client_remove_instance_property(dir,
			    pmessage->instance_id, PR_READ_RECEIPT_REQUESTED,
			    &result))
				return FALSE;	
			if (exmdb_client_get_message_property(dir, username, CP_ACP,
			    pmessage->message_id, PR_READ_RECEIPT_REQUESTED,
			    &pvalue) && pvb_enabled(pvalue) &&
			    !exmdb_client_remove_message_property(dir,
			    pmessage->cpid, pmessage->message_id,
			    PR_READ_RECEIPT_REQUESTED))
				return FALSE;
		}
		if (read_flag & rfClearNotifyUnread) {
			if (!exmdb_client_remove_instance_property(dir,
			    pmessage->instance_id, PR_NON_RECEIPT_NOTIFICATION_REQUESTED,
			    &result))
				return FALSE;	
			if (exmdb_client_get_message_property(dir, username, CP_ACP,
			    pmessage->message_id, PR_NON_RECEIPT_NOTIFICATION_REQUESTED,
			    &pvalue) && pvb_enabled(pvalue) &&
			    !exmdb_client_remove_message_property(dir,
			    pmessage->cpid, pmessage->message_id,
			    PR_NON_RECEIPT_NOTIFICATION_REQUESTED))
				return FALSE;
		}
		if (!exmdb_client_get_instance_property(dir,
		    pmessage->instance_id, PR_MESSAGE_FLAGS,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		auto v = static_cast<uint32_t *>(pvalue);
		if (!(*v & MSGFLAG_UNMODIFIED))
			return TRUE;
		*v &= ~MSGFLAG_UNMODIFIED;
		propval.proptag = PR_MESSAGE_FLAGS;
		propval.pvalue = v;
		if (!exmdb_client_set_instance_property(dir,
		    pmessage->instance_id, &propval, &result))
			return FALSE;
		if (!exmdb_client->mark_modified(dir, pmessage->message_id))
			return FALSE;
		return TRUE;
	}
	default:
		return TRUE;
	}
	if (*pb_changed) {
		if (!exmdb_client->set_message_read_state(dir, username,
		    pmessage->message_id, tmp_byte, &read_cn))
			return FALSE;
		propval.proptag = PR_READ;
		propval.pvalue = &tmp_byte;
		if (!exmdb_client_set_instance_property(dir,
		    pmessage->instance_id, &propval, &result))
			return FALSE;	
		if (result != 0)
			return TRUE;
	}
	if (b_notify) {
		if (!exmdb_client->get_message_brief(dir, pmessage->cpid,
		    pmessage->message_id, &pbrief))
			return FALSE;	
		if (pbrief != nullptr)
			common_util_notify_receipt(pmessage->pstore->get_account(),
				NOTIFY_RECEIPT_READ, pbrief);
		propvals.count = 2;
		propvals.ppropval = propval_buff;
		propval_buff[0].proptag = PR_READ_RECEIPT_REQUESTED;
		propval_buff[0].pvalue = deconst(&fake_false);
		propval_buff[1].proptag = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
		propval_buff[1].pvalue = deconst(&fake_false);
		exmdb_client->set_instance_properties(dir,
			pmessage->instance_id, &propvals, &problems);
		exmdb_client->set_message_properties(dir, username,
			CP_ACP, pmessage->message_id, &propvals, &problems);
	}
	return TRUE;
}
