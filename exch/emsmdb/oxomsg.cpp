// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"
#include "logon_object.hpp"
#include "message_object.hpp"
#include "rop_funcs.hpp"
#include "rop_processor.hpp"

using namespace std::string_literals;
using namespace gromox;

enum { /* for RopSubmitMessage */
	ROP_SUBMIT_FLAG_PREPROCESS = 0x1U,
	ROP_SUBMIT_FLAG_NEEDS_SPOOLER = 0x2U,
};

enum { /* for PR_SUBMIT_FLAGS (unused in Gromox) */
	SUBMITFLAG_LOCKED = 0x1U,
	SUBMITFLAG_PREPROCESS = 0x2U,
};

enum class repr_grant {
	error = -1, no_impersonation, send_on_behalf, send_as,
};

/**
 * @send_as:	if true, copy PR_SENT_REPR to PR_SENDER
 * 		if false, leave PR_SENT_REPR at its value
 *
 * Re-lookup PR_SENT_REP and PR_SENDER and fill in ADDRTYPE, EMAIL_ADDRESS,
 * SMTP_ADDRESS, etc.
 */
static ec_error_t oxomsg_rectify_message(message_object *pmessage,
    const char *representing_username, bool send_as) try
{
	uint64_t nt_time;
	uint8_t tmp_byte;
	int32_t tmp_level;
	BINARY sender_srch, repr_srch;
	std::string sender_essdn, sender_dispname, repr_essdn, repr_dispname;
	repr_dispname.resize(256);
	PROBLEM_ARRAY tmp_problems;
	
	auto account = pmessage->plogon->get_account();
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	tmp_byte = 1;
	nt_time = rop_util_current_nttime();
	tmp_level = -1;
	if (cvt_username_to_essdn(account, g_emsmdb_org_name,
	    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
	    sender_essdn) != ecSuccess)
		return ecRpcFailed;
	if (!mysql_adaptor_get_user_displayname(account, sender_dispname))
		return ecRpcFailed;
	HX_strupper(sender_essdn.data());
	auto sender_eid = common_util_username_to_addressbook_entryid(account);
	if (sender_eid == nullptr)
		return ecRpcFailed;
	auto repr_eid = sender_eid;
	const std::string sender_skb = "EX:" + sender_essdn;
	sender_srch.cb = sender_skb.size() + 1;
	sender_srch.pv = deconst(sender_skb.c_str());
	bool oneoff_repr = false;
	if (strcasecmp(account, representing_username) == 0) {
		repr_essdn = sender_essdn;
		repr_dispname = sender_dispname;
	} else if (cvt_username_to_essdn(representing_username,
	    g_emsmdb_org_name, mysql_adaptor_get_user_ids,
	    mysql_adaptor_get_domain_ids, repr_essdn) == ecSuccess) {
		if (!mysql_adaptor_get_user_displayname(representing_username, repr_dispname))
			return ecRpcFailed;
		HX_strupper(repr_essdn.data());
		repr_eid = common_util_username_to_addressbook_entryid(representing_username);
		if (repr_eid == nullptr)
			return ecRpcFailed;
	} else {
		repr_essdn = repr_dispname = representing_username;
		repr_eid = cu_username_to_oneoff(representing_username, representing_username);
		if (repr_eid == nullptr)
			return ecServerOOM;
		oneoff_repr = true;
	}
	const std::string repr_skb = oneoff_repr ? ("SMTP:"s + representing_username) :
	                             ("EX:" + repr_essdn);
	repr_srch.cb = repr_skb.size() + 1;
	repr_srch.pv = deconst(repr_skb.c_str());
	char msgid[UADDR_SIZE+2];
	make_inet_msgid(msgid, std::size(msgid), 0x4553);
	TAGGED_PROPVAL pv[] = {
		{PR_READ, &tmp_byte},
		{PR_CLIENT_SUBMIT_TIME, &nt_time},
		{PR_CONTENT_FILTER_SCL, &tmp_level},
		{PR_MESSAGE_LOCALE_ID, &pinfo->lcid_string},
		{PR_SENDER_SMTP_ADDRESS, deconst(send_as ? representing_username : account)},
		{PR_SENDER_ADDRTYPE, deconst("EX")},
		{PR_SENDER_EMAIL_ADDRESS, deconst(send_as ? repr_essdn.c_str() : sender_essdn.c_str())},
		{PR_SENDER_NAME, deconst(send_as ? repr_dispname.c_str() : sender_dispname.c_str())},
		{PR_SENDER_ENTRYID, send_as ? repr_eid : sender_eid},
		{PR_SENDER_SEARCH_KEY, send_as ? &repr_srch : &sender_srch},
		{PR_SENT_REPRESENTING_SMTP_ADDRESS, deconst(representing_username)},
		{PR_SENT_REPRESENTING_ADDRTYPE, deconst(oneoff_repr ? "SMTP" : "EX")},
		{PR_SENT_REPRESENTING_EMAIL_ADDRESS, deconst(repr_essdn.c_str())},
		{PR_SENT_REPRESENTING_NAME, deconst(repr_dispname.c_str())},
		{PR_SENT_REPRESENTING_ENTRYID, repr_eid},
		{PR_SENT_REPRESENTING_SEARCH_KEY, &repr_srch},
		{PR_INTERNET_MESSAGE_ID, msgid},
	};
	TPROPVAL_ARRAY tmp_propvals = {std::size(pv), pv};
	if (!pmessage->set_properties(&tmp_propvals, &tmp_problems))
		return ecRpcFailed;
	return pmessage->save();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1166: ENOMEM");
	return ecRpcFailed;
}

/**
 * Returns:
 * - %true and @username is empty: no delegation was requested
 * - %true and @username is set: delegation with given identity;
 *   identity guaranteed to exist; caller still needs to perform a
 *   permission check.
 * - %false: unable to contact server,
 *   or requested identity not present in the system
 */
static bool oxomsg_extract_delegate(message_object *pmessage,
    std::string &username)
{
	static constexpr proptag_t proptag_buff[] =
		{PR_SENT_REPRESENTING_ADDRTYPE, PR_SENT_REPRESENTING_EMAIL_ADDRESS,
		PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_SENT_REPRESENTING_ENTRYID};
	static constexpr PROPTAG_ARRAY tmp_proptags =
		{std::size(proptag_buff), deconst(proptag_buff)};
	TPROPVAL_ARRAY tmp_propvals;
	
	if (!pmessage->get_properties(0, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (0 == tmp_propvals.count) {
		username.clear();
		return TRUE;
	}
	auto addrtype = tmp_propvals.get<const char>(PR_SENT_REPRESENTING_ADDRTYPE);
	auto emaddr   = tmp_propvals.get<const char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	if (addrtype != nullptr) {
		auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr,
		           g_emsmdb_org_name, mysql_adaptor_userid_to_name, username);
		if (ret == ecSuccess)
			return true;
		else if (ret != ecNullObject)
			return false;
	}
	auto str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr && *str != '\0') {
		username = str;
		return TRUE;
	}
	auto ret = cvt_entryid_to_smtpaddr(tmp_propvals.get<const BINARY>(PR_SENT_REPRESENTING_ENTRYID),
	           g_emsmdb_org_name, mysql_adaptor_userid_to_name, username);
	if (ret == ecSuccess)
		return TRUE;
	if (ret == ecNullObject) {
		username.clear();
		return TRUE;
	}
	mlog(LV_WARN, "W-1643: rejecting submission of msgid %llxh because "
		"its PR_SENT_REPRESENTING_ENTRYID does not reference "
		"a user in the local system",
		static_cast<unsigned long long>(pmessage->message_id));
	return false;
}

/**
 * @send_as:	whether to evaluate either the Send-As or Send-On-Behalf list
 */
static int oxomsg_test_perm(const char *account, const char *maildir, bool send_as) try
{
	auto dlg_path = maildir + std::string(send_as ? "/config/sendas.txt" : "/config/delegates.txt");
	std::vector<std::string> delegate_list;
	auto ret = read_file_by_line(dlg_path.c_str(), delegate_list);
	if (ret != 0 && ret != ENOENT) {
		mlog(LV_ERR, "E-2064: %s: %s", dlg_path.c_str(), strerror(ret));
		return ret;
	}
	for (const auto &deleg : delegate_list)
		if (strcasecmp(deleg.c_str(), account) == 0 ||
		    mysql_adaptor_check_mlist_include(deleg.c_str(), account))
			return 1;
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1500: ENOMEM");
	return false;
}

/**
 * @account:	"secretary account"
 * @repr:	"boss account"
 */
static repr_grant oxomsg_get_perm(const char *account, const char *repr)
{
	if (strcasecmp(account, repr) == 0)
		return repr_grant::send_as;
	sql_meta_result mres;
	if (mysql_adaptor_meta(repr, WANTPRIV_METAONLY, mres) != 0)
		return repr_grant::error;
	auto repdir = mres.maildir.c_str();
	auto ret = oxomsg_test_perm(account, repdir, true);
	if (ret < 0)
		return repr_grant::error;
	if (ret > 0)
		return repr_grant::send_as;
	ret = oxomsg_test_perm(account, repdir, false);
	if (ret < 0)
		return repr_grant::error;
	if (ret > 0)
		return repr_grant::send_on_behalf;
	return repr_grant::no_impersonation;
}

static ec_error_t pass_scheduling(const char *code, const char *account,
    const char *username, message_object &msg, const char *cls)
{
	/*
	 * IPM.Schedule messages are special; PR_SENT_REPRESENTING contains the
	 * organizer, not the delegator. So there is no delegation to
	 * check/reject. oxcmail_export also checks message class again. (The
	 * organizer may also be in the recipient list, or in
	 * PidLidAppointmentUnsendableRecipients.)
	 */
	if (class_match_prefix(cls, "IPM.Schedule") == 0)
		return ecSuccess;
	mlog(LV_ERR, "%s: %s tried to send message %llxh (class %s) with repr/from=<%s>, "
		"but user has no delegate/sendas permission.",
		code, account, static_cast<unsigned long long>(msg.get_id()),
		znul(cls), username);
	return ecAccessDenied;
}

ec_error_t rop_submitmessage(uint8_t submit_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin) try
{
	int timer_id;
	BOOL b_marked;
	ems_objtype object_type;
	uint16_t rcpt_num;
	char command_buff[1024];
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return ecError;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private())
		return ecNotSupported;
	if (plogon->logon_mode == logon_mode::guest) {
		mlog(LV_INFO, "I-2145: submitmessage denied because %s is guest", plogon->account);
		return ecAccessDenied;
	}

	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::message)
		return ecNotSupported;
	if (pmessage->get_id() == 0)
		return ecNotSupported;
	if (pmessage->importing()) {
		mlog(LV_INFO, "I-2146: submitmessage denied because "
		        "message %llxh is under construction",
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}
	auto tag_access = pmessage->get_tag_access();
	if (!(tag_access & MAPI_ACCESS_MODIFY)) {
		mlog(LV_INFO, "I-2147: submitmessage denied because "
		        "%s has no MAPI_ACCESS_MODIFY on message %llxh",
		        plogon->account,
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}
	if (!pmessage->get_recipient_num(&rcpt_num))
		return ecError;
	if (rcpt_num > g_max_rcpt)
		return ecTooManyRecips;

	static constexpr proptag_t ptbuf_one[] = {PR_ASSOCIATED, PR_MESSAGE_CLASS};
	static constexpr PROPTAG_ARRAY ptags_one = {std::size(ptbuf_one), deconst(ptbuf_one)};
	if (!pmessage->get_properties(0, &ptags_one, &tmp_propvals))
		return ecError;
	auto flag = tmp_propvals.get<const uint8_t>(PR_ASSOCIATED);
	/* FAI message cannot be sent */
	if (flag != nullptr && *flag != 0) {
		mlog(LV_INFO, "I-2160: submitmessage denied because "
		        "message %llxh is FAI",
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}
	std::string username;
	if (!oxomsg_extract_delegate(pmessage, username))
		return ecError;
	auto account = plogon->get_account();
	repr_grant repr_grant;
	if (username.empty()) {
		/* "No impersonation requested" is modeled as {impersonate yourself}. */
		username = account;
		repr_grant = repr_grant::send_as;
	} else {
		repr_grant = oxomsg_get_perm(account, username.c_str());
	}
	if (repr_grant < repr_grant::send_on_behalf) {
		auto ret = pass_scheduling("E-2081", account, username.c_str(), *pmessage,
		           tmp_propvals.get<const char>(PR_MESSAGE_CLASS));
		if (ret != ecSuccess)
			return ret;
	}
	auto ret = oxomsg_rectify_message(pmessage, username.c_str(),
	           repr_grant >= repr_grant::send_as);
	if (ret != ecSuccess)
		return ret;
	
	static constexpr proptag_t ptbuf_two[] =
		{PR_MAX_SUBMIT_MESSAGE_SIZE, PR_PROHIBIT_SEND_QUOTA, PR_MESSAGE_SIZE_EXTENDED};
	static constexpr PROPTAG_ARRAY ptags_two =
		{std::size(ptbuf_two), deconst(ptbuf_two)};
	if (!plogon->get_properties(&ptags_two, &tmp_propvals))
		return ecError;

	auto sendquota = tmp_propvals.get<uint32_t>(PR_PROHIBIT_SEND_QUOTA);
	auto storesize = tmp_propvals.get<uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	/* Sendquota is in KiB, storesize in bytes */
	if (sendquota != nullptr && storesize != nullptr &&
	    static_cast<uint64_t>(*sendquota) * 1024 <= *storesize)
		return ecQuotaExceeded;

	auto num = tmp_propvals.get<const uint32_t>(PR_MAX_SUBMIT_MESSAGE_SIZE);
	uint64_t max_length = UINT64_MAX;
	if (num != nullptr)
		max_length = static_cast<uint64_t>(*num) << 10;
	static constexpr proptag_t ptbuf_three[] =
		{PR_MESSAGE_SIZE, PR_MESSAGE_FLAGS,
		PR_DEFERRED_SEND_TIME, PR_DEFERRED_SEND_NUMBER,
		PR_DEFERRED_SEND_UNITS, PR_DELETE_AFTER_SUBMIT};
	PROPTAG_ARRAY tmp_proptags;
	tmp_proptags.count = (submit_flags & ROP_SUBMIT_FLAG_NEEDS_SPOOLER) ?
	                     2 : std::size(ptbuf_three);
	tmp_proptags.pproptag = deconst(ptbuf_three);
	if (!pmessage->get_properties(0, &tmp_proptags, &tmp_propvals))
		return ecError;
	num = tmp_propvals.get<const uint32_t>(PR_MESSAGE_SIZE);
	if (num == nullptr)
		return ecError;
	if (max_length != UINT64_MAX && *num > max_length)
		return EC_EXCEEDED_SIZE;
	auto message_flags = tmp_propvals.get<uint32_t>(PR_MESSAGE_FLAGS);
	if (message_flags == nullptr)
		return ecError;
	if (*message_flags & MSGFLAG_SUBMITTED) {
		mlog(LV_INFO, "I-2148: submitmessage denied because "
		        "message %llxh is already submitted",
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}
	BOOL b_unsent = (*message_flags & MSGFLAG_UNSENT) ? TRUE : false;
	flag = tmp_propvals.get<uint8_t>(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = flag != nullptr && *flag != 0 ? TRUE : false;
	/* we don't use spool queue, so disable the whole functionality */
	auto dir = plogon->get_dir();
#if 0
	/* check if it is already in spooler queue */
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (!exmdb_client->is_msg_present(dir, fid_spooler,
	    pmessage->get_id(), &b_exist))
		return ecError;
	if (b_exist)
		return ecAccessDenied;
	if (submit_flags & ROP_SUBMIT_FLAG_NEEDS_SPOOLER) {
		if (!exmdb_client->link_message(dir, pinfo->cpid,
		    fid_spooler, pmessage->get_id(), &b_result) || !b_result)
			return ecError;
		return ecSuccess;
	}
#endif
	
	if (!exmdb_client->try_mark_submit(dir, pmessage->get_id(), &b_marked))
		return ecError;
	if (!b_marked) {
		mlog(LV_INFO, "I-2149: submitmessage denied because "
		        "message %llxh failed try_mark_submit",
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}
	
	auto deferred_time = props_to_defer_interval(tmp_propvals);
	if (deferred_time > 0) {
		snprintf(command_buff, 1024, "%s %s %llu",
		         common_util_get_submit_command(),
		         plogon->get_account(),
		         static_cast<unsigned long long>(rop_util_get_gc_value(pmessage->get_id())));
		timer_id = common_util_add_timer(
			command_buff, deferred_time);
		if (0 == timer_id) {
			exmdb_client->clear_submit(dir, pmessage->get_id(), b_unsent);
			return ecError;
		}
		exmdb_client->set_message_timer(dir, pmessage->get_id(), timer_id);
		pmessage->reload();
		return ecSuccess;
	}
	
	ret = cu_send_message(plogon, pmessage, true);
	if (ret != ecSuccess && ret != ecWarnWithErrors)
		exmdb_client->clear_submit(dir, pmessage->get_id(), b_unsent);
	else if (!b_delete)
		pmessage->reload();
	else
		pmessage->clear_unsent();
	return ret;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2353: ENOMEM");
	return ecServerOOM;
}

ec_error_t rop_abortsubmit(uint64_t folder_id, uint64_t message_id,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_exist;
	uint32_t *ptimer_id;
	uint64_t fid_spooler;
	uint32_t *pmessage_flags;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return ecError;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private())
		return ecNotSupported;
	if (plogon->logon_mode == logon_mode::guest)
		return ecAccessDenied;
	if (!exmdb_client->is_msg_present(plogon->get_dir(), folder_id,
	    message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotFound;
	if (!exmdb_client->get_message_property(plogon->get_dir(),
	    nullptr, CP_ACP, message_id, PR_MESSAGE_FLAGS,
	    reinterpret_cast<void **>(&pmessage_flags)))
		return ecError;
	if (pmessage_flags == nullptr)
		return ecError;
	if (*pmessage_flags & MSGFLAG_SUBMITTED) {
		if (!exmdb_client->get_message_timer(plogon->get_dir(),
		    message_id, &ptimer_id))
			return ecError;
		if (ptimer_id != nullptr && !common_util_cancel_timer(*ptimer_id))
			return ecUnableToAbort;
		if (!exmdb_client->clear_submit(plogon->get_dir(), message_id, TRUE))
			return ecError;
		if (!common_util_save_message_ics(plogon, message_id, nullptr))
			return ecError;
		return ecSuccess;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (!exmdb_client->is_msg_present(plogon->get_dir(), fid_spooler,
	    message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotInQueue;
	/* unlink the message in spooler queue */
	if (!exmdb_client->unlink_message(plogon->get_dir(), pinfo->cpid,
	    fid_spooler, message_id))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_getaddresstypes(STRING_ARRAY *paddress_types, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	static constexpr const char *address_types[] = {"SMTP", "EX"};
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private())
		return ecNotSupported;
	paddress_types->count = 2;
	paddress_types->ppstr = const_cast<char **>(address_types);
	return ecSuccess;
}

ec_error_t rop_setspooler(LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	return plogon->is_private() ? ecSuccess : ecNotSupported;
}

ec_error_t rop_spoolerlockmessage(uint64_t message_id, uint8_t lock_stat,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_exist;
	BOOL b_result;
	uint64_t new_id;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t fid_spooler;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return ecError;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private())
		return ecNotSupported;
	if (plogon->logon_mode == logon_mode::guest)
		return ecAccessDenied;
	if (lock_stat != LOCK_STAT_1STFINISHED)
		return ecSuccess;
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	auto dir = plogon->get_dir();
	if (!exmdb_client->is_msg_present(dir, fid_spooler, message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotInQueue;
	/* unlink the message in spooler queue */
	if (!exmdb_client->unlink_message(dir, pinfo->cpid,
	    fid_spooler, message_id))
		return ecError;

	static constexpr proptag_t proptag_buff[] =
		{PR_DELETE_AFTER_SUBMIT, PR_TARGET_ENTRYID, PR_PARENT_ENTRYID};
	static constexpr PROPTAG_ARRAY tmp_proptags =
		{std::size(proptag_buff), deconst(proptag_buff)};
	if (!exmdb_client->get_message_properties(dir, nullptr, CP_ACP,
	    message_id, &tmp_proptags, &tmp_propvals))
		return ecError;
	auto flag = tmp_propvals.get<const uint8_t>(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = flag != nullptr && *flag != 0 ? TRUE : false;
	auto ptarget = tmp_propvals.get<const BINARY>(PR_TARGET_ENTRYID);
	auto bin = tmp_propvals.get<const BINARY>(PR_PARENT_ENTRYID);
	if (bin == nullptr)
		return ecError;
	if (!cu_entryid_to_fid(*plogon, bin, &parent_id))
		return ecError;
	if (NULL != ptarget) {
		if (!cu_entryid_to_mid(*plogon, ptarget, &folder_id, &new_id))
			return ecError;
		if (!exmdb_client->movecopy_message(dir, pinfo->cpid,
		    message_id, folder_id, new_id, b_delete, &b_result))
			return ecError;
	} else if (b_delete) {
		exmdb_client->delete_message(dir,
			plogon->account_id, pinfo->cpid,
			parent_id, message_id, TRUE, &b_result);
	}
	return ecSuccess;
}

ec_error_t rop_transportsend(TPROPVAL_ARRAY **pppropvals, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin) try
{
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private())
		return ecNotSupported;
	if (plogon->logon_mode == logon_mode::guest) {
		mlog(LV_INFO, "I-2143: transportsend disallowed because %s is guest", plogon->account);
		return ecAccessDenied;
	}
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::message)
		return ecNotSupported;
	if (pmessage->get_id() == 0)
		return ecNotSupported;
	if (pmessage->importing()) {
		mlog(LV_INFO, "I-2144: transportsend disallowed because "
		        "message %llxh is under construction",
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}

	static constexpr uint32_t rq_tags1[] = {PR_MESSAGE_FLAGS};
	static constexpr uint32_t cls_tags1[] = {PR_MESSAGE_CLASS};
	static constexpr PROPTAG_ARRAY rq_tags = {1, deconst(rq_tags1)};
	static constexpr PROPTAG_ARRAY cls_tags = {1, deconst(cls_tags1)};
	TPROPVAL_ARRAY outvalues{};
	if (!exmdb_client->get_message_properties(plogon->get_dir(), nullptr,
	    CP_ACP, pmessage->get_id(), &rq_tags, &outvalues))
		return ecError;
	auto msgflags = outvalues.get<const uint32_t>(PR_MESSAGE_FLAGS);
	if (msgflags != nullptr && *msgflags & MSGFLAG_SUBMITTED) {
		mlog(LV_INFO, "I-2068: transportsend disallowed because "
		        "message %llxh was already submitted once",
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}
	std::string username;
	if (!oxomsg_extract_delegate(pmessage, username))
		return ecError;
	auto account = plogon->get_account();
	repr_grant repr_grant;
	if (username.empty()) {
		username = account;
		repr_grant = repr_grant::send_as;
	} else {
		repr_grant = oxomsg_get_perm(account, username.c_str());
	}
	if (repr_grant < repr_grant::send_on_behalf) {
		TPROPVAL_ARRAY cls_vals{};
		if (pmessage->get_properties(0, &cls_tags, &cls_vals) != 0)
			/* ignore, since we can test for cls_vals fill */;
		auto ret = pass_scheduling("E-2080", account, username.c_str(), *pmessage,
		           cls_vals.get<const char>(PR_MESSAGE_CLASS));
		if (ret != ecSuccess)
			return ret;
	}
	auto ret = oxomsg_rectify_message(pmessage, username.c_str(),
	           repr_grant >= repr_grant::send_as);
	if (ret != ecSuccess)
		return ret;
	*pppropvals = cu_alloc<TPROPVAL_ARRAY>();
	if (NULL != *pppropvals) {
		static constexpr proptag_t proptag_buff[] =
			{PR_SENDER_NAME, PR_SENDER_ENTRYID, PR_SENDER_SEARCH_KEY,
			PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_ENTRYID,
			PR_SENT_REPRESENTING_SEARCH_KEY, PR_PROVIDER_SUBMIT_TIME};
		static constexpr PROPTAG_ARRAY proptags =
			{std::size(proptag_buff), deconst(proptag_buff)};
		if (!pmessage->get_properties(0, &proptags, *pppropvals)) {
			*pppropvals = NULL;
		} else if (!(**pppropvals).has(PR_PROVIDER_SUBMIT_TIME)) {
			auto nt = cu_alloc<uint64_t>();
			if (nt != nullptr) {
				*nt = rop_util_current_nttime();
				auto err = cu_set_propval(*pppropvals, PR_PROVIDER_SUBMIT_TIME, nt);
				if (err != ecSuccess)
					return err;
			}
		}
	}
	return cu_send_message(plogon, pmessage, false);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2352: ENOMEM");
	return ecServerOOM;
}

ec_error_t rop_transportnewmail(uint64_t message_id, uint64_t folder_id,
    const char *pstr_class, uint32_t message_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!exmdb_client->transport_new_mail(plogon->get_dir(), message_id,
	    folder_id, message_flags, pstr_class))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_gettransportfolder(uint64_t *pfolder_id, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecNullObject;
	if (!plogon->is_private())
		return ecNotSupported;
	*pfolder_id = rop_util_make_eid_ex(1, PRIVATE_FID_OUTBOX);
	return ecSuccess;
}

ec_error_t rop_optionsdata(const char *paddress_type, uint8_t want_win32,
    uint8_t *preserved, BINARY *poptions_info, BINARY *phelp_file,
    char **ppfile_name, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	*preserved = 1;
	poptions_info->cb = 300;
	poptions_info->pv = common_util_alloc(poptions_info->cb);
	if (poptions_info->pv == nullptr)
		return ecServerOOM;
	memset(poptions_info->pv, 0, poptions_info->cb);
	phelp_file->cb = 0;
	*ppfile_name = NULL;
	return ecSuccess;
}
