// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "logon_object.h"
#include "message_object.h"
#include "rop_funcs.hpp"
#include "rop_processor.h"

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
	BINARY search_sender, search_repr;
	static constexpr size_t essdn_buff_size = 1024;
	auto essdn_sender = std::make_unique<char[]>(essdn_buff_size);
	auto essdn_repr = std::make_unique<char[]>(essdn_buff_size);
	char dispname_sender[256], dispname_repr[256];
	PROBLEM_ARRAY tmp_problems;
	
	auto account = pmessage->plogon->get_account();
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	tmp_byte = 1;
	nt_time = rop_util_current_nttime();
	tmp_level = -1;
	if (!common_util_username_to_essdn(account, essdn_sender.get(), essdn_buff_size))
		return ecRpcFailed;
	if (!common_util_get_user_displayname(account,
	    dispname_sender, std::size(dispname_sender)))
		return ecRpcFailed;
	auto eid_sender = common_util_username_to_addressbook_entryid(account);
	if (eid_sender == nullptr)
		return ecRpcFailed;
	auto eid_repr = eid_sender;
	const std::string search_buff = "EX:"s + essdn_sender.get();
	search_sender.cb = search_buff.size() + 1;
	search_sender.pv = deconst(search_buff.c_str());
	bool oneoff_repr = false;
	if (strcasecmp(account, representing_username) == 0) {
		strcpy(essdn_repr.get(), essdn_sender.get());
		strcpy(dispname_repr, dispname_sender);
	} else if (common_util_username_to_essdn(representing_username,
	    essdn_repr.get(), essdn_buff_size)) {
		if (!common_util_get_user_displayname(representing_username,
		    dispname_repr, std::size(dispname_repr)))
			return ecRpcFailed;
		eid_repr = common_util_username_to_addressbook_entryid(
										representing_username);
		if (eid_repr == nullptr)
			return ecRpcFailed;
	} else {
		strcpy(essdn_repr.get(), representing_username);
		strcpy(dispname_repr, representing_username);
		eid_repr = cu_username_to_oneoff(representing_username, representing_username);
		if (eid_repr == nullptr)
			return ecServerOOM;
		oneoff_repr = true;
	}
	const std::string sk_repr = oneoff_repr ? ("SMTP:"s + representing_username) :
	                            ("EX:"s + essdn_repr.get());
	search_repr.cb = sk_repr.size() + 1;
	search_repr.pv = deconst(sk_repr.c_str());
	char msgid[UADDR_SIZE+2];
	make_inet_msgid(msgid, std::size(msgid), 0x4553);
	TAGGED_PROPVAL pv[] = {
		{PR_READ, &tmp_byte},
		{PR_CLIENT_SUBMIT_TIME, &nt_time},
		{PR_CONTENT_FILTER_SCL, &tmp_level},
		{PR_MESSAGE_LOCALE_ID, &pinfo->lcid_string},
		{PR_SENDER_SMTP_ADDRESS, deconst(send_as ? representing_username : account)},
		{PR_SENDER_ADDRTYPE, deconst("EX")},
		{PR_SENDER_EMAIL_ADDRESS, send_as ? essdn_repr.get() : essdn_sender.get()},
		{PR_SENDER_NAME, send_as ? dispname_repr : dispname_sender},
		{PR_SENDER_ENTRYID, send_as ? eid_repr : eid_sender},
		{PR_SENDER_SEARCH_KEY, send_as ? &search_repr : &search_sender},
		{PR_SENT_REPRESENTING_SMTP_ADDRESS, deconst(representing_username)},
		{PR_SENT_REPRESENTING_ADDRTYPE, deconst(oneoff_repr ? "SMTP" : "EX")},
		{PR_SENT_REPRESENTING_EMAIL_ADDRESS, essdn_repr.get()},
		{PR_SENT_REPRESENTING_NAME, dispname_repr},
		{PR_SENT_REPRESENTING_ENTRYID, eid_repr},
		{PR_SENT_REPRESENTING_SEARCH_KEY, &search_repr},
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

static bool oxomsg_extract_delegate(message_object *pmessage,
    char *username, size_t ulen)
{
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 4;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_SENT_REPRESENTING_ADDRTYPE;
	proptag_buff[1] = PR_SENT_REPRESENTING_EMAIL_ADDRESS;
	proptag_buff[2] = PR_SENT_REPRESENTING_SMTP_ADDRESS;
	proptag_buff[3] = PR_SENT_REPRESENTING_ENTRYID;
	if (!pmessage->get_properties(0, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (0 == tmp_propvals.count) {
		username[0] = '\0';
		return TRUE;
	}
	auto str = tmp_propvals.get<const char>(PR_SENT_REPRESENTING_ADDRTYPE);
	if (str != nullptr) {
		if (strcmp(str, "0") == 0) {
			/*
			 * PR_SENT_* is strangely reset when MFCMAPI
			 * 21.2.21207.01 imports .msg files.
			 */
			username[0] = '\0';
			return TRUE;
		} else if (strcasecmp(str, "EX") == 0) {
			str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr) {
				auto ret = common_util_essdn_to_username(str, username, ulen);
				if (!ret)
					mlog(LV_WARN, "W-1642: Rejecting submission of msgid %llxh because user <%s> is not from this system",
					        static_cast<unsigned long long>(pmessage->message_id), str);
				return ret;
			}
		} else if (strcasecmp(str, "SMTP") == 0) {
			str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr) {
				gx_strlcpy(username, str, ulen);
				return TRUE;
			}
		}
	}
	str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr) {
		gx_strlcpy(username, str, ulen);
		return TRUE;
	}
	auto eid = tmp_propvals.get<const BINARY>(PR_SENT_REPRESENTING_ENTRYID);
	if (eid != nullptr) {
		auto ret = common_util_entryid_to_username(eid, username, ulen);
		if (!ret)
			mlog(LV_WARN, "W-1643: rejecting submission of msgid %llxh because its PR_SENT_REPRESENTING_ENTRYID does not reference a user in the local system",
			        static_cast<unsigned long long>(pmessage->message_id));
		return ret;
	}
	username[0] = '\0';
	return TRUE;
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
		mlog(LV_ERR, "E-2045: %s: %s", dlg_path.c_str(), strerror(ret));
		return ret;
	}
	for (const auto &deleg : delegate_list)
		if (strcasecmp(deleg.c_str(), account) == 0 ||
		    common_util_check_mlist_include(deleg.c_str(), account))
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
	char repdir[256];
	if (!common_util_get_maildir(repr, repdir, std::size(repdir)))
		return repr_grant::error;
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
	 * IPM.Schedule is special; PR_SENT_REPRESENTING contains the
	 * organizer, not the delegator. So there is no delegation to
	 * check/reject. oxcmail_export also checks message class again.
	 */
	if (cls != nullptr && strncasecmp(cls, "IPM.Schedule.", 13) == 0)
		return ecSuccess;
	mlog(LV_ERR, "%s: %s tried to send message %llxh (class %s) with repr/from=<%s>, "
		"but user has no delegate/sendas permission.",
		code, account, static_cast<unsigned long long>(msg.get_id()),
		znul(cls), username);
	return ecAccessDenied;
}

ec_error_t rop_submitmessage(uint8_t submit_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	int timer_id;
	BOOL b_marked;
	ems_objtype object_type;
	uint16_t rcpt_num;
	char username[UADDR_SIZE];
	char command_buff[1024];
	uint32_t proptag_buff[6];
	PROPTAG_ARRAY tmp_proptags;
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
	
	tmp_proptags.count = 2;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_ASSOCIATED;
	proptag_buff[1] = PR_MESSAGE_CLASS;
	if (!pmessage->get_properties(0, &tmp_proptags, &tmp_propvals))
		return ecError;
	auto flag = tmp_propvals.get<const uint8_t>(PR_ASSOCIATED);
	/* FAI message cannot be sent */
	if (flag != nullptr && *flag != 0) {
		mlog(LV_INFO, "I-2160: submitmessage denied because "
		        "message %llxh is FAI",
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}
	if (!oxomsg_extract_delegate(pmessage, username, std::size(username)))
		return ecError;
	auto account = plogon->get_account();
	repr_grant repr_grant;
	if (*username == '\0') {
		/* "No impersonation requested" is modeled as {impersonate yourself}. */
		gx_strlcpy(username, account, std::size(username));
		repr_grant = repr_grant::send_as;
	} else {
		repr_grant = oxomsg_get_perm(account, username);
	}
	if (repr_grant < repr_grant::send_on_behalf) {
		auto ret = pass_scheduling("E-2081", account, username, *pmessage,
		           tmp_propvals.get<const char>(PR_MESSAGE_CLASS));
		if (ret != ecSuccess)
			return ret;
	}
	auto ret = oxomsg_rectify_message(pmessage, username,
	           repr_grant >= repr_grant::send_as);
	if (ret != ecSuccess)
		return ret;
	
	tmp_proptags.count = 3;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_MAX_SUBMIT_MESSAGE_SIZE;
	proptag_buff[1] = PR_PROHIBIT_SEND_QUOTA;
	proptag_buff[2] = PR_MESSAGE_SIZE_EXTENDED;
	if (!plogon->get_properties(&tmp_proptags, &tmp_propvals))
		return ecError;

	auto sendquota = tmp_propvals.get<uint32_t>(PR_PROHIBIT_SEND_QUOTA);
	auto storesize = tmp_propvals.get<uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	/* Sendquota is in KiB, storesize in bytes */
	if (sendquota != nullptr && storesize != nullptr &&
	    static_cast<uint64_t>(*sendquota) * 1024 <= *storesize)
		return ecQuotaExceeded;

	auto inum = tmp_propvals.get<const int32_t>(PR_MAX_SUBMIT_MESSAGE_SIZE);
	int32_t max_length = inum != nullptr ? *inum : -1;
	tmp_proptags.count = (submit_flags & ROP_SUBMIT_FLAG_NEEDS_SPOOLER) ? 2 : 6;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_MESSAGE_SIZE;
	proptag_buff[1] = PR_MESSAGE_FLAGS;
	proptag_buff[2] = PR_DEFERRED_SEND_TIME;
	proptag_buff[3] = PR_DEFERRED_SEND_NUMBER;
	proptag_buff[4] = PR_DEFERRED_SEND_UNITS;
	proptag_buff[5] = PR_DELETE_AFTER_SUBMIT;
	if (!pmessage->get_properties(0, &tmp_proptags, &tmp_propvals))
		return ecError;
	auto num = tmp_propvals.get<const uint32_t>(PR_MESSAGE_SIZE);
	if (num == nullptr)
		return ecError;
	if (max_length > 0 && *num > static_cast<uint32_t>(max_length))
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
	if (!exmdb_client::check_message(dir, fid_spooler,
	    pmessage->get_id(), &b_exist))
		return ecError;
	if (b_exist)
		return ecAccessDenied;
	if (submit_flags & ROP_SUBMIT_FLAG_NEEDS_SPOOLER) {
		if (!exmdb_client::link_message(dir, pinfo->cpid,
		    fid_spooler, pmessage->get_id(), &b_result) || !b_result)
			return ecError;
		return ecSuccess;
	}
#endif
	
	if (!exmdb_client::try_mark_submit(dir, pmessage->get_id(), &b_marked))
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
			exmdb_client::clear_submit(dir, pmessage->get_id(), b_unsent);
			return ecError;
		}
		exmdb_client::set_message_timer(dir, pmessage->get_id(), timer_id);
		pmessage->reload();
		return ecSuccess;
	}
	
	ret = cu_send_message(plogon, pmessage, true);
	if (ret != ecSuccess && ret != ecWarnWithErrors)
		exmdb_client::clear_submit(dir, pmessage->get_id(), b_unsent);
	else if (!b_delete)
		pmessage->reload();
	else
		pmessage->clear_unsent();
	return ret;
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
	if (!exmdb_client::check_message(plogon->get_dir(), folder_id,
	    message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotFound;
	if (!exmdb_client::get_message_property(plogon->get_dir(),
	    nullptr, CP_ACP, message_id, PR_MESSAGE_FLAGS,
	    reinterpret_cast<void **>(&pmessage_flags)))
		return ecError;
	if (pmessage_flags == nullptr)
		return ecError;
	if (*pmessage_flags & MSGFLAG_SUBMITTED) {
		if (!exmdb_client::get_message_timer(plogon->get_dir(),
		    message_id, &ptimer_id))
			return ecError;
		if (ptimer_id != nullptr && !common_util_cancel_timer(*ptimer_id))
			return ecUnableToAbort;
		if (!exmdb_client::clear_submit(plogon->get_dir(), message_id, TRUE))
			return ecError;
		if (!common_util_save_message_ics(plogon, message_id, nullptr))
			return ecError;
		return ecSuccess;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (!exmdb_client::check_message(plogon->get_dir(), fid_spooler,
	    message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotInQueue;
	/* unlink the message in spooler queue */
	if (!exmdb_client::unlink_message(plogon->get_dir(), pinfo->cpid,
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
	uint32_t proptag_buff[3];
	PROPTAG_ARRAY tmp_proptags;
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
	if (!exmdb_client::check_message(dir, fid_spooler, message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotInQueue;
	/* unlink the message in spooler queue */
	if (!exmdb_client::unlink_message(dir, pinfo->cpid,
	    fid_spooler, message_id))
		return ecError;
	tmp_proptags.count = 3;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_DELETE_AFTER_SUBMIT;
	proptag_buff[1] = PR_TARGET_ENTRYID;
	proptag_buff[2] = PR_PARENT_ENTRYID;
	if (!exmdb_client::get_message_properties(dir, nullptr, CP_ACP,
	    message_id, &tmp_proptags, &tmp_propvals))
		return ecError;
	auto flag = tmp_propvals.get<const uint8_t>(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = flag != nullptr && *flag != 0 ? TRUE : false;
	auto ptarget = tmp_propvals.get<const BINARY>(PR_TARGET_ENTRYID);
	auto bin = tmp_propvals.get<const BINARY>(PR_PARENT_ENTRYID);
	if (bin == nullptr)
		return ecError;
	if (!cu_entryid_to_fid(plogon, bin, &parent_id))
		return ecError;
	if (NULL != ptarget) {
		if (!cu_entryid_to_mid(plogon, ptarget, &folder_id, &new_id))
			return ecError;
		if (!exmdb_client::movecopy_message(dir,
		    plogon->account_id, pinfo->cpid, message_id, folder_id,
		    new_id, b_delete, &b_result))
			return ecError;
	} else if (b_delete) {
		exmdb_client::delete_message(dir,
			plogon->account_id, pinfo->cpid,
			parent_id, message_id, TRUE, &b_result);
	}
	return ecSuccess;
}

ec_error_t rop_transportsend(TPROPVAL_ARRAY **pppropvals, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	char username[UADDR_SIZE];
	PROPTAG_ARRAY proptags;
	uint32_t proptag_buff[7];
	
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
	if (!exmdb_client::get_message_properties(plogon->get_dir(), nullptr,
	    CP_ACP, pmessage->get_id(), &rq_tags, &outvalues))
		return ecError;
	auto msgflags = outvalues.get<const uint32_t>(PR_MESSAGE_FLAGS);
	if (msgflags != nullptr && *msgflags & MSGFLAG_SUBMITTED) {
		mlog(LV_INFO, "I-2144: transportsend disallowed because "
		        "message %llxh was already submitted once",
		        static_cast<unsigned long long>(pmessage->get_id()));
		return ecAccessDenied;
	}
	if (!oxomsg_extract_delegate(pmessage, username, std::size(username)))
		return ecError;
	auto account = plogon->get_account();
	repr_grant repr_grant;
	if (*username == '\0') {
		gx_strlcpy(username, account, std::size(username));
		repr_grant = repr_grant::send_as;
	} else {
		repr_grant = oxomsg_get_perm(account, username);
	}
	if (repr_grant < repr_grant::send_on_behalf) {
		TPROPVAL_ARRAY cls_vals{};
		if (pmessage->get_properties(0, &cls_tags, &cls_vals) != 0)
			/* ignore, since we can test for cls_vals fill */;
		auto ret = pass_scheduling("E-2080", account, username, *pmessage,
		           cls_vals.get<const char>(PR_MESSAGE_CLASS));
		if (ret != ecSuccess)
			return ret;
	}
	auto ret = oxomsg_rectify_message(pmessage, username,
	           repr_grant >= repr_grant::send_as);
	if (ret != ecSuccess)
		return ret;
	*pppropvals = cu_alloc<TPROPVAL_ARRAY>();
	if (NULL != *pppropvals) {
		proptags.count = 7;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = PR_SENDER_NAME;
		proptag_buff[1] = PR_SENDER_ENTRYID;	
		proptag_buff[2] = PR_SENDER_SEARCH_KEY;
		proptag_buff[3] = PR_SENT_REPRESENTING_NAME;
		proptag_buff[4] = PR_SENT_REPRESENTING_ENTRYID;
		proptag_buff[5] = PR_SENT_REPRESENTING_SEARCH_KEY;
		proptag_buff[6] = PR_PROVIDER_SUBMIT_TIME;
		if (!pmessage->get_properties(0, &proptags, *pppropvals))
			*pppropvals = NULL;
		if (!(**pppropvals).has(PR_PROVIDER_SUBMIT_TIME)) {
			auto nt = cu_alloc<uint64_t>();
			if (nt != nullptr) {
				*nt = rop_util_current_nttime();
				cu_set_propval(*pppropvals, PR_PROVIDER_SUBMIT_TIME, nt);
			}
		}
	}
	return cu_send_message(plogon, pmessage, false);
}

ec_error_t rop_transportnewmail(uint64_t message_id, uint64_t folder_id,
    const char *pstr_class, uint32_t message_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!exmdb_client::transport_new_mail(plogon->get_dir(), message_id,
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
