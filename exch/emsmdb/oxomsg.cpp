// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <string>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
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

static gxerr_t oxomsg_rectify_message(message_object *pmessage,
    const char *representing_username)
{
	BINARY *pentryid;
	uint64_t nt_time;
	uint8_t tmp_byte;
	int32_t tmp_level;
	BINARY search_bin;
	BINARY search_bin1;
	char essdn_buff[1024];
	char tmp_display[256];
	char essdn_buff1[1024];
	char tmp_display1[256];
	char search_buff[1024];
	char search_buff1[1024];
	PROBLEM_ARRAY tmp_problems;
	
	auto account = pmessage->plogon->get_account();
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	tmp_byte = 1;
	nt_time = rop_util_current_nttime();
	tmp_level = -1;
	if (!common_util_username_to_essdn(account, essdn_buff, GX_ARRAY_SIZE(essdn_buff)))
		return GXERR_CALL_FAILED;
	if (!common_util_get_user_displayname(account,
	    tmp_display, arsizeof(tmp_display)))
		return GXERR_CALL_FAILED;
	pentryid = common_util_username_to_addressbook_entryid(account);
	if (NULL == pentryid) {
		return GXERR_CALL_FAILED;
	}
	search_bin.cb = gx_snprintf(search_buff, GX_ARRAY_SIZE(search_buff), "EX:%s", essdn_buff) + 1;
	search_bin.pv = search_buff;
	if (0 != strcasecmp(account, representing_username)) {
		if (!common_util_username_to_essdn(representing_username,
		    essdn_buff1, GX_ARRAY_SIZE(essdn_buff1)))
			return GXERR_CALL_FAILED;
		if (!common_util_get_user_displayname(representing_username,
		    tmp_display1, arsizeof(tmp_display1)))
			return GXERR_CALL_FAILED;
		pentryid = common_util_username_to_addressbook_entryid(
										representing_username);
		if (NULL == pentryid) {
			return GXERR_CALL_FAILED;
		}
	} else {
		strcpy(essdn_buff1, essdn_buff);
		strcpy(tmp_display1, tmp_display);
	}
	search_bin1.cb = gx_snprintf(search_buff1, GX_ARRAY_SIZE(search_buff1), "EX:%s", essdn_buff1) + 1;
	search_bin1.pv = search_buff1;
	char msgid[UADDR_SIZE+2];
	make_inet_msgid(msgid, arsizeof(msgid), 0x4553);
	TAGGED_PROPVAL pv[] = {
		{PR_READ, &tmp_byte},
		{PR_CLIENT_SUBMIT_TIME, &nt_time},
		{PR_CONTENT_FILTER_SCL, &tmp_level},
		{PR_MESSAGE_LOCALE_ID, &pinfo->lcid_string},
		{PR_SENDER_SMTP_ADDRESS, deconst(account)},
		{PR_SENDER_ADDRTYPE, deconst("EX")},
		{PR_SENDER_EMAIL_ADDRESS, essdn_buff},
		{PR_SENDER_NAME, tmp_display},
		{PR_SENDER_ENTRYID, pentryid},
		{PR_SENDER_SEARCH_KEY, &search_bin},
		{PR_SENT_REPRESENTING_SMTP_ADDRESS, deconst(representing_username)},
		{PR_SENT_REPRESENTING_ADDRTYPE, deconst("EX")},
		{PR_SENT_REPRESENTING_EMAIL_ADDRESS, essdn_buff1},
		{PR_SENT_REPRESENTING_NAME, tmp_display1},
		{PR_SENT_REPRESENTING_ENTRYID, pentryid},
		{PR_SENT_REPRESENTING_SEARCH_KEY, &search_bin1},
		{PR_INTERNET_MESSAGE_ID, msgid},
	};
	TPROPVAL_ARRAY tmp_propvals = {arsizeof(pv), pv};
	if (!pmessage->set_properties(&tmp_propvals, &tmp_problems))
		return GXERR_CALL_FAILED;
	return pmessage->save();
}

static BOOL oxomsg_check_delegate(message_object *pmessage, char *username, size_t ulen)
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
		if (strcasecmp(str, "EX") == 0) {
			str = tmp_propvals.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr) {
				auto ret = common_util_essdn_to_username(str, username, ulen);
				if (!ret)
					fprintf(stderr, "W-1642: Rejecting submission of msgid %llxh because user <%s> is not from this system\n",
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
			fprintf(stderr, "W-1643: rejecting submission of msgid %llxh because its PR_SENT_REPRESENTING_ENTRYID does not reference a user in the local system\n",
			        static_cast<unsigned long long>(pmessage->message_id));
		return ret;
	}
	username[0] = '\0';
	return TRUE;
}

static BOOL oxomsg_check_permission(const char *account,
	const char *account_representing) try
{
	char maildir[256];
	
	if (0 == strcasecmp(account, account_representing)) {
		return TRUE;
	}
	if (!common_util_get_maildir(account_representing, maildir, arsizeof(maildir)))
		return FALSE;
	auto dlg_path = maildir + "/config/delegates.txt"s;
	struct srcitem { char a[324]; };
	auto pfile = list_file_initd(dlg_path.c_str(), nullptr, "%s:324");
	if (NULL == pfile) {
		return FALSE;
	}
	auto item_num = pfile->get_size();
	auto pitem = static_cast<srcitem *>(pfile->get_list());
	for (decltype(item_num) i = 0; i < item_num; ++i) {
		if (strcasecmp(pitem[i].a, account) == 0 ||
		    common_util_check_mlist_include(pitem[i].a, account)) {
			return TRUE;
		}
	}
	return FALSE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1500: ENOMEM\n");
	return false;
}

uint32_t rop_submitmessage(uint8_t submit_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	int timer_id;
	BOOL b_marked;
	int object_type;
	uint16_t rcpt_num;
	char username[UADDR_SIZE];
	int32_t max_length;
	uint32_t mail_length;
	uint32_t message_flags;
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
	if (!plogon->check_private())
		return ecNotSupported;
	if (plogon->logon_mode == LOGON_MODE_GUEST)
		return ecAccessDenied;

	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	if (pmessage->get_id() == 0)
		return ecNotSupported;
	if (pmessage->check_importing())
		return ecAccessDenied;
	auto tag_access = pmessage->get_tag_access();
	if (!(tag_access & MAPI_ACCESS_MODIFY))
		return ecAccessDenied;
	if (!pmessage->get_recipient_num(&rcpt_num))
		return ecError;
	if (rcpt_num > g_max_rcpt)
		return ecTooManyRecips;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_ASSOCIATED;
	if (!pmessage->get_properties(0, &tmp_proptags, &tmp_propvals))
		return ecError;
	auto pvalue = tmp_propvals.getval(PR_ASSOCIATED);
	/* FAI message cannot be sent */
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		return ecAccessDenied;
	}
	
	if (!oxomsg_check_delegate(pmessage, username, GX_ARRAY_SIZE(username)))
		return ecError;
	auto account = plogon->get_account();
	if (*username == '\0')
		gx_strlcpy(username, account, GX_ARRAY_SIZE(username));
	else if (!oxomsg_check_permission(account, username))
		return ecAccessDenied;

	gxerr_t err = oxomsg_rectify_message(pmessage, username);
	if (err != GXERR_SUCCESS)
		return gxerr_to_hresult(err);
	
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

	pvalue = tmp_propvals.getval(PR_MAX_SUBMIT_MESSAGE_SIZE);
	max_length = -1;
	if (NULL != pvalue) {
		max_length = *(int32_t*)pvalue;
	}
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
	pvalue = tmp_propvals.getval(PR_MESSAGE_SIZE);
	if (NULL == pvalue) {
		return ecError;
	}
	mail_length = *(uint32_t*)pvalue;
	if (max_length > 0 && mail_length > static_cast<uint32_t>(max_length))
		return EC_EXCEEDED_SIZE;
	pvalue = tmp_propvals.getval(PR_MESSAGE_FLAGS);
	if (NULL == pvalue) {
		return ecError;
	}
	message_flags = *(uint32_t*)pvalue;
	if (message_flags & MSGFLAG_SUBMITTED)
		return ecAccessDenied;
	BOOL b_unsent = (message_flags & MSGFLAG_UNSENT) ? TRUE : false;
	pvalue = tmp_propvals.getval(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = pvalue != nullptr && *static_cast<uint8_t *>(pvalue) != 0 ? TRUE : false;
	/* we don't use spool queue, so disable the whole functionality */
#if 0
	/* check if it is already in spooler queue */
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (!exmdb_client_check_message(plogon->get_dir(), fid_spooler,
	    pmessage->get_id(), &b_exist))
		return ecError;
	if (b_exist)
		return ecAccessDenied;
	if (submit_flags & ROP_SUBMIT_FLAG_NEEDS_SPOOLER) {
		if (!exmdb_client_link_message(plogon->get_dir(), pinfo->cpid,
		    fid_spooler, pmessage->get_id(), &b_result) || !b_result)
			return ecError;
		return ecSuccess;
	}
#endif
	
	if (!exmdb_client_try_mark_submit(plogon->get_dir(),
	    pmessage->get_id(), &b_marked))
		return ecError;
	if (!b_marked)
		return ecAccessDenied;
	
	auto deferred_time = props_to_defer_interval(tmp_propvals);
	if (deferred_time > 0) {
		snprintf(command_buff, 1024, "%s %s %llu",
		         common_util_get_submit_command(),
		         plogon->get_account(),
		         static_cast<unsigned long long>(rop_util_get_gc_value(pmessage->get_id())));
		timer_id = common_util_add_timer(
			command_buff, deferred_time);
		if (0 == timer_id) {
			goto SUBMIT_FAIL;
		}
		exmdb_client_set_message_timer(plogon->get_dir(),
			pmessage->get_id(), timer_id);
		pmessage->reload();
		return ecSuccess;
	}
	
	if (!common_util_send_message(plogon, pmessage->get_id(), TRUE))
		goto SUBMIT_FAIL;
	if (!b_delete)
		pmessage->reload();
	else
		pmessage->clear_unsent();
	return ecSuccess;

 SUBMIT_FAIL:
	exmdb_client_clear_submit(plogon->get_dir(), pmessage->get_id(), b_unsent);
	return ecError;
}

uint32_t rop_abortsubmit(uint64_t folder_id, uint64_t message_id,
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
	if (!plogon->check_private())
		return ecNotSupported;
	if (plogon->logon_mode == LOGON_MODE_GUEST)
		return ecAccessDenied;
	if (!exmdb_client_check_message(plogon->get_dir(), folder_id,
	    message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotFound;
	if (!exmdb_client_get_message_property(plogon->get_dir(),
	    nullptr, 0, message_id, PR_MESSAGE_FLAGS,
	    reinterpret_cast<void **>(&pmessage_flags)))
		return ecError;
	if (NULL == pmessage_flags) {
		return ecError;
	}
	if (*pmessage_flags & MSGFLAG_SUBMITTED) {
		if (!exmdb_client_get_message_timer(plogon->get_dir(),
		    message_id, &ptimer_id))
			return ecError;
		if (ptimer_id != nullptr && !common_util_cancel_timer(*ptimer_id))
			return ecUnableToAbort;
		if (!exmdb_client_clear_submit(plogon->get_dir(), message_id, TRUE))
			return ecError;
		if (!common_util_save_message_ics(plogon, message_id, nullptr))
			return ecError;
		return ecSuccess;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (!exmdb_client_check_message(plogon->get_dir(), fid_spooler,
	    message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotInQueue;
	/* unlink the message in spooler queue */
	if (!exmdb_client_unlink_message(plogon->get_dir(), pinfo->cpid,
	    fid_spooler, message_id))
		return ecError;
	return ecSuccess;
}

uint32_t rop_getaddresstypes(STRING_ARRAY *paddress_types, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	static constexpr const char *address_types[] = {"SMTP", "EX"};
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->check_private())
		return ecNotSupported;
	paddress_types->count = 2;
	paddress_types->ppstr = const_cast<char **>(address_types);
	return ecSuccess;
}

uint32_t rop_setspooler(LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->check_private())
		return ecNotSupported;
	return ecSuccess;
}

uint32_t rop_spoolerlockmessage(uint64_t message_id, uint8_t lock_stat,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_exist;
	BOOL b_result;
	BOOL b_delete;
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
	if (!plogon->check_private())
		return ecNotSupported;
	if (plogon->logon_mode == LOGON_MODE_GUEST)
		return ecAccessDenied;
	if (LOCK_STAT_1STFINISHED != lock_stat) {
		return ecSuccess;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (!exmdb_client_check_message(plogon->get_dir(), fid_spooler,
	    message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotInQueue;
	/* unlink the message in spooler queue */
	if (!exmdb_client_unlink_message(plogon->get_dir(), pinfo->cpid,
	    fid_spooler, message_id))
		return ecError;
	tmp_proptags.count = 3;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_DELETE_AFTER_SUBMIT;
	proptag_buff[1] = PR_TARGET_ENTRYID;
	proptag_buff[2] = PR_PARENT_ENTRYID;
	if (!exmdb_client_get_message_properties(plogon->get_dir(), nullptr, 0,
	    message_id, &tmp_proptags, &tmp_propvals))
		return ecError;
	auto pvalue = tmp_propvals.getval(PR_DELETE_AFTER_SUBMIT);
	b_delete = FALSE;
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_delete = TRUE;
	}
	
	auto ptarget = tmp_propvals.get<BINARY>(PR_TARGET_ENTRYID);
	pvalue = tmp_propvals.getval(PR_PARENT_ENTRYID);
	if (NULL == pvalue) {
		return ecError;
	}
	if (!common_util_from_folder_entryid(plogon,
	    static_cast<BINARY *>(pvalue), &parent_id))
		return ecError;
	if (NULL != ptarget) {
		if (!common_util_from_message_entryid(plogon, ptarget,
		    &folder_id, &new_id))
			return ecError;
		if (!exmdb_client_movecopy_message(plogon->get_dir(),
		    plogon->account_id, pinfo->cpid, message_id, folder_id,
		    new_id, b_delete, &b_result))
			return ecError;
	} else if (b_delete) {
		exmdb_client_delete_message(plogon->get_dir(),
			plogon->account_id, pinfo->cpid,
			parent_id, message_id, TRUE, &b_result);
	}
	return ecSuccess;
}

uint32_t rop_transportsend(TPROPVAL_ARRAY **pppropvals, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	void *pvalue;
	int object_type;
	char username[UADDR_SIZE];
	PROPTAG_ARRAY proptags;
	TAGGED_PROPVAL propval;
	uint32_t proptag_buff[7];
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->check_private())
		return ecNotSupported;
	if (plogon->logon_mode == LOGON_MODE_GUEST)
		return ecAccessDenied;
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	if (pmessage->get_id() == 0)
		return ecNotSupported;
	if (pmessage->check_importing())
		return ecAccessDenied;
	if (!exmdb_client_get_message_property(plogon->get_dir(), nullptr, 0,
	    pmessage->get_id(), PR_MESSAGE_FLAGS, &pvalue))
		return ecError;
	if (pvalue != nullptr && *static_cast<uint32_t *>(pvalue) & MSGFLAG_SUBMITTED)
		return ecAccessDenied;
	if (!oxomsg_check_delegate(pmessage, username, GX_ARRAY_SIZE(username)))
		return ecError;
	auto account = plogon->get_account();
	if (*username == '\0')
		gx_strlcpy(username, account, GX_ARRAY_SIZE(username));
	else if (!oxomsg_check_permission(account, username))
		return ecAccessDenied;

	gxerr_t err = oxomsg_rectify_message(pmessage, username);
	if (err != GXERR_SUCCESS)
		return gxerr_to_hresult(err);
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
			propval.proptag = PR_PROVIDER_SUBMIT_TIME;
			propval.pvalue = cu_alloc<uint64_t>();
			if (NULL != propval.pvalue) {
				*(uint64_t*)propval.pvalue = rop_util_current_nttime();
				common_util_set_propvals(*pppropvals, &propval);
			}
		}
	}
	if (!common_util_send_message(plogon, pmessage->get_id(), false))
		return ecError;
	return ecSuccess;
}

uint32_t rop_transportnewmail(uint64_t message_id, uint64_t folder_id,
    const char *pstr_class, uint32_t message_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!exmdb_client_transport_new_mail(plogon->get_dir(), message_id,
	    folder_id, message_flags, pstr_class))
		return ecError;
	return ecSuccess;
}

uint32_t rop_gettransportfolder(uint64_t *pfolder_id, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecNullObject;
	if (!plogon->check_private())
		return ecNotSupported;
	*pfolder_id = rop_util_make_eid_ex(1, PRIVATE_FID_OUTBOX);
	return ecSuccess;
}

uint32_t rop_optionsdata(const char *paddress_type, uint8_t want_win32,
    uint8_t *preserved, BINARY *poptions_info, BINARY *phelp_file,
    char **ppfile_name, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	*preserved = 1;
	poptions_info->cb = 300;
	poptions_info->pv = common_util_alloc(poptions_info->cb);
	if (poptions_info->pv == nullptr)
		return ecMAPIOOM;
	memset(poptions_info->pv, 0, poptions_info->cb);
	phelp_file->cb = 0;
	*ppfile_name = NULL;
	return ecSuccess;
}
