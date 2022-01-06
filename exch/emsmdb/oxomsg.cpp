// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <string>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include "emsmdb_interface.h"
#include "message_object.h"
#include "rop_processor.h"
#include "logon_object.h"
#include "exmdb_client.h"
#include <gromox/proc_common.h>
#include "common_util.h"
#include <gromox/list_file.hpp>
#include <gromox/rop_util.hpp>
#include "rops.h"
#include <cstdio>

using namespace std::string_literals;
using namespace gromox;

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
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[20];
	
	auto account = pmessage->plogon->get_account();
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	tmp_propvals.count = 16;
	tmp_propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PR_READ;
	propval_buff[0].pvalue = &tmp_byte;
	tmp_byte = 1;
	propval_buff[1].proptag = PROP_TAG_CLIENTSUBMITTIME;
	propval_buff[1].pvalue = &nt_time;
	nt_time = rop_util_current_nttime();
	propval_buff[2].proptag = PROP_TAG_CONTENTFILTERSPAMCONFIDENCELEVEL;
	propval_buff[2].pvalue = &tmp_level;
	tmp_level = -1;
	propval_buff[3].proptag = PR_MESSAGE_LOCALE_ID;
	propval_buff[3].pvalue = &pinfo->lcid_string;
	propval_buff[4].proptag = PROP_TAG_SENDERSMTPADDRESS;
	propval_buff[4].pvalue = (void*)account;
	propval_buff[5].proptag = PR_SENDER_ADDRTYPE;
	propval_buff[5].pvalue  = deconst("EX");
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
	propval_buff[6].proptag = PR_SENDER_EMAIL_ADDRESS;
	propval_buff[6].pvalue = essdn_buff;
	propval_buff[7].proptag = PR_SENDER_NAME;
	propval_buff[7].pvalue = tmp_display;
	propval_buff[8].proptag = PR_SENDER_ENTRYID;
	propval_buff[8].pvalue = pentryid;
	propval_buff[9].proptag = PR_SENDER_SEARCH_KEY;
	propval_buff[9].pvalue = &search_bin;
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
	propval_buff[10].proptag = PR_SENT_REPRESENTING_SMTP_ADDRESS;
	propval_buff[10].pvalue = (void*)representing_username;
	propval_buff[11].proptag = PR_SENT_REPRESENTING_ADDRTYPE;
	propval_buff[11].pvalue  = deconst("EX");
	propval_buff[12].proptag = PR_SENT_REPRESENTING_EMAIL_ADDRESS;
	propval_buff[12].pvalue = essdn_buff1;
	propval_buff[13].proptag = PR_SENT_REPRESENTING_NAME;
	propval_buff[13].pvalue = tmp_display1;
	propval_buff[14].proptag = PR_SENT_REPRESENTING_ENTRYID;
	propval_buff[14].pvalue = pentryid;
	propval_buff[15].proptag = PR_SENT_REPRESENTING_SEARCH_KEY;
	propval_buff[15].pvalue = &search_bin1;
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
	auto pvalue = tmp_propvals.getval(PR_SENT_REPRESENTING_ADDRTYPE);
	if (NULL != pvalue) {
		if (strcasecmp(static_cast<char *>(pvalue), "EX") == 0) {
			pvalue = tmp_propvals.getval(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (NULL != pvalue) {
				return common_util_essdn_to_username(static_cast<char *>(pvalue),
				       username, ulen);
			}
		} else if (strcasecmp(static_cast<char *>(pvalue), "SMTP") == 0) {
			pvalue = tmp_propvals.getval(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (NULL != pvalue) {
				gx_strlcpy(username, static_cast<char *>(pvalue), ulen);
				return TRUE;
			}
		}
	}
	pvalue = tmp_propvals.getval(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (NULL != pvalue) {
		gx_strlcpy(username, static_cast<char *>(pvalue), ulen);
		return TRUE;
	}
	pvalue = tmp_propvals.getval(PR_SENT_REPRESENTING_ENTRYID);
	if (NULL != pvalue) {
		return common_util_entryid_to_username(static_cast<BINARY *>(pvalue),
		       username, ulen);
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
	time_t cur_time;
	uint32_t tmp_num;
	uint16_t rcpt_num;
	char username[UADDR_SIZE];
	int32_t max_length;
	uint32_t mail_length;
	uint64_t submit_time;
	uint32_t deferred_time;
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
	if (rcpt_num > common_util_get_param(COMMON_UTIL_MAX_RCPT)) {
		return ecTooManyRecips;
	}
	
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
	if ('\0' == username[0]) {
		gx_strlcpy(username, account, GX_ARRAY_SIZE(username));
	} else {
		if (FALSE == oxomsg_check_permission(account, username)) {
			return ecAccessDenied;
		}
	}
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
	tmp_proptags.count = (submit_flags & SUBMIT_FLAG_NEEDS_SPOOLER) ? 2 : 6;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_MESSAGE_SIZE;
	proptag_buff[1] = PR_MESSAGE_FLAGS;
	proptag_buff[2] = PROP_TAG_DEFERREDSENDTIME;
	proptag_buff[3] = PROP_TAG_DEFERREDSENDNUMBER;
	proptag_buff[4] = PROP_TAG_DEFERREDSENDUNITS;
	proptag_buff[5] = PROP_TAG_DELETEAFTERSUBMIT;
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
	pvalue = tmp_propvals.getval(PROP_TAG_DELETEAFTERSUBMIT);
	BOOL b_delete = pvalue != nullptr && *static_cast<uint8_t *>(pvalue) != 0 ? TRUE : false;
	/* we don't use spool queue, so disable the whole functionality */
#if 0
	/* check if it is alread in spooler queue */
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (!exmdb_client_check_message(plogon->get_dir(), fid_spooler,
	    pmessage->get_id(), &b_exist))
		return ecError;
	if (TRUE == b_exist) {
		return ecAccessDenied;
	}
	if (submit_flags & SUBMIT_FLAG_NEEDS_SPOOLER) {
		if (!exmdb_client_link_message(plogon->get_dir(), pinfo->cpid,
		    fid_spooler, pmessage->get_id(), &b_result) || !b_result)
			return ecError;
		return ecSuccess;
	}
#endif
	
	if (!exmdb_client_try_mark_submit(plogon->get_dir(),
	    pmessage->get_id(), &b_marked))
		return ecError;
	if (FALSE == b_marked) {
		return ecAccessDenied;
	}
	
	deferred_time = 0;
	time(&cur_time);
	submit_time = rop_util_unix_to_nttime(cur_time);
	pvalue = tmp_propvals.getval(PROP_TAG_DEFERREDSENDTIME);
	if (NULL != pvalue) {
		if (submit_time < *(uint64_t*)pvalue) {
			deferred_time = rop_util_nttime_to_unix(
						*(uint64_t*)pvalue) - cur_time;
		}
	} else {
		pvalue = tmp_propvals.getval(PROP_TAG_DEFERREDSENDNUMBER);
		if (NULL != pvalue) {
			tmp_num = *(uint32_t*)pvalue;
			pvalue = tmp_propvals.getval(PROP_TAG_DEFERREDSENDUNITS);
			if (NULL != pvalue) {
				switch (*(uint32_t*)pvalue) {
				case 0:
					deferred_time = tmp_num*60;
					break;
				case 1:
					deferred_time = tmp_num*60*60;
					break;
				case 2:
					deferred_time = tmp_num*60*60*24;
					break;
				case 3:
					deferred_time = tmp_num*60*60*24*7;
					break;
				}
			}
		}
	}
	
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
	if (FALSE == b_delete) {
		pmessage->reload();
	} else {
		pmessage->clear_unsent();
	}
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
	if (FALSE == b_exist) {
		return ecNotFound;
	}
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
		if (NULL != ptimer_id) {
			if (FALSE == common_util_cancel_timer(*ptimer_id)) {
				return ecUnableToAbort;
			}
		}
		if (!exmdb_client_clear_submit(plogon->get_dir(), message_id, TRUE))
			return ecError;
		if (FALSE == common_util_save_message_ics(
			plogon, message_id, NULL)) {
			return ecError;
		}
		return ecSuccess;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (!exmdb_client_check_message(plogon->get_dir(), fid_spooler,
	    message_id, &b_exist))
		return ecError;
	if (FALSE == b_exist) {
		return ecNotInQueue;
	}
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
	if (FALSE == b_exist) {
		return ecNotInQueue;
	}
	/* unlink the message in spooler queue */
	if (!exmdb_client_unlink_message(plogon->get_dir(), pinfo->cpid,
	    fid_spooler, message_id))
		return ecError;
	tmp_proptags.count = 3;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_DELETEAFTERSUBMIT;
	proptag_buff[1] = PR_TARGET_ENTRYID;
	proptag_buff[2] = PR_PARENT_ENTRYID;
	if (!exmdb_client_get_message_properties(plogon->get_dir(), nullptr, 0,
	    message_id, &tmp_proptags, &tmp_propvals))
		return ecError;
	auto pvalue = tmp_propvals.getval(PROP_TAG_DELETEAFTERSUBMIT);
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
		if (FALSE == common_util_from_message_entryid(
			plogon, ptarget, &folder_id, &new_id)) {
			return ecError;
		}
		if (!exmdb_client_movecopy_message(plogon->get_dir(),
		    plogon->account_id, pinfo->cpid, message_id, folder_id,
		    new_id, b_delete, &b_result))
			return ecError;
	} else if (TRUE == b_delete) {
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
	if ('\0' == username[0]) {
		gx_strlcpy(username, account, GX_ARRAY_SIZE(username));
	} else {
		if (FALSE == oxomsg_check_permission(account, username)) {
			return ecAccessDenied;
		}
	}
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
		proptag_buff[6] = PROP_TAG_PROVIDERSUBMITTIME;
		if (!pmessage->get_properties(0, &proptags, *pppropvals))
			*pppropvals = NULL;
		if (!(**pppropvals).has(PROP_TAG_PROVIDERSUBMITTIME)) {
			propval.proptag = PROP_TAG_PROVIDERSUBMITTIME;
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
