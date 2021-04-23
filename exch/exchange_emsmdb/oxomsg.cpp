// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
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

static gxerr_t oxomsg_rectify_message(MESSAGE_OBJECT *pmessage,
    const char *representing_username)
{
	BINARY *pentryid;
	uint64_t nt_time;
	uint8_t tmp_byte;
	int32_t tmp_level;
	BINARY search_bin;
	BINARY search_bin1;
	const char *account;
	char essdn_buff[1024];
	char tmp_display[256];
	char essdn_buff1[1024];
	char tmp_display1[256];
	char search_buff[1024];
	char search_buff1[1024];
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[20];
	
	account = logon_object_get_account(pmessage->plogon);
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
	propval_buff[3].proptag = PROP_TAG_MESSAGELOCALEID;
	propval_buff[3].pvalue = &pinfo->lcid_string;
	propval_buff[4].proptag = PROP_TAG_SENDERSMTPADDRESS;
	propval_buff[4].pvalue = (void*)account;
	propval_buff[5].proptag = PROP_TAG_SENDERADDRESSTYPE;
	propval_buff[5].pvalue  = deconst("EX");
	if (!common_util_username_to_essdn(account, essdn_buff, GX_ARRAY_SIZE(essdn_buff)))
		return GXERR_CALL_FAILED;
	if (FALSE == common_util_get_user_displayname(account, tmp_display)) {
		return GXERR_CALL_FAILED;
	}
	pentryid = common_util_username_to_addressbook_entryid(account);
	if (NULL == pentryid) {
		return GXERR_CALL_FAILED;
	}
	search_bin.cb = gx_snprintf(search_buff, GX_ARRAY_SIZE(search_buff), "EX:%s", essdn_buff) + 1;
	search_bin.pv = search_buff;
	propval_buff[6].proptag = PROP_TAG_SENDEREMAILADDRESS;
	propval_buff[6].pvalue = essdn_buff;
	propval_buff[7].proptag = PROP_TAG_SENDERNAME;
	propval_buff[7].pvalue = tmp_display;
	propval_buff[8].proptag = PROP_TAG_SENDERENTRYID;
	propval_buff[8].pvalue = pentryid;
	propval_buff[9].proptag = PROP_TAG_SENDERSEARCHKEY;
	propval_buff[9].pvalue = &search_bin;
	if (0 != strcasecmp(account, representing_username)) {
		if (!common_util_username_to_essdn(representing_username,
		    essdn_buff1, GX_ARRAY_SIZE(essdn_buff1)))
			return GXERR_CALL_FAILED;
		if (FALSE == common_util_get_user_displayname(
			representing_username, tmp_display1)) {
			return GXERR_CALL_FAILED;
		}
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
	propval_buff[10].proptag = PROP_TAG_SENTREPRESENTINGSMTPADDRESS;
	propval_buff[10].pvalue = (void*)representing_username;
	propval_buff[11].proptag = PROP_TAG_SENTREPRESENTINGADDRESSTYPE;
	propval_buff[11].pvalue  = deconst("EX");
	propval_buff[12].proptag = PROP_TAG_SENTREPRESENTINGEMAILADDRESS;
	propval_buff[12].pvalue = essdn_buff1;
	propval_buff[13].proptag = PROP_TAG_SENTREPRESENTINGNAME;
	propval_buff[13].pvalue = tmp_display1;
	propval_buff[14].proptag = PROP_TAG_SENTREPRESENTINGENTRYID;
	propval_buff[14].pvalue = pentryid;
	propval_buff[15].proptag = PROP_TAG_SENTREPRESENTINGSEARCHKEY;
	propval_buff[15].pvalue = &search_bin1;
	if (FALSE == message_object_set_properties(
		pmessage, &tmp_propvals, &tmp_problems)) {
		return GXERR_CALL_FAILED;
	}
	return message_object_save(pmessage);
}

static BOOL oxomsg_check_delegate(MESSAGE_OBJECT *pmessage, char *username, size_t ulen)
{
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 4;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_SENTREPRESENTINGADDRESSTYPE;
	proptag_buff[1] = PROP_TAG_SENTREPRESENTINGEMAILADDRESS;
	proptag_buff[2] = PROP_TAG_SENTREPRESENTINGSMTPADDRESS;
	proptag_buff[3] = PROP_TAG_SENTREPRESENTINGENTRYID;
	if (FALSE == message_object_get_properties(
		pmessage, 0, &tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
	if (0 == tmp_propvals.count) {
		username[0] = '\0';
		return TRUE;
	}
	auto pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_SENTREPRESENTINGADDRESSTYPE);
	if (NULL != pvalue) {
		if (strcasecmp(static_cast<char *>(pvalue), "EX") == 0) {
			pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
			if (NULL != pvalue) {
				return common_util_essdn_to_username(static_cast<char *>(pvalue),
				       username, ulen);
			}
		} else if (strcasecmp(static_cast<char *>(pvalue), "SMTP") == 0) {
			pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
			if (NULL != pvalue) {
				gx_strlcpy(username, static_cast<char *>(pvalue), ulen);
				return TRUE;
			}
		}
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
	if (NULL != pvalue) {
		gx_strlcpy(username, static_cast<char *>(pvalue), ulen);
		return TRUE;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
					PROP_TAG_SENTREPRESENTINGENTRYID);
	if (NULL != pvalue) {
		return common_util_entryid_to_username(static_cast<BINARY *>(pvalue),
		       username, ulen);
	}
	username[0] = '\0';
	return TRUE;
}

static BOOL oxomsg_check_permission(const char *account,
	const char *account_representing)
{
	char maildir[256];
	char temp_path[256];
	
	if (0 == strcasecmp(account, account_representing)) {
		return TRUE;
	}
	if (FALSE == common_util_get_maildir(
		account_representing, maildir)) {
		return FALSE;
	}
	snprintf(temp_path, GX_ARRAY_SIZE(temp_path), "%s/config/delegates.txt", maildir);
	struct srcitem { char a[256]; };
	auto pfile = list_file_initd(temp_path, nullptr, "%s:256");
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
}

uint32_t rop_submitmessage(uint8_t submit_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int timer_id;
	BOOL b_marked;
	int object_type;
	time_t cur_time;
	uint32_t tmp_num;
	uint16_t rcpt_num;
	char username[UADDR_SIZE];
	int32_t max_length;
	const char *account;
	uint32_t tag_access;
	uint32_t mail_length;
	uint64_t submit_time;
	uint32_t deferred_time;
	uint32_t message_flags;
	char command_buff[1024];
	uint32_t proptag_buff[6];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return ecError;
	}
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	
	if (FALSE == logon_object_check_private(plogon)) {
		return ecNotSupported;
	}
	
	if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
		return ecAccessDenied;
	}
	
	auto pmessage = static_cast<MESSAGE_OBJECT *>(rop_processor_get_object(plogmap,
	                logon_id, hin, &object_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_MESSAGE != object_type) {
		return ecNotSupported;
	}
	if (0 == message_object_get_id(pmessage)) {
		return ecNotSupported;
	}
	if (TRUE == message_object_check_importing(pmessage)) {
		return ecAccessDenied;
	}
	
	tag_access = message_object_get_tag_access(pmessage);
	if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
		return ecAccessDenied;
	}
	
	if (FALSE == message_object_get_recipient_num(
		pmessage, &rcpt_num)) {
		return ecError;
	}
	if (rcpt_num > common_util_get_param(COMMON_UTIL_MAX_RCPT)) {
		return ecTooManyRecips;
	}
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_ASSOCIATED;
	if (FALSE == message_object_get_properties(
		pmessage, 0, &tmp_proptags, &tmp_propvals)) {
		return ecError;
	}
	auto pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_ASSOCIATED);
	/* FAI message cannot be sent */
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		return ecAccessDenied;
	}
	
	if (!oxomsg_check_delegate(pmessage, username, GX_ARRAY_SIZE(username)))
		return ecError;
	account = logon_object_get_account(plogon);
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
	proptag_buff[0] = PROP_TAG_MAXIMUMSUBMITMESSAGESIZE;
	proptag_buff[1] = PROP_TAG_PROHIBITSENDQUOTA;
	proptag_buff[2] = PR_MESSAGE_SIZE_EXTENDED;
	if (FALSE == logon_object_get_properties(
		plogon, &tmp_proptags, &tmp_propvals)) {
		return ecError;
	}

	auto sendquota = static_cast<uint32_t *>(common_util_get_propvals(&tmp_propvals, PROP_TAG_PROHIBITSENDQUOTA));
	auto storesize = static_cast<uint64_t *>(common_util_get_propvals(&tmp_propvals, PR_MESSAGE_SIZE_EXTENDED));
	/* Sendquota is in KiB, storesize in bytes */
	if (sendquota != nullptr && storesize != nullptr &&
	    static_cast<uint64_t>(*sendquota) * 1024 <= *storesize)
		return ecQuotaExceeded;

	pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_MAXIMUMSUBMITMESSAGESIZE);
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
	if (FALSE == message_object_get_properties(
		pmessage, 0, &tmp_proptags, &tmp_propvals)) {
		return ecError;
	}
	pvalue = common_util_get_propvals(&tmp_propvals, PR_MESSAGE_SIZE);
	if (NULL == pvalue) {
		return ecError;
	}
	mail_length = *(uint32_t*)pvalue;
	if (max_length > 0 && mail_length > static_cast<uint32_t>(max_length))
		return EC_EXCEEDED_SIZE;
	pvalue = common_util_get_propvals(&tmp_propvals, PR_MESSAGE_FLAGS);
	if (NULL == pvalue) {
		return ecError;
	}
	message_flags = *(uint32_t*)pvalue;
	if (MESSAGE_FLAG_SUBMITTED & message_flags) {
		return ecAccessDenied;
	}
	BOOL b_unsent = (message_flags & MESSAGE_FLAG_UNSENT) ? TRUE : false;
	pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_DELETEAFTERSUBMIT);
	BOOL b_delete = pvalue != nullptr && *static_cast<uint8_t *>(pvalue) != 0 ? TRUE : false;
	/* we don't use spool queue, so disable the whole functionality */
#if 0
	/* check if it is alread in spooler queue */
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon), fid_spooler,
		message_object_get_id(pmessage), &b_exist)) {
		return ecError;
	}
	if (TRUE == b_exist) {
		return ecAccessDenied;
	}
	if (submit_flags & SUBMIT_FLAG_NEEDS_SPOOLER) {
		if (FALSE == exmdb_client_link_message(
			logon_object_get_dir(plogon), pinfo->cpid,
			fid_spooler, message_object_get_id(pmessage),
			&b_result) || FALSE == b_result) {
			return ecError;
		}
		return ecSuccess;
	}
#endif
	
	if (FALSE == exmdb_client_try_mark_submit(
		logon_object_get_dir(plogon),
		message_object_get_id(pmessage), &b_marked)) {
		return ecError;
	}
	if (FALSE == b_marked) {
		return ecAccessDenied;
	}
	
	deferred_time = 0;
	time(&cur_time);
	submit_time = rop_util_unix_to_nttime(cur_time);
	pvalue = common_util_get_propvals(&tmp_propvals,
							PROP_TAG_DEFERREDSENDTIME);
	if (NULL != pvalue) {
		if (submit_time < *(uint64_t*)pvalue) {
			deferred_time = rop_util_nttime_to_unix(
						*(uint64_t*)pvalue) - cur_time;
		}
	} else {
		pvalue = common_util_get_propvals(&tmp_propvals,
							PROP_TAG_DEFERREDSENDNUMBER);
		if (NULL != pvalue) {
			tmp_num = *(uint32_t*)pvalue;
			pvalue = common_util_get_propvals(&tmp_propvals,
								PROP_TAG_DEFERREDSENDUNITS);
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
			logon_object_get_account(plogon),
			static_cast<unsigned long long>(rop_util_get_gc_value(
				message_object_get_id(pmessage))));
		timer_id = common_util_add_timer(
			command_buff, deferred_time);
		if (0 == timer_id) {
			goto SUBMIT_FAIL;
		}
		exmdb_client_set_message_timer(
			logon_object_get_dir(plogon),
			message_object_get_id(pmessage), timer_id);
		message_object_reload(pmessage);
		return ecSuccess;
	}
	
	if (FALSE == common_util_send_message(plogon,
		message_object_get_id(pmessage), TRUE)) {
		goto SUBMIT_FAIL;
	}
	if (FALSE == b_delete) {
		message_object_reload(pmessage);
	} else {
		message_object_clear_unsent(pmessage);
	}
	return ecSuccess;

 SUBMIT_FAIL:
	exmdb_client_clear_submit(logon_object_get_dir(plogon),
				message_object_get_id(pmessage), b_unsent);
	return ecError;
}

uint32_t rop_abortsubmit(uint64_t folder_id, uint64_t message_id,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_exist;
	uint32_t *ptimer_id;
	uint64_t fid_spooler;
	uint32_t *pmessage_flags;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return ecError;
	}
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return ecNotSupported;
	}
	if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
		return ecAccessDenied;
	}
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon),
		folder_id, message_id, &b_exist)) {
		return ecError;
	}
	if (FALSE == b_exist) {
		return ecNotFound;
	}
	if (!exmdb_client_get_message_property(logon_object_get_dir(plogon),
	    nullptr, 0, message_id, PR_MESSAGE_FLAGS,
	    reinterpret_cast<void **>(&pmessage_flags)))
		return ecError;
	if (NULL == pmessage_flags) {
		return ecError;
	}
	if (*pmessage_flags & MESSAGE_FLAG_SUBMITTED) {
		if (FALSE == exmdb_client_get_message_timer(
			logon_object_get_dir(plogon), message_id, &ptimer_id)) {
			return ecError;
		}
		if (NULL != ptimer_id) {
			if (FALSE == common_util_cancel_timer(*ptimer_id)) {
				return ecUnableToAbort;
			}
		}
		if (FALSE == exmdb_client_clear_submit(
			logon_object_get_dir(plogon), message_id, TRUE)) {
			return ecError;
		}
		if (FALSE == common_util_save_message_ics(
			plogon, message_id, NULL)) {
			return ecError;
		}
		return ecSuccess;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon),
		fid_spooler, message_id, &b_exist)) {
		return ecError;
	}
	if (FALSE == b_exist) {
		return ecNotInQueue;
	}
	/* unlink the message in spooler queue */
	if (FALSE == exmdb_client_unlink_message(
		logon_object_get_dir(plogon), pinfo->cpid,
		fid_spooler, message_id)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_getaddresstypes(STRING_ARRAY *paddress_types,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	static const char *const address_types[] = {"SMTP", "EX"};
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return ecNotSupported;
	}
	paddress_types->count = 2;
	paddress_types->ppstr = const_cast<char **>(address_types);
	return ecSuccess;
}

uint32_t rop_setspooler(void *plogmap, uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return ecNotSupported;
	}
	return ecSuccess;
}

uint32_t rop_spoolerlockmessage(uint64_t message_id,
	uint8_t lock_stat, void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_exist;
	BOOL b_result;
	BOOL b_delete;
	BINARY *ptarget;
	uint64_t new_id;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t fid_spooler;
	uint32_t proptag_buff[3];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return ecError;
	}
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return ecNotSupported;
	}
	if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
		return ecAccessDenied;
	}
	if (LOCK_STAT_1STFINISHED != lock_stat) {
		return ecSuccess;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon),
		fid_spooler, message_id, &b_exist)) {
		return ecError;
	}
	if (FALSE == b_exist) {
		return ecNotInQueue;
	}
	/* unlink the message in spooler queue */
	if (FALSE == exmdb_client_unlink_message(
		logon_object_get_dir(plogon), pinfo->cpid,
		fid_spooler, message_id)) {
		return ecError;
	}
	tmp_proptags.count = 3;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_DELETEAFTERSUBMIT;
	proptag_buff[1] = PROP_TAG_TARGETENTRYID;
	proptag_buff[2] = PR_PARENT_ENTRYID;
	if (FALSE == exmdb_client_get_message_properties(
		logon_object_get_dir(plogon), NULL, 0,
		message_id, &tmp_proptags, &tmp_propvals)) {
		return ecError;
	}
	auto pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_DELETEAFTERSUBMIT);
	b_delete = FALSE;
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_delete = TRUE;
	}
	
	ptarget = static_cast<BINARY *>(common_util_get_propvals(&tmp_propvals,
	          PROP_TAG_TARGETENTRYID));
	pvalue = common_util_get_propvals(&tmp_propvals, PR_PARENT_ENTRYID);
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
		if (FALSE == exmdb_client_movecopy_message(
			logon_object_get_dir(plogon),
			logon_object_get_account_id(plogon),
			pinfo->cpid, message_id, folder_id,
			new_id, b_delete, &b_result)) {
			return ecError;
		}
	} else if (TRUE == b_delete) {
		exmdb_client_delete_message(logon_object_get_dir(plogon),
			logon_object_get_account_id(plogon), pinfo->cpid,
			parent_id, message_id, TRUE, &b_result);
	}
	return ecSuccess;
}

uint32_t rop_transportsend(TPROPVAL_ARRAY **pppropvals,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pvalue;
	int object_type;
	char username[UADDR_SIZE];
	const char *account;
	PROPTAG_ARRAY proptags;
	TAGGED_PROPVAL propval;
	uint32_t proptag_buff[7];
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return ecNotSupported;
	}
	if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
		return ecAccessDenied;
	}
	auto pmessage = static_cast<MESSAGE_OBJECT *>(rop_processor_get_object(plogmap,
	                logon_id, hin, &object_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_MESSAGE != object_type) {
		return ecNotSupported;
	}
	if (0 == message_object_get_id(pmessage)) {
		return ecNotSupported;
	}
	if (TRUE == message_object_check_importing(pmessage)) {
		return ecAccessDenied;
	}
	if (!exmdb_client_get_message_property(logon_object_get_dir(plogon),
	    nullptr, 0, message_object_get_id(pmessage), PR_MESSAGE_FLAGS,
	    &pvalue))
		return ecError;
	if (NULL != pvalue && (*(uint32_t*)pvalue &
		MESSAGE_FLAG_SUBMITTED)) {
		return ecAccessDenied;
	}
	if (!oxomsg_check_delegate(pmessage, username, GX_ARRAY_SIZE(username)))
		return ecError;
	account = logon_object_get_account(plogon);
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
		proptag_buff[0] = PROP_TAG_SENDERNAME;
		proptag_buff[1] = PROP_TAG_SENDERENTRYID;	
		proptag_buff[2] = PROP_TAG_SENDERSEARCHKEY;
		proptag_buff[3] = PROP_TAG_SENTREPRESENTINGNAME;
		proptag_buff[4] = PROP_TAG_SENTREPRESENTINGENTRYID;
		proptag_buff[5] = PROP_TAG_SENTREPRESENTINGSEARCHKEY;
		proptag_buff[6] = PROP_TAG_PROVIDERSUBMITTIME;
		if (FALSE == message_object_get_properties(
			pmessage, 0, &proptags, *pppropvals)) {
			*pppropvals = NULL;
		}
		if (NULL == common_util_get_propvals(
			*pppropvals, PROP_TAG_PROVIDERSUBMITTIME)) {
			propval.proptag = PROP_TAG_PROVIDERSUBMITTIME;
			propval.pvalue = cu_alloc<uint64_t>();
			if (NULL != propval.pvalue) {
				*(uint64_t*)propval.pvalue = rop_util_current_nttime();
				common_util_set_propvals(*pppropvals, &propval);
			}
		}
	}
	if (FALSE == common_util_send_message(plogon,
		message_object_get_id(pmessage), FALSE)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_transportnewmail(uint64_t message_id,
	uint64_t folder_id, const char *pstr_class,
	uint32_t message_flags, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (FALSE == exmdb_client_transport_new_mail(
		logon_object_get_dir(plogon), message_id,
		folder_id, message_flags, pstr_class)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_gettransportfolder(uint64_t *pfolder_id,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecNullObject;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return ecNotSupported;
	}
	*pfolder_id = rop_util_make_eid_ex(1, PRIVATE_FID_OUTBOX);
	return ecSuccess;
}

uint32_t rop_optionsdata(const char *paddress_type,
	uint8_t want_win32, uint8_t *preserved,
	BINARY *poptions_info, BINARY *phelp_file,
	char **ppfile_name, void *plogmap,
	uint8_t logon_id, uint32_t hin)
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
