#include "emsmdb_interface.h"
#include "message_object.h"
#include "rop_processor.h"
#include "logon_object.h"
#include "exmdb_client.h"
#include "proc_common.h"
#include "common_util.h"
#include "list_file.h"
#include "rop_util.h"
#include "rops.h"
#include <stdio.h>


static BOOL oxomsg_rectify_message(MESSAGE_OBJECT *pmessage,
	const char *representing_username)
{
	BINARY *pentryid;
	uint64_t nt_time;
	uint8_t tmp_byte;
	int32_t tmp_level;
	BINARY search_bin;
	BINARY search_bin1;
	EMSMDB_INFO *pinfo;
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
	pinfo = emsmdb_interface_get_emsmdb_info();
	tmp_propvals.count = 16;
	tmp_propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PROP_TAG_READ;
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
	propval_buff[5].pvalue = "EX";
	if (FALSE == common_util_username_to_essdn(account, essdn_buff)) {
		return FALSE;
	}
	if (FALSE == common_util_get_user_displayname(account, tmp_display)) {
		return FALSE;
	}
	pentryid = common_util_username_to_addressbook_entryid(account);
	if (NULL == pentryid) {
		return FALSE;
	}
	search_bin.cb = snprintf(search_buff, 1024, "EX:%s", essdn_buff) + 1;
	search_bin.pb = search_buff;
	propval_buff[6].proptag = PROP_TAG_SENDEREMAILADDRESS;
	propval_buff[6].pvalue = essdn_buff;
	propval_buff[7].proptag = PROP_TAG_SENDERNAME;
	propval_buff[7].pvalue = tmp_display;
	propval_buff[8].proptag = PROP_TAG_SENDERENTRYID;
	propval_buff[8].pvalue = pentryid;
	propval_buff[9].proptag = PROP_TAG_SENDERSEARCHKEY;
	propval_buff[9].pvalue = &search_bin;
	if (0 != strcasecmp(account, representing_username)) {
		if (FALSE == common_util_username_to_essdn(
			representing_username, essdn_buff1)) {
			return FALSE;
		}
		if (FALSE == common_util_get_user_displayname(
			representing_username, tmp_display1)) {
			return FALSE;
		}
		pentryid = common_util_username_to_addressbook_entryid(
										representing_username);
		if (NULL == pentryid) {
			return FALSE;
		}
	} else {
		strcpy(essdn_buff1, essdn_buff);
		strcpy(tmp_display1, tmp_display);
	}
	search_bin1.cb = snprintf(search_buff1, 1024, "EX:%s", essdn_buff1) + 1;
	search_bin1.pb = search_buff1;
	propval_buff[10].proptag = PROP_TAG_SENTREPRESENTINGSMTPADDRESS;
	propval_buff[10].pvalue = (void*)representing_username;
	propval_buff[11].proptag = PROP_TAG_SENTREPRESENTINGADDRESSTYPE;
	propval_buff[11].pvalue = "EX";
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
		return FALSE;	
	}
	return message_object_save(pmessage);
}

static BOOL oxomsg_check_delegate(MESSAGE_OBJECT *pmessage, char *username)
{
	void *pvalue;
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
	pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_SENTREPRESENTINGADDRESSTYPE);
	if (NULL != pvalue) {
		if (0 == strcasecmp(pvalue, "EX")) {
			pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
			if (NULL != pvalue) {
				return common_util_essdn_to_username(pvalue, username);
			}
		} else if (0 == strcasecmp(pvalue, "SMTP")) {
			pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
			if (NULL != pvalue) {
				strncpy(username, pvalue, 256);
				return TRUE;
			}
		}
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
	if (NULL != pvalue) {
		strncpy(username, pvalue, 256);
		return TRUE;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
					PROP_TAG_SENTREPRESENTINGENTRYID);
	if (NULL != pvalue) {
		return common_util_entryid_to_username(pvalue, username);
	}
	username[0] = '\0';
	return TRUE;
}

static BOOL oxomsg_check_permission(const char *account,
	const char *account_representing)
{
	char *pitem;
	int i, item_num;
	LIST_FILE *pfile;
	char maildir[256];
	char temp_path[256];
	
	if (0 == strcasecmp(account, account_representing)) {
		return TRUE;
	}
	if (FALSE == common_util_get_maildir(
		account_representing, maildir)) {
		return FALSE;
	}
	sprintf(temp_path, "%s/config/delegates.txt", maildir);
	pfile = list_file_init(temp_path, "%s:256");
	if (NULL == pfile) {
		return FALSE;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(pitem + 256*i, account) ||
			TRUE == common_util_check_mlist_include(
			pitem + 256*i, account)) {
			list_file_free(pfile);
			return TRUE;
		}
	}
	list_file_free(pfile);
	return FALSE;
}

uint32_t rop_submitmessage(uint8_t submit_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int timer_id;
	void *pvalue;
	BOOL b_exist;
	BOOL b_marked;
	BOOL b_result;
	BOOL b_unsent;
	BOOL b_delete;
	BINARY tmp_bin;
	int object_type;
	time_t cur_time;
	uint32_t tmp_num;
	uint16_t rcpt_num;
	char username[256];
	int32_t max_length;
	EMSMDB_INFO *pinfo;
	const char *account;
	uint32_t tag_access;
	uint32_t mail_length;
	LOGON_OBJECT *plogon;
	uint64_t fid_spooler;
	uint64_t submit_time;
	uint32_t deferred_time;
	uint32_t message_flags;
	char command_buff[1024];
	MESSAGE_OBJECT *pmessage;
	uint32_t proptag_buff[6];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	
	if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
		return EC_ACCESS_DENIED;
	}
	
	pmessage = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pmessage) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_MESSAGE != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (0 == message_object_get_id(pmessage)) {
		return EC_NOT_SUPPORTED;
	}
	if (TRUE == message_object_check_importing(pmessage)) {
		return EC_ACCESS_DENIED;
	}
	
	tag_access = message_object_get_tag_access(pmessage);
	if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
		return EC_ACCESS_DENIED;
	}
	
	if (FALSE == message_object_get_recipient_num(
		pmessage, &rcpt_num)) {
		return EC_ERROR;	
	}
	if (rcpt_num > common_util_get_param(COMMON_UTIL_MAX_RCPT)) {
		return EC_TOO_MANY_RECIPIENTS;
	}
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_ASSOCIATED;
	if (FALSE == message_object_get_properties(
		pmessage, 0, &tmp_proptags, &tmp_propvals)) {
		return EC_ERROR;	
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_ASSOCIATED);
	/* FAI message cannot be sent */
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		return EC_ACCESS_DENIED;
	}
	
	if (FALSE == oxomsg_check_delegate(pmessage, username)) {
		return EC_ERROR;
	}
	account = logon_object_get_account(plogon);
	if ('\0' == username[0]) {
		strcpy(username, account);
	} else {
		if (FALSE == oxomsg_check_permission(account, username)) {
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == oxomsg_rectify_message(pmessage, username)) {
		return EC_ERROR;
	}
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_MAXIMUMSUBMITMESSAGESIZE;
	if (FALSE == logon_object_get_properties(
		plogon, &tmp_proptags, &tmp_propvals)) {
		return EC_ERROR;	
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_MAXIMUMSUBMITMESSAGESIZE);
	max_length = -1;
	if (NULL != pvalue) {
		max_length = *(int32_t*)pvalue;
	}
	
	if (submit_flags & SUBMIT_FLAG_NEEDS_SPOOLER) {
		tmp_proptags.count = 2;
	} else {
		tmp_proptags.count = 6;
	}
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_MESSAGESIZE;
	proptag_buff[1] = PROP_TAG_MESSAGEFLAGS;
	proptag_buff[2] = PROP_TAG_DEFERREDSENDTIME;
	proptag_buff[3] = PROP_TAG_DEFERREDSENDNUMBER;
	proptag_buff[4] = PROP_TAG_DEFERREDSENDUNITS;
	proptag_buff[5] = PROP_TAG_DELETEAFTERSUBMIT;
	if (FALSE == message_object_get_properties(
		pmessage, 0, &tmp_proptags, &tmp_propvals)) {
		return EC_ERROR;
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_MESSAGESIZE);
	if (NULL == pvalue) {
		return EC_ERROR;
	}
	mail_length = *(uint32_t*)pvalue;
	if (max_length > 0 && mail_length > max_length) {
		return EC_EXCEEDED_SIZE;
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_MESSAGEFLAGS);
	if (NULL == pvalue) {
		return EC_ERROR;
	}
	message_flags = *(uint32_t*)pvalue;
	if (MESSAGE_FLAG_SUBMITTED & message_flags) {
		return EC_ACCESS_DENIED;
	}
	if (message_flags & MESSAGE_FLAG_UNSENT) {
		b_unsent = TRUE;
	} else {
		b_unsent = FALSE;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_DELETEAFTERSUBMIT);
	b_delete = FALSE;
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_delete = TRUE;
	}
	
	/* we don't use spool queue, so disable the whole functionality */
#if 0
	/* check if it is alread in spooler queue */
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon), fid_spooler,
		message_object_get_id(pmessage), &b_exist)) {
		return EC_ERROR;
	}
	if (TRUE == b_exist) {
		return EC_ACCESS_DENIED;
	}
	if (submit_flags & SUBMIT_FLAG_NEEDS_SPOOLER) {
		if (FALSE == exmdb_client_link_message(
			logon_object_get_dir(plogon), pinfo->cpid,
			fid_spooler, message_object_get_id(pmessage),
			&b_result) || FALSE == b_result) {
			return EC_ERROR;	
		}
		return EC_SUCCESS;
	}
#endif
	
	if (FALSE == exmdb_client_try_mark_submit(
		logon_object_get_dir(plogon),
		message_object_get_id(pmessage), &b_marked)) {
		return EC_ERROR;	
	}
	if (FALSE == b_marked) {
		return EC_ACCESS_DENIED;
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
		snprintf(command_buff, 1024, "notifysend %s %llu",
			logon_object_get_account(plogon),
			message_object_get_id(pmessage));
		timer_id = common_util_add_timer(
			command_buff, deferred_time);
		if (0 == timer_id) {
			goto SUBMIT_FAIL;
		}
		exmdb_client_set_message_timer(
			logon_object_get_dir(plogon),
			message_object_get_id(pmessage), timer_id);
		message_object_reload(pmessage);
		return EC_SUCCESS;
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
	return EC_SUCCESS;

SUBMIT_FAIL:
	exmdb_client_clear_submit(logon_object_get_dir(plogon),
				message_object_get_id(pmessage), b_unsent);
	return EC_ERROR;
}

uint32_t rop_abortsubmit(uint64_t folder_id, uint64_t message_id,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_exist;
	BOOL b_result;
	EMSMDB_INFO *pinfo;
	uint32_t *ptimer_id;
	LOGON_OBJECT *plogon;
	uint64_t fid_spooler;
	uint32_t *pmessage_flags;
	uint32_t proptag_buff[0];
	PROPTAG_ARRAY tmp_proptags;
	
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
		return EC_ACCESS_DENIED;
	}
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon),
		folder_id, message_id, &b_exist)) {
		return EC_ERROR;
	}
	if (FALSE == b_exist) {
		return EC_NOT_FOUND;
	}
	if (FALSE == exmdb_client_get_message_property(
		logon_object_get_dir(plogon), NULL, 0, message_id,
		PROP_TAG_MESSAGEFLAGS, (void**)&pmessage_flags)) {
		return EC_ERROR;	
	}
	if (NULL == pmessage_flags) {
		return EC_ERROR;
	}
	if (*pmessage_flags & MESSAGE_FLAG_SUBMITTED) {
		if (FALSE == exmdb_client_get_message_timer(
			logon_object_get_dir(plogon), message_id, &ptimer_id)) {
			return EC_ERROR;	
		}
		if (NULL != ptimer_id) {
			if (FALSE == common_util_cancel_timer(*ptimer_id)) {
				return EC_UNABLE_TO_ABORT;
			}
		}
		if (FALSE == exmdb_client_clear_submit(
			logon_object_get_dir(plogon), message_id, TRUE)) {
			return EC_ERROR;
		}
		if (FALSE == common_util_save_message_ics(
			plogon, message_id, NULL)) {
			return EC_ERROR;	
		}
		return EC_SUCCESS;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon),
		fid_spooler, message_id, &b_exist)) {
		return EC_ERROR;	
	}
	if (FALSE == b_exist) {
		return EC_NOT_IN_QUEUE;
	}
	/* unlink the message in spooler queue */
	if (FALSE == exmdb_client_unlink_message(
		logon_object_get_dir(plogon), pinfo->cpid,
		fid_spooler, message_id)) {
		return EC_ERROR;	
	}
	return EC_SUCCESS;
}

uint32_t rop_getaddresstypes(STRING_ARRAY *paddress_types,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	LOGON_OBJECT *plogon;
	static char* address_types[] = {"SMTP", "EX"};
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	paddress_types->count = 2;
	paddress_types->ppstr = address_types;
	return EC_SUCCESS;
}

uint32_t rop_setspooler(void *plogmap, uint8_t logon_id, uint32_t hin)
{
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	return EC_SUCCESS;
}

uint32_t rop_spoolerlockmessage(uint64_t message_id,
	uint8_t lock_stat, void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pvalue;
	BOOL b_exist;
	BOOL b_result;
	BOOL b_delete;
	BINARY *ptarget;
	uint64_t new_id;
	EMSMDB_INFO *pinfo;
	uint64_t parent_id;
	uint64_t folder_id;
	LOGON_OBJECT *plogon;
	uint64_t fid_spooler;
	uint32_t proptag_buff[3];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
		return EC_ACCESS_DENIED;
	}
	if (LOCK_STAT_1STFINISHED != lock_stat) {
		return EC_SUCCESS;
	}
	fid_spooler = rop_util_make_eid_ex(1, PRIVATE_FID_SPOOLER_QUEUE);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon),
		fid_spooler, message_id, &b_exist)) {
		return EC_ERROR;	
	}
	if (FALSE == b_exist) {
		return EC_NOT_IN_QUEUE;
	}
	/* unlink the message in spooler queue */
	if (FALSE == exmdb_client_unlink_message(
		logon_object_get_dir(plogon), pinfo->cpid,
		fid_spooler, message_id)) {
		return EC_ERROR;	
	}
	tmp_proptags.count = 3;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_DELETEAFTERSUBMIT;
	proptag_buff[1] = PROP_TAG_TARGETENTRYID;
	proptag_buff[2] = PROP_TAG_PARENTENTRYID;
	if (FALSE == exmdb_client_get_message_properties(
		logon_object_get_dir(plogon), NULL, 0,
		message_id, &tmp_proptags, &tmp_propvals)) {
		return EC_ERROR;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_DELETEAFTERSUBMIT);
	b_delete = FALSE;
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_delete = TRUE;
	}
	
	ptarget = common_util_get_propvals(&tmp_propvals,
							PROP_TAG_TARGETENTRYID);
	pvalue = common_util_get_propvals(&tmp_propvals,
							PROP_TAG_PARENTENTRYID);
	if (NULL == pvalue) {
		return EC_ERROR;
	}
	if (FALSE == common_util_from_folder_entryid(
		plogon, pvalue, &parent_id)) {
		return EC_ERROR;
	}
	if (NULL != ptarget) {
		if (FALSE == common_util_from_message_entryid(
			plogon, ptarget, &folder_id, &new_id)) {
			return EC_ERROR;	
		}
		if (FALSE == exmdb_client_movecopy_message(
			logon_object_get_dir(plogon),
			logon_object_get_account_id(plogon),
			pinfo->cpid, message_id, folder_id,
			new_id, b_delete, &b_result)) {
			return EC_ERROR;
		}
	} else if (TRUE == b_delete) {
		exmdb_client_delete_message(logon_object_get_dir(plogon),
			logon_object_get_account_id(plogon), pinfo->cpid,
			parent_id, message_id, TRUE, &b_result);
	}
	return EC_SUCCESS;
}

uint32_t rop_transportsend(TPROPVAL_ARRAY **pppropvals,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pvalue;
	int object_type;
	char username[256];
	const char *account;
	LOGON_OBJECT *plogon;
	PROPTAG_ARRAY proptags;
	TAGGED_PROPVAL propval;
	uint32_t proptag_buff[7];
	MESSAGE_OBJECT *pmessage;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
		return EC_ACCESS_DENIED;
	}
	pmessage = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pmessage) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_MESSAGE != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (0 == message_object_get_id(pmessage)) {
		return EC_NOT_SUPPORTED;
	}
	if (TRUE == message_object_check_importing(pmessage)) {
		return EC_ACCESS_DENIED;
	}
	if (FALSE == exmdb_client_get_message_property(
		logon_object_get_dir(plogon), NULL, 0,
		message_object_get_id(pmessage),
		PROP_TAG_MESSAGEFLAGS, &pvalue)) {
		return EC_ERROR;	
	}
	if (NULL != pvalue && (*(uint32_t*)pvalue &
		MESSAGE_FLAG_SUBMITTED)) {
		return EC_ACCESS_DENIED;	
	}
	if (FALSE == oxomsg_check_delegate(pmessage, username)) {
		return EC_ERROR;
	}
	account = logon_object_get_account(plogon);
	if ('\0' == username[0]) {
		strcpy(username, account);
	} else {
		if (FALSE == oxomsg_check_permission(account, username)) {
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == oxomsg_rectify_message(pmessage, username)) {
		return EC_ERROR;
	}
	*pppropvals = common_util_alloc(sizeof(TPROPVAL_ARRAY));
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
			propval.pvalue = common_util_alloc(sizeof(uint64_t));
			if (NULL != propval.pvalue) {
				*(uint64_t*)propval.pvalue = rop_util_current_nttime();
				common_util_set_propvals(*pppropvals, &propval);
			}
		}
	}
	if (FALSE == common_util_send_message(plogon,
		message_object_get_id(pmessage), FALSE)) {
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t rop_transportnewmail(uint64_t message_id,
	uint64_t folder_id, const char *pstr_class,
	uint32_t message_flags, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	LOGON_OBJECT *plogon;	
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	if (FALSE == exmdb_client_transport_new_mail(
		logon_object_get_dir(plogon), message_id,
		folder_id, message_flags, pstr_class)) {
		return EC_ERROR;	
	}
	return EC_SUCCESS;
}

uint32_t rop_gettransportfolder(uint64_t *pfolder_id,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_NULL_OBJECT;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return EC_NOT_SUPPORTED;
	}
	*pfolder_id = rop_util_make_eid_ex(1, PRIVATE_FID_OUTBOX);
	return EC_SUCCESS;
}

uint32_t rop_optionsdata(const char *paddress_type,
	uint8_t want_win32, uint8_t *preserved,
	BINARY *poptions_info, BINARY *phelp_file,
	char **ppfile_name, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	*preserved = 1;
	poptions_info->cb = 300;
	poptions_info->pb = common_util_alloc(poptions_info->cb);
	if (NULL == poptions_info->pb) {
		return EC_OUT_OF_MEMORY;
	}
	memset(poptions_info->pb, 0, poptions_info->cb);
	phelp_file->cb = 0;
	*ppfile_name = NULL;
	return EC_SUCCESS;
}
