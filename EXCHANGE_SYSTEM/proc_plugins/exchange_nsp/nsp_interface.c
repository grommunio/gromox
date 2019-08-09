#include "nsp_interface.h"
#include "common_util.h"
#include "proc_common.h"
#include "list_file.h"
#include "ab_tree.h"
#include "util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

typedef struct _SORT_ITEM {
	uint32_t minid;
	char *string;
} SORT_ITEM;

static BOOL g_session_check;

static BOOL (*verify_cpid)(uint32_t cpid);
static BOOL (*get_domain_ids)(const char *domainname,
	int *pdomain_id, int *porg_id);
static BOOL (*get_maildir)(const char *username, char *maildir);
static BOOL (*get_id_from_username)(const char *username, int *puser_id);

static uint32_t nsp_interface_fetch_property(SIMPLE_TREE_NODE *pnode,
	BOOL b_ephid, uint32_t codepage, uint32_t proptag,
	PROPERTY_VALUE *pprop, char *pbuff)
{
	int minid;
	int temp_len;
	char dn[1280];
	GUID temp_guid;
	uint8_t node_type;
	const uint8_t *pguid;
	DCERPC_INFO rpc_info;
	uint32_t display_type;
	EPHEMERAL_ENTRYID ephid;
	PERMANENT_ENTRYID permeid;
	
	temp_len = 1024;
	pprop->proptag = proptag;
	pprop->reserved = 0;
	node_type = ab_tree_get_node_type(pnode);
	switch (proptag) {
	case PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE:
	case PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE_STRING8:
		if (NODE_TYPE_ROOM != node_type &&
			NODE_TYPE_PERSOPN != node_type &&
			NODE_TYPE_EQUIPMENT != node_type) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_server_dn(pnode, dn, sizeof(dn));
		strcat(dn, "/cn=Microsoft Private MDB");
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_ADDRESSBOOKOBJECTGUID:
		ab_tree_node_to_guid(pnode, &temp_guid);
		if (NULL == pbuff) {
			pprop->value.bin.pb = ndr_stack_alloc(NDR_STACK_OUT, 16);
			if (NULL == pprop->value.bin.pb) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.bin.pb = pbuff;
		}
		common_util_guid_to_binary(&temp_guid, &pprop->value.bin);
		break;
	case PROP_TAG_ADDRESSBOOKCONTAINERID:
		pnode = simple_tree_node_get_parent(pnode);
		if (NULL == pnode) {
			pprop->value.l = 0;
		} else {
			pprop->value.l = ab_tree_get_node_minid(pnode);
		}
		break;
	case PROP_TAG_ADDRESSTYPE:
	case PROP_TAG_ADDRESSTYPE_STRING8:
		pprop->value.pstr = "EX";
		break;
	case PROP_TAG_EMAILADDRESS:
	case PROP_TAG_EMAILADDRESS_STRING8:
		if (FALSE == ab_tree_node_to_dn(pnode, dn, 1024)) {
			return MAPI_E_INVALID_OBJECT;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_OBJECTTYPE:
		if (NODE_TYPE_MLIST == node_type) {
			pprop->value.l = OT_DISTLIST;
		} else if (NODE_TYPE_FOLDER == node_type) {
			pprop->value.l = OT_FOLDER;
		} else {
			pprop->value.l = OT_MAILUSER;
		}
		break;
	case PROP_TAG_DISPLAYTYPE:
		if (NODE_TYPE_MLIST == node_type) {
			pprop->value.l = DT_DISTLIST;
		} else {
			pprop->value.l = DT_MAILUSER;
		}
		break;
	case PROP_TAG_DISPLAYTYPEEX:
		if (NODE_TYPE_ROOM == node_type) {
			pprop->value.l = DT_ROOM;
		} else if (NODE_TYPE_EQUIPMENT == node_type) {
			pprop->value.l = DT_EQUIPMENT;
		} else {
			pprop->value.l = DT_MAILUSER | DTE_FLAG_ACL_CAPABLE;
		}
		break;
	case PROP_TAG_MAPPINGSIGNATURE:
		pprop->value.bin.cb = 16;
		if (NULL == pbuff) {
			pprop->value.bin.pb = ndr_stack_alloc(NDR_STACK_OUT, 16);
			if (NULL == pprop->value.bin.pb) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.bin.pb = pbuff;
		}
		pguid = common_util_get_nspi_guid();
		memcpy(pprop->value.bin.pb, pguid, 16);
		break;
	case PROP_TAG_SENDRICHINFO:
		pprop->value.b = 1;
		break;
	case PROP_TAG_TEMPLATEID:
		if (NODE_TYPE_MLIST == node_type) {
			display_type = DT_DISTLIST;
		} else {
			display_type = DT_MAILUSER;
		}
		if (FALSE == ab_tree_node_to_dn(pnode, dn, 1024)) {
			return MAPI_E_NOT_FOUND;
		}
		if (FALSE == common_util_set_permanententryid(
			display_type, NULL, dn, &permeid) || FALSE ==
			common_util_permanent_entryid_to_binary(
			&permeid, &pprop->value.bin)) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		break;
	case PROP_TAG_ENTRYID:
	case PROP_TAG_RECORDKEY:
	case PROP_TAG_ORIGINALENTRYID:
		if (NODE_TYPE_MLIST == node_type) {
			display_type = DT_DISTLIST;
		} else {
			display_type = DT_MAILUSER;
		}
		if (FALSE == b_ephid) {
			if (FALSE == ab_tree_node_to_dn(pnode, dn, 1024)) {
				return MAPI_E_NOT_FOUND;
			}
			if (FALSE == common_util_set_permanententryid(
				display_type, NULL, dn, &permeid) || FALSE ==
				common_util_permanent_entryid_to_binary(
				&permeid, &pprop->value.bin)) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			common_util_set_ephemeralentryid(display_type,
				ab_tree_get_node_minid(pnode), &ephid);
			if (FALSE == common_util_ephemeral_entryid_to_binary(
				&ephid, &pprop->value.bin)) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		}
		break;
	case PROP_TAG_SEARCHKEY:
		if (FALSE == ab_tree_node_to_dn(pnode, dn, 1024)) {
			return MAPI_E_NOT_FOUND;
		}
		pprop->value.bin.cb = strlen(dn) + 4;
		if (NULL == pbuff) {
			pprop->value.bin.pb = ndr_stack_alloc(
				NDR_STACK_OUT, pprop->value.bin.cb);
			if (NULL == pprop->value.bin.pb) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.bin.pb = pbuff;
		}
		sprintf(pprop->value.bin.pb, "EX:%s", dn);
		upper_string(pprop->value.bin.pb);
		break;
	case PROP_TAG_INSTANCEKEY:
		if (NULL == pbuff) {
			pprop->value.bin.pb = ndr_stack_alloc(NDR_STACK_OUT, 4);
			if (NULL == pprop->value.bin.pb) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.bin.pb = pbuff;
		}
		pprop->value.bin.cb = 4;
		minid = ab_tree_get_node_minid(pnode);
		pprop->value.bin.pb[0] = minid & 0xFF;
		pprop->value.bin.pb[1] = (minid >> 8) & 0xFF;
		pprop->value.bin.pb[2] = (minid >> 16) & 0xFF;
		pprop->value.bin.pb[3] = (minid >> 24) & 0xFF;
		break;
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
		if (node_type != NODE_TYPE_PERSOPN &&
			node_type != NODE_TYPE_EQUIPMENT &&
			node_type != NODE_TYPE_ROOM) {
			return MAPI_E_NOT_FOUND;
		}
	case PROP_TAG_DISPLAYNAME:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
		ab_tree_get_display_name(pnode, codepage, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8:
		if (node_type != NODE_TYPE_PERSOPN &&
			node_type != NODE_TYPE_EQUIPMENT &&
			node_type != NODE_TYPE_ROOM) {
			return MAPI_E_NOT_FOUND;
		}
	case PROP_TAG_DISPLAYNAME_STRING8:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8:
		ab_tree_get_display_name(pnode, codepage, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(
						NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_TITLE:
		if (NODE_TYPE_PERSOPN == node_type) {
			ab_tree_get_user_info(pnode, USER_JOB_TITLE, dn);
			if ('\0' == dn[0]) {
				return MAPI_E_NOT_FOUND;
			}
			if (NULL == pbuff) {
				pprop->value.pstr = ndr_stack_alloc(
					NDR_STACK_OUT, strlen(dn) + 1);
				if (NULL == pprop->value.pstr) {
					return MAPI_E_NOT_ENOUGH_MEMORY;
				}
			} else {
				pprop->value.pstr = pbuff;
			}
			strcpy(pprop->value.pstr, dn);
		} else if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_title(codepage, dn);
			if (NULL == pbuff) {
				pprop->value.pstr = ndr_stack_alloc(
					NDR_STACK_OUT, strlen(dn) + 1);
				if (NULL == pprop->value.pstr) {
					return MAPI_E_NOT_ENOUGH_MEMORY;
				}
			} else {
				pprop->value.pstr = pbuff;
			}
			strcpy(pprop->value.pstr, dn);
		} else {
			return MAPI_E_NOT_FOUND;
		}
		break;
	case PROP_TAG_TITLE_STRING8:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_JOB_TITLE, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(
						NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_NICKNAME:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_NICK_NAME, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_NICKNAME_STRING8:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_NICK_NAME, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(
						NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_PRIMARYTELEPHONENUMBER:
	case PROP_TAG_BUSINESSTELEPHONENUMBER:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_BUSINESS_TEL, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8:
	case PROP_TAG_BUSINESSTELEPHONENUMBER_STRING8:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_BUSINESS_TEL, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_MOBILETELEPHONENUMBER:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_MOBILE_TEL, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_MOBILETELEPHONENUMBER_STRING8:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_MOBILE_TEL, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_HOMEADDRESSSTREET:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_HOME_ADDRESS, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_HOMEADDRESSSTREET_STRING8:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_HOME_ADDRESS, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_COMMENT:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_COMMENT, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_COMMENT_STRING8:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_COMMENT, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_COMPANYNAME:
		ab_tree_get_company_info(pnode, dn, NULL);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_COMPANYNAME_STRING8:
		ab_tree_get_company_info(pnode, dn, NULL);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_DEPARTMENTNAME:
		ab_tree_get_department_name(pnode, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_DEPARTMENTNAME_STRING8:
		ab_tree_get_department_name(pnode, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_OFFICELOCATION:
		ab_tree_get_company_info(pnode, NULL, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_OFFICELOCATION_STRING8:
		ab_tree_get_company_info(pnode, NULL, dn);
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pstr = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		break;
	case PROP_TAG_ACCOUNT:
	case PROP_TAG_ACCOUNT_STRING8:
	case PROP_TAG_SMTPADDRESS:
	case PROP_TAG_SMTPADDRESS_STRING8:
		if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		} else if (NODE_TYPE_PERSOPN == node_type ||
			NODE_TYPE_EQUIPMENT == node_type ||
			NODE_TYPE_ROOM == node_type) {
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn);
		} else {
			return MAPI_E_NOT_FOUND;
		}
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		if (NULL == pbuff) {
			pprop->value.pstr = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.pstr = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		break;
	case PROP_TAG_ADDRESSBOOKPROXYADDRESSES:
	case PROP_TAG_ADDRESSBOOKPROXYADDRESSES_STRING8:
		if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		} else if (NODE_TYPE_PERSOPN == node_type ||
			NODE_TYPE_EQUIPMENT == node_type ||
			NODE_TYPE_ROOM == node_type) {
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn);
		} else {
			return MAPI_E_NOT_FOUND;
		}
		if ('\0' == dn[0]) {
			return MAPI_E_NOT_FOUND;
		}
		pprop->value.string_array.cvalues = 1;
		if (NULL == pbuff) {
			pprop->value.string_array.ppstr =
				ndr_stack_alloc(NDR_STACK_OUT, sizeof(char**));
			if (NULL == pprop->value.string_array.ppstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
			pprop->value.string_array.ppstr[0] =
				ndr_stack_alloc(NDR_STACK_OUT, strlen(dn) + 6);
			if (NULL == pprop->value.string_array.ppstr[0]) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.string_array.ppstr = (char**)pbuff;
			pprop->value.string_array.ppstr[0] = pbuff + sizeof(char**);
		}
		sprintf(pprop->value.string_array.ppstr[0], "SMTP:%s", dn);
		break;
	case PROP_TAG_ADDRESSBOOKNETWORKADDRESS:
	case PROP_TAG_ADDRESSBOOKNETWORKADDRESS_STRING8:
		rpc_info = get_rpc_info();
		temp_len = strlen(rpc_info.ep_host);
		pprop->value.string_array.cvalues = 2;
		if (NULL == pbuff) {
			pprop->value.string_array.ppstr =
				ndr_stack_alloc(NDR_STACK_OUT, 2*sizeof(char**));
			if (NULL == pprop->value.string_array.ppstr) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
			pprop->value.string_array.ppstr[0] =
				ndr_stack_alloc(NDR_STACK_OUT, temp_len + 14);
			if (NULL == pprop->value.string_array.ppstr[0]) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
			pprop->value.string_array.ppstr[1] =
				ndr_stack_alloc(NDR_STACK_OUT, temp_len - 12);
			if (NULL == pprop->value.string_array.ppstr[1]) {
				return MAPI_E_NOT_ENOUGH_MEMORY;
			}
		} else {
			pprop->value.string_array.ppstr = (char**)pbuff;
			pprop->value.string_array.ppstr[0] =
						pbuff + 2*sizeof(char**);
			pprop->value.string_array.ppstr[1] =
				pbuff + 2*sizeof(char**) + temp_len + 1;
		}
		sprintf(pprop->value.string_array.ppstr[0],
			"ncacn_ip_tcp:%s", rpc_info.ep_host);
		sprintf(pprop->value.string_array.ppstr[1],
			"ncacn_http:%s", rpc_info.ep_host);
		break;
	case PROP_TAG_CREATIONTIME:
		if (node_type == NODE_TYPE_MLIST) {
			ab_tree_get_mlist_info(pnode, NULL, dn, NULL);
		} else if (node_type == NODE_TYPE_PERSOPN) {
			ab_tree_get_user_info(pnode, USER_CREATE_DAY, dn);
		} else {
			return MAPI_E_NOT_FOUND;
		}
		common_util_day_to_filetime(dn, &pprop->value.ftime);
		break;
	case PROP_TAG_THUMBNAILPHOTO:
		if (node_type != NODE_TYPE_PERSOPN) {
			return MAPI_E_NOT_FOUND;
		}
		ab_tree_get_user_info(pnode, USER_STORE_PATH, dn);
		strcat(dn, "/config/portrait.jpg");
		if (FALSE == common_util_load_file(dn, &pprop->value.bin)) {
			return MAPI_E_NOT_FOUND;
		}
		break;
	default:
		return MAPI_E_NOT_FOUND;
	}
	return MAPI_E_SUCCESS;
}		

static uint32_t nsp_interface_fetch_row(SIMPLE_TREE_NODE *pnode,
	BOOL b_ephid, uint32_t codepage, PROPTAG_ARRAY *pproptags,
	PROPERTY_ROW *prow)
{
	int i;
	uint32_t err_val;
	uint32_t tmp_tag;
	uint8_t node_type;
	PROPERTY_VALUE *pprop;
	
	node_type = ab_tree_get_node_type(pnode);
	if (node_type > 0x80) {
		return MAPI_E_INVALID_OBJECT;
	}
	for (i=0; i<pproptags->cvalues; i++) {
		pprop = common_util_propertyrow_enlarge(prow);
		if (NULL == pprop) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		err_val = nsp_interface_fetch_property(pnode, b_ephid,
				codepage, pproptags->pproptag[i], pprop, NULL);
		if (MAPI_E_SUCCESS != err_val) {
			tmp_tag = pprop->proptag;
			tmp_tag &= 0xFFFF0000;
			tmp_tag += PROPVAL_TYPE_ERROR;
			pprop->proptag = tmp_tag;
			pprop->value.err = err_val;
		}
	}
	return MAPI_E_SUCCESS;
}

void nsp_interface_init(BOOL b_check)
{
	g_session_check = b_check;
}

int nsp_interface_run()
{
	get_domain_ids = query_service("get_domain_ids");
	if (NULL == get_domain_ids) {
		printf("[exchange_nsp]: fail to get"
			" \"get_domain_ids\" service\n");
		return -1;
	}
	get_maildir = query_service("get_maildir");
	if (NULL == get_maildir) {
		printf("[exchange_nsp]: fail to get"
				" \"get_maildir\" service\n");
		return -1;
	}
	get_id_from_username = query_service("get_id_from_username");
	if (NULL == get_id_from_username) {
		printf("[exchange_nsp]: fail to get "
			"\"get_id_from_username\" service\n");
		return -1;
	}
	verify_cpid = query_service("verify_cpid");
	if (NULL == verify_cpid) {
		printf("[exchange_nsp]: fail to get"
				" \"verify_cpid\" service\n");
		return -1;
	}
	return 0;
}

int nsp_interface_stop()
{
	return 0;
}

void nsp_interface_free()
{
	/* do nothing */
}

int nsp_interface_bind(uint64_t hrpc, uint32_t flags,
	STAT *pstat, FLATUID *pserver_guid, NSPI_HANDLE *phandle)
{
	int org_id;
	int base_id;
	int domain_id;
	char *pdomain;
	AB_BASE *pbase;
	DCERPC_INFO rpc_info;
	
	rpc_info = get_rpc_info();
	if (0 != (flags & FLAG_ANONYMOUSLOGIN)) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return MAPI_E_FAILONEPROVIDER;
	}
	if (CODEPAGE_UNICODE == pstat->codepage) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return MAPI_E_NO_SUPPORT;
	}
	/* check if valid cpid has been supplied */
	if (FALSE == verify_cpid(pstat->codepage)) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return MAPI_E_UNKNOWN_CPID;
	}
	pdomain = strchr(rpc_info.username, '@');
	if (NULL == pdomain) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return MAPI_E_LOGON_FAILED;
	}
	pdomain ++;
	if (FALSE == get_domain_ids(pdomain, &domain_id, &org_id)) {
		phandle->handle_type = HANDLE_EXCHANGE_NSP;
		memset(&phandle->guid, 0, sizeof(GUID));
		return MAPI_E_CALL_FAILED;
	}
	phandle->handle_type = HANDLE_EXCHANGE_NSP;
	if (0 == org_id) {
		base_id = domain_id * (-1);
	} else {
		base_id = org_id;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase) {
		memset(&phandle->guid, 0, sizeof(GUID));
		return MAPI_E_CALL_FAILED;
	}
	phandle->guid = pbase->guid;
	ab_tree_put_base(pbase);
	if (NULL != pserver_guid) {
		*(GUID*)pserver_guid = common_util_get_server_guid();
	}
	return MAPI_E_SUCCESS;
}

uint32_t nsp_interface_unbind(NSPI_HANDLE *phandle, uint32_t reserved)
{
	memset(phandle, 0, sizeof(NSPI_HANDLE));
	return MAPI_E_UNBINDSUCCESS;
}

static uint32_t nsp_interface_minid_in_list(
	SINGLE_LIST *plist, uint32_t row)
{
	int count;
	SINGLE_LIST_NODE *pnode;
	
	count = 0;
	for (pnode=single_list_get_head(plist); NULL!=pnode;
		pnode=single_list_get_after(plist, pnode)) {
		if (count == row) {
			return ab_tree_get_node_minid(pnode->pdata);
		}
		count ++;
	}
	return 0;
}

static void nsp_interface_position_in_list(STAT *pstat,
	SINGLE_LIST *plist, uint32_t *pout_row,
	uint32_t *pout_last_row, uint32_t *pcount)
{
	BOOL b_found;
	uint32_t row;
	uint32_t minid;
	uint32_t last_row;
	SINGLE_LIST_NODE *pnode;

	*pcount = single_list_get_nodes_num(plist);
	if (*pcount > 0) {
		last_row = *pcount - 1;
	} else {
		last_row = 0;
	}
	if (MID_CURRENT == pstat->cur_rec) {
		/* fractional positioning MS-OXNSPI 3.1.4.5.2 */
		row = pstat->num_pos * (last_row + 1) / pstat->total_rec;
		if (row > last_row) {
			row = last_row;
		}
	} else {
		/* absolute positioning MS-OXNSPI 3.1.4.5.1 */
		if (MID_BEGINNING_OF_TABLE == pstat->cur_rec) {
			row = 0;
		}
		else if (MID_END_OF_TABLE ==  pstat->cur_rec) {
			row = last_row + 1;
		} else {
			b_found = FALSE;
			row = 0;
			for (pnode=single_list_get_head(plist); NULL!=pnode;
				pnode=single_list_get_after(plist, pnode)) {
				minid = ab_tree_get_node_minid(pnode->pdata);
				if (0 != minid && minid == pstat->cur_rec) {
					b_found = TRUE;
					break;
				}
				row ++;
			}
			if (FALSE == b_found) {
				/* In this case the position is undefined.
				   To avoid problems we will use first row */
				row = 0;
			}
		}
	}
	*pout_row = row;
	*pout_last_row = last_row;
}

static void nsp_interface_position_in_table(STAT *pstat,
	SIMPLE_TREE_NODE *pnode, uint32_t *pout_row,
	uint32_t *pout_last_row, uint32_t *pcount)
{
	BOOL b_found;
	uint32_t row;
	uint32_t minid;
	uint32_t last_row;

	*pcount = ab_tree_get_leaves_num(pnode);
	if (*pcount > 0) {
		last_row = *pcount - 1;
	} else {
		last_row = 0;
	}
	if (MID_CURRENT == pstat->cur_rec) {
		/* fractional positioning MS-OXNSPI 3.1.4.5.2 */
		row = pstat->num_pos * (last_row + 1) / pstat->total_rec;
		if (row > last_row) {
			row = last_row;
		}
	} else {
		/* absolute positioning MS-OXNSPI 3.1.4.5.1 */
		if (MID_BEGINNING_OF_TABLE == pstat->cur_rec) {
			row = 0;
		}
		else if (MID_END_OF_TABLE == pstat->cur_rec) {
			row = last_row + 1;
		} else {
			b_found = FALSE;
			row = 0;
			pnode = simple_tree_node_get_child(pnode);
			if (NULL != pnode) {
				do {
					if (ab_tree_get_node_type(pnode) < 0x80) {
						minid = ab_tree_get_node_minid(pnode);
						if (0 != minid && minid == pstat->cur_rec) {
							b_found = TRUE;
							break;
						}
						row ++;
					}
				} while (pnode = simple_tree_node_get_slibling(pnode));
				
			}
			if (FALSE == b_found) {
				/* In this case the position is undefined.
				   To avoid problems we will use first row */
				row = 0;
			}
		}
	}
	*pout_row = row;
	*pout_last_row = last_row;
}

static uint32_t nsp_interface_minid_in_table(
	SIMPLE_TREE_NODE *pnode, uint32_t row)
{
	int count;
	
	pnode = simple_tree_node_get_child(pnode);
	if (NULL == pnode) {
		return 0;
	}
	count = 0;
	do {
		if (count == row) {
			return ab_tree_get_node_minid(pnode);
		}
		if (ab_tree_get_node_type(pnode) < 0x80) {
			count ++;
		}
	} while (pnode=simple_tree_node_get_slibling(pnode));
	return 0;
}

int nsp_interface_update_stat(NSPI_HANDLE handle,
	uint32_t reserved, STAT *pstat, int32_t *pdelta)
{
	int base_id;
	uint32_t row;
	uint32_t total;
	AB_BASE *pbase;
	uint32_t last_row;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SINGLE_LIST_NODE *psnode;
	
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		return MAPI_E_NO_SUPPORT;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		return MAPI_E_CALL_FAILED;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return MAPI_E_CALL_FAILED;
	}
	if (0 == pstat->container_id) {
		pgal_list = &pbase->gal_list;
		nsp_interface_position_in_list(pstat,
			pgal_list, &row, &last_row, &total);
	} else {
		pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
		if (NULL == pnode) {
			ab_tree_put_base(pbase);
			return MAPI_E_INVALID_BOOKMARK;
		}
		nsp_interface_position_in_table(pstat,
			pnode, &row, &last_row, &total);
	}
	if (pstat->delta != 0) {
		/* adjust row  by delta */
		if (pstat->delta > 0) {
			row += pstat->delta;
			if (row > last_row) {
				row = last_row + 1;
			}
		} else {
			if (abs(pstat->delta) >= row) {
				row = 0;
			} else {
				row -= abs(pstat->delta);
			}
		}
	}
	if (row == last_row + 1) {
		pstat->cur_rec = MID_END_OF_TABLE;
	} else if (0 == row) {
		pstat->cur_rec = MID_BEGINNING_OF_TABLE;
	} else {
		if (0 == pstat->container_id) {
			pstat->cur_rec = nsp_interface_minid_in_list(pgal_list, row);
		} else {
			pstat->cur_rec = nsp_interface_minid_in_table(pnode, row);
		}
		if (0 == pstat->cur_rec) {
			row = 0;
			pstat->cur_rec = MID_BEGINNING_OF_TABLE;
		}
	}
	ab_tree_put_base(pbase);
	if (NULL != pdelta) {
		*pdelta = row - pstat->num_pos;
	}
	pstat->delta = 0;
	pstat->num_pos = row;
	pstat->total_rec = total;
	return MAPI_E_SUCCESS;
}

static void nsp_interface_make_ptyperror_row(
	PROPTAG_ARRAY *pproptags, PROPERTY_ROW *prow)
{
	int i;
	uint32_t tmp_tag;
	
	prow->reserved = 0x0;
	prow->cvalues = pproptags->cvalues;
	prow->pprops = ndr_stack_alloc(NDR_STACK_OUT,
			sizeof(PROPERTY_VALUE)*prow->cvalues);
	if (NULL == prow->pprops) {
		return;
	}
	for (i=0; i<prow->cvalues; i++) {
		tmp_tag = pproptags->pproptag[i];
		tmp_tag = (tmp_tag & 0xFFFF0000) | PROPVAL_TYPE_ERROR;

		prow->pprops[i].proptag = tmp_tag;
		prow->pprops[i].reserved = 0x0;
		prow->pprops[i].value.err = 0;
	}
}

int nsp_interface_query_rows(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, uint32_t table_count, uint32_t *ptable,
	uint32_t count, PROPTAG_ARRAY *pproptags, PROPROW_SET **pprows)
{
	int i;
	int total;
	int base_id;
	BOOL b_ephid;
	int tmp_count;
	AB_BASE *pbase;
	uint32_t result;
	uint32_t last_row;
	uint32_t start_pos;
	PROPERTY_ROW *prow;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SIMPLE_TREE_NODE *pnode1;
	SINGLE_LIST_NODE *psnode;
	
	
	if (FLAG_EPHID & flags) {
		b_ephid = TRUE;
	} else {
		b_ephid = FALSE;
	}
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	if (0 == count && NULL == ptable) {
		*pprows = NULL;
		return MAPI_E_INVALID_PARAMETER;
	}
	
	/* MS-OXNSPI 3.1.4.1.8.10 */
	if (0 == count) {
		count = 1;
	}
	
	if (NULL == pproptags) {
		pproptags = ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY));
		if (NULL == pproptags) {
			*pprows = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		pproptags->cvalues = 7;
		pproptags->pproptag = ndr_stack_alloc(NDR_STACK_IN,
						sizeof(uint32_t)*pproptags->cvalues);
		if (NULL == pproptags) {
			*pprows = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		pproptags->pproptag[0] = PROP_TAG_ADDRESSBOOKCONTAINERID;
		pproptags->pproptag[1] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[2] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[3] = PROP_TAG_DISPLAYNAME_STRING8;
		pproptags->pproptag[4] = PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8;
		pproptags->pproptag[5] = PROP_TAG_DEPARTMENTNAME_STRING8;
		pproptags->pproptag[6] = PROP_TAG_OFFICELOCATION_STRING8;
	} else {
		if (pproptags->cvalues > 100) {
			*pprows = NULL;
			return MAPI_E_TABLE_TOO_BIG;
		}
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	*pprows = common_util_proprowset_init();
	if (NULL == *pprows) {
		*pprows = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		*pprows = NULL;
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return MAPI_E_CALL_FAILED;
	}
	
	if (NULL == ptable) {
		if (0 == pstat->container_id) {
			pgal_list = &pbase->gal_list;
			nsp_interface_position_in_list(pstat,
				pgal_list, &start_pos, &last_row, &total);
		} else {
			pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
			if (NULL == pnode) {
				result = MAPI_E_INVALID_BOOKMARK;
				goto EXIT_QUERY_ROWS;
			}
			nsp_interface_position_in_table(pstat,
				pnode, &start_pos, &last_row, &total);
			pnode1 = simple_tree_node_get_child(pnode);
			if (NULL == pnode1) {
				result = MAPI_E_SUCCESS;
				goto EXIT_QUERY_ROWS;
			}
		}
		if (0 == total) {
			result = MAPI_E_SUCCESS;
			goto EXIT_QUERY_ROWS;
		}
		if (pstat->delta >= 0) {
			start_pos += pstat->delta;
			if (start_pos >= total) {
				start_pos = total;
			}
		} else {
			if (abs(pstat->delta) > pstat->num_pos) {
				start_pos = 0;
			} else {
				start_pos -= abs(pstat->delta);
			}
		}

		tmp_count = total - start_pos;
		if (count < tmp_count) {
			tmp_count = count;
		}
		if (0 == tmp_count) {
			result = MAPI_E_SUCCESS;
			goto EXIT_QUERY_ROWS;
		}
		i = 0;
		if (0 == pstat->container_id) {
			for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
				psnode=single_list_get_after(pgal_list, psnode)) {
				if (i >= start_pos && i < start_pos + tmp_count) {
					prow = common_util_proprowset_enlarge(*pprows);
					if (NULL == prow || NULL ==
						common_util_propertyrow_init(prow)) {
						result = MAPI_E_NOT_ENOUGH_MEMORY;
						goto EXIT_QUERY_ROWS;
					}
					result = nsp_interface_fetch_row(psnode->pdata,
						b_ephid, pstat->codepage, pproptags, prow);
					if (MAPI_E_SUCCESS != result) {
						goto EXIT_QUERY_ROWS;
					}
				}
				i ++;
			}
		} else {
			do {
				if (ab_tree_get_node_type(pnode1) > 0x80) {
					continue;
				}
				if (i >= start_pos && i < start_pos + tmp_count) {
					prow = common_util_proprowset_enlarge(*pprows);
					if (NULL == prow || NULL ==
						common_util_propertyrow_init(prow)) {
						result = MAPI_E_NOT_ENOUGH_MEMORY;
						goto EXIT_QUERY_ROWS;
					}
					result = nsp_interface_fetch_row(pnode1,
						b_ephid, pstat->codepage, pproptags, prow);
					if (MAPI_E_SUCCESS != result) {
						goto EXIT_QUERY_ROWS;
					}
				}
				i ++;
			} while (pnode1=simple_tree_node_get_slibling(pnode1));
		}

		if (start_pos + tmp_count == last_row + 1) {
			pstat->cur_rec = MID_END_OF_TABLE;
		} else if (0 == start_pos + tmp_count) {
			pstat->cur_rec = MID_BEGINNING_OF_TABLE;
		} else {
			if (0 == pstat->container_id) {
				pstat->cur_rec = nsp_interface_minid_in_list(
							pgal_list, start_pos + tmp_count);
			} else {
				pstat->cur_rec = nsp_interface_minid_in_table(
								pnode, start_pos + tmp_count);
			}
			if (0 == pstat->cur_rec) {
				pstat->cur_rec = MID_BEGINNING_OF_TABLE;
				start_pos = 0;
				tmp_count = 0;
			}
		}
		pstat->delta = 0;
		pstat->num_pos = start_pos + tmp_count;
		pstat->total_rec = total;
	} else {
		for (i=0; i<table_count; i++) {
			prow = common_util_proprowset_enlarge(*pprows);
			if (NULL == prow || NULL ==
				common_util_propertyrow_init(prow)) {
				result = MAPI_E_NOT_ENOUGH_MEMORY;
				goto EXIT_QUERY_ROWS;
			}
			pnode = ab_tree_minid_to_node(pbase, ptable[i]);
			if (NULL == pnode) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
				continue;
			}
			result = nsp_interface_fetch_row(pnode,
				b_ephid, pstat->codepage, pproptags, prow);
			if (MAPI_E_SUCCESS != result) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
			}
		}
	}
	result = MAPI_E_SUCCESS;
	
EXIT_QUERY_ROWS:
	ab_tree_put_base(pbase);
	if (MAPI_E_SUCCESS != result) {
		*pprows = NULL;
	}
	return result;
}

int nsp_interface_seek_entries(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPERTY_VALUE *ptarget, PROPTAG_ARRAY *ptable,
	PROPTAG_ARRAY *pproptags, PROPROW_SET **pprows)
{
	int total;
	int i, row;
	int base_id;
	AB_BASE *pbase;
	uint32_t result;
	uint32_t last_row;
	uint32_t start_pos;
	PROPERTY_ROW *prow;
	uint32_t tmp_minid;
	char temp_name[1024];
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SIMPLE_TREE_NODE *pnode1;
	SINGLE_LIST_NODE *psnode;
	
	
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	if (0 != reserved) {
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	if (SORT_TYPE_DISPLAYNAME == pstat->sort_type) {
		if (PROP_TAG_DISPLAYNAME != ptarget->proptag &&
			PROP_TAG_DISPLAYNAME_STRING8 != ptarget->proptag) {
			*pprows = NULL;
			return MAPI_E_CALL_FAILED;
		}
	} else if (SORT_TYPE_PHONETICDISPLAYNAME == pstat->sort_type) {
		if (PROP_TAG_ADDRESSBOOKPHONETICDISPLAYNAME != ptarget->proptag
			&& PROP_TAG_ADDRESSBOOKPHONETICDISPLAYNAME_STRING8 != 
			ptarget->proptag) {
			*pprows = NULL;
			return MAPI_E_CALL_FAILED;
		}
	} else {
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	if (NULL == pproptags) {
		pproptags = ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY));
		if (NULL == pproptags) {
			*pprows = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		pproptags->cvalues = 7;
		pproptags->pproptag = ndr_stack_alloc(NDR_STACK_IN,
						sizeof(uint32_t)*pproptags->cvalues);
		if (NULL == pproptags) {
			*pprows = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		pproptags->pproptag[0] = PROP_TAG_ADDRESSBOOKCONTAINERID;
		pproptags->pproptag[1] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[2] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[3] = PROP_TAG_DISPLAYNAME_STRING8;
		pproptags->pproptag[4] = PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8;
		pproptags->pproptag[5] = PROP_TAG_DEPARTMENTNAME_STRING8;
		pproptags->pproptag[6] = PROP_TAG_OFFICELOCATION_STRING8;
	} else {
		if (pproptags->cvalues > 100) {
			*pprows = NULL;
			return MAPI_E_TABLE_TOO_BIG;
		}
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	*pprows = common_util_proprowset_init();
	if (NULL == *pprows) {
		*pprows = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		*pprows = NULL;
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return MAPI_E_CALL_FAILED;
	}
	
	if (NULL != ptable) {
		row = 0;
		tmp_minid = 0;
		for (i=0; i<ptable->cvalues; i++) {
			pnode1 = ab_tree_minid_to_node(pbase, ptable->pproptag[i]);
			if (NULL == pnode1) {
				continue;
			}
			ab_tree_get_display_name(pnode1, pstat->codepage, temp_name);
			if (strcasecmp(temp_name, ptarget->value.pstr) < 0) {
				continue;
			}
			if (0 == tmp_minid) {
				tmp_minid = ptable->pproptag[i];
				row = i;
			}
			if (0 != tmp_minid) {
				prow = common_util_proprowset_enlarge(*pprows);
				if (NULL == prow || NULL ==
					common_util_propertyrow_init(prow)) {
					result = MAPI_E_NOT_ENOUGH_MEMORY;
					goto EXIT_SEEK_ENTRIES;
				}
				result = nsp_interface_fetch_row(pnode1, TRUE,
							pstat->codepage, pproptags, prow);
				if (MAPI_E_SUCCESS != result) {
					nsp_interface_make_ptyperror_row(pproptags, prow);
				}
			}
		}
		
		if (0 == tmp_minid) {
			result = MAPI_E_NOT_FOUND;
			goto EXIT_SEEK_ENTRIES;
		}
		
		pstat->total_rec = (*pprows)->crows;
		pstat->cur_rec = tmp_minid;
		pstat->num_pos = row;
	} else {
		if (0 == pstat->container_id) {
			pgal_list = &pbase->gal_list;
			nsp_interface_position_in_list(pstat,
				pgal_list, &start_pos, &last_row, &total);
		} else {
			pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
			if (NULL == pnode) {
				result = MAPI_E_INVALID_BOOKMARK;
				goto EXIT_SEEK_ENTRIES;
			}
			nsp_interface_position_in_table(pstat,
				pnode, &start_pos, &last_row, &total);
			pnode1 = simple_tree_node_get_child(pnode);
			if (NULL == pnode1) {
				result = MAPI_E_NOT_FOUND;
				goto EXIT_SEEK_ENTRIES;
			}
		}
		
		if (0 == total) {
			result = MAPI_E_NOT_FOUND;
			goto EXIT_SEEK_ENTRIES;
		}
		row = 0;
		if (0 == pstat->container_id) {
			for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
				psnode=single_list_get_after(pgal_list, psnode),row++) {
				if (i < start_pos) {
					continue;
				}
				ab_tree_get_display_name(psnode->pdata,
					pstat->codepage, temp_name);
				if (strcasecmp(temp_name, ptarget->value.pstr) >= 0) {
					prow = common_util_proprowset_enlarge(*pprows);
					if (NULL == prow ||
						NULL == common_util_propertyrow_init(prow)) {
						result = MAPI_E_NOT_ENOUGH_MEMORY;
						goto EXIT_SEEK_ENTRIES;
					}
					if (MAPI_E_SUCCESS != nsp_interface_fetch_row(
						psnode->pdata, TRUE, pstat->codepage,
						pproptags, prow)) {
						result = MAPI_E_CALL_FAILED;
						goto EXIT_SEEK_ENTRIES;
					}
					break;
				}
			}
			if (NULL == psnode) {
				result = MAPI_E_NOT_FOUND;
				goto EXIT_SEEK_ENTRIES;
			}
			pstat->cur_rec = ab_tree_get_node_minid(psnode->pdata);
		} else {
			pnode1 = simple_tree_node_get_child(pnode);
			do {
				if (ab_tree_get_node_type(pnode1) > 0x80) {
					continue;
				}
				if (row < start_pos) {
					row ++;
					continue;
				}
				ab_tree_get_display_name(pnode1,
					pstat->codepage, temp_name);
				if (strcasecmp(temp_name, ptarget->value.pstr) >= 0) {
					prow = common_util_proprowset_enlarge(*pprows);
					if (NULL == prow ||
						NULL == common_util_propertyrow_init(prow)) {
						result = MAPI_E_NOT_ENOUGH_MEMORY;
						goto EXIT_SEEK_ENTRIES;
					}
					if (MAPI_E_SUCCESS != nsp_interface_fetch_row(
						pnode1, TRUE, pstat->codepage, pproptags, prow)) {
						result = MAPI_E_CALL_FAILED;
						goto EXIT_SEEK_ENTRIES;
					}
					break;
				}
				row ++;
			} while (pnode1=simple_tree_node_get_slibling(pnode1));
			if (NULL == pnode1) {
				result = MAPI_E_NOT_FOUND;
				goto EXIT_SEEK_ENTRIES;
			}
			pstat->cur_rec = ab_tree_get_node_minid(pnode1);
		}
		pstat->num_pos = row;
	}
	
	result = MAPI_E_SUCCESS;

EXIT_SEEK_ENTRIES:
	ab_tree_put_base(pbase);
	if (MAPI_E_SUCCESS != result) {
		*pprows = NULL;
	}
	return result;
}

static BOOL nsp_interface_match_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, RESTRICTION *pfilter)
{
	int i;
	char *ptoken;
	uint8_t node_type;
	char temp_buff[1024];
	PROPERTY_VALUE prop_val;
	
	switch (pfilter->res_type) {
	case RESTRICTION_TYPE_AND:
		for (i=0; i<pfilter->res.res_and.cres; i++) {
			if (FALSE == nsp_interface_match_node(pnode,
				codepage, &pfilter->res.res_and.pres[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case RESTRICTION_TYPE_OR:
		for (i=0; i<pfilter->res.res_and.cres; i++) {
			if (TRUE == nsp_interface_match_node(pnode,
				codepage, &pfilter->res.res_or.pres[i])) {
				return TRUE;
			}
		}
		return FALSE;
	case RESTRICTION_TYPE_NOT:
		if (TRUE == nsp_interface_match_node(pnode,
			codepage, pfilter->res.res_not.pres)) {
			return FALSE;
		}
		return TRUE;
	case RESTRICTION_TYPE_CONTENT:
		return FALSE;
	case RESTRICTION_TYPE_PROPERTY:
		if (NULL == pfilter->res.res_property.pprop) {
			return TRUE;
		}
		if (PROP_TAG_ANR == pfilter->res.res_property.proptag) {
			if (MAPI_E_SUCCESS == nsp_interface_fetch_property(pnode,
				FALSE, codepage, PROP_TAG_ACCOUNT, &prop_val, temp_buff)) {
				if (NULL != strcasestr(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			ptoken = strchr(pfilter->res.res_property.pprop->value.pstr, ':');
			if (NULL != ptoken) {
				/* =SMTP:user@company.com */
				if (NULL != strcasestr(temp_buff, ptoken + 1)) {
					return TRUE;
				}
			} else {
				if (0 == strcasecmp(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			if (MAPI_E_SUCCESS == nsp_interface_fetch_property(
				pnode, FALSE, codepage, PROP_TAG_DISPLAYNAME,
				&prop_val, temp_buff)) {
				if (NULL != strcasestr(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			return FALSE;
		} else if (PROP_TAG_ANR_STRING8 == pfilter->res.res_property.proptag) {
			if (MAPI_E_SUCCESS == nsp_interface_fetch_property(pnode, FALSE,
				codepage, PROP_TAG_ACCOUNT_STRING8, &prop_val, temp_buff)) {
				if (NULL != strcasestr(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(pfilter->res.res_property.pprop->value.pstr, ':');
			if (NULL != ptoken) {
				if (NULL != strcasestr(temp_buff, ptoken + 1)) {
					return TRUE;
				}
			} else {
				if (0 == strcasecmp(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			if (MAPI_E_SUCCESS == nsp_interface_fetch_property(
				pnode, FALSE, codepage, PROP_TAG_DISPLAYNAME_STRING8,
				&prop_val, temp_buff)) {
				if (NULL != strcasestr(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			return FALSE;
		}
		if (MAPI_E_SUCCESS != nsp_interface_fetch_property(pnode,
			FALSE, codepage, pfilter->res.res_property.proptag,
			&prop_val, temp_buff)) {
			return FALSE;
		}
		switch (pfilter->res.res_property.proptag & 0xFFFF) {
		case PROPVAL_TYPE_SHORT:
			switch (pfilter->res.res_property.relop) {
			case RELOP_LT:
				if (prop_val.value.s <
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_LE:
				if (prop_val.value.s <=
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
			case RELOP_GT:
				if (prop_val.value.s >
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GE:
				if (prop_val.value.s >=
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_EQ:
				if (prop_val.value.s ==
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_NE:
				if (prop_val.value.s !=
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case PROPVAL_TYPE_LONG:
			switch (pfilter->res.res_property.relop) {
			case RELOP_LT:
				if (prop_val.value.l <
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_LE:
				if (prop_val.value.l <=
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GT:
				if (prop_val.value.l >
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GE:
				if (prop_val.value.l >=
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_EQ:
				if (prop_val.value.l ==
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_NE:
				if (prop_val.value.l !=
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case PROPVAL_TYPE_BYTE:
			switch (pfilter->res.res_property.relop) {
			case RELOP_LT:
				if (prop_val.value.b <
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_LE:
				if (prop_val.value.b <=
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GT:
				if (prop_val.value.b >
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GE:
				if (prop_val.value.b >=
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_EQ:
				if (prop_val.value.b ==
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_NE:
				if (prop_val.value.b !=
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case PROPVAL_TYPE_STRING:
		case PROPVAL_TYPE_WSTRING:
			switch (pfilter->res.res_property.relop) {
			case RELOP_LT:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) < 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_LE:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) <= 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GT:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) > 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GE:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) >= 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_EQ:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) == 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_NE:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) != 0) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		}
		return FALSE;
	case RESTRICTION_TYPE_PROPCOMPARE:
		return FALSE;
	case RESTRICTION_TYPE_BITMASK:
		return FALSE;
	case RESTRICTION_TYPE_SIZE:
		return FALSE;
	case RESTRICTION_TYPE_EXIST:
		node_type = ab_tree_get_node_type(pnode);
		if (node_type > 0x80) {
			return FALSE;
		}
		if (MAPI_E_SUCCESS != nsp_interface_fetch_property(pnode,
			FALSE, codepage, pfilter->res.res_exist.proptag,
			&prop_val, temp_buff)) {
			return FALSE;
		}
		return TRUE;
	case RESTRICTION_TYPE_SUBRESTRICTION:
		return FALSE;
	}	
}

int nsp_interface_get_matches(NSPI_HANDLE handle, uint32_t reserved1,
	STAT *pstat, PROPTAG_ARRAY *preserved, uint32_t reserved2,
	RESTRICTION *pfilter, PROPERTY_NAME *ppropname, uint32_t requested,
	PROPTAG_ARRAY **ppoutmids, PROPTAG_ARRAY *pproptags, PROPROW_SET **pprows)
{
	int i;
	int total;
	int base_id;
	char *pitem;
	int user_id;
	int item_num;
	int last_row;
	int start_pos;
	AB_BASE *pbase;
	uint32_t result;
	LIST_FILE *pfile;
	char maildir[256];
	uint32_t *pproptag;
	PROPERTY_ROW *prow;
	char temp_path[256];
	char temp_buff[1024];
	SINGLE_LIST *pgal_list;
	PROPERTY_VALUE prop_val;
	SIMPLE_TREE_NODE *pnode;
	SINGLE_LIST_NODE *psnode;
	
	
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		*ppoutmids = NULL;
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	if (SORT_TYPE_DISPLAYNAME != pstat->sort_type &&
		SORT_TYPE_PHONETICDISPLAYNAME != pstat->sort_type &&
		SORT_TYPE_DISPLAYNAME_RO != pstat->sort_type &&
		SORT_TYPE_DISPLAYNAME_W != pstat->sort_type) {
		*ppoutmids = NULL;
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	if (0 != reserved1 || NULL != ppropname) {
		*ppoutmids = NULL;
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppoutmids = NULL;
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	*ppoutmids = common_util_proptagarray_init();
	if (NULL == *ppoutmids) {
		*pprows = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	if (NULL == pproptags) {
		*pprows = NULL;
	} else {
		if (pproptags->cvalues > 100) {
			*ppoutmids = NULL;
			*pprows = NULL;
			return MAPI_E_TABLE_TOO_BIG;
		}
		*pprows = common_util_proprowset_init();
		if (NULL == *pprows) {
			*ppoutmids = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppoutmids = NULL;
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	
	if (PROP_TAG_ADDRESSBOOKPUBLICDELEGATES == pstat->container_id) {
		pnode = ab_tree_minid_to_node(pbase, pstat->cur_rec);
		if (NULL == pnode) {
			result = MAPI_E_INVALID_BOOKMARK;
			goto EXIT_GET_MATCHES;
		}
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, temp_buff);
		if (FALSE == get_maildir(temp_buff, maildir)) {
			result = MAPI_E_CALL_FAILED;
			goto EXIT_GET_MATCHES;
		}
		sprintf(temp_path, "%s/config/delegates.txt", maildir);
		pfile = list_file_init(temp_path, "%s:256");
		if (NULL == pfile) {
			result = MAPI_E_SUCCESS;
			goto EXIT_GET_MATCHES;
		}
		item_num = list_file_get_item_num(pfile);
		pitem = list_file_get_list(pfile);
		for (i=0; i<item_num; i++) {
			if ((*ppoutmids)->cvalues > requested) {
				break;
			}
			if (FALSE == get_id_from_username(pitem + 256*i, &user_id) ||
				NULL == (pnode = ab_tree_uid_to_node(pbase, user_id))) {
				continue;
			}
			if (NULL != pfilter && FALSE == nsp_interface_match_node(
				pnode, pstat->codepage, pfilter)) {
				continue;	
			}
			pproptag = common_util_proptagarray_enlarge(*ppoutmids);
			if (NULL == pproptag) {
				list_file_free(pfile);
				result = MAPI_E_NOT_ENOUGH_MEMORY;
				goto EXIT_GET_MATCHES;
			}
			*pproptag = ab_tree_get_node_minid(pnode);
		}
		list_file_free(pfile);
		result = MAPI_E_SUCCESS;
		goto FETCH_ROWS;
	}
	if (NULL != pfilter) {
		if (0 == pstat->container_id) {
			pgal_list = &pbase->gal_list;
			nsp_interface_position_in_list(pstat,
				pgal_list, &start_pos, &last_row, &total);
			i = 0;
			for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
				psnode=single_list_get_after(pgal_list, psnode)) {
				if (i > last_row || (*ppoutmids)->cvalues > requested) {
					break;
				} else if (i < start_pos) {
					i ++;
					continue;
				}
				if (TRUE == nsp_interface_match_node(psnode->pdata,
					pstat->codepage, pfilter)) {
					pproptag = common_util_proptagarray_enlarge(*ppoutmids);
					if (NULL == pproptag) {
						result = MAPI_E_NOT_ENOUGH_MEMORY;
						goto EXIT_GET_MATCHES;
					}
					*pproptag = ab_tree_get_node_minid(psnode->pdata);
				}
				i ++;
			}
		} else {
			pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
			if (NULL == pnode) {
				result = MAPI_E_INVALID_BOOKMARK;
				goto EXIT_GET_MATCHES;
			}
			nsp_interface_position_in_table(pstat,
				pnode, &start_pos, &last_row, &total);
			pnode = simple_tree_node_get_child(pnode);
			if (NULL == pnode) {
				result = MAPI_E_SUCCESS;
				goto EXIT_GET_MATCHES;
			}
			i = 0;
			do {
				if (i > last_row || (*ppoutmids)->cvalues > requested) {
					break;
				} else if (i < start_pos) {
					i ++;
					continue;
				}
				if (TRUE == nsp_interface_match_node(pnode,
					pstat->codepage, pfilter)) {
					pproptag = common_util_proptagarray_enlarge(*ppoutmids);
					if (NULL == pproptag) {
						result = MAPI_E_NOT_ENOUGH_MEMORY;
						goto EXIT_GET_MATCHES;
					}
					*pproptag = ab_tree_get_node_minid(pnode);
				}
				i ++;
			} while (pnode=simple_tree_node_get_slibling(pnode));
		}
	} else {
		pnode = ab_tree_minid_to_node(pbase, pstat->cur_rec);
		if (NULL != pnode && MAPI_E_SUCCESS == nsp_interface_fetch_property(
			pnode, TRUE, pstat->codepage, pstat->container_id, &prop_val,
			temp_buff)) {
			pproptag = common_util_proptagarray_enlarge(*ppoutmids);
			if (NULL == pproptag) {
				result = MAPI_E_NOT_ENOUGH_MEMORY;
				goto EXIT_GET_MATCHES;
			}
			*pproptag = ab_tree_get_node_minid(pnode);
		}
	}

FETCH_ROWS:
	if (NULL != *pprows) {
		for (i=0; i<(*ppoutmids)->cvalues; i++) {
			prow = common_util_proprowset_enlarge(*pprows);
			if (NULL == prow || NULL ==
				common_util_propertyrow_init(prow)) {
				result = MAPI_E_NOT_ENOUGH_MEMORY;
				goto EXIT_GET_MATCHES;
			}
			pnode = ab_tree_minid_to_node(pbase, (*ppoutmids)->pproptag[i]);
			if (NULL == pnode) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
			}
			result = nsp_interface_fetch_row(pnode, TRUE,
						pstat->codepage, pproptags, prow);
			if (MAPI_E_SUCCESS != result) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
			}
		}
	}
	
	result = MAPI_E_SUCCESS;
	
EXIT_GET_MATCHES:
	ab_tree_put_base(pbase);
	if (MAPI_E_SUCCESS != result) {
		*ppoutmids = NULL;
		*pprows = NULL;
	} else {
		/* MS-OXNSPI 3.1.4.1.10.16 */
		pstat->container_id = pstat->cur_rec;
	}
	return result;
}

static int nsp_interface_cmpstring(const void *p1, const void *p2)
{
	return strcasecmp(((SORT_ITEM*)p1)->string, ((SORT_ITEM*)p2)->string);
}

int nsp_interface_resort_restriction(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pinmids, PROPTAG_ARRAY **ppoutmids)
{
	int i;
	int count;
	int base_id;
	BOOL b_found;
	AB_BASE *pbase;
	SORT_ITEM *parray;
	char temp_buff[1024];
	SIMPLE_TREE_NODE *pnode;
	
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		*ppoutmids = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	parray = ndr_stack_alloc(NDR_STACK_IN,
		sizeof(SORT_ITEM)*pinmids->cvalues);
	if (NULL == parray) {
		*ppoutmids = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	*ppoutmids = ndr_stack_alloc(
		NDR_STACK_OUT, sizeof(PROPTAG_ARRAY));
	if (NULL == *ppoutmids) {
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	(*ppoutmids)->pproptag = ndr_stack_alloc(NDR_STACK_OUT,
						sizeof(uint32_t)*pinmids->cvalues);
	if (NULL == (*ppoutmids)->pproptag) {
		*ppoutmids = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppoutmids = NULL;
		return MAPI_E_CALL_FAILED;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppoutmids = NULL;
		return MAPI_E_CALL_FAILED;
	}
	count = 0;
	b_found = FALSE;
	for (i=0; i<pinmids->cvalues; i++) {
		pnode = ab_tree_minid_to_node(pbase, pinmids->pproptag[i]);
		if (NULL == pnode) {
			continue;
		}
		parray[count].minid = pinmids->pproptag[i];
		if (pstat->cur_rec == pinmids->pproptag[i]) {
			b_found = TRUE;
		}
		ab_tree_get_display_name(pnode, pstat->codepage, temp_buff);
		parray[count].string = ndr_stack_alloc(
			NDR_STACK_IN, strlen(temp_buff) + 1);
		if (NULL == parray[count].string) {
			ab_tree_put_base(pbase);
			*ppoutmids = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		strcpy(parray[count].string, temp_buff);
		count ++;
	}
	qsort(parray, count, sizeof(SORT_ITEM), nsp_interface_cmpstring);
	(*ppoutmids)->cvalues = count;
	for (i=0; i<count; i++) {
		(*ppoutmids)->pproptag[i] = parray[i].minid;
	}
	pstat->total_rec = count;
	if (FALSE == b_found) {
		pstat->cur_rec = MID_BEGINNING_OF_TABLE;
		pstat->num_pos = 0;
	}
	ab_tree_put_base(pbase);
	return MAPI_E_SUCCESS;
}

int nsp_interface_dntomid(NSPI_HANDLE handle, uint32_t reserved,
	STRINGS_ARRAY *pnames, PROPTAG_ARRAY **ppoutmids)
{
	int i, id;
	int base_id;
	AB_BASE *pbase;
	SIMPLE_TREE_NODE *ptnode;
	
	if (NULL == pnames) {
		*ppoutmids = NULL;
		return MAPI_E_SUCCESS;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppoutmids = NULL;
		return MAPI_E_CALL_FAILED;
	}
	*ppoutmids = ndr_stack_alloc(NDR_STACK_OUT, sizeof(PROPTAG_ARRAY));
	if (NULL == *ppoutmids) {
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	(*ppoutmids)->pproptag = ndr_stack_alloc(
		NDR_STACK_OUT, sizeof(uint32_t)*pnames->count);
	if (NULL == (*ppoutmids)->pproptag) {
		*ppoutmids = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	(*ppoutmids)->cvalues = pnames->count;
	memset((*ppoutmids)->pproptag, 0, sizeof(uint32_t)*pnames->count);
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppoutmids = NULL;
		return MAPI_E_CALL_FAILED;
	}
	for (i=0; i<pnames->count; i++) {
		if (NULL == pnames->ppstrings[i]) {
			continue;
		}
		ptnode = ab_tree_dn_to_node(pbase, pnames->ppstrings[i]);
		if (NULL != ptnode) {
			(*ppoutmids)->pproptag[i] = ab_tree_get_node_minid(ptnode);
		}
	}
	ab_tree_put_base(pbase);
	return MAPI_E_SUCCESS;
}

static int nsp_interface_get_default_proptags(int node_type,
	BOOL b_unicode, PROPTAG_ARRAY *pproptags)
{
	switch (node_type) {
	case NODE_TYPE_DOMAIN:
	case NODE_TYPE_GROUP:
	case NODE_TYPE_CLASS:
		return MAPI_E_INVALID_OBJECT;
	case NODE_TYPE_PERSOPN:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT:
		if (NODE_TYPE_PERSOPN == node_type) {
			pproptags->cvalues = 31;
		} else {
			pproptags->cvalues = 30;
		}
		pproptags->pproptag = ndr_stack_alloc(NDR_STACK_OUT,
						sizeof(uint32_t)*pproptags->cvalues);
		if (NULL == pproptags->pproptag) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		if (TRUE == b_unicode) {
			pproptags->pproptag[0] = PROP_TAG_DISPLAYNAME;
			pproptags->pproptag[1] = PROP_TAG_NICKNAME;
			pproptags->pproptag[2] = PROP_TAG_TITLE;
			pproptags->pproptag[3] = PROP_TAG_PRIMARYTELEPHONENUMBER;
			pproptags->pproptag[4] = PROP_TAG_MOBILETELEPHONENUMBER;
			pproptags->pproptag[5] = PROP_TAG_HOMEADDRESSSTREET;
			pproptags->pproptag[6] = PROP_TAG_COMMENT;
			pproptags->pproptag[7] = PROP_TAG_COMPANYNAME;
			pproptags->pproptag[8] = PROP_TAG_DEPARTMENTNAME;
			pproptags->pproptag[9] = PROP_TAG_OFFICELOCATION;
			pproptags->pproptag[10] = PROP_TAG_ADDRESSTYPE;
			pproptags->pproptag[11] = PROP_TAG_SMTPADDRESS;
			pproptags->pproptag[12] = PROP_TAG_EMAILADDRESS;
			pproptags->pproptag[13] = PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE;
			pproptags->pproptag[14] = PROP_TAG_ACCOUNT;
			pproptags->pproptag[15] = PROP_TAG_TRANSMITTABLEDISPLAYNAME;
			pproptags->pproptag[16] = PROP_TAG_ADDRESSBOOKPROXYADDRESSES;
			pproptags->pproptag[17] = PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE;
		} else {
			pproptags->pproptag[0] = PROP_TAG_DISPLAYNAME_STRING8;
			pproptags->pproptag[1] = PROP_TAG_NICKNAME_STRING8;
			pproptags->pproptag[2] = PROP_TAG_TITLE_STRING8;
			pproptags->pproptag[3] = PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8;
			pproptags->pproptag[4] = PROP_TAG_MOBILETELEPHONENUMBER_STRING8;
			pproptags->pproptag[5] = PROP_TAG_HOMEADDRESSSTREET_STRING8;
			pproptags->pproptag[6] = PROP_TAG_COMMENT_STRING8;
			pproptags->pproptag[7] = PROP_TAG_COMPANYNAME_STRING8;
			pproptags->pproptag[8] = PROP_TAG_DEPARTMENTNAME_STRING8;
			pproptags->pproptag[9] = PROP_TAG_OFFICELOCATION_STRING8;
			pproptags->pproptag[10] = PROP_TAG_ADDRESSTYPE_STRING8;
			pproptags->pproptag[11] = PROP_TAG_SMTPADDRESS_STRING8;
			pproptags->pproptag[12] = PROP_TAG_EMAILADDRESS_STRING8;
			pproptags->pproptag[13] =
				PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8;
			pproptags->pproptag[14] = PROP_TAG_ACCOUNT_STRING8;
			pproptags->pproptag[15] = PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8;
			pproptags->pproptag[16] = PROP_TAG_ADDRESSBOOKPROXYADDRESSES_STRING8;
			pproptags->pproptag[17] = PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE_STRING8;
		}
		pproptags->pproptag[18] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[19] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[20] = PROP_TAG_ENTRYID;
		pproptags->pproptag[21] = PROP_TAG_RECORDKEY;
		pproptags->pproptag[22] = PROP_TAG_ORIGINALENTRYID;
		pproptags->pproptag[23] = PROP_TAG_SEARCHKEY;
		pproptags->pproptag[24] = PROP_TAG_INSTANCEKEY;
		pproptags->pproptag[25] = PROP_TAG_MAPPINGSIGNATURE;
		pproptags->pproptag[26] = PROP_TAG_SENDRICHINFO;
		pproptags->pproptag[27] = PROP_TAG_TEMPLATEID;
		pproptags->pproptag[28] = PROP_TAG_ADDRESSBOOKOBJECTGUID;
		pproptags->pproptag[29] = PROP_TAG_CREATIONTIME;
		if (NODE_TYPE_PERSOPN == node_type) {
			pproptags->pproptag[30] = PROP_TAG_THUMBNAILPHOTO;
		}
		break;
	case NODE_TYPE_MLIST:
		pproptags->cvalues = 21;
		pproptags->pproptag = ndr_stack_alloc(NDR_STACK_OUT,
						sizeof(uint32_t)*pproptags->cvalues);
		if (NULL == pproptags->pproptag) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		if (TRUE == b_unicode) {
			pproptags->pproptag[0] = PROP_TAG_DISPLAYNAME;
			pproptags->pproptag[1] = PROP_TAG_ADDRESSTYPE;
			pproptags->pproptag[2] = PROP_TAG_SMTPADDRESS;
			pproptags->pproptag[3] = PROP_TAG_EMAILADDRESS;
			pproptags->pproptag[4] = PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE;
			pproptags->pproptag[5] = PROP_TAG_COMPANYNAME;
			pproptags->pproptag[6] = PROP_TAG_DEPARTMENTNAME;
			pproptags->pproptag[7] = PROP_TAG_ADDRESSBOOKPROXYADDRESSES;
		} else {
			pproptags->pproptag[0] = PROP_TAG_DISPLAYNAME_STRING8;
			pproptags->pproptag[1] = PROP_TAG_ADDRESSTYPE_STRING8;
			pproptags->pproptag[2] = PROP_TAG_SMTPADDRESS_STRING8;
			pproptags->pproptag[3] = PROP_TAG_EMAILADDRESS_STRING8;
			pproptags->pproptag[4] =
				PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8;
			pproptags->pproptag[5] = PROP_TAG_COMPANYNAME_STRING8;
			pproptags->pproptag[6] = PROP_TAG_DEPARTMENTNAME_STRING8;
			pproptags->pproptag[7] =
				PROP_TAG_ADDRESSBOOKPROXYADDRESSES_STRING8;
		}
		pproptags->pproptag[8] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[9] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[10] = PROP_TAG_DISPLAYTYPEEX;
		pproptags->pproptag[11] = PROP_TAG_ENTRYID;
		pproptags->pproptag[12] = PROP_TAG_RECORDKEY;
		pproptags->pproptag[13] = PROP_TAG_ORIGINALENTRYID;
		pproptags->pproptag[14] = PROP_TAG_SEARCHKEY;
		pproptags->pproptag[15] = PROP_TAG_INSTANCEKEY;
		pproptags->pproptag[16] = PROP_TAG_MAPPINGSIGNATURE;
		pproptags->pproptag[17] = PROP_TAG_SENDRICHINFO;
		pproptags->pproptag[18] = PROP_TAG_TEMPLATEID;
		pproptags->pproptag[19] = PROP_TAG_ADDRESSBOOKOBJECTGUID;
		pproptags->pproptag[20] = PROP_TAG_CREATIONTIME;
		break;
	case NODE_TYPE_FOLDER:
		pproptags->cvalues = 18;
		pproptags->pproptag = ndr_stack_alloc(NDR_STACK_OUT,
						sizeof(uint32_t)*pproptags->cvalues);
		if (NULL == pproptags->pproptag) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		if (TRUE == b_unicode) {
			pproptags->pproptag[0] = PROP_TAG_DISPLAYNAME;
			pproptags->pproptag[1] = PROP_TAG_ADDRESSTYPE;
			pproptags->pproptag[2] = PROP_TAG_EMAILADDRESS;
			pproptags->pproptag[3] = PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE;
		} else {
			pproptags->pproptag[0] = PROP_TAG_DISPLAYNAME_STRING8;
			pproptags->pproptag[1] = PROP_TAG_ADDRESSTYPE_STRING8;
			pproptags->pproptag[2] = PROP_TAG_EMAILADDRESS_STRING8;
			pproptags->pproptag[3] =
				PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8;
		}
		pproptags->pproptag[4] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[5] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[6] = PROP_TAG_DISPLAYTYPEEX;
		pproptags->pproptag[7] = PROP_TAG_ENTRYID;
		pproptags->pproptag[8] = PROP_TAG_RECORDKEY;
		pproptags->pproptag[9] = PROP_TAG_ORIGINALENTRYID;
		pproptags->pproptag[10] = PROP_TAG_SEARCHKEY;
		pproptags->pproptag[11] = PROP_TAG_INSTANCEKEY;
		pproptags->pproptag[12] = PROP_TAG_COMPANYNAME_STRING8;
		pproptags->pproptag[13] = PROP_TAG_DEPARTMENTNAME_STRING8;
		pproptags->pproptag[14] = PROP_TAG_MAPPINGSIGNATURE;
		pproptags->pproptag[15] = PROP_TAG_SENDRICHINFO;
		pproptags->pproptag[16] = PROP_TAG_TEMPLATEID;
		pproptags->pproptag[17] = PROP_TAG_ADDRESSBOOKOBJECTGUID;
		break;
	default:
		return MAPI_E_INVALID_OBJECT;
	}
	return MAPI_E_SUCCESS;
}


int nsp_interface_get_proplist(NSPI_HANDLE handle, uint32_t flags,
	uint32_t mid, uint32_t codepage, PROPTAG_ARRAY **ppproptags)
{
	int i;
	int count;
	int base_id;
	BOOL b_unicode;
	AB_BASE *pbase;
	char temp_buff[1024];
	PROPERTY_VALUE prop_val;
	SIMPLE_TREE_NODE *pnode;
	
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppproptags = NULL;
		return MAPI_E_CALL_FAILED;
	}
	if (0 == mid) {
		*ppproptags = NULL;
		return MAPI_E_INVALID_OBJECT;
	}
	if (CODEPAGE_UNICODE == codepage) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
	}
	*ppproptags = ndr_stack_alloc(NDR_STACK_OUT, sizeof(PROPTAG_ARRAY));
	if (NULL == *ppproptags) {
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppproptags = NULL;
		return MAPI_E_CALL_FAILED;
	}
	pnode = ab_tree_minid_to_node(pbase, mid);
	if (NULL == pnode) {
		ab_tree_put_base(pbase);
		*ppproptags = NULL;
		return MAPI_E_INVALID_OBJECT;
	}
	if (MAPI_E_SUCCESS == nsp_interface_get_default_proptags(
		ab_tree_get_node_type(pnode), b_unicode,
		*ppproptags)) {
		count = 0;
		for (i=0; i<(*ppproptags)->cvalues; i++) {
			if (MAPI_E_SUCCESS != nsp_interface_fetch_property(
				pnode, FALSE, codepage, (*ppproptags)->pproptag[i],
				&prop_val, temp_buff)) {
				continue;
			}
			if (i != count) {
				(*ppproptags)->pproptag[count] = (*ppproptags)->pproptag[i];
			}
			count ++;
		}
		(*ppproptags)->cvalues = count;
	} else {
		*ppproptags = NULL;
	}
	ab_tree_put_base(pbase);
	return MAPI_E_SUCCESS;
}

int nsp_interface_get_props(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, PROPTAG_ARRAY *pproptags, PROPERTY_ROW **pprows)
{
	int i;
	int count;
	int base_id;
	BOOL b_ephid;
	uint32_t row;
	uint32_t total;
	AB_BASE *pbase;
	BOOL b_unicode;
	BOOL b_proptags;
	uint32_t result;
	uint32_t last_row;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SIMPLE_TREE_NODE *pnode1;
	SINGLE_LIST_NODE *psnode;
	
	
	if (NULL == pstat) {
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	if (flags & FLAG_EPHID) {
		b_ephid = TRUE;
	} else {
		b_ephid = FALSE;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	if (CODEPAGE_UNICODE == pstat->codepage) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
	}
	if (TRUE == b_unicode && NULL != pproptags) {
		for (i=0; i<pproptags->cvalues; i++) {
			if (PROPVAL_TYPE_STRING ==
				(pproptags->pproptag[i] & 0xFFFF)) {
				*pprows = NULL;
				return MAPI_E_NO_SUPPORT;
			}
		}
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	
	if (pstat->cur_rec <= 0x10) {
		if (0 == pstat->container_id) {
			pgal_list = &pbase->gal_list;
			if (MID_BEGINNING_OF_TABLE == pstat->cur_rec) {
				psnode = single_list_get_head(pgal_list);
			} else if (MID_END_OF_TABLE == pstat->cur_rec) {
				psnode = single_list_get_tail(pgal_list);
			} else {
				nsp_interface_position_in_list(pstat,
					pgal_list, &row, &last_row, &total);
				for (i=0,psnode=single_list_get_head(pgal_list);
					NULL!=psnode,i<row; i++,
					psnode=single_list_get_after(pgal_list, psnode));
			}
			if (NULL == psnode) {
				pnode1 = NULL;
			} else {
				pnode1 = psnode->pdata;
			}
		} else {
			pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
			if (NULL == pnode) {
				result = MAPI_E_INVALID_BOOKMARK;
				goto EXIT_GET_PROPS;
			}
			nsp_interface_position_in_table(pstat,
					pnode, &row, &last_row, &total);
			pnode1 = simple_tree_node_get_child(pnode);
			if (NULL != pnode1) {
				i = 0;
				do {
					if (ab_tree_get_node_type(pnode1) > 0x80) {
						continue;
					}
					i ++;
					if (i == row) {
						break;
					}
				} while (pnode1=simple_tree_node_get_slibling(pnode1));
			}
		}
	} else {
		pnode1 = ab_tree_minid_to_node(pbase, pstat->cur_rec);
		if (NULL != pnode1) {
			if (0 != pstat->container_id) {
				pnode = ab_tree_minid_to_node(
					pbase, pstat->container_id);
				if (NULL == pnode) {
					result = MAPI_E_INVALID_BOOKMARK;
					goto EXIT_GET_PROPS;
				}
			}
		}
	}
	b_proptags = TRUE;
	if (NULL == pproptags) {
		b_proptags = FALSE;
		pproptags = ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY));
		if (NULL == pproptags) {
			result = MAPI_E_NOT_ENOUGH_MEMORY;
			goto EXIT_GET_PROPS;
		}
		result = nsp_interface_get_default_proptags(
			ab_tree_get_node_type(pnode1), b_unicode, pproptags);
		if (MAPI_E_SUCCESS != result) {
			goto EXIT_GET_PROPS;
		}
	} else if (pproptags->cvalues > 100) {
		result = MAPI_E_TABLE_TOO_BIG;
		goto EXIT_GET_PROPS;
	}
	*pprows = common_util_propertyrow_init(NULL);
	if (NULL == *pprows) {
		result = MAPI_E_NOT_ENOUGH_MEMORY;
		goto EXIT_GET_PROPS;
	}
	/* MS-OXNSPI 3.1.4.1.7.11 */
	if (NULL == pnode1) {
		nsp_interface_make_ptyperror_row(pproptags, *pprows);
		result = MAPI_W_ERRORS_RETURNED;
	} else {
		result = nsp_interface_fetch_row(pnode1, b_ephid,
					pstat->codepage, pproptags, *pprows);
	}
	if (MAPI_E_SUCCESS == result) {
		if (FALSE == b_proptags) {
			count = 0;
			for (i=0; i<(*pprows)->cvalues; i++) {
				if (PROPVAL_TYPE_ERROR == 
					((*pprows)->pprops[i].proptag & 0XFFFF) &&
					MAPI_E_NOT_FOUND ==
					(*pprows)->pprops[i].value.err) {
					continue;
				}
				if (i != count) {
					(*pprows)->pprops[count] = (*pprows)->pprops[i];
				}
				count ++;
			}
			(*pprows)->cvalues = count;
		} else {
			for (i=0; i<(*pprows)->cvalues; i++) {
				if (PROPVAL_TYPE_ERROR ==
					((*pprows)->pprops[i].proptag & 0XFFFF)) {
					result = MAPI_W_ERRORS_RETURNED;
					break;
				}
			}
		}
	}
	
EXIT_GET_PROPS:
	ab_tree_put_base(pbase);
	if (MAPI_E_SUCCESS != result &&
		MAPI_W_ERRORS_RETURNED != result) {
		*pprows = NULL;
	}
	return result;
}

int nsp_interface_compare_mids(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, uint32_t mid1, uint32_t mid2, uint32_t *presult)
{
	int i;
	int base_id;
	uint32_t result;
	uint32_t minid;
	int pos1, pos2;
	AB_BASE *pbase;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SINGLE_LIST_NODE *psnode;
	
	
	if (NULL != pstat && CODEPAGE_UNICODE == pstat->codepage) {
		return MAPI_E_NO_SUPPORT;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		return MAPI_E_CALL_FAILED;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return MAPI_E_CALL_FAILED;
	}
	
	pos1 = -1;
	pos2 = -1;
	i = 0;
	if (NULL == pstat || 0 == pstat->container_id) {
		pgal_list = &pbase->gal_list;
		for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
			psnode=single_list_get_after(pgal_list, psnode)) {
			minid = ab_tree_get_node_minid(psnode->pdata);
			if (minid == mid1) {
				pos1 = i;
			}
			if (minid == mid2) {
				pos2 = i;
			}
			i ++;
		}
	} else {
		pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
		if (NULL == pnode) {
			result = MAPI_E_INVALID_BOOKMARK;
			goto EXIT_COMPARE_MIDS;
		}
		pnode = simple_tree_node_get_child(pnode);
		if (NULL == pnode) {
			result = MAPI_E_INVALID_BOOKMARK;
			goto EXIT_COMPARE_MIDS;
		}
		do {
			minid = ab_tree_get_node_minid(pnode);
			if (minid == mid1) {
				pos1 = i;
			}
			if (minid == mid2) {
				pos2 = i;
			}
			i ++;
		} while (pnode=simple_tree_node_get_slibling(pnode));
	}
	
	if (-1 == pos1 || -1 == pos2) {
		result = MAPI_E_CALL_FAILED;
		goto EXIT_COMPARE_MIDS;
	}
	*presult = pos2 - pos1;
	
	result = MAPI_E_SUCCESS;
	
EXIT_COMPARE_MIDS:
	ab_tree_put_base(pbase);
	return result;
}

int nsp_interface_mod_props(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, PROPERTY_ROW *prow)
{
	return MAPI_E_NO_SUPPORT;
}

static BOOL nsp_interface_build_specialtable(PROPERTY_ROW *prow,
	BOOL b_unicode, uint32_t codepage, BOOL has_child,
	unsigned int depth, int container_id, const char *str_dname,
	PERMANENT_ENTRYID *ppermeid_parent, PERMANENT_ENTRYID *ppermeid)
{
	int	tmp_tag;
	int tmp_len;
	int proptags[7];
	const char *pdn;
	char tmp_title[1024];
	
	
	prow->reserved = 0x0;
	if (0 == depth) {
		prow->cvalues = 6;
	} else {
		prow->cvalues = 7;
	}
	prow->pprops = ndr_stack_alloc(NDR_STACK_OUT,
			prow->cvalues*sizeof(PROPERTY_VALUE));
	if (NULL == prow->pprops) {
		return FALSE;
	}
	
	/* PROP_TAG_ENTRYID */
	prow->pprops[0].proptag = PROP_TAG_ENTRYID;
	prow->pprops[0].reserved = 0;
	if (FALSE == common_util_permanent_entryid_to_binary(
		ppermeid, &prow->pprops[0].value.bin)) {
		tmp_tag = (int) prow->pprops[0].proptag;
		tmp_tag &= 0xFFFF0000;
		tmp_tag += PROPVAL_TYPE_ERROR;
		prow->pprops[0].proptag = tmp_tag;
		prow->pprops[0].value.err = MAPI_E_NOT_ENOUGH_MEMORY;
	}
	
	/* PROP_TAG_CONTAINERFLAGS */
	prow->pprops[1].proptag = PROP_TAG_CONTAINERFLAGS;
	prow->pprops[1].reserved = 0;
	if (FALSE == has_child) {
		prow->pprops[1].value.l = AB_RECIPIENTS | AB_UNMODIFIABLE;
	} else {
		prow->pprops[1].value.l = AB_RECIPIENTS
			| AB_SUBCONTAINERS | AB_UNMODIFIABLE;
	}
	
	/* PROP_TAG_DEPTH */
	prow->pprops[2].proptag = PROP_TAG_DEPTH;
	prow->pprops[2].reserved = 0;
	prow->pprops[2].value.l = depth;
	
	/* PROP_TAG_ADDRESSBOOKCONTAINERID */
	prow->pprops[3].proptag = PROP_TAG_ADDRESSBOOKCONTAINERID;
	prow->pprops[3].reserved = 0;
	prow->pprops[3].value.l = container_id;
	
	/* PROP_TAG_DISPLAYNAME PROP_TAG_DISPLAYNAME_STRING8 */
	prow->pprops[4].reserved = 0;
	if (TRUE == b_unicode) {
		prow->pprops[4].proptag = PROP_TAG_DISPLAYNAME;
	} else {
		prow->pprops[4].proptag = PROP_TAG_DISPLAYNAME_STRING8;
	}
	if (NULL == str_dname) {
		prow->pprops[4].value.pstr = NULL;
	} else {
		if (TRUE == b_unicode) {
			tmp_len = strlen(str_dname) + 1;
			prow->pprops[4].value.pstr =
				ndr_stack_alloc(NDR_STACK_OUT, tmp_len);
			memcpy(prow->pprops[4].value.pstr, str_dname, tmp_len);
		} else {
			tmp_len = common_util_from_utf8(codepage,
				str_dname, tmp_title, sizeof(tmp_title));
			if (-1 == tmp_len) {
				prow->pprops[4].value.pstr = NULL;
			} else {
				prow->pprops[4].value.pstr =
					ndr_stack_alloc(NDR_STACK_OUT, tmp_len);
				memcpy(prow->pprops[4].value.pstr, tmp_title, tmp_len);
			}
		}
		if (NULL == prow->pprops[4].value.pstr) {
			tmp_tag = (int) prow->pprops[4].proptag;
			tmp_tag &= 0xFFFF0000;
			tmp_tag += PROPVAL_TYPE_ERROR;
			prow->pprops[4].proptag = tmp_tag;
			prow->pprops[4].value.err = MAPI_E_NOT_ENOUGH_MEMORY;
		}
	}
	
	/* PROP_TAG_ADDRESSBOOKISMASTER */
	prow->pprops[5].proptag = PROP_TAG_ADDRESSBOOKISMASTER;
	prow->pprops[5].reserved = 0;
	prow->pprops[5].value.b = 0;
	
	/* PROP_TAG_ADDRESSBOOKPARENTENTRYID */
	if (0 != depth) {
		prow->pprops[6].proptag = PROP_TAG_ADDRESSBOOKPARENTENTRYID;
		prow->pprops[6].reserved = 0;
		if (FALSE == common_util_permanent_entryid_to_binary(
			ppermeid_parent, &prow->pprops[6].value.bin)) {
			tmp_tag = (int) prow->pprops[6].proptag;
			tmp_tag &= 0xFFFF0000;
			tmp_tag += PROPVAL_TYPE_ERROR;
			prow->pprops[6].proptag = tmp_tag;
			prow->pprops[6].value.err = MAPI_E_NOT_ENOUGH_MEMORY;
		}
	}
	return TRUE;
}

static BOOL nsp_interface_has_child(SIMPLE_TREE_NODE *pnode)
{
	pnode = simple_tree_node_get_child(pnode);
	if (NULL == pnode) {
		return FALSE;
	}
	do {
		if (ab_tree_get_node_type(pnode) > 0x80) {
			return TRUE;
		}
	} while (pnode=simple_tree_node_get_slibling(pnode));
	return FALSE;
}

static uint32_t nsp_interface_get_specialtables_from_node(
	SIMPLE_TREE_NODE *pnode, PERMANENT_ENTRYID *ppermeid_parent,
	BOOL b_unicode, uint32_t codepage, PROPROW_SET *prows)
{
	GUID tmp_guid;
	BOOL has_child;
	uint32_t result;
	int container_id;
	PROPERTY_ROW *prow;
	char str_dname[1024];
	SIMPLE_TREE_NODE *pnode1;
	PERMANENT_ENTRYID *ppermeid;
	
	ppermeid = ndr_stack_alloc(NDR_STACK_OUT,
				sizeof(PERMANENT_ENTRYID));
	if (NULL == ppermeid) {
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	ab_tree_node_to_guid(pnode, &tmp_guid);
	if (FALSE == common_util_set_permanententryid(
		DT_CONTAINER, &tmp_guid, NULL, ppermeid)) {
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	prow = common_util_proprowset_enlarge(prows);
	if (NULL == prow) {
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	has_child = nsp_interface_has_child(pnode);
	container_id = ab_tree_get_node_minid(pnode);
	if (0 == container_id) {
		return MAPI_E_CALL_FAILED;
	}
	ab_tree_get_display_name(pnode, codepage, str_dname);
	if (FALSE == nsp_interface_build_specialtable(
		prow, b_unicode, codepage, has_child,
		simple_tree_node_get_depth(pnode), container_id,
		str_dname, ppermeid_parent, ppermeid)) {
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	if (TRUE == has_child) {
		pnode1 = simple_tree_node_get_child(pnode);
		do {
			if (ab_tree_get_node_type(pnode1) > 0x80) {
				result = nsp_interface_get_specialtables_from_node(
					pnode1, ppermeid, b_unicode, codepage, prows);
				if (MAPI_E_SUCCESS != result) {
					return result;
				}
			}
		} while (pnode1=simple_tree_node_get_slibling(pnode1));
	}
	return MAPI_E_SUCCESS;
}

static uint32_t nsp_interface_get_tree_specialtables(
	SIMPLE_TREE *ptree, BOOL b_unicode, uint32_t codepage,
	PROPROW_SET *prows)
{
	SIMPLE_TREE_NODE *pnode;
	
	pnode = simple_tree_get_root(ptree);
	if (NULL == pnode) {
		return MAPI_E_CALL_FAILED;
	}
	return nsp_interface_get_specialtables_from_node(
			pnode, NULL, b_unicode, codepage, prows);
}

int nsp_interface_get_specialtable(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, uint32_t *pversion, PROPROW_SET **pprows)
{
	int base_id;
	BOOL b_unicode;
	AB_BASE *pbase;
	uint32_t result;
	uint32_t codepage;
	PROPERTY_ROW *prow;
	DOMAIN_NODE *pdomain;
	SINGLE_LIST_NODE *pnode;
	PERMANENT_ENTRYID permeid;
	
	
	if (flags & FLAG_CREATIONTEMPLATES) {
		*pprows = NULL;
		/* creation of templates table */
		return MAPI_E_SUCCESS;
	}

	if (flags & FLAG_UNICODESTRINGS) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
	}
	
	if (NULL == pstat) {
		codepage = 1252;
	} else {
		codepage = pstat->codepage;
	}
	
	/* in MS-OXNSPI 3.1.4.1.3 server processing rules */
	if (FALSE == b_unicode && CODEPAGE_UNICODE == codepage) {
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	
	(*pversion) ++;
	
	*pprows = common_util_proprowset_init();
	if (NULL == *pprows) {
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	
	/* build the gal root */
	prow = common_util_proprowset_enlarge(*pprows);
	if (NULL == prow) {
		*pprows = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	
	if (FALSE == common_util_set_permanententryid(
		DT_CONTAINER, NULL, NULL, &permeid)) {
		*pprows = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	if (FALSE == nsp_interface_build_specialtable(prow,
		b_unicode, codepage, FALSE, 0, 0, NULL, NULL,
		&permeid)) {
		*pprows = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	for (pnode=single_list_get_head(&pbase->list); NULL!=pnode;
		pnode=single_list_get_after(&pbase->list, pnode)) {
		pdomain = pnode->pdata;
		result = nsp_interface_get_tree_specialtables(
			&pdomain->tree, b_unicode, codepage, *pprows);
		if (MAPI_E_SUCCESS != result) {
			ab_tree_put_base(pbase);
			*pprows = NULL;
			return result;
		}
	}
	ab_tree_put_base(pbase);
	return MAPI_E_SUCCESS;
}

int nsp_interface_get_templateinfo(NSPI_HANDLE handle,
	uint32_t flags, uint32_t type, char *pdn, uint32_t codepage,
	uint32_t locale_id, PROPERTY_ROW **ppdata)
{
	*ppdata = NULL;
	return MAPI_E_NO_SUPPORT;
}

int nsp_interface_mod_linkatt(NSPI_HANDLE handle, uint32_t flags,
	uint32_t proptag, uint32_t mid, BINARY_ARRAY *pentry_ids)
{
	int i, fd;
	int base_id;
	char *pitem;
	int item_num;
	AB_BASE *pbase;
	uint32_t result;
	uint32_t tmp_mid;
	LIST_FILE *pfile;
	char maildir[256];
	char username[256];
	char temp_path[256];
	DCERPC_INFO rpc_info;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	SIMPLE_TREE_NODE *ptnode;
	
	if (0 == mid) {
		return MAPI_E_INVALID_OBJECT;
	}
	if (PROP_TAG_ADDRESSBOOKPUBLICDELEGATES != proptag) {
		return MAPI_E_NO_SUPPORT;
	}
	rpc_info = get_rpc_info();
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		return MAPI_E_CALL_FAILED;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return MAPI_E_CALL_FAILED;
	}
	double_list_init(&tmp_list);
	ptnode = ab_tree_minid_to_node(pbase, mid);
	if (NULL == ptnode) {
		result = MAPI_E_INVALID_OBJECT;
		goto EXIT_MOD_LINKATT;
	}
	switch (ab_tree_get_node_type(ptnode)) {
	case NODE_TYPE_PERSOPN:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT:
		break;
	default:
		result = MAPI_E_INVALID_OBJECT;
		goto EXIT_MOD_LINKATT;
	}
	ab_tree_get_user_info(ptnode, USER_MAIL_ADDRESS, username);
	if (0 != strcasecmp(username, rpc_info.username)) {
		result = MAPI_E_NO_ACCESS;
		goto EXIT_MOD_LINKATT;
	}
	if (FALSE == get_maildir(username, maildir)) {
		result = MAPI_E_CALL_FAILED;
		goto EXIT_MOD_LINKATT;
	}
	sprintf(temp_path, "%s/config/delegates.txt", maildir);
	pfile = list_file_init(temp_path, "%s:256");
	if (NULL != pfile) {
		item_num = list_file_get_item_num(pfile);
		pitem = list_file_get_list(pfile);
		for (i=0; i<item_num; i++) {
			pnode = malloc(sizeof(DOUBLE_LIST_NODE));
			if (NULL == pnode) {
				result = MAPI_E_NOT_ENOUGH_MEMORY;
				goto EXIT_MOD_LINKATT;
			}
			pnode->pdata = strdup(pitem + 256*i);
			if (NULL == pnode->pdata) {
				free(pnode);
				result = MAPI_E_NOT_ENOUGH_MEMORY;
				goto EXIT_MOD_LINKATT;
			}
			double_list_append_as_tail(&tmp_list, pnode);
		}
		list_file_free(pfile);
	}
	for (i=0; i<pentry_ids->cvalues; i++) {
		if (pentry_ids->pbin[i].cb < 32) {
			continue;
		}
		if (32 == pentry_ids->pbin[i].cb) {
			tmp_mid = pentry_ids->pbin[i].pb[28];
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[29]) << 8;
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[30]) << 16;
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[31]) << 24;
			ptnode = ab_tree_minid_to_node(pbase, tmp_mid);
		} else {
			ptnode = ab_tree_dn_to_node(pbase,
				pentry_ids->pbin[i].pb + 28);
		}
		if (NULL == ptnode) {
			continue;
		}
		ab_tree_get_user_info(ptnode, USER_MAIL_ADDRESS, username);
		if (flags & MOD_FLAG_DELETE) {
			for (pnode=double_list_get_head(&tmp_list); NULL!=pnode;
				pnode=double_list_get_after(&tmp_list, pnode)) {
				if (0 == strcasecmp(username, pnode->pdata)) {
					double_list_remove(&tmp_list, pnode);
					free(pnode->pdata);
					free(pnode);
					break;
				}
			}
		} else {
			for (pnode=double_list_get_head(&tmp_list); NULL!=pnode;
				pnode=double_list_get_after(&tmp_list, pnode)) {
				if (0 == strcasecmp(username, pnode->pdata)) {
					break;
				}
			}
			if (NULL == pnode) {
				pnode = malloc(sizeof(DOUBLE_LIST_NODE));
				if (NULL == pnode) {
					result = MAPI_E_NOT_ENOUGH_MEMORY;
					goto EXIT_MOD_LINKATT;
				}
				pnode->pdata = strdup(username);
				if (NULL == pnode->pdata) {
					free(pnode);
					result = MAPI_E_NOT_ENOUGH_MEMORY;
					goto EXIT_MOD_LINKATT;
				}
				double_list_append_as_tail(&tmp_list, pnode);
			}
		}
	}
	if (item_num != double_list_get_nodes_num(&tmp_list)) {
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 == fd) {
			result = MAPI_E_CALL_FAILED;
			goto EXIT_MOD_LINKATT;
		}
		for (pnode=double_list_get_head(&tmp_list); NULL!=pnode;
			pnode=double_list_get_after(&tmp_list, pnode)) {
			write(fd, pnode->pdata, strlen(pnode->pdata));
			write(fd, "\r\n", 2);
		}
		close(fd);
	}
	result = MAPI_E_SUCCESS;
	
EXIT_MOD_LINKATT:
	ab_tree_put_base(pbase);
	while (pnode=double_list_get_from_head(&tmp_list)) {
		free(pnode->pdata);
		free(pnode);
	}
	double_list_free(&tmp_list);
	return result;
}

int nsp_interface_query_columns(NSPI_HANDLE handle, uint32_t reserved,
	uint32_t flags, PROPTAG_ARRAY **ppcolumns)
{
	BOOL b_unicode;
	PROPTAG_ARRAY *pcolumns;
	
	if (flags & FLAG_UNICODEPROPTYPES) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
	}
	pcolumns = ndr_stack_alloc(NDR_STACK_OUT, sizeof(PROPTAG_ARRAY));
	if (NULL == pcolumns) {
		*ppcolumns = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	pcolumns->cvalues = 31;
	pcolumns->pproptag = ndr_stack_alloc(NDR_STACK_OUT,
							sizeof(uint32_t)*pcolumns->cvalues);
	if (NULL == pcolumns->pproptag) {
		*ppcolumns = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	if (TRUE == b_unicode) {
		pcolumns->pproptag[0] = PROP_TAG_DISPLAYNAME;
		pcolumns->pproptag[1] = PROP_TAG_NICKNAME;
		pcolumns->pproptag[2] = PROP_TAG_TITLE;
		pcolumns->pproptag[3] = PROP_TAG_BUSINESSTELEPHONENUMBER;
		pcolumns->pproptag[4] = PROP_TAG_PRIMARYTELEPHONENUMBER;
		pcolumns->pproptag[5] = PROP_TAG_MOBILETELEPHONENUMBER;
		pcolumns->pproptag[6] = PROP_TAG_HOMEADDRESSSTREET;
		pcolumns->pproptag[7] = PROP_TAG_COMMENT;
		pcolumns->pproptag[8] = PROP_TAG_COMPANYNAME;
		pcolumns->pproptag[9] = PROP_TAG_DEPARTMENTNAME;
		pcolumns->pproptag[10] = PROP_TAG_OFFICELOCATION;
		pcolumns->pproptag[11] = PROP_TAG_ADDRESSTYPE;
		pcolumns->pproptag[12] = PROP_TAG_SMTPADDRESS;
		pcolumns->pproptag[13] = PROP_TAG_EMAILADDRESS;
		pcolumns->pproptag[14] = PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE;
		pcolumns->pproptag[15] = PROP_TAG_ACCOUNT;
		pcolumns->pproptag[16] = PROP_TAG_TRANSMITTABLEDISPLAYNAME;
		pcolumns->pproptag[17] = PROP_TAG_ADDRESSBOOKPROXYADDRESSES;
	} else {
		pcolumns->pproptag[0] = PROP_TAG_DISPLAYNAME_STRING8;
		pcolumns->pproptag[1] = PROP_TAG_NICKNAME_STRING8;
		pcolumns->pproptag[2] = PROP_TAG_TITLE_STRING8;
		pcolumns->pproptag[3] = PROP_TAG_BUSINESSTELEPHONENUMBER_STRING8;
		pcolumns->pproptag[4] = PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8;
		pcolumns->pproptag[5] = PROP_TAG_MOBILETELEPHONENUMBER_STRING8;
		pcolumns->pproptag[6] = PROP_TAG_HOMEADDRESSSTREET_STRING8;
		pcolumns->pproptag[7] = PROP_TAG_COMMENT_STRING8;
		pcolumns->pproptag[8] = PROP_TAG_COMPANYNAME_STRING8;
		pcolumns->pproptag[9] = PROP_TAG_DEPARTMENTNAME_STRING8;
		pcolumns->pproptag[10] = PROP_TAG_OFFICELOCATION_STRING8;
		pcolumns->pproptag[11] = PROP_TAG_ADDRESSTYPE_STRING8;
		pcolumns->pproptag[12] = PROP_TAG_SMTPADDRESS_STRING8;
		pcolumns->pproptag[13] = PROP_TAG_EMAILADDRESS_STRING8;
		pcolumns->pproptag[14] =
			PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8;
		pcolumns->pproptag[15] = PROP_TAG_ACCOUNT_STRING8;
		pcolumns->pproptag[16] = PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8;
		pcolumns->pproptag[17] = PROP_TAG_ADDRESSBOOKPROXYADDRESSES_STRING8;
	}
	pcolumns->pproptag[18] = PROP_TAG_OBJECTTYPE;
	pcolumns->pproptag[19] = PROP_TAG_DISPLAYTYPE;
	pcolumns->pproptag[20] = PROP_TAG_DISPLAYTYPEEX;
	pcolumns->pproptag[21] = PROP_TAG_ENTRYID;
	pcolumns->pproptag[22] = PROP_TAG_RECORDKEY;
	pcolumns->pproptag[23] = PROP_TAG_ORIGINALENTRYID;
	pcolumns->pproptag[24] = PROP_TAG_SEARCHKEY;
	pcolumns->pproptag[25] = PROP_TAG_INSTANCEKEY;
	pcolumns->pproptag[26] = PROP_TAG_MAPPINGSIGNATURE;
	pcolumns->pproptag[27] = PROP_TAG_SENDRICHINFO;
	pcolumns->pproptag[28] = PROP_TAG_TEMPLATEID;
	pcolumns->pproptag[29] = PROP_TAG_ADDRESSBOOKOBJECTGUID;
	pcolumns->pproptag[30] = PROP_TAG_CREATIONTIME;
	return MAPI_E_SUCCESS;
}

int nsp_interface_resolve_names(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, STRINGS_ARRAY *pstrs,
	PROPTAG_ARRAY **ppmids, PROPROW_SET **pprows)
{
	int i;
	char *pstr;
	int temp_len;
	
	for (i=0; i<pstrs->count; i++) {
		temp_len = 2*strlen(pstrs->ppstrings[i]) + 1;
		pstr = ndr_stack_alloc(NDR_STACK_IN, temp_len);
		if (NULL == pstr) {
			*ppmids = NULL;
			*pprows = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		if (-1 == common_util_to_utf8(pstat->codepage,
			pstrs->ppstrings[i], pstr, temp_len)) {
			pstrs->ppstrings[i] = NULL;
		} else {
			pstrs->ppstrings[i] = pstr;
		}
	}
	return nsp_interface_resolve_namesw(handle, reserved,
				pstat, pproptags, pstrs, ppmids, pprows);
}

static BOOL nsp_interface_resolve_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, const char *pstr)
{
	char dn[1024];
	
	ab_tree_get_display_name(pnode, codepage, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	if (TRUE == ab_tree_node_to_dn(pnode, dn, sizeof(dn))
		&& 0 == strcasecmp(dn, pstr)) {
		return TRUE;
	}
	ab_tree_get_department_name(pnode, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	switch(ab_tree_get_node_type(pnode)) {
	case NODE_TYPE_PERSOPN:
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_NICK_NAME, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_JOB_TITLE, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_COMMENT, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_MOBILE_TEL, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_BUSINESS_TEL, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_HOME_ADDRESS, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	case NODE_TYPE_MLIST:
		ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	}
	return FALSE;
}

static SIMPLE_TREE_NODE* nsp_interface_resolve_gal(SINGLE_LIST *plist,
	uint32_t codepage, char *pstr, BOOL *pb_ambiguous)
{
	SINGLE_LIST_NODE *pnode;
	SIMPLE_TREE_NODE *ptnode;
	
	ptnode = NULL;
	for (pnode=single_list_get_head(plist); NULL!=pnode;
		pnode=single_list_get_after(plist, pnode)) {
		if (FALSE == nsp_interface_resolve_node(
			pnode->pdata, codepage, pstr)) {
			continue;
		}
		if (NULL != ptnode) {
			*pb_ambiguous = TRUE;
			return NULL;
		} else {
			ptnode = pnode->pdata;
		}
	}
	if (NULL == ptnode) {
		*pb_ambiguous = FALSE;
		return NULL;
	}
	return ptnode;
}

static uint32_t nsp_interface_fetch_smtp_property(
	const char *paddress, uint32_t proptag, PROPERTY_VALUE *pprop)
{
	pprop->proptag = proptag;
	pprop->reserved = 0;
	switch (proptag) {
	case PROP_TAG_ADDRESSTYPE:
	case PROP_TAG_ADDRESSTYPE_STRING8:
		pprop->value.pstr = "SMTP";
		break;
	case PROP_TAG_EMAILADDRESS:
	case PROP_TAG_EMAILADDRESS_STRING8:
		pprop->value.pstr = ndr_stack_alloc(
			NDR_STACK_OUT, strlen(paddress) + 1);
		if (NULL == pprop->value.pstr) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		strcpy(pprop->value.pstr, paddress);
		break;
	case PROP_TAG_OBJECTTYPE:
		pprop->value.l = OT_MAILUSER;
		break;
	case PROP_TAG_DISPLAYTYPE:
		pprop->value.l = DT_MAILUSER;
		break;
	case PROP_TAG_DISPLAYTYPEEX:
		pprop->value.l = DT_MAILUSER;
		break;
	case PROP_TAG_SEARCHKEY:
		pprop->value.bin.cb = strlen(paddress) + 5;
		pprop->value.bin.pb = ndr_stack_alloc(
			NDR_STACK_OUT, pprop->value.bin.cb);
		if (NULL == pprop->value.bin.pb) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		sprintf(pprop->value.bin.pb, "SMTP:%s", paddress);
		upper_string(pprop->value.bin.pb);
		break;
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8:
	case PROP_TAG_DISPLAYNAME:
	case PROP_TAG_DISPLAYNAME_STRING8:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8:
		pprop->value.pstr = ndr_stack_alloc(
			NDR_STACK_OUT, strlen(paddress) + 1);
		if (NULL == pprop->value.pstr) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		strcpy(pprop->value.pstr, paddress);
		break;
	default:
		return MAPI_E_NOT_FOUND;
	}
	return MAPI_E_SUCCESS;
}

static uint32_t nsp_interface_fetch_smtp_row(const char *paddress,
	PROPTAG_ARRAY *pproptags, PROPERTY_ROW *prow)
{
	int i;
	uint32_t err_val;
	uint32_t tmp_tag;
	PROPERTY_VALUE *pprop;
	
	for (i=0; i<pproptags->cvalues; i++) {
		pprop = common_util_propertyrow_enlarge(prow);
		if (NULL == pprop) {
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		err_val = nsp_interface_fetch_smtp_property(
			paddress, pproptags->pproptag[i], pprop);
		if (MAPI_E_SUCCESS != err_val) {
			tmp_tag = pprop->proptag;
			tmp_tag &= 0xFFFF0000;
			tmp_tag += PROPVAL_TYPE_ERROR;
			pprop->proptag = tmp_tag;
			pprop->value.err = err_val;
		}
	}
	return MAPI_E_SUCCESS;
}

int nsp_interface_resolve_namesw(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, STRINGS_ARRAY *pstrs,
	PROPTAG_ARRAY **ppmids, PROPROW_SET **pprows)
{
	int i, j;
	int total;
	int base_id;
	char *ptoken;
	AB_BASE *pbase;
	uint32_t result;
	BOOL b_ambiguous;
	uint32_t last_row;
	uint32_t start_pos;
	uint32_t *pproptag;
	PROPERTY_ROW *prow;
	SIMPLE_TREE_NODE *pnode;
	SIMPLE_TREE_NODE *pnode1;
	SIMPLE_TREE_NODE *pnode2;
	SINGLE_LIST_NODE *psnode;
	
	
	if (CODEPAGE_UNICODE == pstat->codepage) {
		*ppmids = NULL;
		*pprows = NULL;
		return MAPI_E_NO_SUPPORT;
	}
	/*
	[MS-OXNPI] 3.1.4.1.17, If the input parameter Reserved contains
	any value other than 0, the server MUST return one of the return
	values specified in section 2.2.1.2, but Outlook 2010 always send
	non-zero so we skip it.
	*/
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppmids = NULL;
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	if (NULL == pproptags) {
		pproptags = ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY));
		if (NULL == pproptags) {
			*ppmids = NULL;
			*pprows = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		pproptags->cvalues = 7;
		pproptags->pproptag = ndr_stack_alloc(NDR_STACK_IN,
						sizeof(uint32_t)*pproptags->cvalues);
		if (NULL == pproptags) {
			*ppmids = NULL;
			*pprows = NULL;
			return MAPI_E_NOT_ENOUGH_MEMORY;
		}
		pproptags->pproptag[0] = PROP_TAG_ADDRESSBOOKCONTAINERID;
		pproptags->pproptag[1] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[2] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[3] = PROP_TAG_DISPLAYNAME_STRING8;
		pproptags->pproptag[4] = PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8;
		pproptags->pproptag[5] = PROP_TAG_DEPARTMENTNAME_STRING8;
		pproptags->pproptag[6] = PROP_TAG_OFFICELOCATION_STRING8;
	} else {
		if (pproptags->cvalues > 100) {
			*ppmids = NULL;
			*pprows = NULL;
			return MAPI_E_TABLE_TOO_BIG;
		}
	}
	*ppmids = common_util_proptagarray_init();
	if (NULL == *ppmids) {
		*pprows = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	*pprows = common_util_proprowset_init();
	if (NULL == *pprows) {
		*ppmids = NULL;
		return MAPI_E_NOT_ENOUGH_MEMORY;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppmids = NULL;
		*pprows = NULL;
		return MAPI_E_CALL_FAILED;
	}
	
	if (0 == pstat->container_id) {
		for (i=0; i<pstrs->count; i++) {
			pproptag = common_util_proptagarray_enlarge(*ppmids);
			if (NULL == pproptag) {
				result = MAPI_E_NOT_ENOUGH_MEMORY;
				goto EXIT_RESOLVE_NAMESW;
			}
			if (NULL == pstrs->ppstrings[i]) {
				*pproptag = MID_UNRESOLVED;
				continue;
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(pstrs->ppstrings[i], ':');
			if (NULL != ptoken) {
				ptoken ++;
			} else {
				ptoken = pstrs->ppstrings[i];
			}
			pnode = nsp_interface_resolve_gal(&pbase->gal_list,
						pstat->codepage, ptoken, &b_ambiguous);
			if (NULL == pnode) {
				if (TRUE == b_ambiguous) {
					*pproptag = MID_AMBIGUOUS;
				} else {
					if (0 == strncasecmp(pstrs->ppstrings[i],
						"=SMTP:", 6)) {
						prow = common_util_proprowset_enlarge(*pprows);
						if (NULL == prow || NULL ==
							common_util_propertyrow_init(prow)) {
							result = MAPI_E_NOT_ENOUGH_MEMORY;
							goto EXIT_RESOLVE_NAMESW;
						}
						result = nsp_interface_fetch_smtp_row(
							pstrs->ppstrings[i] + 6, pproptags, prow);
						if (MAPI_E_SUCCESS != result) {
							goto EXIT_RESOLVE_NAMESW;
						}
						*pproptag = MID_RESOLVED;
					} else {
						*pproptag = MID_UNRESOLVED;
					}
				}
			} else {
				*pproptag = MID_RESOLVED;
				prow = common_util_proprowset_enlarge(*pprows);
				if (NULL == prow || NULL ==
					common_util_propertyrow_init(prow)) {
					result = MAPI_E_NOT_ENOUGH_MEMORY;
					goto EXIT_RESOLVE_NAMESW;
				}
				result = nsp_interface_fetch_row(pnode, TRUE,
							pstat->codepage, pproptags, prow);
				if (MAPI_E_SUCCESS != result) {
					goto EXIT_RESOLVE_NAMESW;
				}
			}		
		}
	} else {
		pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
		if (NULL == pnode) {
			result = MAPI_E_INVALID_BOOKMARK;
			goto EXIT_RESOLVE_NAMESW;
		}
		nsp_interface_position_in_table(pstat,
			pnode, &start_pos, &last_row, &total);
		for (i=0; i<pstrs->count; i++) {
			pproptag = common_util_proptagarray_enlarge(*ppmids);
			if (NULL == pproptag) {
				result = MAPI_E_NOT_ENOUGH_MEMORY;
				goto EXIT_RESOLVE_NAMESW;
			}
			if (NULL == pstrs->ppstrings[i]) {
				*pproptag = MID_UNRESOLVED;
				continue;
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(pstrs->ppstrings[i], ':');
			if (NULL != ptoken) {
				ptoken ++;
			} else {
				ptoken = pstrs->ppstrings[i];
			}
			*pproptag = MID_UNRESOLVED;
			for (j=0,pnode1=simple_tree_node_get_child(pnode);
				NULL!=pnode1&&j>=start_pos&&j<=last_row;
				pnode1=simple_tree_node_get_slibling(pnode1)) {
				if (ab_tree_get_node_type(pnode1) > 0x80) {
					continue;
				}
				if (TRUE == nsp_interface_resolve_node(
					pnode1, pstat->codepage, ptoken)) {
					if (MID_RESOLVED == *pproptag) {
						*pproptag = MID_AMBIGUOUS;
						break;
					} else {
						*pproptag = MID_RESOLVED;
						pnode2 = pnode1;
					}
				}
				j ++;
			}
			if (MID_RESOLVED == *pproptag) {
				prow = common_util_proprowset_enlarge(*pprows);
				if (NULL == prow || NULL ==
					common_util_propertyrow_init(prow)) {
					result = MAPI_E_NOT_ENOUGH_MEMORY;
					goto EXIT_RESOLVE_NAMESW;
				}
				result = nsp_interface_fetch_row(pnode2, TRUE,
							pstat->codepage, pproptags, prow);
				if (MAPI_E_SUCCESS != result) {
					goto EXIT_RESOLVE_NAMESW;
				}
			}
		}
	}
	result = MAPI_E_SUCCESS;
	
EXIT_RESOLVE_NAMESW:
	ab_tree_put_base(pbase);
	if (MAPI_E_SUCCESS != result) {
		*ppmids = NULL;
		*pprows = NULL;
	}
	return result;
}

void nsp_interface_unbind_rpc_handle(uint64_t hrpc)
{
	/* do nothing */
}
