// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/oxvcard.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>

using namespace gromox;

namespace {
struct vc_delete {
	inline void operator()(MESSAGE_CONTENT *x) const { message_content_free(x); }
};
}

static constexpr uint32_t g_n_proptags[] = 
	{PR_SURNAME, PR_GIVEN_NAME, PR_MIDDLE_NAME,
	PR_DISPLAY_NAME_PREFIX, PR_GENERATION};
static constexpr uint32_t g_workaddr_proptags[] =
	{0x8000001F, 0x8001001F, 0x8002001F, 0x8003001F, 0x8004001F, 0x8005001F};
static constexpr uint32_t g_homeaddr_proptags[] =
	{PR_HOME_ADDRESS_POST_OFFICE_BOX, PR_HOME_ADDRESS_STREET,
	PR_HOME_ADDRESS_CITY, PR_HOME_ADDRESS_STATE_OR_PROVINCE,
	PR_HOME_ADDRESS_POSTAL_CODE, PR_HOME_ADDRESS_COUNTRY};
static constexpr uint32_t g_otheraddr_proptags[] =
	{PR_OTHER_ADDRESS_POST_OFFICE_BOX, PR_OTHER_ADDRESS_STREET,
	PR_OTHER_ADDRESS_CITY, PR_OTHER_ADDRESS_STATE_OR_PROVINCE,
	PR_OTHER_ADDRESS_POSTAL_CODE, PR_OTHER_ADDRESS_COUNTRY};
static constexpr uint32_t g_email_proptags[] =
	{0x8006001F, 0x8007001F, 0x8008001F};
static constexpr uint32_t g_im_proptag = 0x8009001F;
static constexpr uint32_t g_categories_proptag = 0x800A101F;
static constexpr uint32_t g_bcd_proptag = 0x800B0102;
static constexpr uint32_t g_ufld_proptags[] = 
	{0x800C001F, 0x800D001F, 0x800E001F, 0x800F001F};
static constexpr uint32_t g_fbl_proptag = 0x8010001F;
static constexpr uint32_t g_vcarduid_proptag = 0x8011001F;

static BOOL oxvcard_check_compatible(const VCARD *pvcard)
{
	BOOL b_version;
	DOUBLE_LIST *plist;
	VCARD_LINE *pvline;
	DOUBLE_LIST_NODE *pnode;
	
	b_version = FALSE;
	plist = (DOUBLE_LIST*)pvcard;
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pvline = (VCARD_LINE*)pnode->pdata;
		if (strcasecmp(pvline->name, "VERSION") != 0)
			continue;
		auto pstring = pvline->get_first_subval();
		if (pstring == nullptr)
			return FALSE;
		if (strcmp(pstring, "3.0") != 0 &&
		    strcmp(pstring, "4.0") != 0)
			return FALSE;
		b_version = TRUE;
	}
	return b_version ? TRUE : FALSE;
}

static BOOL oxvcard_get_propids(PROPID_ARRAY *ppropids,
	GET_PROPIDS get_propids)
{
	PROPERTY_NAME bf[18];
	size_t start = 0, z = 0;
	
	bf[z++].lid = PidLidWorkAddressPostOfficeBox;
	bf[z++].lid = PidLidWorkAddressStreet;
	bf[z++].lid = PidLidWorkAddressCity;
	bf[z++].lid = PidLidWorkAddressState;
	bf[z++].lid = PidLidWorkAddressPostalCode;
	bf[z++].lid = PidLidWorkAddressCountry;
	bf[z++].lid = PidLidEmail1EmailAddress;
	bf[z++].lid = PidLidEmail2EmailAddress;
	bf[z++].lid = PidLidEmail3EmailAddress;
	bf[z++].lid = PidLidInstantMessagingAddress;
	for (size_t i = start; i < z; ++i) {
		bf[i].guid = PSETID_ADDRESS;
		bf[i].kind = MNID_ID;
	}

	bf[z].guid = PS_PUBLIC_STRINGS;
	bf[z].kind = MNID_ID;
	bf[z++].lid = PidLidCategories;
	bf[z].guid = PS_PUBLIC_STRINGS;
	bf[z].kind = MNID_ID;
	bf[z++].lid = PidLidBusinessCardDisplayDefinition;

	start = z;
	bf[z++].lid = PidLidContactUserField1;
	bf[z++].lid = PidLidContactUserField2;
	bf[z++].lid = PidLidContactUserField3;
	bf[z++].lid = PidLidContactUserField4;
	bf[z++].lid = PidLidFreeBusyLocation;
	for (size_t i = start; i < z; ++i) {
		bf[i].guid = PSETID_ADDRESS;
		bf[i].kind = MNID_ID;
	}
	bf[z].guid = PSETID_GROMOX;
	bf[z].kind = MNID_STRING;
	bf[z++].pname = deconst("vcarduid");

	PROPNAME_ARRAY propnames;
	propnames.count = z;
	propnames.ppropname = bf;
	return get_propids(&propnames, ppropids);
}

static bool is_photo(const char *t)
{
	return strcasecmp(t, "jpeg") == 0 || strcasecmp(t, "jpg") == 0 ||
	       strcasecmp(t, "png") == 0 || strcasecmp(t, "gif") == 0 ||
	       strcasecmp(t, "bmp") == 0;
}

MESSAGE_CONTENT* oxvcard_import(
	const VCARD *pvcard, GET_PROPIDS get_propids)
{
	int i;
	int count;
	int tmp_len;
	int ufld_count;
	int mail_count;
	int list_count;
	BINARY tmp_bin;
	uint16_t propid;
	BOOL b_encoding;
	uint32_t proptag;
	struct tm tmp_tm;
	uint8_t tmp_byte;
	size_t decode_len;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	DOUBLE_LIST *plist;
	VCARD_LINE *pvline;
	char* child_buff[16];
	VCARD_VALUE *pvvalue;
	VCARD_PARAM *pvparam;
	PROPID_ARRAY propids;
	BINARY_ARRAY bin_array;
	const char *photo_type;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST_NODE *pnode2;
	const char *address_type;
	STRING_ARRAY child_strings;
	STRING_ARRAY strings_array;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	char tmp_buff[VCARD_MAX_BUFFER_LEN];
	
	mail_count = 0;
	ufld_count = 0;
	child_strings.count = 0;
	child_strings.ppstr = child_buff;
	if (!oxvcard_check_compatible(pvcard))
		return NULL;
	std::unique_ptr<MESSAGE_CONTENT, vc_delete> pmsg(message_content_init());
	if (pmsg == nullptr)
		return NULL;
	if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Contact") != 0)
		return nullptr;
	plist = (DOUBLE_LIST*)pvcard;
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pvline = (VCARD_LINE*)pnode->pdata;
		if (strcasecmp(pvline->name, "UID") == 0) {
			/* Deviation from MS-OXVCARD v8.3 §2.1.3.7.7 */
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				return nullptr;
			if (pmsg->proplist.set(g_vcarduid_proptag, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "FN")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				return nullptr;
			if (pmsg->proplist.set(PR_DISPLAY_NAME, pstring) != 0 ||
			    pmsg->proplist.set(PR_NORMALIZED_SUBJECT, tmp_buff) != 0 ||
			    pmsg->proplist.set(PR_CONVERSATION_TOPIC, tmp_buff) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "N")) {
			count = 0;
			for (pnode1=double_list_get_head(&pvline->value_list);
				NULL!=pnode1; pnode1=double_list_get_after(
				&pvline->value_list, pnode1)) {
				if (count > 4)
					break;
				pvvalue = (VCARD_VALUE*)pnode1->pdata;
				list_count = double_list_get_nodes_num(&pvvalue->subval_list);
				if (list_count > 1)
					return nullptr;
				pnode2 = double_list_get_head(&pvvalue->subval_list);
				if (pnode2 != nullptr && pnode2->pdata != nullptr &&
				    pmsg->proplist.set(g_n_proptags[count], pnode2->pdata) != 0)
					return nullptr;
				count ++;
			}
		} else if (0 == strcasecmp(pvline->name, "NICKNAME")) {
			auto pstring = pvline->get_first_subval();
			if (pstring != nullptr &&
			    pmsg->proplist.set(PR_NICKNAME, pstring) != 0)
					return nullptr;
		} else if (0 == strcasecmp(pvline->name, "PHOTO")) {
			if (pmsg->children.pattachments != nullptr)
				return nullptr;
			b_encoding = FALSE;
			photo_type = NULL;
			for (pnode1=double_list_get_head(&pvline->param_list);
				NULL!=pnode1; pnode1=double_list_get_after(
				&pvline->param_list, pnode1)) {
				pvparam = (VCARD_PARAM*)pnode1->pdata;
				if (0 == strcasecmp(pvparam->name, "ENCODING")) {
					if (pvparam->pparamval_list == nullptr)
						return nullptr;
					pnode2 = double_list_get_head(pvparam->pparamval_list);
					if (pnode2 == nullptr || pnode2->pdata == nullptr ||
					    strcasecmp(static_cast<char *>(pnode2->pdata), "b") != 0)
						return nullptr;
					b_encoding = TRUE;
				} else if (0 == strcasecmp(pvparam->name, "TYPE")) {
					if (pvparam->pparamval_list == nullptr)
						return nullptr;
					pnode2 = double_list_get_head(pvparam->pparamval_list);
					if (pnode2 == nullptr || pnode2->pdata == nullptr)
						return nullptr;
					photo_type = static_cast<char *>(pnode2->pdata);
				}
			}
			if (!b_encoding || photo_type == nullptr)
				return nullptr;

			if (!is_photo(photo_type))
				return nullptr;
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				return nullptr;
			pattachments = attachment_list_init();
			if (pattachments == nullptr)
				return nullptr;
			message_content_set_attachments_internal(pmsg.get(), pattachments);
			pattachment = attachment_content_init();
			if (pattachment == nullptr)
				return nullptr;
			if (!attachment_list_append_internal(pattachments, pattachment)) {
				attachment_content_free(pattachment);
				return nullptr;
			}
			tmp_len = strlen(pstring);
			if (decode64(pstring, tmp_len, tmp_buff,
			    arsizeof(tmp_buff), &decode_len) != 0)
				return nullptr;
			tmp_bin.pc = tmp_buff;
			tmp_bin.cb = decode_len;
			if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0 ||
			    pattachment->proplist.set(PR_ATTACH_EXTENSION, photo_type) != 0)
				return nullptr;
			snprintf(tmp_buff, arsizeof(tmp_buff), "ContactPhoto.%s", photo_type);
			if (pattachment->proplist.set(PR_ATTACH_LONG_FILENAME, tmp_buff) != 0)
				return nullptr;
			tmp_byte = 1;
			if (pmsg->proplist.set(PR_ATTACHMENT_CONTACTPHOTO, &tmp_byte) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "BDAY")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (NULL != strptime(pstring, "%Y-%m-%d", &tmp_tm)) {
				/* Conversion is not exact */
				tmp_int64 = rop_util_unix_to_nttime(mktime(&tmp_tm));
				if (pmsg->proplist.set(PR_BIRTHDAY, &tmp_int64) != 0)
					return nullptr;
			}
		} else if (0 == strcasecmp(pvline->name, "ADR")) {
			pnode1 = double_list_get_head(&pvline->param_list);
			if (pnode1 == nullptr)
				return nullptr;
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (strcasecmp(pvparam->name, "TYPE") != 0 ||
			    pvparam->pparamval_list == nullptr)
				return nullptr;
			pnode2 = double_list_get_head(pvparam->pparamval_list);
			address_type = pnode2 != nullptr && pnode2->pdata != nullptr ? static_cast<char *>(pnode2->pdata) : "";
			count = 0;
			for (pnode1=double_list_get_head(&pvline->value_list);
				NULL!=pnode1; pnode1=double_list_get_after(
				&pvline->value_list, pnode1)) {
				if (count > 5)
					break;
				pvvalue = (VCARD_VALUE*)pnode1->pdata;
				list_count = double_list_get_nodes_num(&pvvalue->subval_list);
				if (list_count > 1)
					return nullptr;
				pnode2 = double_list_get_head(&pvvalue->subval_list);
				if (NULL != pnode2) {
					if (pnode2->pdata == nullptr)
						continue;
					uint32_t tag;
					if (strcasecmp(address_type, "work") == 0)
						tag = g_workaddr_proptags[count];
					else if (strcasecmp(address_type, "home") == 0)
						tag = g_homeaddr_proptags[count];
					else
						tag = g_otheraddr_proptags[count];
					if (pmsg->proplist.set(tag, pnode2->pdata) != 0)
						return nullptr;
				}
				count ++;
			}
		} else if (0 == strcasecmp(pvline->name, "TEL")) {
			pnode1 = double_list_get_head(&pvline->param_list);
			if (pnode1 == nullptr)
				return nullptr;
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (strcasecmp(pvparam->name, "TYPE") != 0 ||
			    pvparam->pparamval_list == nullptr)
				return nullptr;
			pnode2 = double_list_get_head(pvparam->pparamval_list);
			if (pnode2 == nullptr || pnode2->pdata == nullptr)
				return nullptr;
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			uint32_t tag = 0;
			auto keyword = static_cast<char *>(pnode2->pdata);
			if (strcasecmp(keyword, "home") == 0) {
				pnode1 = double_list_get_after(
					&pvline->param_list, pnode1);
				if (pnode1 == nullptr)
					tag = pmsg->proplist.has(PR_HOME_TELEPHONE_NUMBER) ?
					      PR_HOME2_TELEPHONE_NUMBER :
					      PR_HOME_TELEPHONE_NUMBER;
				else if (strcasecmp(static_cast<VCARD_PARAM *>(pnode1->pdata)->name, "fax") == 0)
					tag = PR_HOME_FAX_NUMBER;
				else
					return nullptr;
			} else if (strcasecmp(keyword, "voice") == 0) {
				tag = PR_OTHER_TELEPHONE_NUMBER;
			} else if (strcasecmp(keyword, "work") == 0) {
				pnode1 = double_list_get_after(
					&pvline->param_list, pnode1);
				if (pnode1 == nullptr)
					tag = pmsg->proplist.has(PR_BUSINESS_TELEPHONE_NUMBER) ?
					      PR_BUSINESS2_TELEPHONE_NUMBER :
					      PR_BUSINESS_TELEPHONE_NUMBER;
				else if (strcasecmp(static_cast<VCARD_PARAM *>(pnode1->pdata)->name, "fax") == 0)
					tag = PR_BUSINESS_FAX_NUMBER;
				else
					return nullptr;
			} else if (strcasecmp(keyword, "cell") == 0) {
				tag = PR_MOBILE_TELEPHONE_NUMBER;
			} else if (strcasecmp(keyword, "pager") == 0) {
				tag = PR_PAGER_TELEPHONE_NUMBER;
			} else if (strcasecmp(keyword, "car") == 0) {
				tag = PR_CAR_TELEPHONE_NUMBER;
			} else if (strcasecmp(keyword, "isdn") == 0) {
				tag = PR_ISDN_NUMBER;
			} else if (strcasecmp(keyword, "pref") == 0) {
				tag = PR_PRIMARY_TELEPHONE_NUMBER;
			} else {
				continue;
			}
			if (pmsg->proplist.set(tag, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "EMAIL")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (mail_count > 2)
				continue;
			if (pmsg->proplist.set(g_email_proptags[mail_count++], pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "TITLE")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_TITLE, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "ROLE")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_PROFESSION, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "ORG")) {
			pnode1 = double_list_get_head(&pvline->value_list);
			if (pnode1 == nullptr)
				continue;
			if (NULL != pnode1->pdata) {
				pvvalue = (VCARD_VALUE*)pnode1->pdata;
				pnode2 = double_list_get_head(&pvvalue->subval_list);
				if (pnode2 != nullptr && pnode2->pdata != nullptr &&
				    pmsg->proplist.set(PR_COMPANY_NAME, pnode2->pdata) != 0)
					return nullptr;
			}
			pnode1 = double_list_get_after(&pvline->value_list, pnode1);
			if (NULL != pnode1 && NULL != pnode1->pdata) {
				pvvalue = (VCARD_VALUE*)pnode1->pdata;
				pnode2 = double_list_get_head(&pvvalue->subval_list);
				if (pnode2 != nullptr && pnode2->pdata != nullptr &&
				    pmsg->proplist.set(PR_DEPARTMENT_NAME, pnode2->pdata) != 0)
					return nullptr;
			}
		} else if (strcasecmp(pvline->name, "CATEGORIES") == 0) {
			pnode1 = double_list_get_head(&pvline->value_list);
			if (pnode1 == nullptr)
				continue;
			pvvalue = (VCARD_VALUE*)pnode1->pdata;
			strings_array.count = 0;
			strings_array.ppstr = (char**)tmp_buff;
			for (pnode2=double_list_get_head(&pvvalue->subval_list);
				NULL!=pnode2; pnode2=double_list_get_after(
				&pvvalue->subval_list, pnode2)) {
				if (pnode2->pdata == nullptr)
					continue;
				strings_array.ppstr[strings_array.count++] = static_cast<char *>(pnode2->pdata);
			}
			if (strings_array.count != 0 && strings_array.count < 128 &&
			    pmsg->proplist.set(g_categories_proptag, &strings_array) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "NOTE")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_BODY, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "REV")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (NULL != strptime(pstring, "%Y-%m-%dT%H:%M:%S", &tmp_tm)) {
				/* Conversion is not exact */
				tmp_int64 = rop_util_unix_to_nttime(mktime(&tmp_tm));
				if (pmsg->proplist.set(PR_LAST_MODIFICATION_TIME, &tmp_int64) != 0)
					return nullptr;
			}
		} else if (0 == strcasecmp(pvline->name, "URL")) {
			pnode1 = double_list_get_head(&pvline->param_list);
			if (pnode1 == nullptr)
				return nullptr;
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (strcasecmp(pvparam->name, "TYPE") != 0 ||
			    pvparam->pparamval_list == nullptr)
				return nullptr;
			pnode2 = double_list_get_head(pvparam->pparamval_list);
			if (pnode2 == nullptr || pnode2->pdata == nullptr)
				return nullptr;
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			uint32_t tag;
			auto keyword = static_cast<char *>(pnode2->pdata);
			if (strcasecmp(keyword, "home") == 0)
				tag = PR_PERSONAL_HOME_PAGE;
			else if (strcasecmp(keyword, "work") == 0)
				tag = PR_BUSINESS_HOME_PAGE;
			else
				continue;
			if (pmsg->proplist.set(tag, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline->name, "CLASS") == 0) {
		auto pstring = pvline->get_first_subval();
		if (pstring != nullptr) {
			if (strcasecmp(pstring, "PRIVATE") == 0)
				tmp_int32 = SENSITIVITY_PRIVATE;
			else if (strcasecmp(pstring, "CONFIDENTIAL") == 0)
				tmp_int32 = SENSITIVITY_COMPANY_CONFIDENTIAL;
			else
				tmp_int32 = SENSITIVITY_NONE;
			if (pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != 0)
				return nullptr;
		}
		} else if (0 == strcasecmp(pvline->name, "KEY")) {
			pnode1 = double_list_get_head(&pvline->param_list);
			if (pnode1 == nullptr)
				return nullptr;
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (strcasecmp(pvparam->name, "ENCODING") != 0 ||
			    pvparam->pparamval_list == nullptr)
				return nullptr;
			pnode2 = double_list_get_head(pvparam->pparamval_list);
			if (pnode2 == nullptr || pnode2->pdata == nullptr ||
			    strcasecmp(static_cast<char *>(pnode2->pdata), "b") != 0)
				return nullptr;
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				return nullptr;
			tmp_len = strlen(pstring);
			if (decode64(pstring, tmp_len, tmp_buff,
			    arsizeof(tmp_buff), &decode_len) != 0)
				return nullptr;
			bin_array.count = 1;
			bin_array.pbin = &tmp_bin;
			tmp_bin.pc = tmp_buff;
			tmp_bin.cb = decode_len;
			if (pmsg->proplist.set(PR_USER_X509_CERTIFICATE, &bin_array) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "X-MS-OL-DESIGN")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			tmp_bin.cb = strlen(pstring);
			tmp_bin.pv = deconst(pstring);
			if (pmsg->proplist.set(g_bcd_proptag, &tmp_bin) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "X-MS-CHILD")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (child_strings.count >= GX_ARRAY_SIZE(child_buff))
				return nullptr;
			child_strings.ppstr[child_strings.count++] = deconst(pstring);
		} else if (0 == strcasecmp(pvline->name, "X-MS-TEXT")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (ufld_count > 3)
				return nullptr;
			if (pmsg->proplist.set(g_ufld_proptags[ufld_count++], pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "X-MS-IMADDRESS") ||
			0 == strcasecmp(pvline->name, "X-MS-RM-IMACCOUNT")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(g_im_proptag, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "X-MS-TEL")) {
			pnode1 = double_list_get_head(&pvline->param_list);
			if (pnode1 == nullptr)
				return nullptr;
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (pvparam->pparamval_list != nullptr)
				return nullptr;
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			uint32_t tag;
			if (strcasecmp(pvparam->name, "ASSISTANT") == 0)
				tag = PR_ASSISTANT_TELEPHONE_NUMBER;
			else if (strcasecmp(pvparam->name, "CALLBACK") == 0)
				tag = PR_CALLBACK_TELEPHONE_NUMBER;
			else if (strcasecmp(pvparam->name, "COMPANY") == 0)
				tag = PR_COMPANY_MAIN_PHONE_NUMBER;
			else if (strcasecmp(pvparam->name, "RADIO") == 0)
				tag = PR_RADIO_TELEPHONE_NUMBER;
			else if (strcasecmp(pvparam->name, "TTYTTD") == 0)
				tag = PR_TTYTDD_PHONE_NUMBER;
			else
				return nullptr;
			if (pmsg->proplist.set(tag, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "X-MS-ANNIVERSARY")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (NULL != strptime(pstring, "%Y-%m-%d", &tmp_tm)) {
				/* Conversion is not exact */
				tmp_int64 = rop_util_unix_to_nttime(mktime(&tmp_tm));
				if (pmsg->proplist.set(PR_WEDDING_ANNIVERSARY, &tmp_int64) != 0)
					return nullptr;
			}	
		} else if (0 == strcasecmp(pvline->name, "X-MS-SPOUSE")) {
			pnode1 = double_list_get_head(&pvline->param_list);
			if (pnode1 == nullptr)
				return nullptr;
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (strcasecmp(pvparam->name, "N") != 0 ||
			    pvparam->pparamval_list != nullptr)
				return nullptr;
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_SPOUSE_NAME, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "X-MS-MANAGER")) {
			pnode1 = double_list_get_head(&pvline->param_list);
			if (pnode1 == nullptr)
				return nullptr;
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (strcasecmp(pvparam->name, "N") != 0 ||
			    pvparam->pparamval_list != nullptr)
				return nullptr;
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_MANAGER_NAME, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "X-MS-ASSISTANT")) {
			pnode1 = double_list_get_head(&pvline->param_list);
			if (pnode1 == nullptr)
				return nullptr;
			pvparam = (VCARD_PARAM*)pnode1->pdata;
			if (strcasecmp(pvparam->name, "N") != 0 ||
			    pvparam->pparamval_list != nullptr)
				return nullptr;
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_ASSISTANT, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "FBURL")) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(g_fbl_proptag, pstring) != 0)
				return nullptr;
		} else if (0 == strcasecmp(pvline->name, "X-MS-INTERESTS")) {
			pnode1 = double_list_get_head(&pvline->value_list);
			if (pnode1 == nullptr)
				continue;
			pvvalue = (VCARD_VALUE*)pnode1->pdata;
			strings_array.count = 0;
			strings_array.ppstr = (char**)tmp_buff;
			for (pnode2=double_list_get_head(&pvvalue->subval_list);
				NULL!=pnode2; pnode2=double_list_get_after(
				&pvvalue->subval_list, pnode2)) {
				if (pnode2->pdata == nullptr)
					continue;
				strings_array.ppstr[strings_array.count++] = static_cast<char *>(pnode2->pdata);
			}
			if (strings_array.count != 0 && strings_array.count < 128 &&
			    pmsg->proplist.set(PR_HOBBIES, &strings_array) != 0)
				return nullptr;
		}
	}
	if (child_strings.count != 0 &&
	    pmsg->proplist.set(PR_CHILDRENS_NAMES, &child_strings) != 0)
		return nullptr;
	for (i=0; i<pmsg->proplist.count; i++) {
		proptag = pmsg->proplist.ppropval[i].proptag;
		propid = PROP_ID(proptag);
		if (is_nameprop_id(propid))
			break;
	}
	if (i >= pmsg->proplist.count)
		return pmsg.release();
	if (!oxvcard_get_propids(&propids, get_propids))
		return nullptr;
	for (i=0; i<pmsg->proplist.count; i++) {
		proptag = pmsg->proplist.ppropval[i].proptag;
		propid = PROP_ID(proptag);
		if (!is_nameprop_id(propid))
			continue;
		proptag = propids.ppropid[propid - 0x8000];
		pmsg->proplist.ppropval[i].proptag =
			PROP_TAG(PROP_TYPE(pmsg->proplist.ppropval[i].proptag), proptag);
	}
	return pmsg.release();
}

BOOL oxvcard_export(MESSAGE_CONTENT *pmsg, VCARD *pvcard, GET_PROPIDS get_propids)
{
	BINARY *pbin;
	const char *pvalue;
	STRING_ARRAY *saval = nullptr;
	size_t out_len;
	uint16_t propid;
	uint32_t proptag;
	time_t unix_time;
	struct tm tmp_tm;
	VCARD_LINE *pvline;
	VCARD_VALUE *pvvalue;
	VCARD_PARAM *pvparam;
	PROPID_ARRAY propids;
	const char *photo_type;
	ATTACHMENT_CONTENT *pattachment;
	char tmp_buff[VCARD_MAX_BUFFER_LEN];
	std::string vcarduid;
	static constexpr const char *tel_types[] =
		{"HOME", "HOME", "VOICE", "WORK", "WORK",
		"CELL", "PAGER", "CAR", "ISDN", "PREF"};
	static constexpr const char *ms_tel_types[] =
		{"ASSISTANT", "CALLBACK", "COMPANY", "RADIO", "TTYTTD"};
	static constexpr uint32_t tel_proptags[] =
		{PR_HOME_TELEPHONE_NUMBER, PR_HOME2_TELEPHONE_NUMBER,
		PR_OTHER_TELEPHONE_NUMBER, PR_BUSINESS_TELEPHONE_NUMBER,
		PR_BUSINESS2_TELEPHONE_NUMBER, PR_MOBILE_TELEPHONE_NUMBER,
		PR_PAGER_TELEPHONE_NUMBER, PR_CAR_TELEPHONE_NUMBER,
		PR_ISDN_NUMBER, PR_PRIMARY_TELEPHONE_NUMBER};
	static constexpr uint32_t ms_tel_proptags[] =
		{PR_ASSISTANT_TELEPHONE_NUMBER, PR_CALLBACK_TELEPHONE_NUMBER,
		PR_COMPANY_MAIN_PHONE_NUMBER, PR_RADIO_TELEPHONE_NUMBER,
		PR_TTYTDD_PHONE_NUMBER};
	
	if (!oxvcard_get_propids(&propids, get_propids))
		return FALSE;
	pvcard->clear();
	if (!pvcard->append_line("PROFILE", "VCARD") ||
	    !pvcard->append_line("VERSION", "4.0") ||
	    !pvcard->append_line("MAILER", "gromox-oxvcard") ||
	    !pvcard->append_line("PRODID", "gromox-oxvcard"))
		return false;

	pvalue = pmsg->proplist.get<char>(PR_DISPLAY_NAME);
	if (pvalue == nullptr)
		pvalue = pmsg->proplist.get<char>(PR_NORMALIZED_SUBJECT);
	if (pvalue != nullptr && !pvcard->append_line("FN", pvalue))
		return false;
	
	pvline = vcard_new_line("N");
	if (pvline == nullptr)
		return false;
	pvcard->append_line(pvline);
	for (size_t i = 0; i < 5; ++i) {
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		pvalue = pmsg->proplist.get<char>(g_n_proptags[i]);
		if (pvalue == nullptr)
			continue;
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_NICKNAME);
	if (pvalue != nullptr && !pvcard->append_line("NICKNAME", pvalue))
		return false;
	
	for (size_t i = 0; i < 3; ++i) {
		propid = PROP_ID(g_email_proptags[i]);
		proptag = PROP_TAG(PROP_TYPE(g_email_proptags[i]), propids.ppropid[propid - 0x8000]);
		pvalue = pmsg->proplist.get<char>(proptag);
		if (pvalue == nullptr)
			continue;
		pvline = vcard_new_line("EMAIL");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("TYPE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("INTERNET"))
			return false;
		if (i == 0 && !pvparam->append_paramval("PREF"))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_ATTACHMENT_CONTACTPHOTO);
	if (pvalue != nullptr && *reinterpret_cast<const uint8_t *>(pvalue) != 0 &&
		NULL != pmsg->children.pattachments) {
		for (size_t i = 0; i < pmsg->children.pattachments->count; ++i) {
			pattachment = pmsg->children.pattachments->pplist[i];
			pvalue = pattachment->proplist.get<char>(PR_ATTACH_EXTENSION);
			if (pvalue == nullptr)
				continue;
			if (!is_photo(pvalue))
				continue;
			photo_type = pvalue;
			auto bv = pattachment->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
			if (bv == nullptr)
				continue;
			pvline = vcard_new_line("PHOTO");
			if (pvline == nullptr)
				return false;
			pvcard->append_line(pvline);
			pvparam = vcard_new_param("TYPE");
			if (pvparam == nullptr)
				return false;
			pvline->append_param(pvparam);
			if (!pvparam->append_paramval(photo_type))
				return false;
			pvparam = vcard_new_param("ENCODING");
			if (pvparam == nullptr)
				return false;
			pvline->append_param(pvparam);
			if (!pvparam->append_paramval("B"))
				return false;
			pvvalue = vcard_new_value();
			if (pvvalue == nullptr)
				return false;
			pvline->append_value(pvvalue);
			if (encode64(bv->pb, bv->cb, tmp_buff, VCARD_MAX_BUFFER_LEN - 1, &out_len) != 0)
				return false;
			tmp_buff[out_len] = '\0';
			if (!pvvalue->append_subval(tmp_buff))
				return false;
			break;
		}
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BODY);
	if (pvalue != nullptr && !pvcard->append_line("NOTE", pvalue))
		return false;
	
	pvline = vcard_new_line("ORG");
	if (pvline == nullptr)
		return false;
	pvcard->append_line(pvline);
	pvvalue = vcard_new_value();
	if (pvvalue == nullptr)
		return false;
	pvline->append_value(pvvalue);
	pvalue = pmsg->proplist.get<char>(PR_COMPANY_NAME);
	pvvalue->append_subval(pvalue);
	pvvalue = vcard_new_value();
	if (pvvalue == nullptr)
		return false;
	pvline->append_value(pvvalue);
	pvalue = pmsg->proplist.get<char>(PR_DEPARTMENT_NAME);
	pvvalue->append_subval(pvalue);
	
	pvalue = pmsg->proplist.get<char>(PR_SENSITIVITY);
	if (NULL == pvalue) {
		pvalue = "PUBLIC";
	} else {
		switch (*(uint32_t*)pvalue) {
		case SENSITIVITY_PRIVATE:
			pvalue = "PRIVATE";
			break;
		case SENSITIVITY_COMPANY_CONFIDENTIAL:
			pvalue = "CONFIDENTIAL";
			break;
		default:
			pvalue = "PUBLIC";
			break;
		}
	}
	if (!pvcard->append_line("CLASS", pvalue))
		return false;
	
	pvline = vcard_new_line("ADR");
	if (pvline == nullptr)
		return false;
	pvcard->append_line(pvline);
	pvparam = vcard_new_param("TYPE");
	if (pvparam == nullptr)
		return false;
	pvline->append_param(pvparam);
	if (!pvparam->append_paramval("WORK"))
		return false;
	for (size_t i = 0; i < 6; ++i) {
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		propid = PROP_ID(g_workaddr_proptags[i]);
		proptag = PROP_TAG(PROP_TYPE(g_workaddr_proptags[i]), propids.ppropid[propid - 0x8000]);
		pvalue = pmsg->proplist.get<char>(proptag);
		if (pvalue == nullptr)
			continue;
		pvvalue->append_subval(pvalue);
	}
	pvvalue = vcard_new_value();
	if (pvvalue == nullptr)
		return false;
	pvline->append_value(pvvalue);
	
	pvline = vcard_new_line("ADR");
	if (pvline == nullptr)
		return false;
	pvcard->append_line(pvline);
	pvparam = vcard_new_param("TYPE");
	if (pvparam == nullptr)
		return false;
	pvline->append_param(pvparam);
	if (!pvparam->append_paramval("HOME"))
		return false;
	for (size_t i = 0; i < 6; ++i) {
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		pvalue = pmsg->proplist.get<char>(g_homeaddr_proptags[i]);
		if (pvalue == nullptr)
			continue;
		pvvalue->append_subval(pvalue);
	}
	pvvalue = vcard_new_value();
	if (pvvalue == nullptr)
		return false;
	pvline->append_value(pvvalue);
	
	pvline = vcard_new_line("ADR");
	if (pvline == nullptr)
		return false;
	pvcard->append_line(pvline);
	pvparam = vcard_new_param("TYPE");
	if (pvparam == nullptr)
		return false;
	pvline->append_param(pvparam);
	if (!pvparam->append_paramval("POSTAL"))
		return false;
	for (size_t i = 0; i < 6; ++i) {
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		pvalue = pmsg->proplist.get<char>(g_otheraddr_proptags[i]);
		if (pvalue == nullptr)
			continue;
		pvvalue->append_subval(pvalue);
	}
	pvvalue = vcard_new_value();
	if (pvvalue == nullptr)
		return false;
	pvline->append_value(pvvalue);
	
	for (size_t i = 0; i < 10; ++i) {
		pvalue = pmsg->proplist.get<char>(tel_proptags[i]);
		if (pvalue == nullptr)
			continue;
		pvline = vcard_new_line("TEL");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("TYPE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval(tel_types[i]))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_HOME_FAX_NUMBER);
	if (NULL != pvalue) {
			pvline = vcard_new_line("TEL");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("TYPE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("HOME"))
			return false;
		pvparam = vcard_new_param("FAX");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BUSINESS_FAX_NUMBER);
	if (NULL != pvalue) {
			pvline = vcard_new_line("TEL");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("TYPE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("WORK"))
			return false;
		pvparam = vcard_new_param("FAX");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	propid = PROP_ID(g_categories_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_categories_proptag), propids.ppropid[propid - 0x8000]);
	saval = pmsg->proplist.get<STRING_ARRAY>(proptag);
	if (saval != nullptr) {
		pvline = vcard_new_line("CATEGORIES");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		for (size_t i = 0; i < saval->count; ++i)
			if (!pvvalue->append_subval(saval->ppstr[i]))
				return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_PROFESSION);
	if (pvalue != nullptr && !pvcard->append_line("ROLE", pvalue))
		return false;
	
	pvalue = pmsg->proplist.get<char>(PR_PERSONAL_HOME_PAGE);
	if (NULL != pvalue) {
		pvline = vcard_new_line("URL");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("TYPE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("HOME"))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BUSINESS_HOME_PAGE);
	if (NULL != pvalue) {
		pvline = vcard_new_line("URL");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("TYPE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("WORK"))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	propid = PROP_ID(g_bcd_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_bcd_proptag), propids.ppropid[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	if (pvalue != nullptr && !pvcard->append_line("X-MS-OL-DESIGN", pvalue))
		return false;
	
	saval = pmsg->proplist.get<STRING_ARRAY>(PR_CHILDRENS_NAMES);
	if (NULL != pvalue) {
		for (size_t i = 0; i < saval->count; ++i) {
			if (!pvcard->append_line("X-MS-CHILD", saval->ppstr[i]))
				return false;
		}
	}
	
	for (size_t i = 0; i < 4; ++i) {
		propid = PROP_ID(g_ufld_proptags[i]);
		proptag = PROP_TAG(PROP_TYPE(g_ufld_proptags[i]), propids.ppropid[propid - 0x8000]);
		pvalue = pmsg->proplist.get<char>(proptag);
		if (pvalue == nullptr)
			continue;
		if (!pvcard->append_line("X-MS-TEXT", pvalue))
			return false;
	}
	
	for (size_t i = 0; i < 5; ++i) {
		pvalue = pmsg->proplist.get<char>(ms_tel_proptags[i]);
		if (pvalue == nullptr)
			continue;
		pvline = vcard_new_line("X-MS-TEL");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("TYPE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval(ms_tel_types[i]))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_SPOUSE_NAME);
	if (NULL != pvalue) {
		pvline = vcard_new_line("X-MS-SPOUSE");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("N");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_MANAGER_NAME);
	if (NULL != pvalue) {
		pvline = vcard_new_line("X-MS-MANAGER");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("N");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_ASSISTANT);
	if (NULL != pvalue) {
		pvline = vcard_new_line("X-MS-ASSISTANT");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("N");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(pvalue))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PROP_TAG(PROP_TYPE(g_vcarduid_proptag), propids.ppropid[PROP_ID(g_vcarduid_proptag)-0x8000]));
	if (pvalue == nullptr) try {
		auto guid = GUID::random_new();
		vcarduid = "uuid:" + bin2hex(&guid, sizeof(guid));
		pvalue = vcarduid.c_str();
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1605: ENOMEM\n");
		return false;
	}
	if (pvalue != nullptr && !pvcard->append_line("UID", pvalue))
		return false;

	propid = PROP_ID(g_fbl_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_fbl_proptag), propids.ppropid[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	if (pvalue != nullptr && !pvcard->append_line("FBURL", pvalue))
		return false;
	
	saval = pmsg->proplist.get<STRING_ARRAY>(PR_HOBBIES);
	if (NULL != pvalue) {
		pvline = vcard_new_line("X-MS-INTERESTS");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		for (size_t i = 0; i < saval->count; ++i)
			if (!pvvalue->append_subval(saval->ppstr[i]))
				return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_USER_X509_CERTIFICATE);
	if (NULL != pvalue && 0 != ((BINARY_ARRAY*)pvalue)->count) {
		pvline = vcard_new_line("KEY");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("ENCODING");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("B"))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		pbin = ((BINARY_ARRAY*)pvalue)->pbin;
		if (0 != encode64(pbin->pb, pbin->cb, tmp_buff,
		    VCARD_MAX_BUFFER_LEN - 1, &out_len))
			return false;
		tmp_buff[out_len] = '\0';
		if (!pvvalue->append_subval(tmp_buff))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_TITLE);
	if (!pvcard->append_line("TITLE", pvalue))
		return false;
	
	propid = PROP_ID(g_im_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_im_proptag), propids.ppropid[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	if (!pvcard->append_line("X-MS-IMADDRESS", pvalue))
		return false;
	
	pvalue = pmsg->proplist.get<char>(PR_BIRTHDAY);
	if (NULL != pvalue) {
		unix_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
		gmtime_r(&unix_time, &tmp_tm);
		strftime(tmp_buff, 1024, "%Y-%m-%d", &tmp_tm);
		pvline = vcard_new_line("BDAY");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("VALUE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("DATE"))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(tmp_buff))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_LAST_MODIFICATION_TIME);
	if (NULL != pvalue) {
		unix_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
		gmtime_r(&unix_time, &tmp_tm);
		strftime(tmp_buff, 1024, "%Y-%m-%dT%H:%M:%SZ", &tmp_tm);
		pvline = vcard_new_line("REV");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("VALUE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("DATE-TIME"))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(tmp_buff))
			return false;
	}
	
	pvalue = pmsg->proplist.get<char>(PR_WEDDING_ANNIVERSARY);
	if (NULL != pvalue) {
		unix_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
		gmtime_r(&unix_time, &tmp_tm);
		strftime(tmp_buff, 1024, "%Y-%m-%d", &tmp_tm);
		pvline = vcard_new_line("X-MS-ANNIVERSARY");
		if (pvline == nullptr)
			return false;
		pvcard->append_line(pvline);
		pvparam = vcard_new_param("VALUE");
		if (pvparam == nullptr)
			return false;
		pvline->append_param(pvparam);
		if (!pvparam->append_paramval("DATE"))
			return false;
		pvvalue = vcard_new_value();
		if (pvvalue == nullptr)
			return false;
		pvline->append_value(pvvalue);
		if (!pvvalue->append_subval(tmp_buff))
			return false;
	}
	return TRUE;
}
