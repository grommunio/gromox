// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
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

struct unrecog {
	unrecog(const vcard_line &l) :
		m_what("Line " + std::to_string(l.m_lnum)) {}
	unrecog(const vcard_line &l, const vcard_param &p) :
		m_what("Line " + std::to_string(l.m_lnum) + " Param {" + p.name() + "}") {}
	unrecog(const vcard_line &l, const vcard_value &v) :
		m_what("Line " + std::to_string(l.m_lnum) + " Value {}") {}
	const char *what() const noexcept { return m_what.c_str(); }
	std::string m_what;
};

}

unsigned int g_oxvcard_pedantic;
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
	
	b_version = FALSE;
	for (const auto &line : pvcard->m_lines) {
		auto pvline = &line;
		if (strcasecmp(pvline->name(), "VERSION") != 0)
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

static bool is_fax_param(const vcard_param &p)
{
	if (strcasecmp(p.name(), "type") == 0 && p.m_paramvals.size() > 0 &&
	    strcasecmp(p.m_paramvals[0].c_str(), "fax") == 0)
		return true;
	return strcasecmp(p.name(), "fax") == 0;
}

static std::string join(const char *gn, const char *mn, const char *sn)
{
	std::string r = znul(gn);
	if (mn != nullptr) {
		r += " ";
		r += mn;
	}
	if (sn != nullptr) {
		r +=" ";
		r += sn;
	}
	return r;
}

MESSAGE_CONTENT* oxvcard_import(
	const VCARD *pvcard, GET_PROPIDS get_propids)
{
	int i;
	int count;
	int tmp_len;
	int ufld_count;
	int mail_count;
	BINARY tmp_bin;
	uint16_t propid;
	BOOL b_encoding;
	uint32_t proptag;
	struct tm tmp_tm;
	uint8_t tmp_byte;
	size_t decode_len;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	char* child_buff[16];
	PROPID_ARRAY propids;
	BINARY_ARRAY bin_array;
	const char *photo_type;
	const char *address_type;
	STRING_ARRAY child_strings;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	
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
	for (const auto &line : pvcard->m_lines) try {
		auto pvline = &line;
		auto pvline_name = pvline->name();
		if (strcasecmp(pvline_name, "UID") == 0) {
			/* Deviation from MS-OXVCARD v8.3 §2.1.3.7.7 */
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				throw unrecog(line);
			if (pmsg->proplist.set(g_vcarduid_proptag, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "FN") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				throw unrecog(line);
			if (pmsg->proplist.set(PR_DISPLAY_NAME, pstring) != 0 ||
			    pmsg->proplist.set(PR_NORMALIZED_SUBJECT, pstring) != 0 ||
			    pmsg->proplist.set(PR_CONVERSATION_TOPIC, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "N") == 0) {
			count = 0;
			for (const auto &vnode : pvline->m_values) {
				if (count > 4)
					break;
				auto pvvalue = &vnode;
				auto list_count = pvvalue->m_subvals.size();
				if (list_count > 1)
					throw unrecog(line, vnode);
				if (list_count > 0 &&
				    !pvvalue->m_subvals[0].empty() &&
				    pmsg->proplist.set(g_n_proptags[count], pvvalue->m_subvals[0].c_str()) != 0)
					return nullptr;
				count ++;
			}
		} else if (strcasecmp(pvline_name, "NICKNAME") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring != nullptr &&
			    pmsg->proplist.set(PR_NICKNAME, pstring) != 0)
					return nullptr;
		} else if (strcasecmp(pvline_name, "PHOTO") == 0) {
			if (pmsg->children.pattachments != nullptr)
				throw unrecog(line);
			b_encoding = FALSE;
			photo_type = NULL;
			for (const auto &prnode : pvline->m_params) {
				auto pvparam = &prnode;
				if (strcasecmp(pvparam->name(), "ENCODING") == 0) {
					if (pvparam->m_paramvals.size() == 0 ||
					    strcasecmp(pvparam->m_paramvals[0].c_str(), "b") != 0)
						throw unrecog(line, prnode);
					b_encoding = TRUE;
				} else if (strcasecmp(pvparam->name(), "TYPE") == 0) {
					if (pvparam->m_paramvals.size() == 0)
						throw unrecog(line, prnode);
					auto &s = pvparam->m_paramvals[0];
					if (s.empty())
						throw unrecog(line, prnode);
					photo_type = s.c_str();
				}
			}
			if (!b_encoding || photo_type == nullptr)
				throw unrecog(line);

			if (!is_photo(photo_type))
				throw unrecog(line);
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				throw unrecog(line);
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
			char tmp_buff[VCARD_MAX_BUFFER_LEN];
			if (decode64(pstring, tmp_len, tmp_buff,
			    arsizeof(tmp_buff), &decode_len) != 0)
				throw unrecog(line);
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
		} else if (strcasecmp(pvline_name, "BDAY") == 0) {
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
		} else if (strcasecmp(pvline_name, "ADR") == 0) {
			auto pvparam = pvline->m_params.cbegin();
			if (pvparam == pvline->m_params.cend())
				throw unrecog(line);
			if (strcasecmp(pvparam->name(), "TYPE") != 0 ||
			    pvparam->m_paramvals.size() == 0)
				throw unrecog(line, *pvparam);
			address_type = pvparam->m_paramvals[0].c_str();
			count = 0;
			for (const auto &vnode : pvline->m_values) {
				if (count > 5)
					break;
				auto pvvalue = &vnode;
				auto list_count = pvvalue->m_subvals.size();
				if (list_count > 1)
					throw unrecog(line);
				if (list_count > 0 &&
				    !pvvalue->m_subvals[0].empty()) {
					uint32_t tag;
					if (strcasecmp(address_type, "work") == 0)
						tag = g_workaddr_proptags[count];
					else if (strcasecmp(address_type, "home") == 0)
						tag = g_homeaddr_proptags[count];
					else
						tag = g_otheraddr_proptags[count];
					if (pmsg->proplist.set(tag, pvvalue->m_subvals[0].c_str()) != 0)
						return nullptr;
				}
				count ++;
			}
		} else if (strcasecmp(pvline_name, "TEL") == 0) {
			auto pvparam = pvline->m_params.cbegin();
			if (pvparam == pvline->m_params.cend())
				throw unrecog(line);
			if (strcasecmp(pvparam->name(), "TYPE") != 0 ||
			    pvparam->m_paramvals.size() == 0)
				throw unrecog(line);
			auto keyword = pvparam->m_paramvals[0].c_str();
			if (*keyword == '\0')
				throw unrecog(line, *pvparam);
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			uint32_t tag = 0;
			if (strcasecmp(keyword, "home") == 0) {
				++pvparam;
				if (pvparam == pvline->m_params.cend())
					tag = pmsg->proplist.has(PR_HOME_TELEPHONE_NUMBER) ?
					      PR_HOME2_TELEPHONE_NUMBER :
					      PR_HOME_TELEPHONE_NUMBER;
				else if (is_fax_param(*pvparam))
					tag = PR_HOME_FAX_NUMBER;
				else
					throw unrecog(line, *pvparam);
			} else if (strcasecmp(keyword, "voice") == 0) {
				tag = PR_OTHER_TELEPHONE_NUMBER;
			} else if (strcasecmp(keyword, "work") == 0) {
				++pvparam;
				if (pvparam == pvline->m_params.cend())
					tag = pmsg->proplist.has(PR_BUSINESS_TELEPHONE_NUMBER) ?
					      PR_BUSINESS2_TELEPHONE_NUMBER :
					      PR_BUSINESS_TELEPHONE_NUMBER;
				else if (is_fax_param(*pvparam))
					tag = PR_BUSINESS_FAX_NUMBER;
				else
					throw unrecog(line, *pvparam);
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
		} else if (strcasecmp(pvline_name, "EMAIL") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (mail_count > 2)
				continue;
			if (pmsg->proplist.set(g_email_proptags[mail_count++], pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "TITLE") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_TITLE, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "ROLE") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_PROFESSION, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "ORG") == 0) {
			auto pvvalue = pvline->m_values.cbegin();
			if (pvvalue == pvline->m_values.cend())
				continue;
			{
				if (pvvalue->m_subvals.size() > 0 &&
				    !pvvalue->m_subvals[0].empty() &&
				    pmsg->proplist.set(PR_COMPANY_NAME, pvvalue->m_subvals[0].c_str()) != 0)
					return nullptr;
			}
			++pvvalue;
			if (pvvalue != pvline->m_values.cend()) {
				if (pvvalue->m_subvals.size() > 0 &&
				    !pvvalue->m_subvals[0].empty() &&
				    pmsg->proplist.set(PR_DEPARTMENT_NAME, pvvalue->m_subvals[0].c_str()) != 0)
					return nullptr;
			}
		} else if (strcasecmp(pvline_name, "CATEGORIES") == 0) {
			auto pvvalue = pvline->m_values.cbegin();
			if (pvvalue == pvline->m_values.cend())
				continue;
			char tmp_buff[VCARD_MAX_BUFFER_LEN];
			STRING_ARRAY strings_array;
			strings_array.count = 0;
			strings_array.ppstr = (char**)tmp_buff;
			for (const auto &sv : pvvalue->m_subvals) {
				if (sv.empty())
					continue;
				strings_array.ppstr[strings_array.count++] = deconst(sv.c_str());
			}
			if (strings_array.count != 0 && strings_array.count < 128 &&
			    pmsg->proplist.set(g_categories_proptag, &strings_array) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "NOTE") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_BODY, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "REV") == 0) {
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
		} else if (strcasecmp(pvline_name, "URL") == 0) {
			auto pvparam = pvline->m_params.cbegin();
			if (pvparam == pvline->m_params.cend())
				throw unrecog(line);
			if (strcasecmp(pvparam->name(), "TYPE") != 0 ||
			    pvparam->m_paramvals.size() == 0)
				throw unrecog(line);
			auto keyword = pvparam->m_paramvals[0].c_str();
			if (*keyword == '\0')
				throw unrecog(line, *pvparam);
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			uint32_t tag;
			if (strcasecmp(keyword, "home") == 0)
				tag = PR_PERSONAL_HOME_PAGE;
			else if (strcasecmp(keyword, "work") == 0)
				tag = PR_BUSINESS_HOME_PAGE;
			else
				continue;
			if (pmsg->proplist.set(tag, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "CLASS") == 0) {
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
		} else if (strcasecmp(pvline_name, "KEY") == 0) {
			auto pvparam = pvline->m_params.cbegin();
			if (pvparam == pvline->m_params.cend())
				throw unrecog(line);
			if (strcasecmp(pvparam->name(), "ENCODING") != 0 ||
			    pvparam->m_paramvals.size() == 0 ||
			    strcasecmp(pvparam->m_paramvals[0].c_str(), "b") != 0)
				throw unrecog(line, *pvparam);
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				throw unrecog(line);
			tmp_len = strlen(pstring);
			char tmp_buff[VCARD_MAX_BUFFER_LEN];
			if (decode64(pstring, tmp_len, tmp_buff,
			    arsizeof(tmp_buff), &decode_len) != 0)
				throw unrecog(line);
			bin_array.count = 1;
			bin_array.pbin = &tmp_bin;
			tmp_bin.pc = tmp_buff;
			tmp_bin.cb = decode_len;
			if (pmsg->proplist.set(PR_USER_X509_CERTIFICATE, &bin_array) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "X-MS-OL-DESIGN") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			tmp_bin.cb = strlen(pstring);
			tmp_bin.pv = deconst(pstring);
			if (pmsg->proplist.set(g_bcd_proptag, &tmp_bin) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "X-MS-CHILD") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (child_strings.count >= GX_ARRAY_SIZE(child_buff))
				throw unrecog(line);
			child_strings.ppstr[child_strings.count++] = deconst(pstring);
		} else if (strcasecmp(pvline_name, "X-MS-TEXT") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (ufld_count > 3)
				throw unrecog(line);
			if (pmsg->proplist.set(g_ufld_proptags[ufld_count++], pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "X-MS-IMADDRESS") == 0 ||
		    strcasecmp(pvline_name, "X-MS-RM-IMACCOUNT") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(g_im_proptag, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "X-MS-TEL") == 0) {
			auto pvparam = pvline->m_params.cbegin();
			if (pvparam == pvline->m_params.cend())
				throw unrecog(line);
			if (pvparam->m_paramvals.size() != 0)
				throw unrecog(line, *pvparam);
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			uint32_t tag;
			auto pvparam_name = pvparam->name();
			if (strcasecmp(pvparam_name, "ASSISTANT") == 0)
				tag = PR_ASSISTANT_TELEPHONE_NUMBER;
			else if (strcasecmp(pvparam_name, "CALLBACK") == 0)
				tag = PR_CALLBACK_TELEPHONE_NUMBER;
			else if (strcasecmp(pvparam_name, "COMPANY") == 0)
				tag = PR_COMPANY_MAIN_PHONE_NUMBER;
			else if (strcasecmp(pvparam_name, "RADIO") == 0)
				tag = PR_RADIO_TELEPHONE_NUMBER;
			else if (strcasecmp(pvparam_name, "TTYTTD") == 0)
				tag = PR_TTYTDD_PHONE_NUMBER;
			else
				throw unrecog(line, *pvparam);
			if (pmsg->proplist.set(tag, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "X-MS-ANNIVERSARY") == 0) {
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
		} else if (strcasecmp(pvline_name, "X-MS-SPOUSE") == 0) {
			auto pvparam = pvline->m_params.cbegin();
			if (pvparam == pvline->m_params.cend())
				throw unrecog(line);
			if (strcasecmp(pvparam->name(), "N") != 0 ||
			    pvparam->m_paramvals.size() != 0)
				throw unrecog(line, *pvparam);
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_SPOUSE_NAME, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "X-MS-MANAGER") == 0) {
			auto pvparam = pvline->m_params.cbegin();
			if (pvparam == pvline->m_params.cend())
				throw unrecog(line);
			if (strcasecmp(pvparam->name(), "N") != 0 ||
			    pvparam->m_paramvals.size() != 0)
				throw unrecog(line, *pvparam);
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_MANAGER_NAME, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "X-MS-ASSISTANT") == 0) {
			auto pvparam = pvline->m_params.cbegin();
			if (pvparam == pvline->m_params.cend())
				throw unrecog(line);
			if (strcasecmp(pvparam->name(), "N") != 0 ||
			    pvparam->m_paramvals.size() != 0)
				throw unrecog(line, *pvparam);
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_ASSISTANT, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "FBURL") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(g_fbl_proptag, pstring) != 0)
				return nullptr;
		} else if (strcasecmp(pvline_name, "X-MS-INTERESTS") == 0) {
			auto pvvalue = pvline->m_values.cbegin();
			if (pvvalue == pvline->m_values.cend())
				continue;
			char tmp_buff[VCARD_MAX_BUFFER_LEN];
			STRING_ARRAY strings_array;
			strings_array.count = 0;
			strings_array.ppstr = (char**)tmp_buff;
			for (const auto &sv : pvvalue->m_subvals) {
				if (sv.empty())
					continue;
				strings_array.ppstr[strings_array.count++] = deconst(sv.c_str());
			}
			if (strings_array.count != 0 && strings_array.count < 128 &&
			    pmsg->proplist.set(PR_HOBBIES, &strings_array) != 0)
				return nullptr;
		}
	} catch (const unrecog &e) {
		if (g_oxvcard_pedantic) {
			fprintf(stderr, "E-2140: oxvcard_import stopped parsing that vcard due to pedantry: %s\n", e.what());
			return nullptr;
		}
	}
	if (child_strings.count != 0 &&
	    pmsg->proplist.set(PR_CHILDRENS_NAMES, &child_strings) != 0)
		return nullptr;
	if (!pmsg->proplist.has(PR_DISPLAY_NAME)) {
		auto dn = join(pmsg->proplist.get<char>(PR_GIVEN_NAME),
		          pmsg->proplist.get<char>(PR_MIDDLE_NAME),
		          pmsg->proplist.get<char>(PR_SURNAME));
		if (pmsg->proplist.set(PR_DISPLAY_NAME, dn.c_str()) != 0)
			return nullptr;
	}
	if (!pmsg->proplist.has(PR_NORMALIZED_SUBJECT)) {
		auto dn = pmsg->proplist.get<const char>(PR_DISPLAY_NAME);
		if (dn != nullptr && pmsg->proplist.set(PR_NORMALIZED_SUBJECT, dn) != 0)
			return nullptr;
	}
	if (!pmsg->proplist.has(PR_CONVERSATION_TOPIC)) {
		auto dn = pmsg->proplist.get<const char>(PR_DISPLAY_NAME);
		if (dn != nullptr && pmsg->proplist.set(PR_CONVERSATION_TOPIC, dn) != 0)
			return nullptr;
	}
	for (i=0; i<pmsg->proplist.count; i++) {
		proptag = pmsg->proplist.ppropval[i].proptag;
		propid = PROP_ID(proptag);
		if (is_nameprop_id(propid))
			break;
	}
	if (i >= pmsg->proplist.count)
		/* If no namedprops were set, we can exit early */
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

BOOL oxvcard_export(MESSAGE_CONTENT *pmsg, vcard &vcard, GET_PROPIDS get_propids) try
{
	BINARY *pbin;
	const char *pvalue;
	STRING_ARRAY *saval = nullptr;
	size_t out_len;
	uint16_t propid;
	uint32_t proptag;
	time_t unix_time;
	struct tm tmp_tm;
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
	vcard.clear();
	vcard.append_line("PROFILE", "VCARD");
	vcard.append_line("VERSION", "4.0");
	vcard.append_line("MAILER", "gromox-oxvcard");
	vcard.append_line("PRODID", "gromox-oxvcard");

	pvalue = pmsg->proplist.get<char>(PR_DISPLAY_NAME);
	if (pvalue == nullptr)
		pvalue = pmsg->proplist.get<char>(PR_NORMALIZED_SUBJECT);
	if (pvalue != nullptr) {
		vcard.append_line("FN", pvalue);
	}
	
	auto &n_line = vcard.append_line("N");
	for (size_t i = 0; i < 5; ++i) {
		pvalue = pmsg->proplist.get<char>(g_n_proptags[i]);
		if (pvalue == nullptr)
			continue;
		n_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_NICKNAME);
	if (pvalue != nullptr) {
		vcard.append_line("NICKNAME", pvalue);
	}
	
	for (size_t i = 0; i < 3; ++i) {
		propid = PROP_ID(g_email_proptags[i]);
		proptag = PROP_TAG(PROP_TYPE(g_email_proptags[i]), propids.ppropid[propid - 0x8000]);
		pvalue = pmsg->proplist.get<char>(proptag);
		if (pvalue == nullptr)
			continue;
		auto &email_line = vcard.append_line("EMAIL");
		auto &type_param = email_line.append_param("TYPE");
		type_param.append_paramval("INTERNET");
		if (i == 0) {
			type_param.append_paramval("PREF");
		}
		email_line.append_value(pvalue);
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
			auto &photo_line = vcard.append_line("PHOTO");
			photo_line.append_param("TYPE", photo_type);
			photo_line.append_param("ENCODING", "B");
			if (encode64(bv->pb, bv->cb, tmp_buff, VCARD_MAX_BUFFER_LEN - 1, &out_len) != 0)
				return false;
			tmp_buff[out_len] = '\0';
			photo_line.append_value(tmp_buff);
			break;
		}
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BODY);
	if (pvalue != nullptr) {
		vcard.append_line("NOTE", pvalue);
	}
	
	auto &org_line = vcard.append_line("ORG");
	pvalue = pmsg->proplist.get<char>(PR_COMPANY_NAME);
	org_line.append_value(pvalue);
	pvalue = pmsg->proplist.get<char>(PR_DEPARTMENT_NAME);
	org_line.append_value(pvalue);
	
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
	vcard.append_line("CLASS", pvalue);
	
	auto adr_line = &vcard.append_line("ADR");
	adr_line->append_param("TYPE", "WORK");
	for (size_t i = 0; i < 6; ++i) {
		propid = PROP_ID(g_workaddr_proptags[i]);
		proptag = PROP_TAG(PROP_TYPE(g_workaddr_proptags[i]), propids.ppropid[propid - 0x8000]);
		pvalue = pmsg->proplist.get<char>(proptag);
		if (pvalue == nullptr)
			continue;
		adr_line->append_value(pvalue);
	}
	adr_line->append_value();
	
	adr_line = &vcard.append_line("ADR");
	adr_line->append_param("TYPE", "HOME");
	for (size_t i = 0; i < 6; ++i) {
		pvalue = pmsg->proplist.get<char>(g_homeaddr_proptags[i]);
		if (pvalue == nullptr)
			continue;
		adr_line->append_value(pvalue);
	}
	adr_line->append_value();
	
	adr_line = &vcard.append_line("ADR");
	adr_line->append_param("TYPE", "POSTAL");
	for (size_t i = 0; i < 6; ++i) {
		pvalue = pmsg->proplist.get<char>(g_otheraddr_proptags[i]);
		if (pvalue == nullptr)
			continue;
		adr_line->append_value(pvalue);
	}
	adr_line->append_value();
	
	for (size_t i = 0; i < 10; ++i) {
		pvalue = pmsg->proplist.get<char>(tel_proptags[i]);
		if (pvalue == nullptr)
			continue;
		auto &tel_line = vcard.append_line("TEL");
		tel_line.append_param("TYPE", tel_types[i]);
		tel_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_HOME_FAX_NUMBER);
	if (NULL != pvalue) {
		auto &tel_line = vcard.append_line("TEL");
		tel_line.append_param("TYPE", "HOME");
		tel_line.append_param("FAX");
		tel_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BUSINESS_FAX_NUMBER);
	if (NULL != pvalue) {
		auto &tel_line = vcard.append_line("TEL");
		tel_line.append_param("TYPE", "WORK");
		tel_line.append_param("FAX");
		tel_line.append_value(pvalue);
	}
	
	propid = PROP_ID(g_categories_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_categories_proptag), propids.ppropid[propid - 0x8000]);
	saval = pmsg->proplist.get<STRING_ARRAY>(proptag);
	if (saval != nullptr) {
		auto &cat_line = vcard.append_line("CATEGORIES");
		auto &val = cat_line.append_value();
		for (size_t i = 0; i < saval->count; ++i) {
			val.append_subval(saval->ppstr[i]);
		}
	}
	
	pvalue = pmsg->proplist.get<char>(PR_PROFESSION);
	if (pvalue != nullptr) {
		vcard.append_line("ROLE", pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_PERSONAL_HOME_PAGE);
	if (NULL != pvalue) {
		auto &url_line = vcard.append_line("URL");
		url_line.append_param("TYPE", "HOME");
		url_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BUSINESS_HOME_PAGE);
	if (NULL != pvalue) {
		auto &url_line = vcard.append_line("URL");
		url_line.append_param("TYPE", "WORK");
		url_line.append_value(pvalue);
	}
	
	propid = PROP_ID(g_bcd_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_bcd_proptag), propids.ppropid[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	if (pvalue != nullptr) {
		vcard.append_line("X-MS-OL-DESIGN", pvalue);
	}
	
	saval = pmsg->proplist.get<STRING_ARRAY>(PR_CHILDRENS_NAMES);
	if (NULL != pvalue) {
		for (size_t i = 0; i < saval->count; ++i) {
			vcard.append_line("X-MS-CHILD", saval->ppstr[i]);
		}
	}
	
	for (size_t i = 0; i < 4; ++i) {
		propid = PROP_ID(g_ufld_proptags[i]);
		proptag = PROP_TAG(PROP_TYPE(g_ufld_proptags[i]), propids.ppropid[propid - 0x8000]);
		pvalue = pmsg->proplist.get<char>(proptag);
		if (pvalue == nullptr)
			continue;
		vcard.append_line("X-MS-TEXT", pvalue);
	}
	
	for (size_t i = 0; i < 5; ++i) {
		pvalue = pmsg->proplist.get<char>(ms_tel_proptags[i]);
		if (pvalue == nullptr)
			continue;
		auto &tel_line = vcard.append_line("X-MS-TEL");
		tel_line.append_param("TYPE", ms_tel_types[i]);
		tel_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_SPOUSE_NAME);
	if (NULL != pvalue) {
		auto &sp_line = vcard.append_line("X-MS-SPOUSE");
		sp_line.append_param("N");
		sp_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_MANAGER_NAME);
	if (NULL != pvalue) {
		auto &mgr_line = vcard.append_line("X-MS-MANAGER");
		mgr_line.append_param("N");
		mgr_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_ASSISTANT);
	if (NULL != pvalue) {
		auto &as_line = vcard.append_line("X-MS-ASSISTANT");
		as_line.append_param("N");
		as_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PROP_TAG(PROP_TYPE(g_vcarduid_proptag), propids.ppropid[PROP_ID(g_vcarduid_proptag)-0x8000]));
	if (pvalue == nullptr) {
		auto guid = GUID::random_new();
		vcarduid = "uuid:" + bin2hex(&guid, sizeof(guid));
		pvalue = vcarduid.c_str();
	}
	if (pvalue != nullptr) {
		vcard.append_line("UID", pvalue);
	}

	propid = PROP_ID(g_fbl_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_fbl_proptag), propids.ppropid[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	if (pvalue != nullptr) {
		vcard.append_line("FBURL", pvalue);
	}
	
	saval = pmsg->proplist.get<STRING_ARRAY>(PR_HOBBIES);
	if (NULL != pvalue) {
		auto &int_line = vcard.append_line("X-MS-INTERESTS");
		auto &val = int_line.append_value();
		for (size_t i = 0; i < saval->count; ++i) {
			val.append_subval(saval->ppstr[i]);
		}
	}
	
	pvalue = pmsg->proplist.get<char>(PR_USER_X509_CERTIFICATE);
	if (NULL != pvalue && 0 != ((BINARY_ARRAY*)pvalue)->count) {
		auto &key_line = vcard.append_line("KEY");
		key_line.append_param("ENCODING", "B");
		pbin = ((BINARY_ARRAY*)pvalue)->pbin;
		if (0 != encode64(pbin->pb, pbin->cb, tmp_buff,
		    VCARD_MAX_BUFFER_LEN - 1, &out_len))
			return false;
		tmp_buff[out_len] = '\0';
		key_line.append_value(tmp_buff);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_TITLE);
	vcard.append_line("TITLE", pvalue);
	
	propid = PROP_ID(g_im_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_im_proptag), propids.ppropid[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	vcard.append_line("X-MS-IMADDRESS", pvalue);
	
	pvalue = pmsg->proplist.get<char>(PR_BIRTHDAY);
	if (NULL != pvalue) {
		unix_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
		gmtime_r(&unix_time, &tmp_tm);
		strftime(tmp_buff, 1024, "%Y-%m-%d", &tmp_tm);
		auto &day_line = vcard.append_line("BDAY");
		day_line.append_param("VALUE", "DATE");
		day_line.append_value(tmp_buff);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_LAST_MODIFICATION_TIME);
	if (NULL != pvalue) {
		unix_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
		gmtime_r(&unix_time, &tmp_tm);
		strftime(tmp_buff, 1024, "%Y-%m-%dT%H:%M:%SZ", &tmp_tm);
		auto &day_line = vcard.append_line("REV");
		day_line.append_param("VALUE", "DATE-TIME");
		day_line.append_value(tmp_buff);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_WEDDING_ANNIVERSARY);
	if (NULL != pvalue) {
		unix_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
		gmtime_r(&unix_time, &tmp_tm);
		strftime(tmp_buff, 1024, "%Y-%m-%d", &tmp_tm);
		auto &day_line = vcard.append_line("X-MS-ANNIVERSARY");
		day_line.append_param("VALUE", "DATE");
		day_line.append_value(tmp_buff);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1605: ENOMEM\n");
	return false;
}
