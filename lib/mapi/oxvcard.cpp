// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>
#include <vector>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>

using namespace std::string_literals;
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

namespace gromox {
unsigned int g_oxvcard_pedantic;
}

static constexpr proptag_t g_n_proptags[] = 
	{PR_SURNAME, PR_GIVEN_NAME, PR_MIDDLE_NAME,
	PR_DISPLAY_NAME_PREFIX, PR_GENERATION};
/* The 8000s numbers must match up with the order of the oxvcard_get_propids::bf array */
static constexpr proptag_t g_workaddr_proptags[] =
	{0x8000001F, 0x8001001F, 0x8002001F, 0x8003001F, 0x8004001F, 0x8005001F};
static constexpr proptag_t g_homeaddr_proptags[] =
	{PR_HOME_ADDRESS_POST_OFFICE_BOX, PR_HOME_ADDRESS_STREET,
	PR_HOME_ADDRESS_CITY, PR_HOME_ADDRESS_STATE_OR_PROVINCE,
	PR_HOME_ADDRESS_POSTAL_CODE, PR_HOME_ADDRESS_COUNTRY};
static constexpr proptag_t g_otheraddr_proptags[] =
	{PR_OTHER_ADDRESS_POST_OFFICE_BOX, PR_OTHER_ADDRESS_STREET,
	PR_OTHER_ADDRESS_CITY, PR_OTHER_ADDRESS_STATE_OR_PROVINCE,
	PR_OTHER_ADDRESS_POSTAL_CODE, PR_OTHER_ADDRESS_COUNTRY};
static_assert(std::size(g_workaddr_proptags) == std::size(g_homeaddr_proptags));
static_assert(std::size(g_workaddr_proptags) == std::size(g_otheraddr_proptags));
static constexpr proptag_t g_email_proptags[] =
	{0x8006001F, 0x8007001F, 0x8008001F};
static constexpr proptag_t g_addrtype_proptags[] =
	{0x8012001F, 0x8013001F, 0x8014001F};
static constexpr proptag_t g_im_proptag = 0x8009001F;
static constexpr proptag_t g_categories_proptag = 0x800A101F;
static constexpr proptag_t g_bcd_proptag = 0x800B0102;
static constexpr proptag_t g_ufld_proptags[] = 
	{0x800C001F, 0x800D001F, 0x800E001F, 0x800F001F};
static constexpr proptag_t g_fbl_proptag = 0x8010001F;
static constexpr proptag_t g_vcarduid_proptag = 0x8011001F;

static BOOL oxvcard_check_compatible(const vcard *pvcard)
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
	PROPERTY_NAME bf[21];
	size_t start = 0, z = 0;

	/* bf array must be ordered w.r.t. g_workaddr_proptags et al */
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
		bf[i].guid = PSETID_Address;
		bf[i].kind = MNID_ID;
	}

	bf[z].guid = PS_PUBLIC_STRINGS;
	bf[z].kind = MNID_ID;
	bf[z++].lid = PidLidCategories;
	bf[z].guid = PSETID_Address;
	bf[z].kind = MNID_ID;
	bf[z++].lid = PidLidBusinessCardDisplayDefinition;

	start = z;
	bf[z++].lid = PidLidContactUserField1;
	bf[z++].lid = PidLidContactUserField2;
	bf[z++].lid = PidLidContactUserField3;
	bf[z++].lid = PidLidContactUserField4;
	bf[z++].lid = PidLidFreeBusyLocation;
	for (size_t i = start; i < z; ++i) {
		bf[i].guid = PSETID_Address;
		bf[i].kind = MNID_ID;
	}
	bf[z].guid = PSETID_Gromox;
	bf[z].kind = MNID_STRING;
	bf[z++].pname = deconst("vcarduid");

	bf[z].guid = PSETID_Address;
	bf[z].kind = MNID_ID;
	bf[z++].lid = PidLidEmail1AddressType;
	bf[z].guid = PSETID_Address;
	bf[z].kind = MNID_ID;
	bf[z++].lid = PidLidEmail2AddressType;
	bf[z].guid = PSETID_Address;
	bf[z].kind = MNID_ID;
	bf[z++].lid = PidLidEmail3AddressType;

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

static inline bool has_content(const char *value)
{
	return value != nullptr && *value != '\0';
}

static void add_person(vcard &card, const MESSAGE_CONTENT &msg,
    proptag_t proptag, const char *line_key)
{
	auto value = msg.proplist.get<const char>(proptag);
	if (!has_content(value))
		return;
	auto &line = card.append_line(line_key);
	line.append_param("N");
	line.append_value(value);
}

static void add_string_array(vcard &card, const STRING_ARRAY *arr,
    const char *line_key)
{
	if (arr == nullptr)
		return;
	vcard_value *value = nullptr;
	for (size_t i = 0; i < arr->count; ++i) {
		auto entry = arr->ppstr[i];
		if (!has_content(entry))
			continue;
		if (value == nullptr) {
			auto &line = card.append_line(line_key);
			value = &line.append_value();
		}
		value->append_subval(entry);
	}
}

template<size_t N, typename Func>
static void add_adr(vcard &card, const char *type, Func &&get_part)
{
	std::array<const char *, N> parts{};
	bool has_value = false;
	for (size_t idx = 0; idx < N; ++idx) {
		const char *part = get_part(idx);
		if (has_content(part)) {
			parts[idx] = part;
			has_value = true;
		}
	}
	if (!has_value)
		return;
	auto &adr_line = card.append_line("ADR");
	adr_line.append_param("TYPE", type);
	for (const auto *part : parts)
		adr_line.append_value(znul(part));
	adr_line.append_value();
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

static BOOL xlog_bool(const char *func, unsigned int line)
{
	mlog(LV_ERR, "%s:%u returned false", func, line);
	return false;
}

static std::nullptr_t xlog_null(const char *func, unsigned int line)
{
	mlog(LV_ERR, "%s:%u returned false", func, line);
	return nullptr;
}

#define imp_null xlog_null(__func__, __LINE__)
message_content *oxvcard_import(const vcard *pvcard, GET_PROPIDS get_propids) try
{
	int i;
	int count;
	int ufld_count;
	int mail_count;
	BOOL b_encoding;
	struct tm tmp_tm;
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	uint64_t tmp_int64;
	PROPID_ARRAY propids;
	const char *address_type;
	std::vector<std::string> child_strings;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	
	mail_count = 0;
	ufld_count = 0;
	if (!oxvcard_check_compatible(pvcard))
		return imp_null;
	std::unique_ptr<MESSAGE_CONTENT, vc_delete> pmsg(message_content_init());
	if (pmsg == nullptr)
		return imp_null;
	if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Contact") != ecSuccess)
		return imp_null;
	for (const auto &line : pvcard->m_lines) try {
		auto pvline = &line;
		auto pvline_name = pvline->name();
		if (strcasecmp(pvline_name, "UID") == 0) {
			/* Deviation from MS-OXVCARD v8.3 §2.1.3.7.7 */
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				throw unrecog(line);
			if (pmsg->proplist.set(g_vcarduid_proptag, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "FN") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				throw unrecog(line);
			if (pmsg->proplist.set(PR_DISPLAY_NAME, pstring) != ecSuccess ||
			    pmsg->proplist.set(PR_NORMALIZED_SUBJECT, pstring) != ecSuccess ||
			    pmsg->proplist.set(PR_CONVERSATION_TOPIC, pstring) != ecSuccess)
				return imp_null;
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
				    pmsg->proplist.set(g_n_proptags[count], pvvalue->m_subvals[0].c_str()) != ecSuccess)
					return imp_null;
				count ++;
			}
		} else if (strcasecmp(pvline_name, "NICKNAME") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring != nullptr &&
			    pmsg->proplist.set(PR_NICKNAME, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "PHOTO") == 0) {
			if (pmsg->children.pattachments != nullptr)
				throw unrecog(line);
			b_encoding = FALSE;
			const char *photo_type = nullptr;
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
				return imp_null;
			pmsg->set_attachments_internal(pattachments);
			pattachment = attachment_content_init();
			if (pattachment == nullptr)
				return imp_null;
			if (!pattachments->append_internal(pattachment)) {
				attachment_content_free(pattachment);
				return imp_null;
			}

			auto picture = base64_decode(pstring);
			BINARY tmp_bin;
			tmp_bin.pv = deconst(picture.data());
			tmp_bin.cb = picture.size();
			if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != ecSuccess ||
			    pattachment->proplist.set(PR_ATTACH_EXTENSION, photo_type) != ecSuccess)
				return imp_null;
			if (pattachment->proplist.set(PR_ATTACH_LONG_FILENAME,
			    ("ContactPhoto."s + photo_type).c_str()) != ecSuccess)
				return imp_null;
			tmp_byte = 1;
			if (pmsg->proplist.set(PR_ATTACHMENT_CONTACTPHOTO, &tmp_byte) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "BDAY") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (NULL != strptime(pstring, "%Y-%m-%d", &tmp_tm)) {
				tmp_int64 = rop_util_unix_to_nttime(timegm(&tmp_tm));
				if (pmsg->proplist.set(PR_BIRTHDAY, &tmp_int64) != ecSuccess)
					return imp_null;
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
					if (pmsg->proplist.set(tag, pvvalue->m_subvals[0].c_str()) != ecSuccess)
						return imp_null;
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
			if (pmsg->proplist.set(tag, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "EMAIL") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (mail_count > 2)
				continue;
			if (pmsg->proplist.set(g_email_proptags[mail_count], pstring) != ecSuccess ||
			    pmsg->proplist.set(g_addrtype_proptags[mail_count++], "SMTP") != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "TITLE") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_TITLE, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "ROLE") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_PROFESSION, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "ORG") == 0) {
			auto pvvalue = pvline->m_values.cbegin();
			if (pvvalue == pvline->m_values.cend())
				continue;
			if (pvvalue->m_subvals.size() > 0 &&
			    !pvvalue->m_subvals[0].empty() &&
			    pmsg->proplist.set(PR_COMPANY_NAME, pvvalue->m_subvals[0].c_str()) != ecSuccess)
				return imp_null;
			++pvvalue;
			if (pvvalue != pvline->m_values.cend()) {
				if (pvvalue->m_subvals.size() > 0 &&
				    !pvvalue->m_subvals[0].empty() &&
				    pmsg->proplist.set(PR_DEPARTMENT_NAME, pvvalue->m_subvals[0].c_str()) != ecSuccess)
					return imp_null;
			}
		} else if (strcasecmp(pvline_name, "CATEGORIES") == 0) {
			auto pvvalue = pvline->m_values.cbegin();
			if (pvvalue == pvline->m_values.cend())
				continue;
			std::vector<char *> ptrs;
			STRING_ARRAY strings_array;
			for (const auto &sv : pvvalue->m_subvals) {
				if (sv.empty())
					continue;
				ptrs.push_back(deconst(sv.c_str()));
				if (ptrs.size() >= 128)
					break;
			}
			strings_array.count = ptrs.size();
			strings_array.ppstr = ptrs.data();
			if (strings_array.count != 0 &&
			    pmsg->proplist.set(g_categories_proptag, &strings_array) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "NOTE") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(PR_BODY, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "REV") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (NULL != strptime(pstring, "%Y-%m-%dT%H:%M:%S", &tmp_tm)) {
				tmp_int64 = rop_util_unix_to_nttime(timegm(&tmp_tm));
				if (pmsg->proplist.set(PR_LAST_MODIFICATION_TIME, &tmp_int64) != ecSuccess)
					return imp_null;
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
			if (pmsg->proplist.set(tag, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "CLASS") == 0) {
		auto pstring = pvline->get_first_subval();
		if (pstring != nullptr) {
			if (strcasecmp(pstring, "PRIVATE") == 0)
				tmp_int32 = SENSITIVITY_PRIVATE;
			else if (strcasecmp(pstring, "CONFIDENTIAL") == 0)
				tmp_int32 = SENSITIVITY_COMPANY_CONFIDENTIAL;
			else
				tmp_int32 = SENSITIVITY_NONE;
			if (pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != ecSuccess)
				return imp_null;
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

			auto cert = base64_decode(pstring);
			BINARY bin[1];
			bin[0].pc = deconst(cert.c_str());
			bin[0].cb = cert.size();
			BINARY_ARRAY bin_array;
			bin_array.count = std::size(bin);
			bin_array.pbin = bin;
			if (pmsg->proplist.set(PR_USER_X509_CERTIFICATE, &bin_array) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "X-MS-OL-DESIGN") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			BINARY tmp_bin;
			tmp_bin.cb = strlen(pstring);
			tmp_bin.pv = deconst(pstring);
			if (pmsg->proplist.set(g_bcd_proptag, &tmp_bin) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "X-MS-CHILD") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			child_strings.emplace_back(pstring);
		} else if (strcasecmp(pvline_name, "X-MS-TEXT") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (ufld_count > 3)
				throw unrecog(line);
			if (pmsg->proplist.set(g_ufld_proptags[ufld_count++], pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "X-MS-IMADDRESS") == 0 ||
		    strcasecmp(pvline_name, "X-MS-RM-IMACCOUNT") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(g_im_proptag, pstring) != ecSuccess)
				return imp_null;
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
			if (pmsg->proplist.set(tag, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "X-MS-ANNIVERSARY") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (NULL != strptime(pstring, "%Y-%m-%d", &tmp_tm)) {
				tmp_int64 = rop_util_unix_to_nttime(timegm(&tmp_tm));
				if (pmsg->proplist.set(PR_WEDDING_ANNIVERSARY, &tmp_int64) != ecSuccess)
					return imp_null;
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
			if (pmsg->proplist.set(PR_SPOUSE_NAME, pstring) != ecSuccess)
				return imp_null;
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
			if (pmsg->proplist.set(PR_MANAGER_NAME, pstring) != ecSuccess)
				return imp_null;
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
			if (pmsg->proplist.set(PR_ASSISTANT, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "FBURL") == 0) {
			auto pstring = pvline->get_first_subval();
			if (pstring == nullptr)
				continue;
			if (pmsg->proplist.set(g_fbl_proptag, pstring) != ecSuccess)
				return imp_null;
		} else if (strcasecmp(pvline_name, "X-MS-INTERESTS") == 0) {
			auto pvvalue = pvline->m_values.cbegin();
			if (pvvalue == pvline->m_values.cend())
				continue;
			std::string str;
			for (const auto &sv : pvvalue->m_subvals) {
				if (sv.empty())
					continue;
				if (!str.empty())
					str += ", ";
				str += sv;
			}
			if (!str.empty() &&
			    pmsg->proplist.set(PR_HOBBIES, str.c_str()) != ecSuccess)
				return imp_null;
		}
	} catch (const unrecog &e) {
		if (g_oxvcard_pedantic) {
			mlog(LV_ERR, "E-2140: oxvcard_import stopped parsing that vcard due to pedantry: %s", e.what());
			return nullptr;
		}
	}

	if (child_strings.size() > 0) {
		std::vector<const char *> ptrs;
		for (const auto &s : child_strings)
			ptrs.push_back(s.c_str());
		STRING_ARRAY sa;
		sa.count = ptrs.size();
		sa.ppstr = const_cast<char **>(ptrs.data());
		if (pmsg->proplist.set(PR_CHILDRENS_NAMES, &sa) != ecSuccess)
			return imp_null;
	}
	if (!pmsg->proplist.has(PR_DISPLAY_NAME)) {
		auto dn = join(pmsg->proplist.get<char>(PR_GIVEN_NAME),
		          pmsg->proplist.get<char>(PR_MIDDLE_NAME),
		          pmsg->proplist.get<char>(PR_SURNAME));
		if (pmsg->proplist.set(PR_DISPLAY_NAME, dn.c_str()) != ecSuccess)
			return imp_null;
	}
	if (!pmsg->proplist.has(PR_NORMALIZED_SUBJECT)) {
		auto dn = pmsg->proplist.get<const char>(PR_DISPLAY_NAME);
		if (dn != nullptr && pmsg->proplist.set(PR_NORMALIZED_SUBJECT, dn) != ecSuccess)
			return imp_null;
	}
	if (!pmsg->proplist.has(PR_CONVERSATION_TOPIC)) {
		auto dn = pmsg->proplist.get<const char>(PR_DISPLAY_NAME);
		if (dn != nullptr && pmsg->proplist.set(PR_CONVERSATION_TOPIC, dn) != ecSuccess)
			return imp_null;
	}
	for (i=0; i<pmsg->proplist.count; i++) {
		auto proptag = pmsg->proplist.ppropval[i].proptag;
		auto propid = PROP_ID(proptag);
		if (is_nameprop_id(propid))
			break;
	}
	if (i >= pmsg->proplist.count)
		/* If no namedprops were set, we can exit early */
		return pmsg.release();
	if (!oxvcard_get_propids(&propids, std::move(get_propids)))
		return imp_null;
	for (i=0; i<pmsg->proplist.count; i++) {
		auto proptag = pmsg->proplist.ppropval[i].proptag;
		auto propid = PROP_ID(proptag);
		if (!is_nameprop_id(propid))
			continue;
		uint16_t idx = propid - 0x8000;
		if (idx >= propids.size())
			continue; /* Skip invalid propids */
		proptag = propids[idx];
		pmsg->proplist.ppropval[i].proptag =
			PROP_TAG(PROP_TYPE(pmsg->proplist.ppropval[i].proptag), proptag);
	}
	return pmsg.release();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return nullptr;
}
#undef imp_null

#define exp_false xlog_bool(__func__, __LINE__)
BOOL oxvcard_export(const MESSAGE_CONTENT *pmsg, const char *log_id,
    vcard &vcard, GET_PROPIDS get_propids) try
{
	const char *pvalue;
	size_t out_len;
	struct tm tmp_tm;
	PROPID_ARRAY propids;
	const char *photo_type;
	char tmp_buff[VCARD_MAX_BUFFER_LEN];
	std::string vcarduid;
	static constexpr const char *tel_types[] =
		{"HOME", "HOME", "VOICE", "WORK", "WORK",
		"CELL", "PAGER", "CAR", "ISDN", "PREF"};
	static constexpr const char *ms_tel_types[] =
		{"ASSISTANT", "CALLBACK", "COMPANY", "RADIO", "TTYTTD"};
	static constexpr proptag_t tel_proptags[] =
		{PR_HOME_TELEPHONE_NUMBER, PR_HOME2_TELEPHONE_NUMBER,
		PR_OTHER_TELEPHONE_NUMBER, PR_BUSINESS_TELEPHONE_NUMBER,
		PR_BUSINESS2_TELEPHONE_NUMBER, PR_MOBILE_TELEPHONE_NUMBER,
		PR_PAGER_TELEPHONE_NUMBER, PR_CAR_TELEPHONE_NUMBER,
		PR_ISDN_NUMBER, PR_PRIMARY_TELEPHONE_NUMBER};
	static constexpr proptag_t ms_tel_proptags[] =
		{PR_ASSISTANT_TELEPHONE_NUMBER, PR_CALLBACK_TELEPHONE_NUMBER,
		PR_COMPANY_MAIN_PHONE_NUMBER, PR_RADIO_TELEPHONE_NUMBER,
		PR_TTYTDD_PHONE_NUMBER};
	
	if (!oxvcard_get_propids(&propids, std::move(get_propids)))
		return FALSE;
	vcard.clear();
	vcard.append_line("VERSION", "4.0");
	vcard.append_line("PROFILE", "VCARD");
	vcard.append_line("MAILER", "gromox-oxvcard");
	vcard.append_line("PRODID", "gromox-oxvcard");

	pvalue = pmsg->proplist.get<char>(PR_DISPLAY_NAME);
	if (!has_content(pvalue))
		pvalue = pmsg->proplist.get<char>(PR_NORMALIZED_SUBJECT);
	if (has_content(pvalue))
		vcard.append_line("FN", pvalue);

	const char *name_parts[std::size(g_n_proptags)]{};
	bool has_name_part = false;
	for (size_t i = 0; i < std::size(g_n_proptags); ++i) {
		pvalue = pmsg->proplist.get<char>(g_n_proptags[i]);
		if (has_content(pvalue)) {
			name_parts[i] = pvalue;
			has_name_part = true;
		}
	}
	if (has_name_part) {
		auto &n_line = vcard.append_line("N");
		for (const auto *part : name_parts)
			n_line.append_value(znul(part));
	}

	pvalue = pmsg->proplist.get<char>(PR_NICKNAME);
	if (has_content(pvalue))
		vcard.append_line("NICKNAME", pvalue);
	
	for (size_t i = 0; i < std::size(g_email_proptags); ++i) {
		auto propid = PROP_ID(g_email_proptags[i]);
		auto proptag = PROP_TAG(PROP_TYPE(g_email_proptags[i]), propids[propid - 0x8000]);
		pvalue = pmsg->proplist.get<char>(proptag);
		if (!has_content(pvalue))
			continue;
		auto &email_line = vcard.append_line("EMAIL");
		auto &type_param = email_line.append_param("TYPE");
		type_param.append_paramval("INTERNET");
		if (i == 0)
			type_param.append_paramval("PREF");
		email_line.append_value(pvalue);
	}
	
	auto flag = pmsg->proplist.get<const uint8_t>(PR_ATTACHMENT_CONTACTPHOTO);
	if (flag != nullptr && *flag != 0 && pmsg->children.pattachments != nullptr) {
		for (auto &at : *pmsg->children.pattachments) {
			pvalue = at.proplist.get<char>(PR_ATTACH_EXTENSION);
			if (pvalue == nullptr)
				continue;
			if (!is_photo(pvalue))
				continue;
			photo_type = pvalue;
			auto bv = at.proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
			if (bv == nullptr)
				continue;
			auto &photo_line = vcard.append_line("PHOTO");
			photo_line.append_param("TYPE", photo_type);
			photo_line.append_param("ENCODING", "B");
			if (encode64(bv->pb, bv->cb, tmp_buff, VCARD_MAX_BUFFER_LEN - 1, &out_len) != 0)
				return exp_false;
			if (out_len >= VCARD_MAX_BUFFER_LEN)
				return exp_false;
			tmp_buff[out_len] = '\0';
			photo_line.append_value(tmp_buff);
			break;
		}
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BODY);
	if (has_content(pvalue))
		vcard.append_line("NOTE", pvalue);
	
	const char *company = pmsg->proplist.get<char>(PR_COMPANY_NAME);
	const char *department = pmsg->proplist.get<char>(PR_DEPARTMENT_NAME);
	if (has_content(company) || has_content(department)) {
		auto &org_line = vcard.append_line("ORG");
		org_line.append_value(znul(company));
		org_line.append_value(znul(department));
	}
	
	auto num = pmsg->proplist.get<uint32_t>(PR_SENSITIVITY);
	if (num == nullptr)
		pvalue = "PUBLIC";
	else if (*num == SENSITIVITY_COMPANY_CONFIDENTIAL)
		pvalue = "CONFIDENTIAL";
	else if (*num == SENSITIVITY_PRIVATE)
		pvalue = "PRIVATE";
	else
		pvalue = "PUBLIC";
	vcard.append_line("CLASS", pvalue);
	
	add_adr<std::size(g_workaddr_proptags)>(vcard, "WORK", [&](unsigned int idx) {
		auto propid = PROP_ID(g_workaddr_proptags[idx]);
		auto proptag = PROP_TAG(PROP_TYPE(g_workaddr_proptags[idx]), propids[propid - 0x8000]);
		return pmsg->proplist.get<const char>(proptag);
	});
	add_adr<std::size(g_homeaddr_proptags)>(vcard, "HOME", [&](unsigned int idx) {
		return pmsg->proplist.get<const char>(g_homeaddr_proptags[idx]);
	});
	add_adr<std::size(g_otheraddr_proptags)>(vcard, "POSTAL", [&](unsigned int idx) {
		return pmsg->proplist.get<const char>(g_otheraddr_proptags[idx]);
	});

	for (size_t i = 0; i < std::size(tel_proptags); ++i) {
		pvalue = pmsg->proplist.get<char>(tel_proptags[i]);
		if (!has_content(pvalue))
			continue;
		auto &tel_line = vcard.append_line("TEL");
		tel_line.append_param("TYPE", tel_types[i]);
		tel_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_HOME_FAX_NUMBER);
	if (has_content(pvalue)) {
		auto &tel_line = vcard.append_line("TEL");
		tel_line.append_param("TYPE", "HOME");
		tel_line.append_param("FAX");
		tel_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BUSINESS_FAX_NUMBER);
	if (has_content(pvalue)) {
		auto &tel_line = vcard.append_line("TEL");
		tel_line.append_param("TYPE", "WORK");
		tel_line.append_param("FAX");
		tel_line.append_value(pvalue);
	}
	
	auto propid = PROP_ID(g_categories_proptag);
	auto proptag = PROP_TAG(PROP_TYPE(g_categories_proptag), propids[propid - 0x8000]);
	add_string_array(vcard, pmsg->proplist.get<const STRING_ARRAY>(proptag), "CATEGORIES");
	
	pvalue = pmsg->proplist.get<char>(PR_PROFESSION);
	if (has_content(pvalue))
		vcard.append_line("ROLE", pvalue);
	
	pvalue = pmsg->proplist.get<char>(PR_PERSONAL_HOME_PAGE);
	if (has_content(pvalue)) {
		auto &url_line = vcard.append_line("URL");
		url_line.append_param("TYPE", "HOME");
		url_line.append_value(pvalue);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_BUSINESS_HOME_PAGE);
	if (has_content(pvalue)) {
		auto &url_line = vcard.append_line("URL");
		url_line.append_param("TYPE", "WORK");
		url_line.append_value(pvalue);
	}
	
	propid = PROP_ID(g_bcd_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_bcd_proptag), propids[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	if (has_content(pvalue))
		vcard.append_line("X-MS-OL-DESIGN", pvalue);

	add_string_array(vcard, pmsg->proplist.get<const STRING_ARRAY>(PR_CHILDRENS_NAMES), "X-MS-CHILD");
	
	for (size_t i = 0; i < std::size(g_ufld_proptags); ++i) {
		propid = PROP_ID(g_ufld_proptags[i]);
		proptag = PROP_TAG(PROP_TYPE(g_ufld_proptags[i]), propids[propid - 0x8000]);
		pvalue = pmsg->proplist.get<char>(proptag);
		if (!has_content(pvalue))
			continue;
		vcard.append_line("X-MS-TEXT", pvalue);
	}
	
	for (size_t i = 0; i < std::size(ms_tel_proptags); ++i) {
		pvalue = pmsg->proplist.get<char>(ms_tel_proptags[i]);
		if (!has_content(pvalue))
			continue;
		auto &tel_line = vcard.append_line("X-MS-TEL");
		tel_line.append_param("TYPE", ms_tel_types[i]);
		tel_line.append_value(pvalue);
	}
	
	add_person(vcard, *pmsg, PR_SPOUSE_NAME, "X-MS-SPOUSE");
	add_person(vcard, *pmsg, PR_MANAGER_NAME, "X-MS-MANAGER");
	add_person(vcard, *pmsg, PR_ASSISTANT, "X-MS-ASSISTANT");
	
	pvalue = pmsg->proplist.get<char>(PROP_TAG(PROP_TYPE(g_vcarduid_proptag), propids[PROP_ID(g_vcarduid_proptag)-0x8000]));
	if (!has_content(pvalue)) {
		auto guid = GUID::random_new();
		vcarduid = "uuid:" + bin2hex(guid);
		pvalue = vcarduid.c_str();
	}
	if (has_content(pvalue))
		vcard.append_line("UID", pvalue);

	propid = PROP_ID(g_fbl_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_fbl_proptag), propids[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	if (has_content(pvalue))
		vcard.append_line("FBURL", pvalue);
	
	pvalue = pmsg->proplist.get<char>(PR_HOBBIES);
	if (has_content(pvalue))
		vcard.append_line("X-MS-INTERESTS", pvalue);
	
	auto ba = pmsg->proplist.get<const BINARY_ARRAY>(PR_USER_X509_CERTIFICATE);
	if (ba != nullptr && ba->count != 0) {
		auto &key_line = vcard.append_line("KEY");
		key_line.append_param("ENCODING", "B");
		if (encode64(ba->pbin->pb, ba->pbin->cb, tmp_buff,
		    std::size(tmp_buff) - 1, &out_len) != 0)
			return exp_false;
		if (out_len >= std::size(tmp_buff))
			return exp_false;
		tmp_buff[out_len] = '\0';
		key_line.append_value(tmp_buff);
	}
	
	pvalue = pmsg->proplist.get<char>(PR_TITLE);
	if (has_content(pvalue))
		vcard.append_line("TITLE", pvalue);
	
	propid = PROP_ID(g_im_proptag);
	proptag = PROP_TAG(PROP_TYPE(g_im_proptag), propids[propid - 0x8000]);
	pvalue = pmsg->proplist.get<char>(proptag);
	if (has_content(pvalue))
		vcard.append_line("X-MS-IMADDRESS", pvalue);
	
	auto lnum = pmsg->proplist.get<uint64_t>(PR_BIRTHDAY);
	if (lnum != nullptr) {
		auto unix_time = rop_util_nttime_to_unix(*lnum);
		if (gmtime_r(&unix_time, &tmp_tm) != nullptr) {
			strftime(tmp_buff, 1024, "%Y-%m-%d", &tmp_tm);
			auto &day_line = vcard.append_line("BDAY");
			day_line.append_param("VALUE", "DATE");
			day_line.append_value(tmp_buff);
		}
	}
	
	lnum = pmsg->proplist.get<uint64_t>(PR_LAST_MODIFICATION_TIME);
	if (lnum != nullptr) {
		auto unix_time = rop_util_nttime_to_unix(*lnum);
		if (gmtime_r(&unix_time, &tmp_tm) != nullptr) {
			strftime(tmp_buff, 1024, "%Y-%m-%dT%H:%M:%SZ", &tmp_tm);
			auto &day_line = vcard.append_line("REV");
			day_line.append_param("VALUE", "DATE-TIME");
			day_line.append_value(tmp_buff);
		}
	}
	
	lnum = pmsg->proplist.get<uint64_t>(PR_WEDDING_ANNIVERSARY);
	if (lnum != nullptr) {
		auto unix_time = rop_util_nttime_to_unix(*lnum);
		if (gmtime_r(&unix_time, &tmp_tm) != nullptr) {
			strftime(tmp_buff, 1024, "%Y-%m-%d", &tmp_tm);
			auto &day_line = vcard.append_line("X-MS-ANNIVERSARY");
			day_line.append_param("VALUE", "DATE");
			day_line.append_value(tmp_buff);
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1605: ENOMEM");
	return false;
}
#undef exp_false
