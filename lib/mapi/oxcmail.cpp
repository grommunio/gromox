// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2023 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <vmime/mailboxList.hpp>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/html.hpp>
#include <gromox/ical.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/rtf.hpp>
#include <gromox/rtfcp.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tnef.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>

/* uncomment below macro if you need system to verify X-MS-TNEF-Correlator */
/* #define VERIFY_TNEF_CORRELATOR */

#define MAXIMUM_SEARCHING_DEPTH					10

/*
	Caution. If any errors in parsing any sub type, ignore this sub type.
	for example, if an error appears when parsing tnef attachment, treat
	this tnef sub type as normal attachment. there will be no error for
	parsing email object into message object!
*/

using namespace gromox;
using namemap = std::unordered_map<int, PROPERTY_NAME>;
using propididmap_t = std::unordered_map<uint16_t, uint16_t>;

namespace {

struct FIELD_ENUM_PARAM {
	FIELD_ENUM_PARAM(namemap &r) : phash(r) {}
	NOMOVE(FIELD_ENUM_PARAM);

	EXT_BUFFER_ALLOC alloc{};
	MESSAGE_CONTENT *pmsg = nullptr;
	namemap &phash;
	uint16_t last_propid = 0;
	const char *charset = nullptr;
	bool b_classified = false, b_flag_del = false;
	const MAIL *pmail = nullptr;
};

struct MIME_ENUM_PARAM {
	MIME_ENUM_PARAM(namemap &r) : phash(r) {}
	NOMOVE(MIME_ENUM_PARAM);

	bool b_result = false;
	int attach_id = 0;
	const char *charset = nullptr, *str_zone = nullptr;
	GET_PROPIDS get_propids{};
	EXT_BUFFER_ALLOC alloc{};
	MESSAGE_CONTENT *pmsg = nullptr;
	namemap phash;
	uint16_t last_propid = 0;
	uint64_t nttime_stamp = 0;
	const MIME *pplain = nullptr, *phtml = nullptr, *penriched = nullptr;
	const MIME *pcalendar = nullptr, *preport = nullptr;
};

struct DSN_ENUM_INFO {
	int action_severity;
	TARRAY_SET *prcpts;
	uint64_t submit_time;
};

struct DSN_FILEDS_INFO {
	char final_recipient[UADDR_SIZE];
	int action_severity;
	char remote_mta[128];
	const char *status;
	const char *diagnostic_code;
	const char *x_supplementary_info;
	const char *x_display_name;
};

static constexpr addr_tags tags_self = {
	PR_DISPLAY_NAME, PR_ADDRTYPE, PR_EMAIL_ADDRESS, PR_SMTP_ADDRESS,
	PR_ENTRYID,
};
static constexpr addr_tags tags_sender = {
	PR_SENDER_NAME, PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS,
	PR_SENDER_SMTP_ADDRESS, PR_SENDER_ENTRYID,
};
static constexpr addr_tags tags_sent_repr = {
	PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_ADDRTYPE,
	PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENT_REPRESENTING_SMTP_ADDRESS,
	PR_SENT_REPRESENTING_ENTRYID,
};
static constexpr addr_tags tags_read_rcpt = {
	PidTagReadReceiptName, PidTagReadReceiptAddressType,
	PidTagReadReceiptEmailAddress, PidTagReadReceiptSmtpAddress,
	PR_READ_RECEIPT_ENTRYID,
};

}

enum class oxcmail_type {
	normal, xsigned, encrypted, dsn, mdn, calendar, tnef,
};

namespace {
struct mime_skeleton {
	mime_skeleton() = default;
	~mime_skeleton() { clear(); }
	NOMOVE(mime_skeleton);
	void clear();

	enum oxcmail_type mail_type{};
	enum oxcmail_body body_type{};
	BOOL b_inline = false, b_attachment = false;
	std::string rtf;
	BINARY rtf_bin{};
	char *pplain = nullptr;
	BINARY *phtml = nullptr;
	const char *charset = nullptr, *pmessage_class = nullptr;
	ATTACHMENT_LIST *pattachments = nullptr;
};
using MIME_SKELETON = mime_skeleton;
}

static constexpr char
	PidNameContentClass[] = "Content-Class",
	PidNameKeywords[] = "Keywords";
static constexpr size_t namemap_limit = 0x1000;
static char g_oxcmail_org_name[256];
static GET_USER_IDS oxcmail_get_user_ids;
static GET_USERNAME oxcmail_get_username;

static inline size_t worst_encoding_overhead(size_t in)
{
	/*
	 * (To be used for conversions _from UTF-8_ to any other encoding.)
	 * UTF-7 can be *so* pathological.
	 */
	return 5 * in;
}
	
static int namemap_add(namemap &phash, uint32_t id, PROPERTY_NAME &&el) try
{
	/* Avoid uninitialized read when the copy/transfer is made */
	if (el.kind == MNID_ID)
		el.pname = nullptr;
	else
		el.lid = 0;
	if (phash.size() >= namemap_limit)
		return -ENOSPC;
	if (!phash.emplace(id, std::move(el)).second)
		return -EEXIST;
	return 0;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

BOOL oxcmail_init_library(const char *org_name,
	GET_USER_IDS get_user_ids, GET_USERNAME get_username)
{
	gx_strlcpy(g_oxcmail_org_name, org_name, std::size(g_oxcmail_org_name));
	oxcmail_get_user_ids = get_user_ids;
	oxcmail_get_username = get_username;
	textmaps_init();
	tnef_init_library();
	if (!rtf_init_library() || html_init_library() != ecSuccess)
		return FALSE;	
	return TRUE;
}

static BOOL oxcmail_username_to_essdn(const char *username,
    char *pessdn, enum display_type *dtpp)
{
	unsigned int user_id = 0, domain_id = 0;
	char *pdomain;
	char tmp_name[UADDR_SIZE];
	char hex_string[16];
	char hex_string2[16];
	
	gx_strlcpy(tmp_name, username, std::size(tmp_name));
	pdomain = strchr(tmp_name, '@');
	if (pdomain == nullptr)
		return FALSE;
	*pdomain++ = '\0';
	enum display_type dtypx = DT_MAILUSER;
	if (!oxcmail_get_user_ids(username, &user_id, &domain_id, &dtypx))
		return FALSE;
	encode_hex_int(user_id, hex_string);
	encode_hex_int(domain_id, hex_string2);
	snprintf(pessdn, 1024, "/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
		g_oxcmail_org_name, hex_string2, hex_string, tmp_name);
	HX_strupper(pessdn);
	if (dtpp != nullptr)
		*dtpp = dtypx;
	return TRUE;
}

BOOL oxcmail_essdn_to_username(const char *pessdn,
    char *username, size_t ulen)
{
	char tmp_buff[1024];
	
	auto tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
	               "/o=%s/ou=Exchange Administrative"
		" Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=", g_oxcmail_org_name);
	if (strncasecmp(pessdn, tmp_buff, tmp_len) != 0)
		return FALSE;
	unsigned int user_id = decode_hex_int(&pessdn[tmp_len+8]);
	return oxcmail_get_username(user_id, username, ulen);
}

BOOL oxcmail_entryid_to_username(const BINARY *pbin,
    EXT_BUFFER_ALLOC alloc, char *username, size_t ulen)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	FLATUID provider_uid;
	
	if (pbin->cb < 20)
		return FALSE;
	ext_pull.init(pbin->pb, pbin->cb, alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_uint32(&flags) != EXT_ERR_SUCCESS || flags != 0 ||
	    ext_pull.g_guid(&provider_uid) != EXT_ERR_SUCCESS)
		return FALSE;
	/* Tail functions will use EXT_PULL::*_eid, which parse a full EID */
	ext_pull.m_offset = 0;
	if (provider_uid == muidEMSAB)
		return emsab_to_email(ext_pull, oxcmail_essdn_to_username,
		       username, ulen) ? TRUE : false;
	if (provider_uid == muidOOP)
		return oneoff_to_parts(ext_pull, nullptr, 0, username, ulen) ? TRUE : false;
	return FALSE;
}

static BOOL oxcmail_username_to_oneoff(const char *username,
	const char *pdisplay_name, BINARY *pbin)
{
	EXT_PUSH ext_push;
	ONEOFF_ENTRYID tmp_entry;
	
	tmp_entry.flags = 0;
	tmp_entry.version = 0;
	tmp_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_UNICODE;
	tmp_entry.pdisplay_name = pdisplay_name != nullptr && *pdisplay_name != '\0' ?
	                          deconst(pdisplay_name) : deconst(username);
	tmp_entry.paddress_type = deconst("SMTP");
	tmp_entry.pmail_address = deconst(username);
	if (!ext_push.init(pbin->pb, 1280, EXT_FLAG_UTF16))
		return false;
	auto status = ext_push.p_oneoff_eid(tmp_entry);
	if (EXT_ERR_CHARCNV == status) {
		tmp_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO;
		status = ext_push.p_oneoff_eid(tmp_entry);
	}
	if (status != pack_result::success)
		return FALSE;
	pbin->cb = ext_push.m_offset;
	return TRUE;
}

static BOOL oxcmail_essdn_to_entryid(const char *pessdn, BINARY *pbin)
{
	EXT_PUSH ext_push;
	EMSAB_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	tmp_entryid.version = 1;
	tmp_entryid.type = DT_MAILUSER;
	tmp_entryid.px500dn = deconst(pessdn);
	if (!ext_push.init(pbin->pb, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return false;
	pbin->cb = ext_push.m_offset;
	return TRUE;
}

BOOL oxcmail_username_to_entryid(const char *username,
    const char *pdisplay_name, BINARY *pbin, enum display_type *dtpp)
{
	char x500dn[1024];

	if (oxcmail_username_to_essdn(username, x500dn, dtpp))
		return oxcmail_essdn_to_entryid(x500dn, pbin);
	if (dtpp != nullptr)
		*dtpp = DT_MAILUSER;
	return oxcmail_username_to_oneoff(
	       username, pdisplay_name, pbin);
}

static inline bool oxcmail_is_ascii(const char *s)
{
	return std::all_of(s, s + strlen(s),
	       [](unsigned char c) { return isascii(c); });
}

static unsigned int pick_strtype(const char *token)
{
	return oxcmail_is_ascii(token) ? PT_UNICODE : PT_STRING8;
}

static inline bool oxcmail_check_crlf(const char *s)
{
	return std::any_of(s, s + strlen(s),
	       [](char c) { return c == '\n' || c == '\r'; });
}

static BOOL oxcmail_get_content_param(const MIME *pmime,
	const char *tag, char *value, int length)
{
	int tmp_len;
	
	if (!pmime->get_content_param(tag, value, length))
		return FALSE;
	tmp_len = strlen(value);
	if (('"' == value[0] && '"' == value[tmp_len - 1]) ||
		('\'' == value[0] && '\'' == value[tmp_len - 1])) {
		value[tmp_len - 1] = '\0';
		memmove(value, value + 1, tmp_len - 1);
	}
	return *value != '\0' ? TRUE : false;
}

static BOOL oxcmail_get_field_param(char *field,
	const char *tag, char *value, int length)
{
	char *pend;
	int tmp_len;
	char *pbegin;
	char *ptoken;
	
	ptoken = strchr(field, ';');
	if (ptoken == nullptr)
		return FALSE;
	ptoken ++;
	pbegin = strcasestr(ptoken, tag);
	if (pbegin == nullptr)
		return FALSE;
	pbegin += strlen(tag);
	if (*pbegin != '=')
		return FALSE;
	pbegin ++;
	pend = strchr(pbegin, ';');
	tmp_len = pend == nullptr ? strlen(pbegin) : pend - pbegin;
	if (tmp_len >= length)
		return FALSE;
	memmove(value, pbegin, tmp_len);
	value[tmp_len] = '\0';
	HX_strrtrim(value);
	HX_strltrim(value);
	tmp_len = strlen(value);
	if (('"' == value[0] && '"' == value[tmp_len - 1]) ||
		('\'' == value[0] && '\'' == value[tmp_len - 1])) {
		value[tmp_len - 1] = '\0';
		memmove(value, value + 1, tmp_len - 1);
	}
	return *value == '\0' ? TRUE : false;
}

static void replace_reserved_chars(char *s)
{
	for (; *s != '\0'; ++s)
		if (*s == '"' || *s == '/' || *s == ':' ||
		    *s == '<' || *s == '>' || *s == '|' ||
		    *s == '\\' || (*s >= 0x00 && *s <= 0x1F))
			*s = '_';
}

static void replace_leading_dots(char *str)
{
	char *p;
	for (p = str; *p == '.'; ++p)
		;
	if (p != str)
		memmove(str, p, strlen(str) + 1);
}

static void replace_trailing_dots(char *s)
{
	size_t z = strlen(s);
	while (z-- > 0 && s[z] == '.')
		;
	s[++z] = '\0';
}

static void oxcmail_split_filename(char *file_name, char *extension)
{
	char *ptoken;
	
	replace_reserved_chars(file_name);
	replace_trailing_dots(file_name);
	replace_leading_dots(file_name);
	ptoken = strrchr(file_name, '.');
	if (ptoken == nullptr || strlen(ptoken) >= 16)
		extension[0] = '\0';
	else
		strcpy(extension, ptoken);
}

/**
 * @charset:	charset of the MAPI session
 * @paddr:	always has UTF-8 display name in it
 */
static BOOL oxcmail_parse_recipient(const char *charset,
    const EMAIL_ADDR *paddr, uint32_t rcpt_type, TARRAY_SET *pset) try
{
	BINARY tmp_bin;
	char essdn[1024];
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	char username[UADDR_SIZE];
	char tmp_buff[1280];
	
	if (!paddr->has_value())
		return TRUE;
	auto pproplist = pset->emplace();
	if (pproplist == nullptr)
		return FALSE;
	if (paddr->has_dispname()) {
		if (pproplist->set(PR_DISPLAY_NAME, paddr->display_name) != 0 ||
		    pproplist->set(PR_TRANSMITABLE_DISPLAY_NAME, paddr->display_name) != 0)
			return FALSE;
	} else {
		char dispname[UADDR_SIZE];
		snprintf(dispname, std::size(dispname), "%s@%s", paddr->local_part, paddr->domain);
		if (pproplist->set(PR_DISPLAY_NAME, dispname) != 0 ||
		    pproplist->set(PR_TRANSMITABLE_DISPLAY_NAME, dispname) != 0)
			return FALSE;
	}
	if (paddr->has_addr() && oxcmail_is_ascii(paddr->local_part) &&
	    oxcmail_is_ascii(paddr->domain)) {
		snprintf(username, std::size(username), "%s@%s", paddr->local_part, paddr->domain);
		auto dtypx = DT_MAILUSER;
		if (!oxcmail_username_to_essdn(username, essdn, &dtypx)) {
			essdn[0] = '\0';
			dtypx = DT_MAILUSER;
			tmp_bin.cb = snprintf(tmp_buff, std::size(tmp_buff), "SMTP:%s", username) + 1;
			HX_strupper(tmp_buff);
			if (pproplist->set(PR_ADDRTYPE, "SMTP") != 0 ||
			    pproplist->set(PR_EMAIL_ADDRESS, username) != 0)
				return FALSE;
		} else {
			tmp_bin.cb = snprintf(tmp_buff, std::size(tmp_buff), "EX:%s", essdn) + 1;
			if (pproplist->set(PR_ADDRTYPE, "EX") != 0 ||
			    pproplist->set(PR_EMAIL_ADDRESS, essdn) != 0)
				return FALSE;
		}
		tmp_bin.pc = tmp_buff;
		if (pproplist->set(PR_SMTP_ADDRESS, username) != 0 ||
		    pproplist->set(PR_SEARCH_KEY, &tmp_bin) != 0)
			return FALSE;
		tmp_bin.cb = 0;
		tmp_bin.pc = tmp_buff;
		if ('\0' == essdn[0]) {
			if (!oxcmail_username_to_oneoff(username, paddr->display_name, &tmp_bin))
				return FALSE;
		} else {
			if (!oxcmail_essdn_to_entryid(essdn, &tmp_bin))
				return FALSE;
		}
		if (pproplist->set(PR_ENTRYID, &tmp_bin) != 0 ||
		    pproplist->set(PR_RECIPIENT_ENTRYID, &tmp_bin) != 0 ||
		    pproplist->set(PR_RECORD_KEY, &tmp_bin) != 0)
			return FALSE;
		tmp_int32 = static_cast<uint32_t>(dtypx == DT_DISTLIST ? MAPI_DISTLIST : MAPI_MAILUSER);
		if (pproplist->set(PR_OBJECT_TYPE, &tmp_int32) != 0)
			return FALSE;
		tmp_int32 = static_cast<uint32_t>(dtypx);
		if (pproplist->set(PR_DISPLAY_TYPE, &tmp_int32) != 0)
			return FALSE;
	}
	tmp_byte = 1;
	if (pproplist->set(PR_RESPONSIBILITY, &tmp_byte) != 0)
		return FALSE;
	tmp_int32 = recipSendable;
	if (pproplist->set(PR_RECIPIENT_FLAGS, &tmp_int32) != 0)
		return FALSE;
	return pproplist->set(PR_RECIPIENT_TYPE, &rcpt_type) == 0 ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2049: ENOMEM");
	return false;
}

static BOOL oxcmail_parse_addresses(const char *charset, const char *field,
    uint32_t rcpt_type, TARRAY_SET *pset)
{
	EMAIL_ADDR email_addr;

	vmime::mailboxList mblist;
	try {
		mblist.parse(field);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-2023: ENOMEM");
		return false;
	}
	for (const auto &compo : mblist.getChildComponents()) {
		auto mb = vmime::dynamicCast<vmime::mailbox>(compo);
		if (mb == nullptr)
			continue;
		gx_strlcpy(email_addr.display_name, mb->getName().getConvertedText("utf-8").c_str(), std::size(email_addr.display_name));
		auto &emp = mb->getEmail();
		gx_strlcpy(email_addr.local_part, emp.getLocalName().getConvertedText("utf-8").c_str(), std::size(email_addr.local_part));
		gx_strlcpy(email_addr.domain, emp.getDomainName().getConvertedText("utf-8").c_str(), std::size(email_addr.domain));

		if (*email_addr.local_part == '\0')
			continue;
		if (!oxcmail_parse_recipient(charset,
		    &email_addr, rcpt_type, pset))
			return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_parse_address(const char *charset,
    const EMAIL_ADDR *paddr, uint32_t pr_name, uint32_t pr_addrtype,
    uint32_t pr_emaddr, uint32_t pr_smtpaddr, uint32_t pr_searchkey,
    uint32_t pr_entryid, TPROPVAL_ARRAY *pproplist)
{
	BINARY tmp_bin;
	char essdn[1024];
	char username[UADDR_SIZE];
	char tmp_buff[1280];
	
	if (paddr->has_dispname()) {
		if (pproplist->set(pr_name, paddr->display_name) != 0)
			return false;
	} else if (paddr->has_addr()) {
		snprintf(username, std::size(username), "%s@%s", paddr->local_part, paddr->domain);
		if (pproplist->set(pr_name, username) != 0)
			return FALSE;
	}
	bool ok = paddr->has_addr() && oxcmail_is_ascii(paddr->local_part) &&
	          oxcmail_is_ascii(paddr->domain);
	if (!ok)
		return TRUE;
	snprintf(username, std::size(username), "%s@%s", paddr->local_part, paddr->domain);
	if (pproplist->set(pr_addrtype, "SMTP") != 0 ||
	    pproplist->set(pr_emaddr, username) != 0 ||
	    pproplist->set(pr_smtpaddr, username) != 0)
		return FALSE;
	if (!oxcmail_username_to_essdn(username, essdn, NULL)) {
		essdn[0] = '\0';
		tmp_bin.cb = snprintf(tmp_buff, std::size(tmp_buff), "SMTP:%s", username) + 1;
		HX_strupper(tmp_buff);
	} else {
		tmp_bin.cb = snprintf(tmp_buff, std::size(tmp_buff), "EX:%s", essdn) + 1;
	}
	tmp_bin.pc = tmp_buff;
	if (pproplist->set(pr_searchkey, &tmp_bin) != 0)
		return FALSE;
	tmp_bin.cb = 0;
	tmp_bin.pc = tmp_buff;
	if ('\0' == essdn[0]) {
		if (!oxcmail_username_to_oneoff(username, paddr->display_name, &tmp_bin))
			return FALSE;
	} else {
		if (!oxcmail_essdn_to_entryid(essdn, &tmp_bin))
			return FALSE;
	}
	return pproplist->set(pr_entryid, &tmp_bin) == 0 ? TRUE : false;
}

static BOOL oxcmail_parse_reply_to(const char *charset, const char *field,
    TPROPVAL_ARRAY *pproplist)
{
	uint32_t count;
	BINARY tmp_bin;
	int str_offset;
	uint8_t pad_len;
	EXT_PUSH ext_push;
	char tmp_buff[UADDR_SIZE];
	EMAIL_ADDR email_addr;
	ONEOFF_ENTRYID tmp_entry;
	uint8_t bin_buff[256*1024];
	char str_buff[MIME_FIELD_LEN];
	static constexpr uint8_t pad_bytes[3]{};
	
	count = 0;
	if (!ext_push.init(bin_buff, sizeof(bin_buff), EXT_FLAG_UTF16))
		return false;
	if (ext_push.advance(sizeof(uint32_t)) != EXT_ERR_SUCCESS)
		return FALSE;
	uint32_t offset = ext_push.m_offset;
	if (ext_push.advance(sizeof(uint32_t)) != EXT_ERR_SUCCESS)
		return FALSE;
	str_offset = 0;
	tmp_entry.flags = 0;
	tmp_entry.version = 0;
	tmp_entry.pdisplay_name = email_addr.display_name;
	tmp_entry.paddress_type = deconst("SMTP");
	tmp_entry.pmail_address = tmp_buff;

	vmime::mailboxList mblist;
	try {
		mblist.parse(field);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-2022: ENOMEM");
		return false;
	}
	for (const auto &compo : mblist.getChildComponents()) {
		auto mb = vmime::dynamicCast<vmime::mailbox>(compo);
		if (mb == nullptr)
			continue;
		gx_strlcpy(email_addr.display_name, mb->getName().getConvertedText("utf-8").c_str(), std::size(email_addr.display_name));
		auto &emp = mb->getEmail();
		gx_strlcpy(email_addr.local_part, emp.getLocalName().getConvertedText("utf-8").c_str(), std::size(email_addr.local_part));
		gx_strlcpy(email_addr.domain, emp.getDomainName().getConvertedText("utf-8").c_str(), std::size(email_addr.domain));

		if (*email_addr.local_part == '\0')
			continue;
		if (str_offset != 0)
			str_offset += gx_snprintf(&str_buff[str_offset],
			              std::size(str_buff) - str_offset, ";");
		if (*email_addr.display_name != '\0')
			str_offset += gx_snprintf(&str_buff[str_offset],
			              std::size(str_buff) - str_offset, "%s",
			              email_addr.display_name);
		else
			str_offset += gx_snprintf(&str_buff[str_offset],
			              std::size(str_buff) - str_offset, "%s@%s",
			              email_addr.local_part, email_addr.domain);

		if (!email_addr.has_addr() ||
		    !oxcmail_is_ascii(email_addr.local_part) ||
		    !oxcmail_is_ascii(email_addr.domain))
			continue;

		uint32_t offset1 = ext_push.m_offset;
		if (ext_push.advance(sizeof(uint32_t)) != EXT_ERR_SUCCESS)
			return FALSE;
		snprintf(tmp_buff, std::size(tmp_buff), "%s@%s",
			 email_addr.local_part, email_addr.domain);
		tmp_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_UNICODE;
		auto status = ext_push.p_oneoff_eid(tmp_entry);
		if (EXT_ERR_CHARCNV == status) {
			ext_push.m_offset = offset1 + sizeof(uint32_t);
			tmp_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO;
			status = ext_push.p_oneoff_eid(tmp_entry);
		}
		if (status != pack_result::success)
			return FALSE;
		uint32_t offset2 = ext_push.m_offset;
		uint32_t bytes = offset2 - (offset1 + sizeof(uint32_t));
		ext_push.m_offset = offset1;
		if (ext_push.p_uint32(bytes) != EXT_ERR_SUCCESS)
			return FALSE;
		ext_push.m_offset = offset2;
		pad_len = ((bytes + 3) & ~3) - bytes;
		if (ext_push.p_bytes(pad_bytes, pad_len) != EXT_ERR_SUCCESS)
			return FALSE;
		count++;
	}
	if (0 != count) {
		tmp_bin.cb = ext_push.m_offset;
		tmp_bin.pb = bin_buff;
		uint32_t bytes = ext_push.m_offset - (offset + sizeof(uint32_t));
		ext_push.m_offset = 0;
		if (ext_push.p_uint32(count) != EXT_ERR_SUCCESS)
			return FALSE;
		ext_push.m_offset = offset;
		if (ext_push.p_uint32(bytes) != EXT_ERR_SUCCESS)
			return FALSE;
		if (pproplist->set(PR_REPLY_RECIPIENT_ENTRIES, &tmp_bin) != 0)
			return FALSE;
	}
	if (str_offset > 0 &&
	    pproplist->set(PR_REPLY_RECIPIENT_NAMES, str_buff) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcmail_parse_subject(const char *charset, const char *field,
    TPROPVAL_ARRAY *pproplist)
{
	int i;
	int tmp_len;
	char *ptoken;
	char tmp_buff1[4096];
	char prefix_buff[32];
	char tmp_buff[MIME_FIELD_LEN];
	char utf8_field[MIME_FIELD_LEN];
	static constexpr uint8_t seperator[] = {':', 0x00, ' ', 0x00};
	
	if (!mime_string_to_utf8(charset, field, utf8_field, std::size(utf8_field)))
		return pproplist->set(PR_SUBJECT_A, field) == 0 ? TRUE : false;

	auto subject_len = utf8_to_utf16le(utf8_field,
	              tmp_buff, sizeof(tmp_buff));
	if (subject_len < 0) {
		utf8_truncate(utf8_field, 255);
		subject_len = utf8_to_utf16le(utf8_field,
		              tmp_buff, sizeof(tmp_buff));
		if (subject_len < 0)
			subject_len = 0;
	}
	if (subject_len > 512) {
		subject_len = 512;
		tmp_buff[510] = '\0';
		tmp_buff[511] = '\0';
	}
	utf16le_to_utf8(tmp_buff, subject_len, tmp_buff1, sizeof(tmp_buff1));
	if (pproplist->set(PR_SUBJECT, tmp_buff1) != 0)
		return FALSE;
	ptoken = static_cast<char *>(memmem(tmp_buff, subject_len, seperator, 4));
	if (ptoken == nullptr)
		return TRUE;
	tmp_len = ptoken - tmp_buff;
	if (tmp_len < 2 || tmp_len > 6)
		return TRUE;
	for (i = 0; i < tmp_len; i += 2)
		if ((tmp_buff[i] == ':' || tmp_buff[i] == ' ' || HX_isdigit(tmp_buff[0])) &&
		    tmp_buff[i+1] == '\0')
			return TRUE;
	tmp_len += sizeof(seperator);
	memcpy(tmp_buff1, tmp_buff, tmp_len);
	tmp_buff1[tmp_len] = '\0';
	tmp_buff1[tmp_len + 1] = '\0';
	utf16le_to_utf8(tmp_buff1, tmp_len + 2,
		prefix_buff, sizeof(prefix_buff));
	if (pproplist->set(PR_SUBJECT_PREFIX, prefix_buff) != 0)
		return FALSE;
	utf16le_to_utf8(tmp_buff + tmp_len,
		subject_len - tmp_len, tmp_buff1,
		sizeof(tmp_buff1));
	return pproplist->set(PR_NORMALIZED_SUBJECT, tmp_buff1) == 0 ? TRUE : false;
}

static BOOL oxcmail_parse_thread_topic(const char *charset,
    const char *field, TPROPVAL_ARRAY *pproplist)
{
	char utf8_field[MIME_FIELD_LEN];
	
	if (mime_string_to_utf8(charset, field, utf8_field, std::size(utf8_field)))
		return pproplist->set(PR_CONVERSATION_TOPIC, utf8_field) == 0 ? TRUE : false;
	return pproplist->set(PR_CONVERSATION_TOPIC_A, field) == 0 ? TRUE : false;
}

static BOOL oxcmail_parse_thread_index(const char *charset, const char *field,
    TPROPVAL_ARRAY *pproplist)
{
	BINARY tmp_bin;
	char tmp_buff[MIME_FIELD_LEN];
	
	if (!mime_string_to_utf8(charset, field, tmp_buff, std::size(tmp_buff)))
		return TRUE;
	auto len = sizeof(tmp_buff);
	if (decode64(field, strlen(field), tmp_buff, std::size(tmp_buff), &len) != 0)
		return TRUE;
	tmp_bin.pc = tmp_buff;
	tmp_bin.cb = len;
	return pproplist->set(PR_CONVERSATION_INDEX, &tmp_bin) == 0 ? TRUE : false;
}

static BOOL oxcmail_parse_keywords(const char *charset, const char *field,
    uint16_t propid, TPROPVAL_ARRAY *pproplist)
{
	int i, len;
	BOOL b_start;
	char *ptoken_prev;
	STRING_ARRAY strings;
	char* string_buff[1024];
	char tmp_buff[MIME_FIELD_LEN];
	uint32_t tag;
	
	if (!mime_string_to_utf8(charset, field, tmp_buff, std::size(tmp_buff))) {
		tag = PROP_TAG(PT_MV_STRING8, propid);
		gx_strlcpy(tmp_buff, field, std::size(tmp_buff));
	} else {
		tag = PROP_TAG(PT_MV_UNICODE, propid);
	}
	strings.count = 0;
	strings.ppstr = string_buff;
	len = strlen(tmp_buff);
	tmp_buff[len++] = ';';
	ptoken_prev = tmp_buff;
	b_start = FALSE;
	for (i=0; i<len&&strings.count<1024; i++) {
		if (!b_start && (tmp_buff[i] == ' ' || tmp_buff[i] == '\t')) {
			ptoken_prev = tmp_buff + i + 1;
			continue;
		}
		b_start = TRUE;
		if (',' == tmp_buff[i] || ';' == tmp_buff[i]) {
			tmp_buff[i] = '\0';
			strings.ppstr[strings.count++] = ptoken_prev;
			b_start = FALSE;
			ptoken_prev = tmp_buff + i + 1;
		}
	}
	if (strings.count == 0)
		return TRUE;
	return pproplist->set(tag, &strings) == 0 ? TRUE : false;
}

static BOOL oxcmail_parse_response_suppress(const char *unfield,
    TPROPVAL_ARRAY *pproplist)
{
	BOOL b_start;
	char *ptoken_prev;
	uint32_t tmp_int32;
	
	if (strcasecmp(unfield, "NONE") == 0) {
		return TRUE;
	} else if (strcasecmp(unfield, "ALL") == 0) {
		tmp_int32 = UINT32_MAX;
		return pproplist->set(PR_AUTO_RESPONSE_SUPPRESS, &tmp_int32) == 0 ? TRUE : false;
	}
	char field[MIME_FIELD_LEN];
	gx_strlcpy(field, unfield, std::size(field));
	auto len = strlen(field);
	field[len++] = ';';
	ptoken_prev = field;
	b_start = FALSE;
	tmp_int32 = 0;
	for (size_t i = 0; i < len; ++i) {
		if (!b_start && (field[i] == ' ' || field[i] == '\t')) {
			ptoken_prev = field + i + 1;
			continue;
		}
		b_start = TRUE;
		if (',' == field[i] || ';' == field[i]) {
			field[i] = '\0';
			if (strcasecmp("DR", ptoken_prev) == 0)
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_DR;
			else if (strcasecmp("NDR", ptoken_prev) == 0)
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_NDR;
			else if (strcasecmp("RN", ptoken_prev) == 0)
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_RN;
			else if (strcasecmp("NRN", ptoken_prev) == 0)
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_NRN;
			else if (strcasecmp("OOF", ptoken_prev) == 0)
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_OOF;
			else if (strcasecmp("AutoReply", ptoken_prev) == 0)
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_AUTOREPLY;
			b_start = FALSE;
			ptoken_prev = field + i + 1;
		}
	}
	if (tmp_int32 == 0)
		return TRUE;
	return pproplist->set(PR_AUTO_RESPONSE_SUPPRESS, &tmp_int32) == 0 ? TRUE : false;
}

static inline bool cttype_is_voiceaudio(const char *s)
{
	static constexpr char types[][10] =
		{"audio/gsm", "audio/mp3", "audio/wav", "audio/wma"};
	return std::any_of(std::cbegin(types), std::cend(types),
	       [=](const char *e) { return strcasecmp(e, s) == 0; });
}

static inline bool cttype_is_image(const char *s)
{
	static constexpr char types[][12] =
		{"image/jpeg", "image/jpg", "image/pjpeg", "image/gif",
		"image/bmp", "image/png", "image/x-png"};
	return std::any_of(std::cbegin(types), std::cend(types),
	       [=](const char *e) { return strcasecmp(e, s) == 0; });
}

static inline unsigned int om_parse_sensitivity(const char *s)
{
	/* MS-OXCMAIL v22 §2.1.3.2.6 pg 31 */
	if (strcasecmp(s, "Personal") == 0)
		return SENSITIVITY_PERSONAL;
	if (strcasecmp(s, "Private") == 0)
		return SENSITIVITY_PRIVATE;
	if (strcasecmp(s, "Company-Confidential") == 0)
		return SENSITIVITY_COMPANY_CONFIDENTIAL;
	return SENSITIVITY_NONE;
}

static inline unsigned int om_parse_importance(const char *s)
{
	/* MS-OXCMAIL v22 §2.2.3.2.5 pg 61 */
	if (strcasecmp(s, "Low") == 0)
		return IMPORTANCE_LOW;
	if (strcasecmp(s, "High") == 0)
		return IMPORTANCE_HIGH;
	return IMPORTANCE_NORMAL;
}

static inline unsigned int om_parse_priority(const char *s)
{
	/* RFC 2156 §5.3.6 pg 96, MS-OXCMAIL v22 §2.2.3.2.5 pg 60 */
	if (strcasecmp(s, "Non-Urgent") == 0)
		return IMPORTANCE_LOW;
	if (strcasecmp(s, "Urgent") == 0)
		return IMPORTANCE_HIGH;
	return IMPORTANCE_NORMAL;
}

static inline unsigned int om_parse_xpriority(const char *s)
{
	/* MS-OXCMAIL v22 §2.2.3.2.5 pg 61 */
	if (*s == '5' || *s == '4')
		return IMPORTANCE_LOW;
	if (*s == '2' || *s == '1')
		return IMPORTANCE_HIGH;
	return IMPORTANCE_NORMAL;
}

static inline unsigned int om_parse_senderidresult(const char *s)
{
	if (strcasecmp(s, "Neutral") == 0)
		return SENDER_ID_NEUTRAL;
	if (strcasecmp(s, "Pass") == 0)
		return SENDER_ID_PASS;
	if (strcasecmp(s, "Fail") == 0)
		return SENDER_ID_FAIL;
	if (strcasecmp(s, "SoftFail") == 0)
		return SENDER_ID_SOFT_FAIL;
	if (strcasecmp(s, "None") == 0)
		return SENDER_ID_NONE;
	if (strcasecmp(s, "TempError") == 0)
		return SENDER_ID_TEMP_ERROR;
	if (strcasecmp(s, "PermError") == 0)
		return SENDER_ID_PERM_ERROR;
	return 0;
}

static BOOL oxcmail_parse_content_class(const char *field, const MAIL *pmail,
    uint16_t *plast_propid, namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	GUID tmp_guid;
	char tmp_class[1024];
	const char *mclass;
	
	if (0 == strcasecmp(field, "fax")) {
		auto pmime = pmail->get_head();
		if (strcasecmp(pmime->content_type, "multipart/mixed") != 0)
			return TRUE;
		pmime = pmime->get_child();
		if (pmime == nullptr)
			return TRUE;
		if (strcasecmp(pmime->content_type, "text/html") != 0)
			return TRUE;
		pmime = pmime->get_sibling();
		if (pmime == nullptr)
			return TRUE;
		if (strcasecmp(pmime->content_type, "image/tiff") != 0)
			return TRUE;
		mclass = "IPM.Note.Microsoft.Fax";
	} else if (0 == strcasecmp(field, "fax-ca")) {
		mclass = "IPM.Note.Microsoft.Fax.CA";
	} else if (0 == strcasecmp(field, "missedcall")) {
		auto pmime = pmail->get_head();
		auto cttype = pmime->content_type;
		if (!cttype_is_voiceaudio(cttype))
			return TRUE;
		mclass = "IPM.Note.Microsoft.Missed.Voice";
	} else if (0 == strcasecmp(field, "voice-uc")) {
		auto pmime = pmail->get_head();
		auto cttype = pmime->content_type;
		if (!cttype_is_voiceaudio(cttype))
			return TRUE;
		mclass = "IPM.Note.Microsoft.Conversation.Voice";
	} else if (0 == strcasecmp(field, "voice-ca")) {
		auto pmime = pmail->get_head();
		auto cttype = pmime->content_type;
		if (!cttype_is_voiceaudio(cttype))
			return TRUE;
		mclass = "IPM.Note.Microsoft.Voicemail.UM.CA";
	} else if (0 == strcasecmp(field, "voice")) {
		auto pmime = pmail->get_head();
		auto cttype = pmime->content_type;
		if (!cttype_is_voiceaudio(cttype))
			return TRUE;
		mclass = "IPM.Note.Microsoft.Voicemail.UM";
	} else if (0 == strncasecmp(field, "urn:content-class:custom.", 25)) {
		snprintf(tmp_class, std::size(tmp_class), "IPM.Note.Custom.%s", field + 25);
		mclass = tmp_class;
	} else if (0 == strncasecmp(field, "InfoPathForm.", 13)) {
		auto ptoken = strchr(field + 13, '.');
		if (NULL != ptoken) {
			snprintf(tmp_class, std::size(tmp_class), "%.*s",
			         static_cast<int>(ptoken - (field + 13)), field + 13);
			if (tmp_guid.from_str(tmp_class)) {
				PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON,
				                         PidLidInfoPathFromName};
				if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
					return FALSE;
				uint32_t tag = PROP_TAG(pick_strtype(ptoken), *plast_propid);
				if (pproplist->set(tag, ptoken) != 0)
					return FALSE;
				(*plast_propid) ++;
			}
		}
		snprintf(tmp_class, std::size(tmp_class), "IPM.InfoPathForm.%s", field + 13);
		mclass = tmp_class;
	} else {
		PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS,
		                         0, deconst(PidNameContentClass)};
		if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
			return FALSE;
		uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
		if (pproplist->set(tag, field) != 0)
			return FALSE;
		(*plast_propid) ++;
		return TRUE;
	}
	return pproplist->set(PR_MESSAGE_CLASS, mclass) == 0 ? TRUE : false;
}

static BOOL oxcmail_parse_message_flag(const char *field,
    uint16_t *plast_propid, namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	BOOL b_unicode;
	uint8_t tmp_byte;
	double tmp_double;
	uint32_t tmp_int32;
	
	PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidFlagRequest};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
	if (pproplist->set(tag, field) != 0)
		return FALSE;
	(*plast_propid) ++;
	tmp_int32 = followupFlagged;
	if (pproplist->set(PR_FLAG_STATUS, &tmp_int32) != 0)
		return FALSE;
	
	auto str = pproplist->get<const char>(PR_SUBJECT);
	if (str != nullptr) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
		str = pproplist->get<char>(PR_SUBJECT_A);
	}
	if (str != nullptr) {
		propname = {MNID_ID, PSETID_COMMON, PidLidFlagRequest};
		if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
			return FALSE;
		tag = PROP_TAG(b_unicode ? PT_UNICODE : PT_STRING8, *plast_propid);
		if (pproplist->set(tag, str) != 0)
			return FALSE;
		(*plast_propid) ++;
	}
	
	propname = {MNID_ID, PSETID_TASK, PidLidTaskStatus};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_int32 = 0;
	if (pproplist->set(PROP_TAG(PT_LONG, *plast_propid), &tmp_int32) != 0)
		return FALSE;
	(*plast_propid) ++;
	
	propname = {MNID_ID, PSETID_TASK, PidLidTaskComplete};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_byte = 0;
	if (pproplist->set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return FALSE;
	(*plast_propid) ++;
	
	propname = {MNID_ID, PSETID_TASK, PidLidPercentComplete};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_double = 0.0;
	if (pproplist->set(PROP_TAG(PT_DOUBLE, *plast_propid), &tmp_double) != 0)
		return FALSE;
	(*plast_propid) ++;
	tmp_int32 = todoRecipientFlagged;
	return pproplist->set(PR_TODO_ITEM_FLAGS, &tmp_int32) == 0 ? TRUE : false;
}

static BOOL oxcmail_parse_classified(const char *field, uint16_t *plast_propid,
    namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	uint8_t tmp_byte;
	
	if (strcasecmp(field, "true") != 0 && strcasecmp(field, "false") != 0)
		return TRUE;
	PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidClassified};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_byte = 1;
	if (pproplist->set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return FALSE;
	(*plast_propid)++;
	return TRUE;
}

static BOOL oxcmail_parse_classkeep(const char *field, uint16_t *plast_propid,
    namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	if (strcasecmp(field, "true") != 0 && strcasecmp(field, "false") != 0)
		return TRUE;
	PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidClassificationKeep};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint8_t tmp_byte = strcasecmp(field, "true") == 0;
	if (pproplist->set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != 0)
		return FALSE;
	(*plast_propid)++;
	return TRUE;
}

static BOOL oxcmail_parse_classification(const char *field,
    uint16_t *plast_propid, namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidClassification};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
	if (pproplist->set(tag, field) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_classdesc(const char *field, uint16_t *plast_propid,
    namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidClassificationDescription};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
	if (pproplist->set(tag, field) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_classid(const char *field, uint16_t *plast_propid,
    namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidClassificationGuid};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
	if (pproplist->set(tag, field) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_enum_mail_head(const char *key, const char *field, void *pparam)
{
	time_t tmp_time;
	uint8_t tmp_byte;
	uint64_t tmp_int64;
	EMAIL_ADDR email_addr;
	
	auto penum_param = static_cast<FIELD_ENUM_PARAM *>(pparam);
	if (strcasecmp(key, "From") == 0) {
		parse_mime_addr(&email_addr, field);
		if (!oxcmail_parse_address(penum_param->charset, &email_addr,
		    PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_ADDRTYPE,
		    PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENT_REPRESENTING_SMTP_ADDRESS,
		    PR_SENT_REPRESENTING_SEARCH_KEY, PR_SENT_REPRESENTING_ENTRYID,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Sender") == 0) {
		parse_mime_addr(&email_addr, field);
		if (!oxcmail_parse_address(penum_param->charset, &email_addr,
		    PR_SENDER_NAME, PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS,
		    PR_SENDER_SMTP_ADDRESS, PR_SENDER_SEARCH_KEY,
		    PR_SENDER_ENTRYID, &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Reply-To") == 0) {
		if (!oxcmail_parse_reply_to(penum_param->charset, field,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "To") == 0) {
		if (!oxcmail_parse_addresses(penum_param->charset, field, MAPI_TO,
		    penum_param->pmsg->children.prcpts))
			return FALSE;
	} else if (strcasecmp(key, "Cc") == 0) {
		if (!oxcmail_parse_addresses(penum_param->charset, field, MAPI_CC,
		    penum_param->pmsg->children.prcpts))
			return FALSE;
	} else if (strcasecmp(key, "Bcc") == 0) {
		if (!oxcmail_parse_addresses(penum_param->charset, field, MAPI_BCC,
		    penum_param->pmsg->children.prcpts))
			return FALSE;
	} else if (strcasecmp(key, "Return-Receipt-To") == 0) {
		tmp_byte = 1;
		if (penum_param->pmsg->proplist.set(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED, &tmp_byte) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Disposition-Notification-To") == 0) {
		tmp_byte = 1;
		if (penum_param->pmsg->proplist.set(PR_READ_RECEIPT_REQUESTED, &tmp_byte) != 0)
			return FALSE;
		tmp_byte = 1;
		if (penum_param->pmsg->proplist.set(PR_NON_RECEIPT_NOTIFICATION_REQUESTED, &tmp_byte) != 0)
			return FALSE;
		parse_mime_addr(&email_addr, field);
		if (!oxcmail_parse_address(penum_param->charset,
		    &email_addr, PidTagReadReceiptName,
		    PidTagReadReceiptAddressType, PidTagReadReceiptEmailAddress,
		    PidTagReadReceiptSmtpAddress, PR_READ_RECEIPT_SEARCH_KEY,
		    PR_READ_RECEIPT_ENTRYID, &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Message-ID") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_INTERNET_MESSAGE_ID : PR_INTERNET_MESSAGE_ID_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Date") == 0) {
		if (parse_rfc822_timestamp(field, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (penum_param->pmsg->proplist.set(PR_CLIENT_SUBMIT_TIME, &tmp_int64) != 0)
				return FALSE;
		}
	} else if (strcasecmp(key, "References") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_INTERNET_REFERENCES : PR_INTERNET_REFERENCES_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Sensitivity") == 0) {
		uint32_t tmp_int32 = om_parse_sensitivity(field);
		if (penum_param->pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Importance") == 0 ||
		strcasecmp(key, "X-MSMail-Priority") == 0) {
		uint32_t tmp_int32 = om_parse_importance(field);
		if (penum_param->pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Priority") == 0) {
		uint32_t tmp_int32 = om_parse_priority(field);
		if (penum_param->pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-Priority") == 0) {
		uint32_t tmp_int32 = om_parse_xpriority(field);
		if (penum_param->pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Subject") == 0) {
		if (!oxcmail_parse_subject(penum_param->charset, field,
		    &penum_param->pmsg->proplist))
			return FALSE;
		if (!penum_param->pmsg->proplist.has(PR_SUBJECT_PREFIX)) {
			tmp_byte = '\0';
			if (penum_param->pmsg->proplist.set(PR_SUBJECT_PREFIX, &tmp_byte) != 0)
				return FALSE;
			auto str = penum_param->pmsg->proplist.get<const char>(PR_SUBJECT);
			if (str == nullptr) {
				str = penum_param->pmsg->proplist.get<char>(PR_SUBJECT_A);
				if (str != nullptr &&
				    penum_param->pmsg->proplist.set(PR_NORMALIZED_SUBJECT_A, str) != 0)
					return FALSE;
			} else if (penum_param->pmsg->proplist.set(PR_NORMALIZED_SUBJECT, str) != 0) {
				return FALSE;
			}
		}
	} else if (strcasecmp(key, "Thread-Topic") == 0) {
		if (!oxcmail_parse_thread_topic(penum_param->charset, field,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Thread-Index") == 0) {
		if (!oxcmail_parse_thread_index(penum_param->charset, field,
		    &penum_param->pmsg->proplist))
				return FALSE;
	} else if (strcasecmp(key, "In-Reply-To") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_IN_REPLY_TO_ID : PR_IN_REPLY_TO_ID_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Reply-By") == 0) {
		if (parse_rfc822_timestamp(field, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (penum_param->pmsg->proplist.set(PR_REPLY_TIME, &tmp_int64) != 0)
				return FALSE;
		}
	} else if (strcasecmp(key, "Content-Language") == 0) {
		uint32_t tmp_int32 = ltag_to_lcid(field);
		if (tmp_int32 != 0 &&
		    penum_param->pmsg->proplist.set(PR_MESSAGE_LOCALE_ID, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Accept-Language") == 0 ||
		strcasecmp(key, "X-Accept-Language") == 0) {
		PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS,
		                         0, deconst("Accept-Language")};
		if (namemap_add(penum_param->phash, penum_param->last_propid,
		    std::move(propname)) != 0)
			return FALSE;
		uint32_t tag = PROP_TAG(pick_strtype(field), penum_param->last_propid);
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
		penum_param->last_propid ++;
	} else if (strcasecmp(key, "Keywords") == 0) {
		PROPERTY_NAME propname = {MNID_STRING, PS_PUBLIC_STRINGS,
		                         0, deconst(PidNameKeywords)};
		if (namemap_add(penum_param->phash, penum_param->last_propid,
		    std::move(propname)) != 0)
			return FALSE;
		if (!oxcmail_parse_keywords(penum_param->charset, field,
		    penum_param->last_propid, &penum_param->pmsg->proplist))
			return FALSE;
		penum_param->last_propid ++;
	} else if (strcasecmp(key, "Expires") == 0 ||
		strcasecmp(key, "Expiry-Date") == 0) {
		if (parse_rfc822_timestamp(field, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (penum_param->pmsg->proplist.set(PR_EXPIRY_TIME, &tmp_int64) != 0)
				return FALSE;
		}
	} else if (strcasecmp(key, "X-Auto-Response-Suppress") == 0) {
		if (!oxcmail_parse_response_suppress(field,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Content-Class") == 0) {
		if (!oxcmail_parse_content_class(field,
		    penum_param->pmail, &penum_param->last_propid,
		    penum_param->phash, &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "X-Message-Flag") == 0) {
		if (!oxcmail_parse_message_flag(field,
		    &penum_param->last_propid, penum_param->phash,
		    &penum_param->pmsg->proplist))
			return FALSE;
		penum_param->b_flag_del = true;
	} else if (strcasecmp(key, "List-Help") == 0 ||
		strcasecmp(key, "X-List-Help") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_LIST_HELP : PR_LIST_HELP_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "List-Subscribe") == 0 ||
		strcasecmp(key, "X-List-Subscribe") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_LIST_SUBSCRIBE : PR_LIST_SUBSCRIBE_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "List-Unsubscribe") == 0 ||
		strcasecmp(key, "X-List-Unsubscribe") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_LIST_UNSUBSCRIBE : PR_LIST_UNSUBSCRIBE_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-Payload-Class") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_ATTACH_PAYLOAD_CLASS : PR_ATTACH_PAYLOAD_CLASS_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-MS-Exchange-Organization-PRD") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_PURPORTED_SENDER_DOMAIN : PR_PURPORTED_SENDER_DOMAIN_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-MS-Exchange-Organization-SenderIdResult") == 0) {
		uint32_t tmp_int32 = om_parse_senderidresult(field);
		if (tmp_int32 != 0 &&
		    penum_param->pmsg->proplist.set(PR_SENDER_ID_STATUS, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-MS-Exchange-Organization-SCL") == 0) {
		int32_t tmp_int32 = strtol(field, nullptr, 0);
		if (penum_param->pmsg->proplist.set(PR_CONTENT_FILTER_SCL, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-Microsoft-Classified") == 0) {
		if (!oxcmail_parse_classified(field,
		    &penum_param->last_propid, penum_param->phash,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "X-Microsoft-ClassKeep") == 0) {
		if (penum_param->b_classified &&
		    !oxcmail_parse_classkeep(field,
		    &penum_param->last_propid, penum_param->phash,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "X-Microsoft-Classification") == 0) {
		if (penum_param->b_classified &&
		    !oxcmail_parse_classification(field,
		    &penum_param->last_propid, penum_param->phash,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "X-Microsoft-ClassDesc") == 0) {
		if (penum_param->b_classified &&
		    !oxcmail_parse_classdesc(field,
		    &penum_param->last_propid, penum_param->phash,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "X-Microsoft-ClassID") == 0) {
		if (penum_param->b_classified &&
		    !oxcmail_parse_classid(field,
		    &penum_param->last_propid, penum_param->phash,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "X-CallingTelephoneNumber") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_SENDER_TELEPHONE_NUMBER :
		               PR_SENDER_TELEPHONE_NUMBER_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-VoiceMessageSenderName") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		                  PidTagVoiceMessageSenderName :
		                  PidTagVoiceMessageSenderName_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-AttachmentOrder") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PidTagVoiceMessageAttachmentOrder :
		               PidTagVoiceMessageAttachmentOrder_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-CallID") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PidTagCallId : PidTagCallId_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-VoiceMessageDuration") == 0) {
		uint32_t tmp_int32 = strtoul(field, nullptr, 0);
		if (penum_param->pmsg->proplist.set(PidTagVoiceMessageDuration, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-FaxNumberOfPages") == 0) {
		uint32_t tmp_int32 = strtoul(field, nullptr, 0);
		if (penum_param->pmsg->proplist.set(PidTagFaxNumberOfPages, &tmp_int32) != 0)
			return FALSE;
	} else if (strcasecmp(key, "Content-ID") == 0) {
		size_t tmp_int32 = strlen(field);
		if (tmp_int32 > 0) {
			char rw[MIME_FIELD_LEN];
			if (field[0] == '<' && field[tmp_int32-1] == '>') {
				snprintf(rw, std::size(rw), "%.*s",
				         static_cast<int>(tmp_int32 - 1), &field[1]);
				field = rw;
			}
			uint32_t tag = oxcmail_is_ascii(field) ?
			               PR_BODY_CONTENT_ID : PR_BODY_CONTENT_ID_A;
			if (penum_param->pmsg->proplist.set(tag, field) != 0)
				return FALSE;
		}
	} else if (strcasecmp(key, "Content-Base") == 0) {
		PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS,
		                         0, deconst("Content-Base")};
		if (namemap_add(penum_param->phash, penum_param->last_propid,
		    std::move(propname)) != 0)
			return FALSE;
		uint32_t tag = PROP_TAG(pick_strtype(field), penum_param->last_propid);
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
		penum_param->last_propid ++;
	} else if (strcasecmp(key, "Content-Location") == 0) {
		uint32_t tag = oxcmail_is_ascii(field) ?
		               PR_BODY_CONTENT_LOCATION : PR_BODY_CONTENT_LOCATION_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-MS-Exchange-Organization-AuthAs") == 0 ||
		strcasecmp(key, "X-MS-Exchange-Organization-AuthDomain") == 0 ||
		strcasecmp(key, "X-MS-Exchange-Organization-AuthMechanism") == 0 ||
		strcasecmp(key, "X-MS-Exchange-Organization-AuthSource") == 0 ||
		strcasecmp(key, "X-Mailer") == 0 ||
		strcasecmp(key, "User-Agent") == 0) {
		PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS, 0,
		                         static_cast<char *>(penum_param->alloc(strlen(key) + 1))};
		if (propname.pname == nullptr)
			return FALSE;
		strcpy(propname.pname, key);
		if (namemap_add(penum_param->phash, penum_param->last_propid,
		    std::move(propname)) != 0)
			return FALSE;
		uint32_t tag = PROP_TAG(pick_strtype(field), penum_param->last_propid);
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
		penum_param->last_propid ++;
	} else if (strcasecmp(key, "Received") == 0 &&
	    !penum_param->pmsg->proplist.has(PR_MESSAGE_DELIVERY_TIME)) {
		/* Try to find a halfway useful value for last delivery for EML imports */
		for (auto p = strchr(field, ';'); p != nullptr;
		     p = strchr(p, ';')) {
			if (!parse_rfc822_timestamp(++p, &tmp_time))
				continue;
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (penum_param->pmsg->proplist.set(PR_MESSAGE_DELIVERY_TIME, &tmp_int64) != 0)
				return false;
		}
	}
	return TRUE;
}

static BOOL oxcmail_parse_transport_message_header(const MIME *pmime,
    TPROPVAL_ARRAY *pproplist)
{
	size_t tmp_len;
	char tmp_buff[1024*1024];
	
	tmp_len = sizeof(tmp_buff) - 1;
	if (!pmime->read_head(tmp_buff, &tmp_len))
		return TRUE;
	tmp_buff[tmp_len + 1] = '\0';
	uint32_t tag = oxcmail_is_ascii(tmp_buff) ?
	               PR_TRANSPORT_MESSAGE_HEADERS :
	               PR_TRANSPORT_MESSAGE_HEADERS_A;
	if (pproplist->set(tag, tmp_buff) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcmail_parse_message_body(const char *charset, const MIME *pmime,
    TPROPVAL_ARRAY *pproplist)
{
	BINARY tmp_bin;
	char best_charset[32];
	char temp_charset[32];
	const char *content_type;
	
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		mlog(LV_ERR, "%s:MIME::get_length: unsuccessful", __func__);
		return false;
	}
	std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(rdlength + 1));
	if (pcontent == nullptr)
		return FALSE;
	size_t length = rdlength;
	if (!pmime->read_content(pcontent.get(), &length))
		return TRUE;
	pcontent[length] = '\0';
	auto content_size = mb_to_utf8_len(pcontent.get());
	std::unique_ptr<char[], stdlib_delete> cutf(me_alloc<char>(content_size + 1));
	if (cutf == nullptr)
		return false;
	if (oxcmail_get_content_param(pmime, "charset", temp_charset, 32))
		gx_strlcpy(best_charset, temp_charset, std::size(best_charset));
	else
		gx_strlcpy(best_charset, charset, std::size(best_charset));
	content_type = pmime->content_type;
	if (0 == strcasecmp(content_type, "text/html")) {
		uint32_t tmp_int32 = cset_to_cpid(best_charset);
		if (pproplist->set(PR_INTERNET_CPID, &tmp_int32) != 0)
			return FALSE;
		tmp_bin.cb = length;
		tmp_bin.pc = pcontent.get();
		if (pproplist->set(PR_HTML, &tmp_bin) != 0)
			return false;
	} else if (0 == strcasecmp(content_type, "text/plain")) {
		TAGGED_PROPVAL propval;
		if (string_to_utf8(best_charset, pcontent.get(), cutf.get(), content_size)) {
			propval.proptag = PR_BODY;
			propval.pvalue  = cutf.get();
			if (!utf8_valid(cutf.get())) {
				mlog(LV_NOTICE, "utf8_valid failed for a text/plain MIME part");
				utf8_filter(cutf.get());
			}
		} else {
			propval.proptag = PR_BODY_A;
			propval.pvalue  = pcontent.get();
		}
		if (pproplist->set(propval) != 0)
			return false;
	} else if (0 == strcasecmp(content_type, "text/enriched")) {
		enriched_to_html(pcontent.get(), cutf.get(), content_size);
		uint32_t tmp_int32 = cset_to_cpid(best_charset);
		if (pproplist->set(PR_INTERNET_CPID, &tmp_int32) != 0)
			return FALSE;
		tmp_bin.cb = strlen(cutf.get());
		tmp_bin.pc = cutf.get();
		if (pproplist->set(PR_HTML, &tmp_bin) != 0)
			return false;
	}
	return TRUE;
}

static void oxcmail_enum_attachment(const MIME *pmime, void *pparam)
{
	BOOL b_unifn;
	char *ptoken;
	BINARY tmp_bin;
	time_t tmp_time;
	uint64_t tmp_int64;
	uint32_t tmp_int32;
	char extension[16];
	char mode_buff[32];
	char dir_buff[256];
	char tmp_buff[1024];
	char site_buff[256];
	char file_name[512];
	char date_buff[128];
	char mime_charset[32];
	MESSAGE_CONTENT *pmsg;
	char display_name[512];
	ATTACHMENT_CONTENT *pattachment;
	
	auto pmime_enum = static_cast<MIME_ENUM_PARAM *>(pparam);
	if (!pmime_enum->b_result)
		return;
	if (pmime == pmime_enum->phtml ||
		pmime == pmime_enum->pplain ||
		pmime == pmime_enum->pcalendar ||
		pmime == pmime_enum->penriched ||
		pmime == pmime_enum->preport) {
		return;
	}
	if (pmime->mime_type == mime_type::multiple)
		return;
	pmime_enum->b_result = false;
	pattachment = attachment_content_init();
	if (pattachment == nullptr)
		return;
	if (!pmime_enum->pmsg->children.pattachments->append_internal(pattachment)) {
		attachment_content_free(pattachment);
		return;
	}
	auto cttype = pmime->content_type;
	auto newval = strcasecmp(cttype, "application/ms-tnef") == 0 ?
	              "application/octet-stream" : cttype;
	if (pattachment->proplist.set(PR_ATTACH_MIME_TAG, newval) != 0)
		return;
	auto b_filename = pmime->get_filename(tmp_buff, std::size(tmp_buff));
	if (b_filename) {
		if (mime_string_to_utf8(pmime_enum->charset, tmp_buff,
		    file_name, std::size(file_name))) {
			b_unifn = TRUE;
		} else {
			b_unifn = FALSE;
			strcpy(file_name, tmp_buff);
		}
		oxcmail_split_filename(file_name, extension);
		if ('\0' == extension[0]) {
			auto pext = mime_to_extension(cttype);
			if (pext != NULL) {
				sprintf(extension, ".%s", pext);
				HX_strlcat(file_name, extension, sizeof(file_name));
			}
		}
	} else {
		b_unifn = TRUE;
		if ('\0' != extension[0]) {
			auto pext = mime_to_extension(cttype);
			if (NULL != pext) {
				sprintf(extension, ".%s", pext);
				HX_strlcat(file_name, extension, sizeof(file_name));
			} else {
				strcpy(extension, ".dat");
			}
		}
		pmime_enum->attach_id ++;
		sprintf(file_name, "attachment%d%s",
			pmime_enum->attach_id, extension);
	}
	if (extension[0] != '\0' &&
	    pattachment->proplist.set(PR_ATTACH_EXTENSION, extension) != 0)
		return;
	if (pattachment->proplist.set(b_unifn ? PR_ATTACH_LONG_FILENAME :
	    PR_ATTACH_LONG_FILENAME_A, file_name) != 0)
		return;
	auto b_description = pmime->get_field("Content-Description", tmp_buff, 256);
	if (b_description) {
		uint32_t tag;
		if (mime_string_to_utf8(pmime_enum->charset, tmp_buff,
		    display_name, std::size(display_name))) {
			tag = PR_DISPLAY_NAME;
		} else {
			tag = PR_DISPLAY_NAME_A;
			strcpy(display_name, tmp_buff);
		}
		if (pattachment->proplist.set(tag, display_name) != 0)
			return;
	}
	bool b_inline = false;
	if (pmime->get_field("Content-Disposition", tmp_buff, 1024)) {
		b_inline = strcmp(tmp_buff, "inline") == 0 || strncasecmp(tmp_buff, "inline;", 7) == 0;
		if (oxcmail_get_field_param(tmp_buff, "create-date", date_buff, 128) &&
		    parse_rfc822_timestamp(date_buff, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (pattachment->proplist.set(PR_CREATION_TIME, &tmp_int64) != 0)
				return;
		}
		if (oxcmail_get_field_param(tmp_buff, "modification-date", date_buff, 128) &&
		    parse_rfc822_timestamp(date_buff, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (pattachment->proplist.set(PR_LAST_MODIFICATION_TIME, &tmp_int64) != 0)
				return;
		}
	}
	if (!pattachment->proplist.has(PR_CREATION_TIME) &&
	    pattachment->proplist.set(PR_CREATION_TIME, &pmime_enum->nttime_stamp) != 0)
		return;
	if (!pattachment->proplist.has(PR_LAST_MODIFICATION_TIME) &&
	    pattachment->proplist.set(PR_LAST_MODIFICATION_TIME, &pmime_enum->nttime_stamp) != 0)
		return;
	if (pmime->get_field("Content-ID", tmp_buff, 128)) {
		tmp_int32 = strlen(tmp_buff);
		if (tmp_int32 > 0) {
			if (tmp_buff[tmp_int32-1] == '>')
				tmp_buff[tmp_int32 - 1] = '\0';
			newval = tmp_buff[0] == '<' ? tmp_buff + 1 : tmp_buff;
			uint32_t tag = oxcmail_is_ascii(newval) ?
			                  PR_ATTACH_CONTENT_ID : PR_ATTACH_CONTENT_ID_A;
			if (pattachment->proplist.set(tag, newval) != 0)
				return;
		}
	}
	if (pmime->get_field("Content-Location", tmp_buff, 1024)) {
		uint32_t tag = oxcmail_is_ascii(tmp_buff) ?
		                  PR_ATTACH_CONTENT_LOCATION :
		                  PR_ATTACH_CONTENT_LOCATION_A;
		if (pattachment->proplist.set(tag, tmp_buff) != 0)
			return;
	}
	if (pmime->get_field("Content-Base", tmp_buff, 1024)) {
		uint32_t tag = oxcmail_is_ascii(tmp_buff) ?
		                  PR_ATTACH_CONTENT_BASE : PR_ATTACH_CONTENT_BASE_A;
		if (pattachment->proplist.set(tag, tmp_buff) != 0)
			return;
	}
	if (b_inline && !cttype_is_image(cttype))
		b_inline = false;
	if (b_inline) {
		if (pmime->get_parent() == nullptr ||
		    (strcasecmp(pmime->get_parent()->content_type, "multipart/related") != 0 &&
		    strcasecmp(pmime->get_parent()->content_type, "multipart/mixed") != 0))
			b_inline = false;
	}
	if (b_inline) {
		tmp_int32 = ATT_MHTML_REF;
		if (pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != 0)
			return;
	}
	if (strcasecmp(cttype, "text/directory") == 0) {
		auto rdlength = pmime->get_length();
		if (rdlength < 0) {
			mlog(LV_ERR, "%s:MIME::get_length:%u: unsuccessful", __func__, __LINE__);
			return;
		}
		size_t content_len = rdlength;
		if (content_len < VCARD_MAX_BUFFER_LEN) {
			auto contallocsz = 3 * content_len + 2;
			std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(contallocsz));
			if (pcontent == nullptr)
				return;
			if (!pmime->read_content(pcontent.get(), &content_len))
				return;
			pcontent[content_len] = '\0';
			if (!oxcmail_get_content_param(pmime, "charset",
			    mime_charset, std::size(mime_charset)))
				gx_strlcpy(mime_charset, !utf8_valid(pcontent.get()) ?
					pmime_enum->charset : "utf-8", std::size(mime_charset));
			if (string_to_utf8(mime_charset, pcontent.get(),
			    &pcontent[content_len+1], contallocsz - content_len - 1)) {
				if (!utf8_valid(pcontent.get() + content_len + 1))
					utf8_filter(pcontent.get() + content_len + 1);
				vcard vcard;
				auto ret = vcard.load_single_from_str_move(pcontent.get() + content_len + 1);
				if (ret == ecSuccess &&
				    (pmsg = oxvcard_import(&vcard, pmime_enum->get_propids)) != nullptr) {
					pattachment->set_embedded_internal(pmsg);
					tmp_int32 = ATTACH_EMBEDDED_MSG;
					if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) == 0)
						pmime_enum->b_result = true;
					return;
				}
			}
			/* parsing as vcard failed */
			tmp_int32 = ATTACH_BY_VALUE;
			if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
				return;
			tmp_bin.cb = content_len;
			tmp_bin.pc = pcontent.get();
			pmime_enum->b_result = pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) == 0;
			return;
		}
	}
	if (strcasecmp(cttype, "message/rfc822") == 0 ||
	    (b_filename && strcasecmp(".eml", extension) == 0)) {
		auto rdlength = pmime->get_length();
		if (rdlength < 0) {
			mlog(LV_ERR, "%s:MIME::get_length:%u: unsuccessful", __func__, __LINE__);
			return;
		}
		size_t content_len = rdlength;
		std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(content_len));
		if (pcontent == nullptr)
			return;
		if (!pmime->read_content(pcontent.get(), &content_len))
			return;
		MAIL mail;
		if (mail.load_from_str_move(pcontent.get(), content_len)) {
			pattachment->proplist.erase(PR_ATTACH_LONG_FILENAME);
			pattachment->proplist.erase(PR_ATTACH_LONG_FILENAME_A);
			pattachment->proplist.erase(PR_ATTACH_EXTENSION);
			pattachment->proplist.erase(PR_ATTACH_EXTENSION_A);
			if (!b_description &&
			    mail.get_head()->get_field("Subject", tmp_buff, 256) &&
			    mime_string_to_utf8(pmime_enum->charset, tmp_buff,
			    file_name, std::size(file_name)) &&
			    pattachment->proplist.set(PR_DISPLAY_NAME, file_name) != 0)
				return;
			tmp_int32 = ATTACH_EMBEDDED_MSG;
			if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
				return;
			pmsg = oxcmail_import(pmime_enum->charset,
				pmime_enum->str_zone, &mail,
				pmime_enum->alloc, pmime_enum->get_propids);
			if (pmsg == nullptr)
				return;
			pattachment->set_embedded_internal(pmsg);
			pmime_enum->b_result = true;
			return;
		}
	}
	if (b_filename && strcasecmp(cttype, "message/external-body") == 0 &&
	    oxcmail_get_content_param(pmime, "access-type", tmp_buff, 32) &&
	    strcasecmp(tmp_buff, "anon-ftp") == 0 &&
	    oxcmail_get_content_param(pmime, "site", site_buff, 256) &&
	    oxcmail_get_content_param(pmime, "directory", dir_buff, 256)) {
		if (!oxcmail_get_content_param(pmime, "mode",
		    mode_buff, std::size(mode_buff)))
			mode_buff[0] = '\0';
		if (strcasecmp(mode_buff, "ascii") == 0)
			strcpy(mode_buff, ";type=a");
		else if (strcasecmp(mode_buff, "image") == 0)
			strcpy(mode_buff, ";type=i");
		tmp_bin.cb = gx_snprintf(tmp_buff, std::size(tmp_buff), "[InternetShortcut]\r\n"
					"URL=ftp://%s/%s/%s%s", site_buff, dir_buff,
					file_name, mode_buff);
		tmp_bin.pc = mode_buff;
		if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0)
			return;
		ptoken = strrchr(file_name, '.');
		if (ptoken != nullptr)
			strcpy(ptoken + 1, "URL");
		else
			strcat(file_name, ".URL");
		uint32_t tag = b_unifn ? PR_ATTACH_LONG_FILENAME : PR_ATTACH_LONG_FILENAME_A;
		if (pattachment->proplist.set(tag, file_name) == 0)
			pmime_enum->b_result = true;
		return;
	}
	tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0)
		return;
	if (strncasecmp(cttype, "text/", 5) == 0 &&
	    oxcmail_get_content_param(pmime, "charset", tmp_buff, 32)) {
		uint32_t tag = oxcmail_is_ascii(tmp_buff) ?
		               PidTagTextAttachmentCharset :
		               PidTagTextAttachmentCharset_A;
		if (pattachment->proplist.set(tag, tmp_buff) != 0)
			return;
	}
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		mlog(LV_ERR, "%s:MIME::get_length:%u: unsuccessful", __func__, __LINE__);
		return;
	}
	size_t content_len = rdlength;
	std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(content_len));
	if (pcontent == nullptr)
		return;
	if (!pmime->read_content(pcontent.get(), &content_len))
		return;
	tmp_bin.cb = content_len;
	tmp_bin.pc = pcontent.get();
	pmime_enum->b_result = pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) == 0;
}

static MESSAGE_CONTENT* oxcmail_parse_tnef(const MIME *pmime,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids)
{
	void *pcontent;
	MESSAGE_CONTENT *pmsg;
	
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		mlog(LV_ERR, "%s:MIME::get_length: unsuccessful", __func__);
		return nullptr;
	}
	size_t content_len = rdlength;
	pcontent = malloc(content_len);
	if (pcontent == nullptr)
		return NULL;
	if (!pmime->read_content(static_cast<char *>(pcontent), &content_len)) {
		free(pcontent);
		return NULL;
	}
	pmsg = tnef_deserialize(pcontent, content_len, alloc,
	       std::move(get_propids), oxcmail_username_to_entryid);
	free(pcontent);
	return pmsg;
}

static void oxcmail_replace_propid(TPROPVAL_ARRAY *pproplist,
    const propididmap_t &phash)
{
	int i;
	uint16_t propid;
	uint32_t proptag;
	
	for (i=0; i<pproplist->count; i++) {
		proptag = pproplist->ppropval[i].proptag;
		propid = PROP_ID(proptag);
		if (!is_nameprop_id(propid))
			continue;
		auto it = phash.find(propid);
		if (it == phash.cend() || it->second == 0) {
			pproplist->erase(proptag);
			i --;
			continue;
		}
		pproplist->ppropval[i].proptag =
			PROP_TAG(PROP_TYPE(pproplist->ppropval[i].proptag), it->second);
	}
}

static BOOL oxcmail_fetch_propname(MESSAGE_CONTENT *pmsg, namemap &phash,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids)
{
	PROPID_ARRAY propids;
	PROPID_ARRAY propids1;
	PROPNAME_ARRAY propnames;
	
	propids.count = 0;
	propids.ppropid = static_cast<uint16_t *>(alloc(sizeof(uint16_t) * phash.size()));
	if (propids.ppropid == nullptr)
		return FALSE;
	propnames.count = 0;
	propnames.ppropname = static_cast<PROPERTY_NAME *>(alloc(sizeof(PROPERTY_NAME) * phash.size()));
	if (propnames.ppropname == nullptr)
		return FALSE;
	for (const auto &pair : phash) {
		propids.ppropid[propids.count++] = pair.first;
		propnames.ppropname[propnames.count++] = pair.second;
	}
	if (!get_propids(&propnames, &propids1))
		return FALSE;
	propididmap_t phash1;
	for (size_t i = 0; i < propids.count; ++i) try {
		phash1.emplace(propids.ppropid[i], propids1.ppropid[i]);
	} catch (const std::bad_alloc &) {
	}
	oxcmail_replace_propid(&pmsg->proplist, phash1);
	if (pmsg->children.prcpts != nullptr)
		for (size_t i = 0; i < pmsg->children.prcpts->count; ++i)
			oxcmail_replace_propid(pmsg->children.prcpts->pparray[i], phash1);
	if (pmsg->children.pattachments != nullptr)
		for (size_t i = 0; i < pmsg->children.pattachments->count; ++i)
			oxcmail_replace_propid(
				&pmsg->children.pattachments->pplist[i]->proplist, phash1);
	return TRUE;
}

static void oxcmail_remove_flag_propties(
	MESSAGE_CONTENT *pmsg, GET_PROPIDS get_propids)
{
	PROPID_ARRAY propids;
	PROPERTY_NAME propname_buff[] = {
		{MNID_ID, PSETID_TASK, PidLidTaskDueDate},
		{MNID_ID, PSETID_TASK, PidLidTaskStartDate},
		{MNID_ID, PSETID_TASK, PidLidTaskDateCompleted},
	};
	const PROPNAME_ARRAY propnames = {std::size(propname_buff), propname_buff};
	
	pmsg->proplist.erase(PR_FLAG_COMPLETE_TIME);
	if (!get_propids(&propnames, &propids))
		return;
	pmsg->proplist.erase(PROP_TAG(PT_SYSTIME, propids.ppropid[0]));
	pmsg->proplist.erase(PROP_TAG(PT_SYSTIME, propids.ppropid[1]));
	pmsg->proplist.erase(PROP_TAG(PT_SYSTIME, propids.ppropid[2]));
}

static BOOL oxcmail_copy_message_proplist(
	MESSAGE_CONTENT *pmsg, MESSAGE_CONTENT *pmsg1)
{
	for (unsigned int i = 0; i < pmsg->proplist.count; ++i)
		if (!pmsg1->proplist.has(pmsg->proplist.ppropval[i].proptag) &&
		    pmsg1->proplist.set(pmsg->proplist.ppropval[i]) != 0)
			return FALSE;
	return TRUE;
}

static BOOL oxcmail_merge_message_attachments(
	MESSAGE_CONTENT *pmsg, MESSAGE_CONTENT *pmsg1)
{
	if (NULL == pmsg1->children.pattachments) {
		pmsg1->children.pattachments = pmsg->children.pattachments;
		pmsg->children.pattachments = NULL;
		return TRUE;
	}
	while (0 != pmsg->children.pattachments->count) {
		if (!pmsg1->children.pattachments->append_internal(pmsg->children.pattachments->pplist[0]))
			return FALSE;
		pmsg->children.pattachments->count --;
		if (pmsg->children.pattachments->count == 0)
			return TRUE;
		memmove(pmsg->children.pattachments->pplist,
			pmsg->children.pattachments->pplist + 1,
			sizeof(void*)*pmsg->children.pattachments->count);
	}
	return TRUE;
}

static bool oxcmail_enum_dsn_action_field(const char *tag,
    const char *value, void *pparam)
{
	int severity;
	
	if (strcasecmp("Action", tag) != 0)
		return true;
	if (strcasecmp("delivered", value) == 0)
		severity = 0;
	else if (strcasecmp("expanded", value) == 0)
		severity = 1;
	else if (strcasecmp("relayed", value) == 0)
		severity = 2;
	else if (strcasecmp("delayed", value) == 0)
		severity = 3;
	else if (strcasecmp("failed", value) == 0)
		severity = 4;
	else
		return true;
	if (severity > *static_cast<int *>(pparam))
		*static_cast<int *>(pparam) = severity;
	return true;
}

static bool oxcmail_enum_dsn_action_fields(const std::vector<dsn_field> &pfields, void *pparam)
{
	return DSN::enum_fields(pfields, oxcmail_enum_dsn_action_field, pparam);
}

static bool oxcmail_enum_dsn_rcpt_field(const char *tag,
    const char *value, void *pparam)
{
	auto pinfo = static_cast<DSN_FILEDS_INFO *>(pparam);
	if (0 == strcasecmp(tag, "Final-Recipient") &&
		0 == strncasecmp(value, "rfc822;", 7)) {
		gx_strlcpy(pinfo->final_recipient, &value[7], std::size(pinfo->final_recipient));
		HX_strrtrim(pinfo->final_recipient);
		HX_strltrim(pinfo->final_recipient);
	} else if (0 == strcasecmp(tag, "Action")) {
		if (strcasecmp("delivered", value) == 0)
			pinfo->action_severity = 0;
		else if (strcasecmp("expanded", value) == 0)
			pinfo->action_severity = 1;
		else if (strcasecmp("relayed", value) == 0)
			pinfo->action_severity = 2;
		else if (strcasecmp("delayed", value) == 0)
			pinfo->action_severity = 3;
		else if (strcasecmp("failed", value) == 0)
			pinfo->action_severity = 4;
	} else if (0 == strcasecmp(tag, "Status")) {
		pinfo->status = value;
	} else if (0 == strcasecmp(tag, "Diagnostic-Code")) {
		pinfo->diagnostic_code = value;
	} else if (0 == strcasecmp(tag, "Remote-MTA")) {
		gx_strlcpy(pinfo->remote_mta, value, std::size(pinfo->remote_mta));
	} else if (0 == strcasecmp(tag, "X-Supplementary-Info")) {
		pinfo->x_supplementary_info = value;
	} else if (0 == strcasecmp(tag, "X-Display-Name")) {
		pinfo->x_display_name = value;
	}
	return true;
}

static std::pair<uint32_t, uint32_t>
status_code_to_diag(unsigned int subject, unsigned int detail)
{
	static constexpr std::pair<uint32_t, uint32_t> noaction = {MAPI_DIAG_NO_DIAGNOSTIC, 0};
	/* cf. IANA list for SMTP Enhanced Status Codes */
	switch (subject) {
	case 1:
		switch (detail) {
		case 1: return {MAPI_DIAG_MAIL_RECIPIENT_UNKNOWN, 1};
		case 2: return {MAPI_DIAG_48, 0};
		case 3: return {MAPI_DIAG_MAIL_ADDRESS_INCORRECT, 0};
		case 4: return {MAPI_DIAG_OR_NAME_AMBIGUOUS, 0};
		case 6: return {MAPI_DIAG_MAIL_RECIPIENT_MOVED, 0};
		default: return {MAPI_DIAG_OR_NAME_UNRECOGNIZED, 0};
		}
		break;
	case 2:
		switch (detail) {
		case 2: [[fallthrough]];
		case 3: return {MAPI_DIAG_LENGTH_CONSTRAINT_VIOLATD, 0};
		case 4: return {MAPI_DIAG_EXPANSION_FAILED, 0};
		default: return {MAPI_DIAG_MAIL_REFUSED, 0};
		}
		break;
	case 3:
		switch (detail) {
		case 2: return noaction;
		case 3: [[fallthrough]];
		case 5: return {MAPI_DIAG_CRITICAL_FUNC_UNSUPPORTED, 0};
		case 4: return {MAPI_DIAG_LENGTH_CONSTRAINT_VIOLATD, 0};
		default: return {MAPI_DIAG_MAIL_REFUSED, 0};
		}
		break;
	case 4:
		switch (detail) {
		case 0: [[fallthrough]];
		case 4: return noaction;
		case 3: return {MAPI_DIAG_NO_DIAGNOSTIC, 6};
		case 6: [[fallthrough]];
		case 8: return {MAPI_DIAG_LOOP_DETECTED, 0};
		case 7: return {MAPI_DIAG_MAXIMUM_TIME_EXPIRED, 0};
		default: return {MAPI_DIAG_MTS_CONGESTED, 0};
		}
		break;
	case 5:
		switch (detail) {
		case 3: return {MAPI_DIAG_TOO_MANY_RECIPIENTS, 0};
		case 4: return {MAPI_DIAG_PARAMETERS_INVALID, 0};
		default: return {MAPI_DIAG_NO_BILATERAL_AGREEMENT, 0};
		}
		break;
	case 6:
		switch (detail) {
		case 2: return {MAPI_DIAG_PROHIBITED_TO_CONVERT, 0};
		case 3: return {MAPI_DIAG_IMPRACTICAL_TO_CONVERT, 0};
		case 4: return {MAPI_DIAG_MULTIPLE_INFO_LOSSES, 0};
		case 5: return {MAPI_DIAG_NO_DIAGNOSTIC, 2};
		default: return {MAPI_DIAG_CONTENT_TYPE_UNSUPPORTED, 0};
		}
		break;
	case 7:
		switch (detail) {
		case 1: return {MAPI_DIAG_SUBMISSION_PROHIBITED, 0};
		case 2: return {MAPI_DIAG_EXPANSION_PROHIBITED, 0};
		case 3: return {MAPI_DIAG_REASSIGNMENT_PROHIBITED, 0};
		default: return {MAPI_DIAG_SECURE_MESSAGING_ERROR, 0};
		}
		break;
	}
	return noaction;
}

static bool oxcmail_enum_dsn_rcpt_fields(const std::vector<dsn_field> &pfields, void *pparam)
{
	int kind;
	int tmp_len;
	char *ptoken1;
	char *ptoken2;
	BINARY tmp_bin;
	char essdn[1280];
	char tmp_buff[1280];
	DSN_FILEDS_INFO f_info;
	char display_name[512];
	
	auto pinfo = static_cast<const DSN_ENUM_INFO *>(pparam);
	f_info.final_recipient[0] = '\0';
	f_info.action_severity = -1;
	f_info.remote_mta[0] = '\0';
	f_info.status = NULL;
	f_info.diagnostic_code = NULL;
	f_info.x_supplementary_info = NULL;
	f_info.x_display_name = NULL;
	DSN::enum_fields(pfields, oxcmail_enum_dsn_rcpt_field, &f_info);
	if (f_info.action_severity < pinfo->action_severity ||
	    *f_info.final_recipient == '\0' || f_info.status == nullptr)
		return true;
	strncpy(tmp_buff, f_info.status, 1024);
	ptoken1 = strchr(tmp_buff, '.');
	if (ptoken1 == nullptr)
		return true;
	*ptoken1 = '\0';
	if (strlen(tmp_buff) != 1)
		return true;
	if (*tmp_buff != '2' && *tmp_buff != '4' && *tmp_buff != '5')
		return true;
	kind = *tmp_buff - '0';
	ptoken1 ++;
	ptoken2 = strchr(ptoken1, '.');
	if (ptoken2 == nullptr)
		return true;
	*ptoken2 = '\0';
	tmp_len = strlen(ptoken1);
	if (tmp_len < 1 || tmp_len > 3)
		return true;
	int subject = strtol(ptoken1, nullptr, 0);
	if (subject > 9 || subject < 0)
		subject = 0;
	ptoken2 ++;
	tmp_len = strlen(ptoken2);
	if (tmp_len < 1 || tmp_len > 3)
		return true;
	int detail = strtol(ptoken2, nullptr, 0);
	if (detail > 9 || detail < 0)
		detail = 0;
	auto pproplist = pinfo->prcpts->emplace();
	if (pproplist == nullptr)
		return false;
	uint32_t tmp_int32 = MAPI_TO;
	if (pproplist->set(PR_RECIPIENT_TYPE, &tmp_int32) != 0)
		return false;
	if (f_info.x_display_name != nullptr &&
	    strlen(f_info.x_display_name) < 256 &&
	    mime_string_to_utf8("utf-8", f_info.x_display_name, display_name,
	    std::size(display_name)) &&
	    pproplist->set(PR_DISPLAY_NAME, display_name) != 0)
		return false;
	auto dtypx = DT_MAILUSER;
	if (!oxcmail_username_to_essdn(f_info.final_recipient, essdn, &dtypx)) {
		essdn[0] = '\0';
		dtypx = DT_MAILUSER;
		tmp_bin.cb = snprintf(tmp_buff, std::size(tmp_buff), "SMTP:%s",
					f_info.final_recipient) + 1;
		HX_strupper(tmp_buff);
		if (pproplist->set(PR_ADDRTYPE, "SMTP") != 0 ||
		    pproplist->set(PR_EMAIL_ADDRESS, f_info.final_recipient) != 0)
			return false;
	} else {
		tmp_bin.cb = gx_snprintf(tmp_buff, std::size(tmp_buff), "EX:%s", essdn) + 1;
		if (pproplist->set(PR_ADDRTYPE, "EX") != 0 ||
		    pproplist->set(PR_EMAIL_ADDRESS, essdn) != 0)
			return false;
	}
	if (pproplist->set(PR_SMTP_ADDRESS, f_info.final_recipient) != 0)
		return false;
	tmp_bin.pc = tmp_buff;
	if (pproplist->set(PR_SEARCH_KEY, &tmp_bin) != 0)
		return false;
	tmp_bin.cb = 0;
	tmp_bin.pc = tmp_buff;
	if ('\0' == essdn[0]) {
		if (!oxcmail_username_to_oneoff(f_info.final_recipient,
		    display_name, &tmp_bin))
			return false;
	} else {
		if (!oxcmail_essdn_to_entryid(essdn, &tmp_bin))
			return false;
	}
	if (pproplist->set(PR_ENTRYID, &tmp_bin) != 0 ||
	    pproplist->set(PR_RECIPIENT_ENTRYID, &tmp_bin) != 0 ||
	    pproplist->set(PR_RECORD_KEY, &tmp_bin) != 0)
		return false;
	tmp_int32 = static_cast<uint32_t>(dtypx == DT_DISTLIST ? MAPI_DISTLIST : MAPI_MAILUSER);
	if (pproplist->set(PR_OBJECT_TYPE, &tmp_int32) != 0)
		return false;
	tmp_int32 = static_cast<uint32_t>(dtypx);
	if (pproplist->set(PR_DISPLAY_TYPE, &tmp_int32) != 0)
		return false;
	tmp_int32 = recipSendable;
	if (pproplist->set(PR_RECIPIENT_FLAGS, &tmp_int32) != 0)
		return false;
	if (f_info.remote_mta[0] != '\0' &&
	    pproplist->set(PR_DSN_REMOTE_MTA, f_info.remote_mta) != 0)
		return false;
	if (pproplist->set(PR_REPORT_TIME, &pinfo->submit_time) != 0)
		return false;
	if (NULL != f_info.x_supplementary_info) {
		if (pproplist->set(PR_SUPPLEMENTARY_INFO, f_info.x_supplementary_info) != 0)
			return false;
	} else {
		if (f_info.diagnostic_code == nullptr)
			snprintf(tmp_buff, 1024, "<%s #%s>",
				f_info.remote_mta, f_info.status);
		else
			snprintf(tmp_buff, 1024, "<%s #%s %s>",
				f_info.remote_mta, f_info.status,
				f_info.diagnostic_code);
		if (pproplist->set(PR_SUPPLEMENTARY_INFO, tmp_buff) != 0)
			return false;
	}
	uint32_t status_code = 100 * kind + 10 * subject + detail;
	if (pproplist->set(PR_NDR_STATUS_CODE, &status_code) != 0)
		return false;
	auto [diagnostic_code, reason_code] = status_code_to_diag(subject, detail);
	if (pproplist->set(PR_NDR_DIAG_CODE, &diagnostic_code) != 0 ||
	    pproplist->set(PR_NDR_REASON_CODE, &reason_code) != 0)
		return false;
	return true;
}

static bool oxcmail_enum_dsn_reporting_mta(const char *tag,
    const char *value, void *pparam)
{
	if (strcasecmp(tag, "Reporting-MTA") != 0)
		return true;
	return static_cast<MESSAGE_CONTENT *>(pparam)->proplist.set(PidTagReportingMessageTransferAgent, value) == 0;
}

static inline const char *om_actsev_to_mclass(unsigned int s)
{
	if (s == 0)
		return "REPORT.IPM.Note.DR";
	if (s == 1)
		return "REPORT.IPM.Note.Expanded.DR";
	if (s == 2)
		return "REPORT.IPM.Note.Relayed.DR";
	if (s == 3)
		return "REPORT.IPM.Note.Delayed.DR";
	if (s == 4)
		return "REPORT.IPM.Note.NDR";
	return nullptr;
}

static const MIME *oxcmail_parse_dsn(const MAIL *pmail, MESSAGE_CONTENT *pmsg)
{
	size_t content_len;
	DSN_ENUM_INFO dsn_info;
	char tmp_buff[256*1024];
	
	auto pmime = pmail->get_head();
	pmime = pmime->get_child();
	if (pmime == nullptr)
		return NULL;
	do {
		if (strcasecmp(pmime->content_type, "message/delivery-status") == 0)
			break;
	} while ((pmime = pmime->get_sibling()) != nullptr);
	if (pmime == nullptr)
		return NULL;
	auto mgl = pmime->get_length();
	if (mgl < 0 || static_cast<size_t>(mgl) > sizeof(tmp_buff))
		return NULL;
	content_len = sizeof(tmp_buff);
	if (!pmime->read_content(tmp_buff, &content_len))
		return NULL;

	DSN dsn;
	if (!dsn.load_from_str_move(tmp_buff, content_len))
		return NULL;
	dsn_info.action_severity = -1;
	dsn.enum_rcpts_fields(oxcmail_enum_dsn_action_fields,
		&dsn_info.action_severity);
	if (dsn_info.action_severity == -1)
		return NULL;
	dsn_info.prcpts = tarray_set_init();
	if (dsn_info.prcpts == nullptr)
		return NULL;
	auto ts = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (ts == nullptr)
		dsn_info.submit_time = rop_util_unix_to_nttime(time(NULL));
	else
		dsn_info.submit_time = *ts;
	if (!dsn.enum_rcpts_fields(oxcmail_enum_dsn_rcpt_fields, &dsn_info)) {
		tarray_set_free(dsn_info.prcpts);
		return NULL;
	}
	pmsg->set_rcpts_internal(dsn_info.prcpts);
	if (!dsn.enum_fields(*dsn.get_message_fields(),
	    oxcmail_enum_dsn_reporting_mta, pmsg))
		return NULL;
	auto as = om_actsev_to_mclass(dsn_info.action_severity);
	if (as != nullptr) {
		gx_strlcpy(tmp_buff, as, std::size(tmp_buff));
		if (pmsg->proplist.set(PR_MESSAGE_CLASS, tmp_buff) != 0)
			return NULL;
	}
	return pmime;
}

static bool oxcmail_enum_mdn(const char *tag,
	const char *value, void *pparam)
{
	size_t len;
	char *ptoken;
	BINARY tmp_bin;
	char tmp_buff[1024];
	auto mcparam = static_cast<MESSAGE_CONTENT *>(pparam);
	
	if (0 == strcasecmp(tag, "Original-Recipient")) {
		if (strncasecmp(value, "rfc822;", 7) == 0 &&
		    mcparam->proplist.set(PR_ORIGINAL_DISPLAY_TO, value + 7) != 0)
			return false;
	} else if (0 == strcasecmp(tag, "Final-Recipient")) {
		if (strncasecmp(value, "rfc822;", 7) == 0 &&
		    !static_cast<MESSAGE_CONTENT *>(pparam)->proplist.has(PR_ORIGINAL_DISPLAY_TO))
			return mcparam->proplist.set(PR_ORIGINAL_DISPLAY_TO, value + 7) == 0;
	} else if (0 == strcasecmp(tag, "Disposition")) {
		auto ptoken2 = strchr(value, ';');
		if (ptoken2 == nullptr)
			return true;
		++ptoken2;
		gx_strlcpy(tmp_buff, ptoken2, std::size(tmp_buff));
		HX_strltrim(tmp_buff);
		ptoken = strchr(tmp_buff, '/');
		if (ptoken != nullptr)
			*ptoken = '\0';
		if (strcasecmp(tmp_buff, "displayed") == 0 ||
		    strcasecmp(tmp_buff, "dispatched") == 0 ||
		    strcasecmp(tmp_buff, "processed") == 0)
			strcpy(tmp_buff, "REPORT.IPM.Note.IPNRN");
		else if (0 == strcasecmp(tmp_buff, "deleted") ||
		    strcasecmp(tmp_buff, "denied") == 0 ||
		    strcasecmp(tmp_buff, "failed") == 0)
			snprintf(tmp_buff, std::size(tmp_buff), "REPORT.IPM.Note.IPNNRN");
		else
			return true;
		return mcparam->proplist.set(PR_MESSAGE_CLASS, tmp_buff) == 0 &&
		       mcparam->proplist.set(PR_REPORT_TEXT, value) == 0;
	} else if (0 == strcasecmp(tag, "X-MSExch-Correlation-Key")) {
		len = strlen(value);
		if (len <= 1024 && decode64(value, len, tmp_buff,
		    std::size(tmp_buff), &len) == 0) {
			tmp_bin.pc = tmp_buff;
			tmp_bin.cb = len;
			return mcparam->proplist.set(PR_PARENT_KEY, &tmp_bin) == 0;
		}
	} else if (0 == strcasecmp(tag, "Original-Message-ID")) {
		return mcparam->proplist.set(PidTagOriginalMessageId, value) == 0 &&
		       mcparam->proplist.set(PR_INTERNET_REFERENCES, value) == 0;
	} else if (0 == strcasecmp(tag, "X-Display-Name")) {
		if (mime_string_to_utf8("utf-8", value, tmp_buff,
		    std::size(tmp_buff)))
			return mcparam->proplist.set(PR_DISPLAY_NAME, tmp_buff) == 0;
		return mcparam->proplist.set(PR_DISPLAY_NAME_A, value) == 0;
	}
	return true;
}

static const MIME *oxcmail_parse_mdn(const MAIL *pmail, MESSAGE_CONTENT *pmsg)
{
	size_t content_len;
	char tmp_buff[256*1024];
	
	auto pmime = pmail->get_head();
	if (strcasecmp(pmime->content_type, "message/disposition-notification") != 0) {
		pmime = pmime->get_child();
		if (pmime == nullptr)
			return NULL;
		do {
			if (strcasecmp(pmime->content_type, "message/disposition-notification") == 0)
				break;
		} while ((pmime = pmime->get_sibling()) != nullptr);
	}
	if (pmime == nullptr)
		return NULL;
	auto mgl = pmime->get_length();
	if (mgl < 0 || static_cast<size_t>(mgl) > sizeof(tmp_buff))
		return NULL;
	content_len = sizeof(tmp_buff);
	if (!pmime->read_content(tmp_buff, &content_len))
		return NULL;

	DSN dsn;
	if (!dsn.load_from_str_move(tmp_buff, content_len) ||
	    !dsn.enum_fields(*dsn.get_message_fields(), oxcmail_enum_mdn, pmsg))
		return NULL;
	dsn.clear();
	auto ts = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (pmsg->proplist.set(PR_ORIGINAL_DELIVERY_TIME, ts) != 0 ||
	    pmsg->proplist.set(PR_RECEIPT_TIME, ts) != 0)
		return NULL;
	for (size_t i = 0; i < pmsg->children.prcpts->count; ++i)
		if (pmsg->children.prcpts->pparray[i]->set(PR_REPORT_TIME, ts) != 0)
			return NULL;
	return pmime;
}

static BOOL oxcmail_parse_encrypted(const MIME *phead, uint16_t *plast_propid,
    namemap &phash, MESSAGE_CONTENT *pmsg)
{
	char tmp_buff[1024];
	
	if (!phead->get_field("Content-Type", tmp_buff, std::size(tmp_buff)))
		return FALSE;
	PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS, 0, deconst("Content-Type")};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0 ||
	    pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), tmp_buff) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_smime_message(const MAIL *pmail, MESSAGE_CONTENT *pmsg) try
{
	size_t offset;
	BINARY tmp_bin;
	uint32_t tmp_int32;
	ATTACHMENT_CONTENT *pattachment;
	
	auto phead = pmail->get_head();
	if (phead == nullptr)
		return FALSE;
	auto rdlength = phead->get_length();
	if (rdlength < 0) {
		mlog(LV_ERR, "%s:MIME::get_length: unsuccessful", __func__);
		return false;
	}
	size_t content_len = rdlength;
	auto pcontent = std::make_unique<char[]>(content_len + 1024);
	auto content_type = phead->content_type;
	if (0 == strcasecmp(content_type, "multipart/signed")) {
		strcpy(pcontent.get(), "Content-Type: ");
		offset = 14;
		if (!phead->get_field("Content-Type", &pcontent[offset], 1024 - offset))
			return FALSE;
		offset += strlen(&pcontent[offset]);
		strcpy(&pcontent[offset], "\r\n\r\n");
		offset += 4;
		if (!phead->read_content(&pcontent[offset], &content_len))
			return FALSE;
		offset += content_len;
	} else {
		if (!phead->read_content(pcontent.get(), &content_len))
			return FALSE;
		offset = content_len;
	}
	pattachment = attachment_content_init();
	if (pattachment == nullptr)
		return FALSE;
	if (!pmsg->children.pattachments->append_internal(pattachment)) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	tmp_bin.cb = offset;
	tmp_bin.pc = pcontent.get();
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0)
		return FALSE;
	tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0 ||
	    pattachment->proplist.set(PR_ATTACH_MIME_TAG, content_type) != 0 ||
	    pattachment->proplist.set(PR_ATTACH_EXTENSION, ".p7m") != 0 ||
	    pattachment->proplist.set(PR_ATTACH_FILENAME, "SMIME.p7m") != 0 ||
	    pattachment->proplist.set(PR_ATTACH_LONG_FILENAME, "SMIME.p7m") != 0 ||
	    pattachment->proplist.set(PR_DISPLAY_NAME, "SMIME.p7m") != 0)
		return FALSE;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1972: ENOMEM");
	return false;
}

static BOOL oxcmail_try_assign_propval(TPROPVAL_ARRAY *pproplist,
    uint32_t pr_normal, uint32_t pr_representing)
{
	if (pproplist->has(pr_normal))
		return TRUE;
	auto pvalue = pproplist->getval(pr_representing);
	if (pvalue == nullptr)
		return TRUE;
	return pproplist->set(pr_normal, pvalue) == 0 ? TRUE : false;
}

static bool atx_is_hidden(const TPROPVAL_ARRAY &props)
{
	auto x = props.get<const uint32_t>(PR_ATTACH_FLAGS);
	if (x != nullptr && (*x & ATT_MHTML_REF))
		return true;
	auto y = props.get<const uint8_t>(PR_ATTACHMENT_HIDDEN);
	if (y != nullptr && *y != 0)
		return true;
	return false;
}

static bool atxlist_all_hidden(const ATTACHMENT_LIST *atl)
{
	if (atl == nullptr || atl->count == 0)
		return false;
	for (size_t i = 0; i < atl->count; ++i)
		if (!atx_is_hidden(atl->pplist[i]->proplist))
			return false;
	return true;
}

static inline bool tnef_vfy_get_field(const MIME *head, char *buf, size_t z)
{
#ifdef VERIFY_TNEF_CORRELATOR
	return head->get_field("X-MS-TNEF-Correlator", buf, z);
#else
	return true;
#endif
}

static inline bool tnef_vfy_check_key(MESSAGE_CONTENT *msg, const char *xtnefcorrel)
{
#ifdef VERIFY_TNEF_CORRELATOR
	auto key = msg->proplist.get<const BINARY>(PR_TNEF_CORRELATION_KEY);
	return key != nullptr && strncmp(key->pb, xtnefcorrel, key->cb) == 0);
#else
	return true;
#endif
}

static bool smime_clearsigned(const char *head_ct, const MIME *head, char (&buf)[256])
{
	if (strcasecmp(head_ct, "multipart/signed") != 0)
		return false;
	if (!oxcmail_get_content_param(head, "protocol", buf, std::size(buf)))
		return false;
	return strcasecmp(buf, "application/pkcs7-signature") == 0 ||
	       strcasecmp(buf, "application/x-pkcs7-signature") == 0;
}

static void select_parts(const MIME *part, MIME_ENUM_PARAM &info)
{
	for (unsigned int i = 0; i < MAXIMUM_SEARCHING_DEPTH; ++i) {
		auto child = part->get_child();
		if (child == nullptr)
			break;
		part = child;
	}
	auto parent = part->get_parent();
	bool alt = false;
	if (parent != nullptr && strcasecmp(parent->content_type,
	    "multipart/alternative") == 0)
		alt = true;
	do {
		auto cttype = part->content_type;
		if (strcasecmp(cttype, "text/plain") == 0 &&
		    info.pplain == nullptr)
			info.pplain = part;
		if (strcasecmp(cttype, "text/html") == 0 &&
		    info.phtml == nullptr)
			info.phtml = part;
		if (strcasecmp(cttype, "text/enriched") == 0 &&
		    info.penriched == nullptr)
			info.penriched = part;
		if (strcasecmp(cttype, "text/calendar") == 0 &&
		    info.pcalendar == nullptr)
			info.pcalendar = part;
		if (!alt || part->mime_type != mime_type::multiple)
			continue;
		for (auto child = part->get_child(); child != nullptr;
		     child = child->get_sibling()) {
			cttype = child->content_type;
			if (strcasecmp(cttype, "text/plain") == 0 &&
			    info.pplain == nullptr)
				info.pplain = child;
			if (strcasecmp(cttype, "text/html") == 0 &&
			    info.phtml == nullptr)
				info.phtml = child;
			if (strcasecmp(cttype, "text/enriched") == 0 &&
			    info.penriched == nullptr)
				info.penriched = child;
			if (strcasecmp(cttype, "text/calendar") == 0 &&
			    info.pcalendar == nullptr)
				info.pcalendar = child;
		}
	} while (alt && (part = part->get_sibling()) != nullptr);
}

MESSAGE_CONTENT *oxcmail_import(const char *charset, const char *str_zone,
    const MAIL *pmail, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids) try
{
	namemap phash;
	MIME_ENUM_PARAM mime_enum{phash};
	FIELD_ENUM_PARAM field_param{phash};
	
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> pmsg(message_content_init());
	if (pmsg == nullptr)
		return NULL;
	/* set default message class */
	if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note") != 0)
		return NULL;
	auto prcpts = tarray_set_init();
	if (prcpts == nullptr)
		return NULL;
	pmsg->set_rcpts_internal(prcpts);

	char default_charset[64];
	if (!pmail->get_charset(default_charset))
		gx_strlcpy(default_charset, charset, std::size(default_charset));
	field_param.alloc = alloc;
	field_param.pmail = pmail;
	field_param.pmsg = pmsg.get();
	field_param.charset = default_charset;
	field_param.last_propid = 0x8000;
	field_param.b_flag_del = false;
	const auto phead = pmail->get_head();
	if (phead == nullptr)
		return NULL;

	char tmp_buff[256];
	field_param.b_classified = phead->get_field("X-Microsoft-Classified", tmp_buff, 16);
	if (!phead->enum_field(oxcmail_enum_mail_head, &field_param))
		return NULL;
	if (!pmsg->proplist.has(PR_SENDER_NAME) &&
	    !pmsg->proplist.has(PR_SENDER_SMTP_ADDRESS)) {
		if (!oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_NAME, PR_SENT_REPRESENTING_NAME) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_SMTP_ADDRESS, PR_SENT_REPRESENTING_SMTP_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_ADDRTYPE, PR_SENT_REPRESENTING_ADDRTYPE) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_EMAIL_ADDRESS, PR_SENT_REPRESENTING_EMAIL_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_SEARCH_KEY, PR_SENT_REPRESENTING_SEARCH_KEY) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_ENTRYID, PR_SENT_REPRESENTING_ENTRYID))
			return NULL;
	} else if (!pmsg->proplist.has(PR_SENT_REPRESENTING_NAME) &&
	    !pmsg->proplist.has(PR_SENT_REPRESENTING_SMTP_ADDRESS)) {
		if (!oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_NAME, PR_SENDER_NAME) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_SENDER_SMTP_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_ADDRTYPE, PR_SENDER_ADDRTYPE) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENDER_EMAIL_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_SEARCH_KEY, PR_SENDER_SEARCH_KEY) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_ENTRYID, PR_SENDER_ENTRYID))
			return NULL;
	}
	if (!pmsg->proplist.has(PR_IMPORTANCE)) {
		uint32_t tmp_int32 = IMPORTANCE_NORMAL;
		if (pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != 0)
			return NULL;
	}
	if (!pmsg->proplist.has(PR_SENSITIVITY)) {
		uint32_t tmp_int32 = SENSITIVITY_NONE;
		if (pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != 0)
			return NULL;
	}
	if (!oxcmail_parse_transport_message_header(phead, &pmsg->proplist))
		return NULL;
	auto ts = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (ts == nullptr) {
		mime_enum.nttime_stamp = rop_util_unix_to_nttime(time(NULL));
		if (pmsg->proplist.set(PR_CLIENT_SUBMIT_TIME,
		    &mime_enum.nttime_stamp) != 0)
			return NULL;
	} else {
		mime_enum.nttime_stamp = *ts;
	}
	if (pmsg->proplist.set(PR_CREATION_TIME, &mime_enum.nttime_stamp) != 0 ||
	    pmsg->proplist.set(PR_LAST_MODIFICATION_TIME, &mime_enum.nttime_stamp) != 0)
		return NULL;

	auto head_ct = phead->content_type;
	if (strcasecmp(head_ct, "application/ms-tnef") == 0 &&
	    tnef_vfy_get_field(phead, tmp_buff, std::size(tmp_buff))) {
		std::unique_ptr<message_content, mc_delete> pmsg1(oxcmail_parse_tnef(phead, alloc, get_propids));
		if (pmsg1 != nullptr && tnef_vfy_check_key(pmsg1.get(), tmp_buff)) {
			if (!oxcmail_fetch_propname(pmsg.get(), phash, alloc, get_propids))
				return NULL;
			if (!oxcmail_copy_message_proplist(pmsg.get(), pmsg1.get()))
				return NULL;
			std::swap(pmsg->children.prcpts, pmsg1->children.prcpts);
			if (field_param.b_flag_del)
				oxcmail_remove_flag_propties(pmsg1.get(), get_propids);
			return pmsg1.release();
		}
	}
	if (strcasecmp(head_ct, "multipart/report") == 0 &&
	    oxcmail_get_content_param(phead, "report-type", tmp_buff, 128) &&
	    strcasecmp("delivery-status", tmp_buff) == 0)
		mime_enum.preport = oxcmail_parse_dsn(pmail, pmsg.get());
	if ((strcasecmp(head_ct, "multipart/report") == 0 &&
	    oxcmail_get_content_param(phead, "report-type", tmp_buff, 128) &&
	    strcasecmp("disposition-notification", tmp_buff) == 0) ||
	    strcasecmp("message/disposition-notification", head_ct) == 0)
		mime_enum.preport = oxcmail_parse_mdn(pmail, pmsg.get());

	bool b_smime = false;
	if (strcasecmp(head_ct, "multipart/mixed") == 0) {
		const MIME *pmime = nullptr, *pmime1 = nullptr;
		if (phead->get_children_num() == 2 &&
		    (pmime = phead->get_child()) != nullptr &&
		    (pmime1 = pmime->get_sibling()) != nullptr &&
		    strcasecmp(pmime->content_type, "text/plain") == 0 &&
		    strcasecmp(pmime1->content_type, "application/ms-tnef") == 0 &&
		    tnef_vfy_get_field(phead, tmp_buff, std::size(tmp_buff))) {
			std::unique_ptr<message_content, mc_delete> pmsg1(oxcmail_parse_tnef(pmime1, alloc, get_propids));
			if (pmsg1 != nullptr && tnef_vfy_check_key(pmsg1.get(), tmp_buff)) {
				if (!oxcmail_parse_message_body(default_charset, pmime, &pmsg->proplist) ||
				    !oxcmail_fetch_propname(pmsg.get(), phash, alloc, get_propids))
					return NULL;
				if (!oxcmail_copy_message_proplist(pmsg.get(), pmsg1.get()))
					return NULL;
				std::swap(pmsg->children.prcpts, pmsg1->children.prcpts);
				if (field_param.b_flag_del)
					oxcmail_remove_flag_propties(pmsg1.get(), get_propids);
				return pmsg1.release();
			}
		}
	} else if (smime_clearsigned(head_ct, phead, tmp_buff)) {
		if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME.MultipartSigned") != 0)
			return NULL;
		b_smime = true;
	} else if (strcasecmp(head_ct, "application/pkcs7-mime") == 0 ||
	    strcasecmp(head_ct, "application/x-pkcs7-mime") == 0) {
		if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME") != 0 ||
		    !oxcmail_parse_encrypted(phead, &field_param.last_propid, phash, pmsg.get()))
			return NULL;
		b_smime = true;
	}
	mime_enum.b_result = true;
	mime_enum.attach_id = 0;
	mime_enum.charset = default_charset;
	mime_enum.str_zone = str_zone;
	mime_enum.get_propids = get_propids;
	mime_enum.alloc = alloc;
	mime_enum.pmsg = pmsg.get();
	mime_enum.phash = phash;
	select_parts(phead, mime_enum);

	if (mime_enum.pplain != nullptr &&
	    !oxcmail_parse_message_body(default_charset,
	    mime_enum.pplain, &pmsg->proplist))
		return NULL;
	if (NULL != mime_enum.phtml) {
		if (!oxcmail_parse_message_body(default_charset,
		    mime_enum.phtml, &pmsg->proplist))
			return NULL;
	} else if (NULL != mime_enum.penriched) {
		if (!oxcmail_parse_message_body(default_charset,
		    mime_enum.penriched, &pmsg->proplist))
			return NULL;
	}
	size_t content_len = 0;
	std::unique_ptr<message_content, mc_delete> pmsg1; /* ical */
	if (NULL != mime_enum.pcalendar) {
		auto rdlength = mime_enum.pcalendar->get_length();
		if (rdlength < 0) {
			mlog(LV_ERR, "%s:MIME::get_length: unsuccessful", __func__);
			return nullptr;
		}
		content_len = rdlength;
		auto contoutsize = 3 * content_len + 2;
		std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(contoutsize));
		if (pcontent == nullptr)
			return NULL;
		if (!mime_enum.pcalendar->read_content(pcontent.get(), &content_len))
			return NULL;
		pcontent[content_len] = '\0';
		char mime_charset[64];
		if (!oxcmail_get_content_param(mime_enum.pcalendar, "charset",
		    mime_charset, std::size(mime_charset)))
			gx_strlcpy(mime_charset, !utf8_valid(pcontent.get()) ?
				default_charset : "utf-8", std::size(mime_charset));
		if (!string_to_utf8(mime_charset, pcontent.get(),
		    &pcontent[content_len+1], contoutsize - content_len - 1)) {
			mime_enum.pcalendar = NULL;
		} else {
			if (!utf8_valid(&pcontent[content_len+1]))
				utf8_filter(&pcontent[content_len+1]);
			ICAL ical;
			if (!ical.load_from_str_move(&pcontent[content_len+1])) {
				mime_enum.pcalendar = nullptr;
			} else {
				pmsg1.reset(oxcical_import_single(str_zone, ical, alloc,
				        get_propids, oxcmail_username_to_entryid).release());
				if (pmsg1 == nullptr)
					mime_enum.pcalendar = NULL;
			}
		}
	}
	assert((mime_enum.pcalendar != nullptr) == (pmsg1 != nullptr)); /* (pcalendar ^ pmsg1) == 0 */
	
	auto pattachments = attachment_list_init();
	if (pattachments == nullptr)
		return NULL;
	pmsg->set_attachments_internal(pattachments);
	if (b_smime) {
		if (!oxcmail_parse_smime_message(pmail, pmsg.get()))
			return NULL;
	} else {
		mime_enum.last_propid = field_param.last_propid;
		pmail->enum_mime(oxcmail_enum_attachment, &mime_enum);
		if (!mime_enum.b_result)
			return NULL;
	}
	if (!oxcmail_fetch_propname(pmsg.get(), phash, alloc, get_propids))
		return NULL;
	if (NULL != mime_enum.pcalendar) {
		if (!pmsg1->proplist.has(PR_MESSAGE_CLASS)) {
			/* multiple calendar objects in attachment list */
			if (pmsg1->children.pattachments != nullptr &&
			    !oxcmail_merge_message_attachments(pmsg1.get(), pmsg.get()))
				return NULL;
			pmsg1.reset();
		} else {
			if (!oxcmail_copy_message_proplist(pmsg.get(), pmsg1.get()) ||
			    !oxcmail_merge_message_attachments(pmsg.get(), pmsg1.get()))
				return NULL;
			pmsg = std::move(pmsg1);
			/* calendar message object can not be displayed
				correctly without PidTagRtfCompressed convert
				PidTagHtml to PidTagRtfCompressed */
			auto phtml_bin = pmsg->proplist.get<const BINARY>(PR_HTML);
			if (NULL != phtml_bin) {
				auto num = pmsg->proplist.get<const uint32_t>(PR_INTERNET_CPID);
				cpid_t cpid = num == nullptr ? CP_UTF8 : static_cast<cpid_t>(*num);
				char *rtfout = nullptr;
				if (html_to_rtf(phtml_bin->pv, phtml_bin->cb, cpid,
				    &rtfout, &content_len) == ecSuccess) {
					auto bv = rtfcp_compress(rtfout, content_len);
					free(rtfout);
					if (bv != nullptr) {
						pmsg->proplist.set(PR_RTF_COMPRESSED, bv);
						rop_util_free_binary(bv);
					}
				}
			}
		}
	}
	if (!pmsg->proplist.has(PR_BODY_W) && !pmsg->proplist.has(PR_BODY_A)) {
		auto phtml_bin = pmsg->proplist.get<const BINARY>(PR_HTML);
		if (NULL != phtml_bin) {
			auto num = pmsg->proplist.get<const uint32_t>(PR_INTERNET_CPID);
			auto cpid = num == nullptr ? CP_UTF8 : static_cast<cpid_t>(*num);
			std::string plainbuf;
			auto ret = html_to_plain(phtml_bin->pc, phtml_bin->cb, plainbuf);
			if (ret < 0)
				return NULL;
			if (ret == CP_UTF8) {
				if (pmsg->proplist.set(PR_BODY_W, plainbuf.data()) != 0)
					return nullptr;
			} else {
				auto z = 3 * plainbuf.size() + 1;
				auto s = static_cast<char *>(alloc(z));
				if (s == nullptr)
					return NULL;
				auto encoding = cpid_to_cset(cpid);
				if (encoding == nullptr)
					encoding = "windows-1252";
				if (string_to_utf8(encoding, plainbuf.c_str(),
				    s, z) && utf8_valid(s))
					pmsg->proplist.set(PR_BODY_W, s);
			}
		}
	}
	if (!pmsg->proplist.has(PR_HTML)) {
		auto s = pmsg->proplist.get<const char>(PR_BODY);
		if (s != nullptr) {
			auto phtml_bin = static_cast<BINARY *>(alloc(sizeof(BINARY)));
			if (phtml_bin == nullptr)
				return NULL;
			phtml_bin->pc = plain_to_html(s);
			if (phtml_bin->pc == nullptr)
				return NULL;
			phtml_bin->cb = strlen(phtml_bin->pc);
			pmsg->proplist.set(PR_HTML, phtml_bin);
			uint32_t tmp_int32 = CP_UTF8;
			if (pmsg->proplist.set(PR_INTERNET_CPID, &tmp_int32) != 0)
				return nullptr;
		}
	}

	if (atxlist_all_hidden(pmsg->children.pattachments)) {
		/*
		 * You know the data model sucks when you cannot determine
		 * all-hidden in O(1) without creating redundant information
		 * like this property.
		 */
		PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidSmartNoAttach};
		const PROPNAME_ARRAY propnames = {1, &propname};
		PROPID_ARRAY propids;
		if (!get_propids(&propnames, &propids))
			return nullptr;
		uint8_t tmp_byte = 1;
		if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]), &tmp_byte) != 0)
			return nullptr;
	}
	if (field_param.b_flag_del)
		oxcmail_remove_flag_propties(pmsg.get(), get_propids);
	return pmsg.release();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2182: ENOMEM");
	return nullptr;
}

static size_t oxcmail_encode_mime_string(const char *charset,
    const char *pstring, char *pout_string, size_t max_length)
{
	size_t offset;
	size_t base64_len;
	auto alloc_size = worst_encoding_overhead(strlen(pstring)) + 1;
	std::unique_ptr<char[]> tmp_buff;
	try {
		tmp_buff = std::make_unique<char[]>(alloc_size);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1539: ENOMEM");
		return 0;
	}

	if (oxcmail_is_ascii(pstring) && !oxcmail_check_crlf(pstring)) {
		auto string_len = strlen(pstring);
		if (string_len >= max_length)
			return 0;
		memcpy(pout_string, pstring, string_len + 1);
		return string_len;
	}
	if (string_from_utf8(charset, pstring, tmp_buff.get(), alloc_size)) {
		auto string_len = strlen(tmp_buff.get());
		offset = std::max(0, gx_snprintf(pout_string,
		         max_length, "=?%s?B?", charset));
		if (encode64(tmp_buff.get(), string_len, pout_string + offset,
		    max_length - offset, &base64_len) != 0)
			return 0;
	} else {
		auto string_len = strlen(pstring);
		offset = std::max(0, gx_snprintf(pout_string,
		         max_length, "=?utf-8?B?"));
		if (encode64(pstring, string_len, pout_string + offset,
		    max_length - offset, &base64_len) != 0)
			return 0;
	}
	offset += base64_len;
	if (offset + 3 >= max_length)
		return 0;
	strcpy(&pout_string[offset], "?=");
	return offset + 2;
}

BOOL oxcmail_get_smtp_address(const TPROPVAL_ARRAY &props,
    const addr_tags *ptags, ENTRYID_TO_USERNAME ey2u, ESSDN_TO_USERNAME es2u,
    EXT_BUFFER_ALLOC alloc, char *username, size_t ulen)
{
	auto pproplist = &props;
	const auto &tags = ptags != nullptr ? *ptags : tags_self;
	auto s = pproplist->get<const char>(tags.pr_smtpaddr);
	if (s != nullptr) {
		gx_strlcpy(username, s, ulen);
		return TRUE;
	}
	s = pproplist->get<char>(tags.pr_addrtype);
	if (s != nullptr) {
		if (strcasecmp(s, "SMTP") == 0) {
			s = pproplist->get<char>(tags.pr_emaddr);
			if (s != nullptr) {
				gx_strlcpy(username, s, ulen);
				return TRUE;
			}
		} else if (strcasecmp(s, "EX") == 0) {
			s = pproplist->get<char>(tags.pr_emaddr);
			if (s != nullptr && es2u(s, username, ulen))
				return TRUE;
		}
	}
	auto pvalue = pproplist->get<const BINARY>(tags.pr_entryid);
	if (pvalue == nullptr)
		return false;
	return ey2u(pvalue, alloc, username, ulen);
}

/**
 * Only useful for DSN generation.
 */
static bool oxcmail_get_rcpt_address(const TPROPVAL_ARRAY &props,
    EXT_BUFFER_ALLOC alloc, const addr_tags &tags,
    char *username, size_t ulen)
{
	auto em = props.get<const char>(tags.pr_smtpaddr);
	if (em != nullptr) {
		snprintf(username, ulen, "rfc822;%s", em);
		return true;
	}
	auto at = props.get<char>(tags.pr_addrtype);
	if (at != nullptr) {
		em = props.get<char>(tags.pr_emaddr);
		if (strcasecmp(at, "SMTP") == 0) {
			if (em != nullptr) {
				snprintf(username, ulen, "rfc822;%s", znul(em));
				return true;
			}
		} else if (strcasecmp(at, "EX") == 0) {
			if (em != nullptr) {
				auto ok = oxcmail_essdn_to_username(em, &username[7],
				          ulen > 8 ? ulen - 7 : 0);
				if (ok) {
					memcpy(username, "rfc822;", 7);
					username[7] = '\0';
					return true;
				}
			}
		} else {
			snprintf(username, ulen, "%s;%s", at, znul(em));
			return true;
		}
	}
	auto v = props.get<const BINARY>(tags.pr_entryid);
	if (v != nullptr) {
		auto ok = oxcmail_entryid_to_username(v, alloc, &username[7],
			  ulen > 8 ? ulen - 7 : 0);
		if (ok) {
			memcpy(username, "rfc822;", 7);
			username[7] = '\0';
			return true;
		}
	}
	if (at != nullptr) {
		snprintf(username, ulen, "%s;%s", at, znul(em));
		return true;
	}
	return false;
}

static BOOL oxcmail_export_addresses(const char *charset, TARRAY_SET *prcpts,
    uint32_t rcpt_type, EXT_BUFFER_ALLOC alloc, char *field, size_t fdsize)
{
	size_t offset = 0;
	char username[UADDR_SIZE];
	
	for (size_t i = 0; i < prcpts->count; ++i) {
		auto prcpt = prcpts->pparray[i];
		auto pvalue = prcpt->get<uint32_t>(PR_RECIPIENT_TYPE);
		if (pvalue == nullptr || *pvalue != rcpt_type)
			continue;
		if (0 != offset) {
			if (offset + 5 >= fdsize)
				return false;
			strcpy(&field[offset], ",\r\n\t");
			offset += 4;
		}
		auto pdisplay_name = prcpt->get<char>(PR_DISPLAY_NAME);
		if (NULL != pdisplay_name) {
			field[offset++] = '"';
			if (offset >= fdsize)
				return FALSE;
			auto tmp_len = oxcmail_encode_mime_string(
				charset, pdisplay_name, field + offset,
			               fdsize - offset);
			if (tmp_len == 0)
				return FALSE;
			offset += tmp_len;
			field[offset++] = '"';
			if (offset >= fdsize)
				return FALSE;
		}
		if (oxcmail_get_smtp_address(*prcpt, &tags_self,
		    oxcmail_entryid_to_username, oxcmail_essdn_to_username,
		    alloc, username, std::size(username)))
			offset += std::max(0, gx_snprintf(field + offset, fdsize - offset,
			          pdisplay_name != nullptr ? " <%s>" : "<%s>", username));
	}
	if (0 == offset || offset >= fdsize)
		return FALSE;
	return TRUE;
}

static BOOL oxcmail_export_reply_to(const MESSAGE_CONTENT *pmsg,
    const char *charset, EXT_BUFFER_ALLOC alloc, char *field)
{
	size_t fieldmax = MIME_FIELD_LEN;
	EXT_PULL ext_pull;
	BINARY_ARRAY address_array;
	
	auto pbin = pmsg->proplist.get<BINARY>(PR_REPLY_RECIPIENT_ENTRIES);
	if (pbin == nullptr)
		return FALSE;
	/*
	 * PR_REPLY_RECIPIENT_NAMES is semicolon-separated, but there is no way
	 * to distinguish between semicolon as a separator and semicolon as
	 * part of a name. So we ignore that property altogether.
	 */
	ext_pull.init(pbin->pb, pbin->cb, alloc, EXT_FLAG_WCOUNT);
	if (ext_pull.g_flatentry_a(&address_array) != EXT_ERR_SUCCESS)
		return FALSE;
	size_t offset = 0;
	for (size_t i = 0; i < address_array.count; ++i) {
		if (0 != offset) {
			if (offset + 3 >= fieldmax)
				return false;
			strcpy(&field[offset], ", ");
			offset += 2;
		}
		EXT_PULL ep2;
		ONEOFF_ENTRYID oo;
		ep2.init(address_array.pbin[i].pb, address_array.pbin[i].cb, alloc, EXT_FLAG_UTF16);
		if (ep2.g_oneoff_eid(&oo) != EXT_ERR_SUCCESS ||
		    strcasecmp(oo.paddress_type, "SMTP") != 0) {
			mlog(LV_WARN, "W-1964: skipping non-SMTP reply-to entry");
			continue;
		}
		if (oo.pdisplay_name != nullptr && *oo.pdisplay_name != '\0') {
			if (offset + 2 >= fieldmax)
				return false;
			strcpy(&field[offset++], "\"");
			auto tmp_len = oxcmail_encode_mime_string(charset,
					oo.pdisplay_name, field + offset,
					MIME_FIELD_LEN - offset);
			offset += tmp_len;
			if (offset + 3 >= fieldmax)
				return false;
			strcpy(&field[offset], "\" ");
			offset += 2;
		}
		offset += std::max(0, gx_snprintf(&field[offset], MIME_FIELD_LEN - offset,
		          "<%s>", oo.pmail_address));
	}
	if (offset == 0 || offset >= fieldmax)
		return FALSE;
	field[offset] = '\0';
	return TRUE;
}

static BOOL oxcmail_export_address(const MESSAGE_CONTENT *pmsg,
    EXT_BUFFER_ALLOC alloc, const addr_tags &tags, const char *charset,
    char *field, size_t fdsize)
{
	int offset;
	char address[UADDR_SIZE];
	
	offset = 0;
	auto pvalue = pmsg->proplist.get<char>(tags.pr_name);
	if (pvalue != nullptr && *pvalue != '\0') {
		if (strlen(pvalue) >= std::size(address))
			goto EXPORT_ADDRESS;
		field[offset++] = '"';
		offset += oxcmail_encode_mime_string(charset,
		          pvalue, field + offset, fdsize - offset);
		field[offset++] = '"';
		field[offset++] = ' ';
		field[offset] = '\0';
	}
 EXPORT_ADDRESS:
	if (oxcmail_get_smtp_address(pmsg->proplist, &tags,
	    oxcmail_entryid_to_username, oxcmail_essdn_to_username,
	    alloc, address, std::size(address)))
		offset += gx_snprintf(field + offset, fdsize - offset, "<%s>", address);
	else if (offset > 0)
		/*
		 * RFC 5322 §3.4's ABNF mandates an address at all times.
		 * If we only emitted "Display Name", parsers can
		 * preferentially treat that as the email address, so let's add
		 * <> to nudge them.
		 */
		offset += gx_snprintf(field + offset, fdsize - offset, "<>");
	if (offset == 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcmail_export_content_class(
	const char *pmessage_class, char *field)
{
	if (strcasecmp(pmessage_class, "IPM.Note.Microsoft.Fax") == 0)
		strcpy(field, "fax");
	else if (strcasecmp(pmessage_class, "IPM.Note.Microsoft.Fax.CA") == 0)
		strcpy(field, "fax-ca");
	else if (strcasecmp(pmessage_class, "IPM.Note.Microsoft.Missed.Voice") == 0)
		strcpy(field, "missedcall");
	else if (strcasecmp(pmessage_class, "IPM.Note.Microsoft.Conversation.Voice") == 0)
		strcpy(field, "voice-uc");
	else if (strcasecmp(pmessage_class, "IPM.Note.Microsoft.Voicemail.UM.CA") == 0)
		strcpy(field, "voice-ca");
	else if (strcasecmp(pmessage_class, "IPM.Note.Microsoft.Voicemail.UM") == 0)
		strcpy(field, "voice");
	else if (strncasecmp(pmessage_class, "IPM.Note.Custom.", 16) == 0)
		snprintf(field, 1024,
			"urn:content-class:custom.%s",
			pmessage_class + 16);
	else
		return FALSE;
	return TRUE;
}

static enum oxcmail_type oxcmail_get_mail_type(const char *pmessage_class)
{
	if (strcasecmp( pmessage_class, "IPM.Note.SMIME.MultipartSigned") == 0)
		return oxcmail_type::xsigned;
	if (strncasecmp(pmessage_class, "IPM.InfoPathForm.", 17) == 0 &&
	    strtailcase(pmessage_class, ".SMIME.MultipartSigned") == 0)
		return oxcmail_type::xsigned;
	if (strcasecmp(pmessage_class, "IPM.Note.SMIME") == 0)
		return oxcmail_type::encrypted;
	if (strncasecmp(pmessage_class, "IPM.InfoPathForm.", 17) == 0 &&
	    strtailcase(pmessage_class, ".SMIME") == 0)
		return oxcmail_type::encrypted;
	if (0 == strcasecmp(pmessage_class, "IPM.Note") ||
		0 == strncasecmp(pmessage_class, "IPM.Note.", 9) ||
	    strncasecmp(pmessage_class, "IPM.InfoPathForm.", 17) == 0)
		return oxcmail_type::normal;
	if (strncasecmp(pmessage_class, "REPORT.", 7) == 0) {
		if (strtailcase(pmessage_class, ".DR") == 0 ||
		    strtailcase(pmessage_class, ".Expanded.DR") == 0 ||
		    strtailcase(pmessage_class, ".Relayed.DR") == 0 ||
		    strtailcase(pmessage_class, ".Delayed.DR") == 0 ||
		    strtailcase(pmessage_class, ".NDR") == 0)
			return oxcmail_type::dsn;
		if (strtailcase(pmessage_class, ".IPNRN") == 0 ||
		    strtailcase(pmessage_class, ".IPNNRN") == 0)
			return oxcmail_type::mdn;
	}
	if (0 == strcasecmp(pmessage_class, "IPM.Appointment") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Request") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Pos") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Tent") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Neg") ||
	    strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Canceled") == 0)
		return oxcmail_type::calendar;
	return oxcmail_type::tnef;
}

static BOOL oxcmail_load_mime_skeleton(const MESSAGE_CONTENT *pmsg,
    const char *pcharset, BOOL b_tnef, enum oxcmail_body body_type,
    MIME_SKELETON *pskeleton)
{
	int i;
	char *pbuff;
	BINARY *prtf;
	ATTACHMENT_CONTENT *pattachment;
	pskeleton->clear();
	pskeleton->charset = pcharset;
	pskeleton->pmessage_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS);
	if (pskeleton->pmessage_class == nullptr)
		pskeleton->pmessage_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (NULL == pskeleton->pmessage_class) {
		mlog(LV_DEBUG, "oxcmail: missing message class for exporting");
		return FALSE;
	}
	pskeleton->mail_type = oxcmail_get_mail_type(
						pskeleton->pmessage_class);
	if (pskeleton->mail_type == oxcmail_type::xsigned ||
	    pskeleton->mail_type == oxcmail_type::encrypted)
		if (b_tnef)
			b_tnef = FALSE;
	if (b_tnef)
		pskeleton->mail_type = oxcmail_type::tnef;
	pskeleton->body_type = body_type;
	pskeleton->pplain = pmsg->proplist.get<char>(PR_BODY);
	if (pskeleton->mail_type == oxcmail_type::xsigned ||
	    pskeleton->mail_type == oxcmail_type::encrypted ||
	    pskeleton->mail_type == oxcmail_type::tnef) {
		/* do nothing */
	} else {
		uint8_t *flag = nullptr;
		auto pvalue = pmsg->proplist.get<uint32_t>(PR_NATIVE_BODY_INFO);
		if (NULL != pvalue && NATIVE_BODY_RTF == *pvalue &&
		    ((flag = pmsg->proplist.get<uint8_t>(PR_RTF_IN_SYNC)) == nullptr ||
		    *flag == 0)) {
 FIND_RTF:
			prtf = pmsg->proplist.get<BINARY>(PR_RTF_COMPRESSED);
			if (NULL != prtf) {
				ssize_t unc_size = rtfcp_uncompressed_size(prtf);
				pbuff = nullptr;
				if (unc_size >= 0) {
					pbuff = me_alloc<char>(unc_size);
					if (pbuff == nullptr)
						return false;
				}
				size_t rtf_len = unc_size;
				if (unc_size >= 0 && rtfcp_uncompress(prtf, pbuff, &rtf_len)) {
					pskeleton->pattachments = attachment_list_init();
					if (NULL == pskeleton->pattachments) {
						free(pbuff);
						return FALSE;
					}
					if (rtf_to_html(pbuff, rtf_len, pcharset, pskeleton->rtf,
					    pskeleton->pattachments)) {
						pskeleton->rtf_bin.pv = pskeleton->rtf.data();
						free(pbuff);
						pskeleton->rtf_bin.cb = pskeleton->rtf.size();
						pskeleton->phtml = &pskeleton->rtf_bin;
						if (0 == pskeleton->pattachments->count) {
							attachment_list_free(pskeleton->pattachments);
							pskeleton->pattachments = NULL;
						} else {
							pskeleton->b_inline = TRUE;
						}
					} else {
						attachment_list_free(pskeleton->pattachments);
						pskeleton->pattachments = NULL;
						free(pbuff);
						pskeleton->mail_type = oxcmail_type::tnef;
					}
				} else {
					free(pbuff);
					pskeleton->mail_type = oxcmail_type::tnef;
				}
			}
		} else {
			pskeleton->phtml = pmsg->proplist.get<BINARY>(PR_HTML);
			if (pskeleton->phtml == nullptr)
				goto FIND_RTF;
		}
	}
	if (pmsg->children.pattachments == nullptr)
		return TRUE;
	for (i=0; i<pmsg->children.pattachments->count; i++) {
		pattachment = pmsg->children.pattachments->pplist[i];
		if (NULL != pattachment->pembedded) {
			pskeleton->b_attachment = TRUE;
			continue;
		}
		auto pvalue = pattachment->proplist.get<uint32_t>(PR_ATTACH_FLAGS);
		if (pvalue != nullptr && (*pvalue & ATT_MHTML_REF)) {
			if (pattachment->proplist.has(PR_ATTACH_CONTENT_ID) ||
			    pattachment->proplist.has(PR_ATTACH_CONTENT_LOCATION)) {
				pskeleton->b_inline = TRUE;
				continue;
			}
		}
		pskeleton->b_attachment = TRUE;
	}
	return TRUE;
}

void mime_skeleton::clear()
{
	auto pskeleton = this;
	if (NULL != pskeleton->pattachments) {
		attachment_list_free(pskeleton->pattachments);
		pskeleton->pattachments = nullptr;
	}
}

static inline const char *importance_to_text(const uint32_t *v)
{
	if (v == nullptr)
		return nullptr;
	switch (*v) {
	case IMPORTANCE_LOW: return "Low";
	case IMPORTANCE_NORMAL: return "Normal";
	case IMPORTANCE_HIGH: return "High";
	default: return nullptr;
	}
}

static const char *sensitivity_to_text(const uint32_t *v)
{
	if (v == nullptr)
		return nullptr;
	switch (*v) {
	case SENSITIVITY_NONE: return "Normal";
	case SENSITIVITY_PERSONAL: return "Personal";
	case SENSITIVITY_PRIVATE: return "Private";
	case SENSITIVITY_COMPANY_CONFIDENTIAL: return "Company-Confidential";
	default: return nullptr;
	}
}

static const char *sender_id_to_text(const uint32_t *v)
{
	if (v == nullptr)
		return nullptr;
	switch (*v) {
	case SENDER_ID_NEUTRAL: return "Neutral";
	case SENDER_ID_PASS: return "Pass";
	case SENDER_ID_FAIL: return "Fail";
	case SENDER_ID_SOFT_FAIL: return "SoftFail";
	case SENDER_ID_NONE: return "None";
	case SENDER_ID_TEMP_ERROR: return "TempError";
	case SENDER_ID_PERM_ERROR: return "PermError";
	default: return nullptr;
	}
}

static bool oxcmail_export_sender(const MESSAGE_CONTENT *pmsg, const char *cset,
    EXT_BUFFER_ALLOC alloc, MIME *phead, bool sched)
{
	if (sched)
		return true;
	char tmp_field[MIME_FIELD_LEN];
	auto str  = pmsg->proplist.get<const char>(PR_SENDER_SMTP_ADDRESS);
	auto str1 = pmsg->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr && str1 != nullptr) {
		if (strcasecmp(str, str1) == 0)
			return true; /* field not needed */
		if (!oxcmail_export_address(pmsg, alloc, tags_sender, cset,
		    tmp_field, std::size(tmp_field)))
			return true; /* not present */
		if (!phead->set_field("Sender", tmp_field))
			return FALSE;
		return true;
	}
	str  = pmsg->proplist.get<char>(PR_SENDER_ADDRTYPE);
	str1 = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_ADDRTYPE);
	if (str == nullptr || str1 == nullptr || strcasecmp(str, "SMTP") != 0 ||
	    strcasecmp(str1, "SMTP") != 0)
		return true;
	str  = pmsg->proplist.get<char>(PR_SENDER_EMAIL_ADDRESS);
	str1 = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	if (str == nullptr || str1 == nullptr || strcasecmp(str, str1) == 0)
		return true;
	if (oxcmail_export_address(pmsg, alloc, tags_sender, cset,
	    tmp_field, std::size(tmp_field)) &&
	    !phead->set_field("Sender", tmp_field))
		return false;
	return true;
}

static bool oxcmail_export_fromsender(const MESSAGE_CONTENT *pmsg,
    const char *cset, EXT_BUFFER_ALLOC alloc, MIME *phead, bool sched)
{
	char tmp_field[MIME_FIELD_LEN];
	if (sched) {
		if (oxcmail_export_address(pmsg, alloc, tags_sender,
		    cset, tmp_field, std::size(tmp_field)) &&
		    !phead->set_field("From", tmp_field))
			return false;
		return true;
	}
	if (oxcmail_export_address(pmsg, alloc, tags_sent_repr,
	    cset, tmp_field, std::size(tmp_field))) {
		if (!phead->set_field("From", tmp_field))
			return FALSE;
	} else if (oxcmail_export_address(pmsg, alloc, tags_sender,
	    cset, tmp_field, std::size(tmp_field)) &&
	    !phead->set_field("Sender", tmp_field)) {
		return FALSE;
	}
	return true;
}

static bool oxcmail_export_receiptto(const MESSAGE_CONTENT *pmsg,
    const char *cset, EXT_BUFFER_ALLOC alloc, MIME *phead, bool sched)
{
	char tmp_field[MIME_FIELD_LEN];
	auto flag = pmsg->proplist.get<uint8_t>(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED);
	if (flag == nullptr || *flag == 0)
		return true;
	if (oxcmail_export_address(pmsg, alloc, tags_read_rcpt,
	    cset, tmp_field, std::size(tmp_field)))
		/* ok */;
	else if (oxcmail_export_address(pmsg, alloc, tags_sender,
	    cset, tmp_field, std::size(tmp_field)))
		/* ok */;
	else if (sched && oxcmail_export_address(pmsg, alloc, tags_sent_repr,
	    cset, tmp_field, std::size(tmp_field)))
		/* ok */;
	else
		return true; /* No recipient */
	return phead->set_field("Return-Receipt-To", tmp_field);
}

static bool oxcmail_export_receiptflg(const MESSAGE_CONTENT *pmsg,
    const char *cset, EXT_BUFFER_ALLOC alloc, MIME *phead, bool sched)
{
	char tmp_field[MIME_FIELD_LEN];
	auto flag = pmsg->proplist.get<uint8_t>(PR_READ_RECEIPT_REQUESTED);
	if (flag == nullptr || *flag == 0)
		return true;
	if (oxcmail_export_address(pmsg, alloc, tags_read_rcpt,
	    cset, tmp_field, std::size(tmp_field)))
		/* ok */;
	else if (sched && oxcmail_export_address(pmsg, alloc, tags_sent_repr,
	    cset, tmp_field, std::size(tmp_field)))
		/* ok */;
	else
		return true; /* No recipient */
	return phead->set_field("Disposition-Notification-To", tmp_field);
}

static bool oxcmail_export_tocc(const MESSAGE_CONTENT *pmsg,
    const MIME_SKELETON *pskeleton, EXT_BUFFER_ALLOC alloc, MIME *phead)
{
	if (pmsg->children.prcpts == nullptr)
		return true;
	char tmp_field[MIME_FIELD_LEN];
	if (oxcmail_export_addresses(pskeleton->charset, pmsg->children.prcpts,
	    MAPI_TO, alloc, tmp_field, std::size(tmp_field)) &&
	    !phead->set_field("To", tmp_field))
		return FALSE;
	if (oxcmail_export_addresses(pskeleton->charset, pmsg->children.prcpts,
	    MAPI_CC, alloc, tmp_field, std::size(tmp_field)) &&
	    !phead->set_field("Cc", tmp_field))
		return FALSE;
	if (strncasecmp(pskeleton->pmessage_class, "IPM.Schedule.Meeting.", 21) == 0 ||
	    strcasecmp(pskeleton->pmessage_class, "IPM.Task") == 0||
	    strncasecmp(pskeleton->pmessage_class, "IPM.Task.", 9) == 0)
		return true;
	if (oxcmail_export_addresses(pskeleton->charset,
	    pmsg->children.prcpts, MAPI_BCC, alloc,
	    tmp_field, std::size(tmp_field)) &&
	    !phead->set_field("Bcc", tmp_field))
		return FALSE;
	return true;
}

static BOOL oxcmail_export_mail_head(const MESSAGE_CONTENT *pmsg,
	MIME_SKELETON *pskeleton, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, GET_PROPNAME get_propname,
	MIME *phead)
{
	size_t tmp_len = 0;
	time_t tmp_time;
	size_t base64_len;
	struct tm time_buff;
	PROPID_ARRAY propids;

	auto sched = pskeleton->mail_type == oxcmail_type::calendar;
	if (!phead->set_field("MIME-Version", "1.0") ||
	    !oxcmail_export_sender(pmsg, pskeleton->charset, alloc, phead, sched) ||
	    !oxcmail_export_fromsender(pmsg, pskeleton->charset, alloc, phead, sched) ||
	    !oxcmail_export_receiptto(pmsg, pskeleton->charset, alloc, phead, sched) ||
	    !oxcmail_export_receiptflg(pmsg, pskeleton->charset, alloc, phead, sched) ||
	    !oxcmail_export_tocc(pmsg, pskeleton, alloc, phead))
		return false;
	char tmp_buff[MIME_FIELD_LEN];
	char tmp_field[MIME_FIELD_LEN];
	if (oxcmail_export_reply_to(pmsg, pskeleton->charset, alloc, tmp_field) &&
	    !phead->set_field("Reply-To", tmp_field))
		return FALSE;
	if (oxcmail_export_content_class(pskeleton->pmessage_class, tmp_field)) {
		if (!phead->set_field("Content-Class", tmp_field))
			return FALSE;
	} else if (0 == strncasecmp(
		pskeleton->pmessage_class,
		"IPM.InfoPathForm.", 17)) {
		PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidInfoPathFromName};
		const PROPNAME_ARRAY propnames = {1, &propname};
		if (!get_propids(&propnames, &propids))
			return FALSE;
		auto str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
		if (str != nullptr) {
			auto str1 = strrchr(str, '.');
			if (str1 != nullptr)
				str = str1 + 1;
			snprintf(tmp_field, 1024, "InfoPathForm.%s", str);
			if (!phead->set_field("Content-Class", tmp_field))
				return FALSE;
		}
	}
	auto str = pmsg->proplist.get<const char>(PR_SENDER_TELEPHONE_NUMBER);
	if (str != nullptr && !phead->set_field("X-CallingTelephoneNumber", str))
		return FALSE;
	auto num = pmsg->proplist.get<const uint32_t>(PidTagVoiceMessageDuration);
	if (num != nullptr) {
		snprintf(tmp_field, std::size(tmp_field), "%ld", static_cast<long>(*num));
		if (!phead->set_field("X-VoiceMessageDuration", tmp_field))
			return FALSE;
	}
	str = pmsg->proplist.get<char>(PidTagVoiceMessageSenderName);
	if (str != nullptr && !phead->set_field("X-VoiceMessageSenderName", str))
		return FALSE;
	num = pmsg->proplist.get<uint32_t>(PidTagFaxNumberOfPages);
	if (num != nullptr) {
		snprintf(tmp_field, std::size(tmp_field), "%lu", static_cast<unsigned long>(*num));
		if (!phead->set_field("X-FaxNumberOfPages", tmp_field))
			return FALSE;
	}
	str = pmsg->proplist.get<char>(PidTagVoiceMessageAttachmentOrder);
	if (str != nullptr && !phead->set_field("X-AttachmentOrder", str))
		return FALSE;
	str = pmsg->proplist.get<char>(PidTagCallId);
	if (str != nullptr && !phead->set_field("X-CallID", str))
		return FALSE;
	str = importance_to_text(pmsg->proplist.get<const uint32_t>(PR_IMPORTANCE));
	if (str != nullptr && !phead->set_field("Importance", str))
		return false;
	str = sensitivity_to_text(pmsg->proplist.get<const uint32_t>(PR_SENSITIVITY));
	if (str != nullptr && !phead->set_field("Sensitivity", str))
		return false;
	
	auto lnum = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	tmp_time = lnum == nullptr ? time(nullptr) :
	           rop_util_nttime_to_unix(*lnum);
	strftime(tmp_field, 128, "%a, %d %b %Y %H:%M:%S %z",
					localtime_r(&tmp_time, &time_buff));
	if (!phead->set_field("Date", tmp_field))
		return FALSE;
	
	str  = pmsg->proplist.get<char>(PR_SUBJECT_PREFIX);
	auto str1 = pmsg->proplist.get<const char>(PR_NORMALIZED_SUBJECT);
	if (str != nullptr && str1 != nullptr) {
		snprintf(tmp_buff, MIME_FIELD_LEN, "%s%s", str, str1);
		if (oxcmail_encode_mime_string(pskeleton->charset,
		    tmp_buff, tmp_field, std::size(tmp_field)) > 0 &&
		    !phead->set_field("Subject", tmp_field))
			return FALSE;
	} else {
		str = pmsg->proplist.get<char>(PR_SUBJECT);
		if (str != nullptr && oxcmail_encode_mime_string(pskeleton->charset,
		    str, tmp_field, std::size(tmp_field)) > 0 &&
		    !phead->set_field("Subject", tmp_field))
			return FALSE;
	}
	str = pmsg->proplist.get<char>(PR_CONVERSATION_TOPIC);
	if (str != nullptr && oxcmail_encode_mime_string(pskeleton->charset,
	    str, tmp_field, std::size(tmp_field)) > 0 &&
	    !phead->set_field("Thread-Topic", tmp_field))
		return FALSE;
	auto bv = pmsg->proplist.get<BINARY>(PR_CONVERSATION_INDEX);
	if (bv != nullptr &&
	    encode64(bv->pb, bv->cb, tmp_field, 1024, &base64_len) == 0 &&
	    !phead->set_field("Thread-Index", tmp_field))
		return FALSE;
	str = pmsg->proplist.get<char>(PR_INTERNET_MESSAGE_ID);
	if (str != nullptr && !phead->set_field("Message-ID", str))
		return FALSE;
	str = pmsg->proplist.get<char>(PR_INTERNET_REFERENCES);
	if (str != nullptr && !phead->set_field("References", str))
		return FALSE;
	PROPERTY_NAME propname = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameKeywords)};
	const PROPNAME_ARRAY propnames = {1, &propname};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto sa = pmsg->proplist.get<STRING_ARRAY>(PROP_TAG(PT_MV_UNICODE, propids.ppropid[0]));
	if (sa != nullptr) {
		tmp_len = 0;
		for (size_t i = 0; i < sa->count; ++i) {
			if (0 != tmp_len) {
				strcpy(tmp_field, " ,");
				tmp_len += 2;
			}
			if (tmp_len >= MIME_FIELD_LEN)
				break;
			tmp_len += oxcmail_encode_mime_string(pskeleton->charset,
					sa->ppstr[i],
					tmp_field + tmp_len, MIME_FIELD_LEN - tmp_len);
		}
		if (tmp_len > 0 && tmp_len < MIME_FIELD_LEN &&
		    !phead->set_field("Keywords", tmp_field))
			return FALSE;
	}
	str = pmsg->proplist.get<char>(PR_IN_REPLY_TO_ID);
	if (str != nullptr && !phead->set_field("In-Reply-To", str))
		return FALSE;
	str = pmsg->proplist.get<char>(PR_LIST_HELP);
	if (str != nullptr && !phead->set_field("List-Help", str))
		return FALSE;
	str = pmsg->proplist.get<char>(PR_LIST_SUBSCRIBE);
	if (str != nullptr && !phead->set_field("List-Subscribe", str))
		return FALSE;
	str = pmsg->proplist.get<char>(PR_LIST_UNSUBSCRIBE);
	if (str != nullptr && !phead->set_field("List-Unsubscribe", str))
		return FALSE;
	num = pmsg->proplist.get<uint32_t>(PR_MESSAGE_LOCALE_ID);
	if (num != nullptr) {
		str = deconst(lcid_to_ltag(*num));
		if (str != nullptr && !phead->set_field("Content-Language", str))
			return FALSE;
	}
	propname = {MNID_ID, PSETID_COMMON, PidLidClassified};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	auto flag = pmsg->proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]));
	if (flag != nullptr && *flag != 0 &&
	    !phead->set_field("X-Microsoft-Classified", "true"))
		return FALSE;
	propname = {MNID_ID, PSETID_COMMON, PidLidClassificationKeep};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	flag = pmsg->proplist.get<uint8_t>(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]));
	if (flag != nullptr && *flag != 0 &&
	    !phead->set_field("X-Microsoft-ClassKeep", "true"))
		return FALSE;
	propname = {MNID_ID, PSETID_COMMON, PidLidClassification};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
	if (str != nullptr && !phead->set_field("X-Microsoft-Classification", str))
		return FALSE;
	propname = {MNID_ID, PSETID_COMMON, PidLidClassificationDescription};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
	if (str != nullptr && !phead->set_field("X-Microsoft-ClassDesc", str))
		return FALSE;
	propname = {MNID_ID, PSETID_COMMON, PidLidClassificationGuid};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
	if (str != nullptr && !phead->set_field("X-Microsoft-ClassID", str))
		return FALSE;
	
	if ((NULL != pmsg->children.pattachments &&
		pmsg->children.pattachments->count) > 0 ||
		(NULL != pskeleton->pattachments &&
		pskeleton->pattachments->count > 0)) {
		if (!phead->set_field("X-MS-Has-Attach", "yes"))
			return FALSE;
	}
	
	num = pmsg->proplist.get<uint32_t>(PR_AUTO_RESPONSE_SUPPRESS);
	if (num != nullptr && *num != 0) {
		if (*num == UINT32_MAX) {
			if (!phead->set_field("X-Auto-Response-Suppress", "ALL"))
				return FALSE;
		} else {
			*tmp_field = '\0';
			if (*num & AUTO_RESPONSE_SUPPRESS_DR)
				strcat(tmp_field, "DR");
			if (*num & AUTO_RESPONSE_SUPPRESS_NDR) {
				if (*tmp_field != '\0')
					strcat(tmp_field, ", ");
				strcat(tmp_field, "NDR");
			}
			if (*num & AUTO_RESPONSE_SUPPRESS_RN) {
				if (*tmp_field != '\0')
					strcat(tmp_field, ", ");
				strcat(tmp_field, "RN");
			}
			if (*num & AUTO_RESPONSE_SUPPRESS_NRN) {
				if (*tmp_field != '\0')
					strcat(tmp_field, ", ");
				strcat(tmp_field, "NRN");
			}
			if (*num & AUTO_RESPONSE_SUPPRESS_OOF) {
				if (*tmp_field != '\0')
					strcat(tmp_field, ", ");
				strcat(tmp_field, "OOF");
			}
			if (*num & AUTO_RESPONSE_SUPPRESS_AUTOREPLY) {
				if (*tmp_field != '\0')
					strcat(tmp_field, ", ");
				strcat(tmp_field, "AutoReply");
			}
		}
		if (tmp_len != 0 && !phead->set_field("X-Auto-Response-Suppress", tmp_field))
			return FALSE;
	}
	
	flag = pmsg->proplist.get<uint8_t>(PR_AUTO_FORWARDED);
	if (flag != nullptr && *flag != 0 &&
	    !phead->set_field("X-MS-Exchange-Organization-AutoForwarded", "true"))
		return FALSE;
	str = sender_id_to_text(pmsg->proplist.get<const uint32_t>(PR_SENDER_ID_STATUS));
	if (str != nullptr &&
	    !phead->set_field("X-MS-Exchange-Organization-SenderIdResult", str))
		return false;
	
	str = pmsg->proplist.get<char>(PR_PURPORTED_SENDER_DOMAIN);
	if (str != nullptr && !phead->set_field("X-MS-Exchange-Organization-PRD", str))
		return FALSE;
	
	auto inum = pmsg->proplist.get<const int32_t>(PR_CONTENT_FILTER_SCL);
	if (inum != nullptr) {
		snprintf(tmp_field, std::size(tmp_field), "%ld", static_cast<long>(*inum));
		if (!phead->set_field("X-MS-Exchange-Organization-SCL", tmp_field))
			return FALSE;
	}
	
	propname = {MNID_ID, PSETID_COMMON, PidLidFlagRequest};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
	if (str != nullptr && *str != '\0') {
		if (!phead->set_field("X-Message-Flag", str))
			return FALSE;
		lnum = pmsg->proplist.get<uint64_t>(PR_REPLY_TIME);
		if (lnum != nullptr) {
			tmp_time = rop_util_nttime_to_unix(*lnum);
			strftime(tmp_field, 128, "%a, %d %b %Y %H:%M:%S %z",
							localtime_r(&tmp_time, &time_buff));
			if (!phead->set_field("Reply-By", tmp_field))
				return FALSE;
		}
	}
	
	if (pskeleton->mail_type == oxcmail_type::tnef) {
		*tmp_field = '\0';
		bv = pmsg->proplist.get<BINARY>(PR_TNEF_CORRELATION_KEY);
		if (bv == nullptr) {
			str = pmsg->proplist.get<char>(PR_INTERNET_MESSAGE_ID);
			if (str != nullptr)
				strncpy(tmp_field, str, 1024);
		} else {
			if (bv->cb < 1024) {
				memcpy(tmp_field, bv->pb, bv->cb);
				tmp_field[bv->cb] = '\0';
			}
		}
		if (!phead->set_field("X-MS-TNEF-Correlator", tmp_field))
			return FALSE;
	}
	
	str = pmsg->proplist.get<char>(PR_BODY_CONTENT_ID);
	if (str != nullptr) {
		snprintf(tmp_buff, sizeof(tmp_buff), "<%s>", str);
		if (!phead->set_field("Content-ID", tmp_buff))
			return FALSE;
	}
	
	str = pmsg->proplist.get<char>(PR_BODY_CONTENT_LOCATION);
	if (str != nullptr && !phead->set_field("Content-Location", str))
		return FALSE;
	
	phead->set_field("X-Mailer", "gromox-oxcmail " PACKAGE_VERSION);
	auto guid = PS_INTERNET_HEADERS;
	for (size_t i = 0; i < pmsg->proplist.count; ++i) {
		auto proptag = pmsg->proplist.ppropval[i].proptag;
		if (!is_nameprop_id(PROP_ID(proptag)))
			continue;
		if (PROP_TYPE(proptag) != PT_STRING8 &&
		    PROP_TYPE(proptag) != PT_UNICODE)
			continue;
		PROPERTY_NAME *ppropname = nullptr;
		if (!get_propname(PROP_ID(proptag), &ppropname))
			return FALSE;
		if (ppropname->guid != guid)
			continue;
		if (ppropname->kind != MNID_STRING ||
		    strcasecmp(ppropname->pname, "Content-Type") == 0)
			continue;
		if (!phead->set_field(ppropname->pname,
		    static_cast<char *>(pmsg->proplist.ppropval[i].pvalue)))
			return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_export_dsn(const MESSAGE_CONTENT *pmsg,
	const char *charset, const char *pmessage_class,
	EXT_BUFFER_ALLOC alloc, char *pdsn_content,
	int max_length)
{
	char action[16];
	TARRAY_SET *prcpts;
	char tmp_buff[1024];
	static constexpr const char status_strings1[][6] =
		{"5.4.0", "5.1.0", "5.6.5", "5.6.5", "5.2.0", "5.3.0", "4.4.3"};
	static constexpr const char status_strings2[][6] =
		{"5.1.0", "5.1.4", "4.4.5", "4.4.6", "5.1.0", "4.4.7",
		"5.3.0", "5.6.0", "5.6.3", "5.6.2", "5.6.0", "5.5.4",
		"5.6.0", "5.3.4", "5.6.0", "5.6.1", "5.5.3", "5.5.5",
		"5.3.3", "5.6.2", "5.6.0", "5.6.0", "4.6.4", "4.6.4",
		"4.6.4", "4.6.4", "5.7.3", "4.4.6", "5.7.2", "5.7.1",
		"5.2.4", "5.6.1", "5.1.3", "5.1.0", "5.1.3", "5.1.1",
		"5.1.0", "5.3.0", "5.3.0", "5.1.0", "5.1.6", "5.1.0",
		"5.1.0", "5.1.6", "5.0.0", "5.0.0", "5.7.0", "5.0.0",
		"5.1.2"};
	
	DSN dsn;
	auto pdsn_fields = dsn.get_message_fields();
	auto str = pmsg->proplist.get<const char>(PidTagReportingMessageTransferAgent);
	if (str == nullptr) {
		strcpy(tmp_buff, "dns; ");
		gethostname(tmp_buff + 5, sizeof(tmp_buff) - 5);
		tmp_buff[std::size(tmp_buff)-1] = '\0';
		if (!dsn.append_field(pdsn_fields, "Reporting-MTA", tmp_buff))
			return FALSE;
	} else {
		if (!dsn.append_field(pdsn_fields, "Reporting-MTA", str))
			return FALSE;
	}
	
	if (strtailcase(pmessage_class, ".DR") == 0)
		strcpy(action, "delivered");
	else if (strtailcase(pmessage_class, ".Expanded.DR") == 0)
		strcpy(action, "expanded");
	else if (strtailcase(pmessage_class, ".Relayed.DR") == 0)
		strcpy(action, "relayed");
	else if (strtailcase(pmessage_class, ".Delayed.DR") == 0)
		strcpy(action, "delayed");
	else if (strtailcase(pmessage_class, ".NDR") == 0)
		strcpy(action, "failed");
	else
		*action = '\0';
	if (pmsg->children.prcpts == nullptr)
		goto SERIALIZE_DSN;
	prcpts = pmsg->children.prcpts;
	for (size_t i = 0; i < prcpts->count; ++i) {
		pdsn_fields = dsn.new_rcpt_fields();
		if (pdsn_fields == nullptr)
			return FALSE;
		if (!oxcmail_get_rcpt_address(*prcpts->pparray[i], alloc,
		    tags_self, tmp_buff, std::size(tmp_buff)))
			*tmp_buff = '\0';
		if (!dsn.append_field(pdsn_fields, "Final-Recipient", tmp_buff))
			return FALSE;
		if (*action != '\0' &&
		    !dsn.append_field(pdsn_fields, "Action", action))
			return FALSE;
		auto num = prcpts->pparray[i]->get<const uint32_t>(PR_NDR_DIAG_CODE);
		if (num != nullptr) {
			if (*num == MAPI_DIAG_NO_DIAGNOSTIC) {
				num = prcpts->pparray[i]->get<uint32_t>(PR_NDR_REASON_CODE);
				if (num != nullptr) {
					strcpy(tmp_buff, *num > 6 ? "5.4.0" :
					       status_strings1[*num]);
					if (!dsn.append_field(pdsn_fields, "Status", tmp_buff))
						return FALSE;
				}
			} else {
				num = prcpts->pparray[i]->get<uint32_t>(PR_NDR_REASON_CODE);
				if (num != nullptr) {
					strcpy(tmp_buff, *num > 48 ? "5.0.0" :
					       status_strings2[*num]);
					if (!dsn.append_field(pdsn_fields, "Status", tmp_buff))
						return FALSE;
				}
			}
		}
		str = prcpts->pparray[i]->get<char>(PR_DSN_REMOTE_MTA);
		if (str != nullptr && !dsn.append_field(pdsn_fields,
		    "Remote-MTA", str))
			return FALSE;
		str = prcpts->pparray[i]->get<char>(PR_SUPPLEMENTARY_INFO);
		if (str != nullptr && !dsn.append_field(pdsn_fields,
		    "X-Supplementary-Info", str))
			return FALSE;
		str = prcpts->pparray[i]->get<char>(PR_DISPLAY_NAME);
		if (str != nullptr && oxcmail_encode_mime_string(charset,
		    str, tmp_buff, std::size(tmp_buff)) > 0 &&
		    !dsn.append_field(pdsn_fields, "X-Display-Name", tmp_buff))
			return FALSE;
	}
 SERIALIZE_DSN:
	return dsn.serialize(pdsn_content, max_length);
}

static BOOL oxcmail_export_mdn(const MESSAGE_CONTENT *pmsg,
	const char *charset, const char *pmessage_class,
	EXT_BUFFER_ALLOC alloc, char *pmdn_content,
	int max_length)
{
	int tmp_len;
	size_t base64_len;
	char tmp_buff[1024];
	char tmp_address[UADDR_SIZE];
	
	tmp_address[0] = '\0';
	auto str = pmsg->proplist.get<const char>(PR_SENDER_SMTP_ADDRESS);
	auto pdisplay_name = pmsg->proplist.get<const char>(PR_SENDER_NAME);
	if (str != nullptr) {
		gx_strlcpy(tmp_address, str, std::size(tmp_address));
	} else {
		str = pmsg->proplist.get<char>(PR_SENDER_ADDRTYPE);
		if (str != nullptr && strcasecmp(str, "SMTP") == 0) {
			str = pmsg->proplist.get<char>(PR_SENDER_EMAIL_ADDRESS);
			if (str != nullptr)
				gx_strlcpy(tmp_address, str, std::size(tmp_address));
		}
	}
	if (tmp_address[0] != '\0')
		goto EXPORT_MDN_CONTENT;
	str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	pdisplay_name = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_NAME);
	if (str != nullptr) {
		gx_strlcpy(tmp_address, str, std::size(tmp_address));
	} else {
		str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_ADDRTYPE);
		if (str != nullptr && strcasecmp(str, "SMTP") == 0) {
			str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr)
				gx_strlcpy(tmp_address, str, std::size(tmp_address));
		}
	}
 EXPORT_MDN_CONTENT:
	DSN dsn;
	auto pdsn_fields = dsn.get_message_fields();
	snprintf(tmp_buff, std::size(tmp_buff), "rfc822;%s", tmp_address);
	if (!dsn.append_field(pdsn_fields, "Final-Recipient", tmp_buff))
		return FALSE;
	tmp_len = strlen(pmessage_class);
	strcpy(tmp_buff, tmp_len >= 6 && strcasecmp(&pmessage_class[tmp_len-6], ".IPNRN") == 0 ?
	       "manual-action/MDN-sent-automatically; displayed" :
	       "manual-action/MDN-sent-automatically; deleted");
	if (!dsn.append_field(pdsn_fields, "Disposition", tmp_buff))
		return FALSE;
	auto bv = pmsg->proplist.get<const BINARY>(PR_PARENT_KEY);
	if (bv != nullptr && encode64(bv->pb, bv->cb, tmp_buff,
	    std::size(tmp_buff), &base64_len) == 0) {
		tmp_buff[base64_len] = '\0';
		if (!dsn.append_field(pdsn_fields, "X-MSExch-Correlation-Key", tmp_buff))
			return FALSE;
	}
	str = pmsg->proplist.get<char>(PidTagOriginalMessageId);
	if (str != nullptr && !dsn.append_field(pdsn_fields,
	    "Original-Message-ID", str))
		return FALSE;
	if (pdisplay_name != nullptr && oxcmail_encode_mime_string(charset,
	    pdisplay_name, tmp_buff, std::size(tmp_buff)) > 0 &&
	    !dsn.append_field(pdsn_fields, "X-Display-Name", tmp_buff))
		return FALSE;
	return dsn.serialize(pmdn_content, max_length);
}

static BOOL oxcmail_export_attachment(ATTACHMENT_CONTENT *pattachment,
    BOOL b_inline, MIME_SKELETON *pskeleton, EXT_BUFFER_ALLOC alloc,
    GET_PROPIDS get_propids, GET_PROPNAME get_propname, MIME *pmime)
{
	int tmp_len;
	BOOL b_vcard;
	size_t offset;
	struct tm time_buff;
	char tmp_field[1024];
	const char *pfile_name = nullptr;
	
	b_vcard = FALSE;
	if (NULL != pattachment->pembedded) {
		/*
		 * "Send as business card" makes Outlook (2019) generate a MAPI
		 * attachment object, representing a file which contains a
		 * vCard 2.0 header and which is marked as text/vcard. oxcmail
		 * just repacks that into the MIME framing.
		 *
		 * "Send as Outlook contact" makes Outlook produce a MAPI-based
		 * attachment. oxcmail will convert this to vCard 4.0 and mark
		 * it as text/directory.
		 */
		auto str = pattachment->pembedded->proplist.get<const char>(PR_MESSAGE_CLASS);
		if (str != nullptr && strcasecmp(str, "IPM.Contact") == 0)
			b_vcard = TRUE;
	}
	
	if (NULL == pattachment->pembedded) {
		auto pcontent_type = pattachment->proplist.get<const char>(PR_ATTACH_MIME_TAG);
		pfile_name = pattachment->proplist.get<char>(PR_ATTACH_LONG_FILENAME);
		if (pfile_name == nullptr)
			pfile_name = pattachment->proplist.get<char>(PR_ATTACH_FILENAME);
		if (NULL == pcontent_type) {
			auto str = pattachment->proplist.get<const char>(PR_ATTACH_EXTENSION);
			if (str != nullptr)
				pcontent_type = extension_to_mime(str + 1);
			if (pcontent_type == nullptr)
				pcontent_type = "application/octet-stream";
		}
		if (strncasecmp(pcontent_type, "multipart/", 10) == 0)
			pcontent_type = "application/octet-stream";
		if (!pmime->set_content_type(pcontent_type))
			return FALSE;
		if (NULL != pfile_name) {
			tmp_field[0] = '"';
			tmp_len = oxcmail_encode_mime_string(
				pskeleton->charset,	pfile_name,
				tmp_field + 1, 512);
			if (tmp_len > 0) {
				strcpy(&tmp_field[tmp_len+1], "\"");
				if (!pmime->set_content_param("name", tmp_field))
					return FALSE;
			}
		}
	} else if (b_vcard) {
		pfile_name = pattachment->proplist.get<char>(PR_ATTACH_LONG_FILENAME);
		if (pfile_name == nullptr)
			pfile_name = pattachment->proplist.get<char>(PR_ATTACH_FILENAME);
		if (!pmime->set_content_type("text/directory"))
			return FALSE;
		if (!pmime->set_content_param("charset", "\"utf-8\"") ||
		    !pmime->set_content_param("profile", "vCard"))
			return FALSE;
	} else {
		if (!pmime->set_content_type("message/rfc822"))
			return FALSE;
	}
	
	auto str = pattachment->proplist.get<const char>(PR_DISPLAY_NAME);
	if (str != nullptr) {
		tmp_len = oxcmail_encode_mime_string(pskeleton->charset,
		          str, tmp_field, std::size(tmp_field));
		if (tmp_len > 0 && !pmime->set_field("Content-Description", tmp_field))
			return FALSE;
	}
	
	auto pctime = pattachment->proplist.get<uint64_t>(PR_CREATION_TIME);
	auto pmtime = pattachment->proplist.get<uint64_t>(PR_LAST_MODIFICATION_TIME);
	if (b_inline) {
		strcpy(tmp_field, "inline; ");
		tmp_len = 8;
	} else {
		strcpy(tmp_field, "attachment; ");
		tmp_len = 12;
	}
	if (NULL != pfile_name) {
		strcpy(&tmp_field[tmp_len], "filename=\"");
		tmp_len += 10;
		tmp_len += oxcmail_encode_mime_string(pskeleton->charset,
				pfile_name, tmp_field + tmp_len, 1024 - tmp_len);
		strcpy(&tmp_field[tmp_len], "\";\r\n\t");
		tmp_len += 5;
	}
	auto tmp_time = time(nullptr);
	if (pctime != nullptr)
		tmp_time = rop_util_nttime_to_unix(*pctime);
	gmtime_r(&tmp_time, &time_buff);
	tmp_len += strftime(tmp_field + tmp_len, 1024 - tmp_len,
		"creation-date=\"%a, %d %b %Y %H:%M:%S GMT\";\r\n\t",
		&time_buff);
	if (pmtime != nullptr)
		tmp_time = rop_util_nttime_to_unix(*pmtime);
	gmtime_r(&tmp_time, &time_buff);
	tmp_len += strftime(tmp_field + tmp_len, 1024 - tmp_len,
		"modification-date=\"%a, %d %b %Y %H:%M:%S GMT\"",
		&time_buff);
	tmp_field[tmp_len] = '\0';
	if (!pmime->set_field("Content-Disposition", tmp_field))
		return FALSE;
	
	str = pattachment->proplist.get<char>(PR_ATTACH_CONTENT_ID);
	if (str != nullptr) {
		snprintf(tmp_field, sizeof(tmp_field), "<%s>", str);
		if (!pmime->set_field("Content-ID", tmp_field))
			return FALSE;
	}
	str = pattachment->proplist.get<char>(PR_ATTACH_CONTENT_LOCATION);
	if (str != nullptr && !pmime->set_field("Content-Location", str))
		return FALSE;
	str = pattachment->proplist.get<char>(PR_ATTACH_CONTENT_BASE);
	if (str != nullptr && !pmime->set_field("Content-Base", str))
		return FALSE;
	
	{
	vcard vcard;
	if (b_vcard && oxvcard_export(pattachment->pembedded, vcard, get_propids)) {
		std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(VCARD_MAX_BUFFER_LEN));
		if (pbuff != nullptr && vcard.serialize(pbuff.get(),
		    VCARD_MAX_BUFFER_LEN)) {
			if (!pmime->write_content(pbuff.get(),
			    strlen(pbuff.get()), mime_encoding::automatic))
				return FALSE;
			return TRUE;
		}
	}
	}
	
	if (NULL != pattachment->pembedded) {
		auto b_tnef = pskeleton->mail_type == oxcmail_type::tnef;
		MAIL imail;
		if (!oxcmail_export(pattachment->pembedded,
		    b_tnef ? TRUE : false, pskeleton->body_type, &imail,
		    alloc, std::move(get_propids), std::move(get_propname)))
			return FALSE;
		auto mail_len = imail.get_length();
		if (mail_len < 0)
			return false;
		alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1,
			"oxcmail_export_attachment");
		STREAM tmp_stream(&pallocator);
		if (!imail.serialize(&tmp_stream))
			return FALSE;
		imail.clear();
		std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(mail_len + 128));
		if (pbuff == nullptr)
			return FALSE;
				
		offset = 0;
		unsigned int size = STREAM_BLOCK_SIZE;
		void *ptr;
		while ((ptr = tmp_stream.get_read_buf(&size)) != nullptr) {
			memcpy(pbuff.get() + offset, ptr, size);
			offset += size;
			size = STREAM_BLOCK_SIZE;
		}
		tmp_stream.clear();
		return pmime->write_content(pbuff.get(), mail_len, mime_encoding::none);
	}
	auto bv = pattachment->proplist.get<const BINARY>(PR_ATTACH_DATA_BIN);
	if (bv != nullptr && bv->cb != 0 &&
	    !pmime->write_content(bv->pc, bv->cb, mime_encoding::base64))
		return FALSE;
	return TRUE;
}

static bool smime_signed_writeout(MAIL &origmail, MIME &origmime,
    /* effective-moved-from */ BINARY *hdrs, MIME_FIELD &f) try
{
	if (hdrs == nullptr || hdrs->cb == 0) {
		auto cbg = strdup("\r\n");
		if (cbg == nullptr)
			return false;
		origmime.content_buf.reset(cbg);
		origmime.content_begin = origmime.content_buf.get();
		origmime.content_length = 2;
		origmime.mime_type = mime_type::single;
		gx_strlcpy(origmime.content_type, "text/plain", std::size(origmime.content_type));
		origmime.head_touched = TRUE;
		return true;
	}
	auto sec = MIME::create();
	if (sec == nullptr)
		return false;
	char buf[512];
	if (!sec->load_from_str_move(nullptr, hdrs->pc, hdrs->cb))
		return false;
	if (!sec->get_field("Content-Type", buf, std::size(buf)))
		return false;
	if (strncasecmp(buf, "multipart/signed", 16) != 0)
		return false;
	if (buf[16] != '\0' && buf[16] != ';')
		return false;
	origmime.f_type_params.insert(origmime.f_type_params.end(),
		std::make_move_iterator(sec->f_type_params.begin()),
		std::make_move_iterator(sec->f_type_params.end()));
	origmime.f_other_fields.insert(origmime.f_other_fields.end(),
		std::make_move_iterator(sec->f_other_fields.begin()),
		std::make_move_iterator(sec->f_other_fields.end()));

	auto content = static_cast<char *>(HX_memdup(sec->content_begin, sec->content_length));
	if (content == nullptr)
		return false;
	origmime.content_buf.reset(content);
	origmime.content_begin = origmime.content_buf.get();
	origmime.content_length = sec->content_length;
	origmime.mime_type = mime_type::single;
	gx_strlcpy(origmime.content_type, "multipart/signed", std::size(origmime.content_type));
	origmime.head_touched = TRUE;
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1093: ENOMEM");
	return false;
}

BOOL oxcmail_export(const MESSAGE_CONTENT *pmsg, BOOL b_tnef,
    enum oxcmail_body body_type,
    MAIL *pmail, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    GET_PROPNAME get_propname) try
{
	int i;
	ICAL ical;
	MIME *phtml;
	MIME *pmime;
	MIME *pplain;
	MIME *pmixed;
	BOOL b_inline;
	MIME *prelated;
	MIME *pcalendar;
	char tmp_method[32];
	char tmp_charset[32];
	const char *pcharset;
	MIME_FIELD mime_field;
	ATTACHMENT_CONTENT *pattachment;
	
	pmail->clear();
	auto num = pmsg->proplist.get<uint32_t>(PR_INTERNET_CPID);
	if (num == nullptr || *num == 1200) {
		pcharset = "utf-8";
	} else {
		pcharset = cpid_to_cset(static_cast<cpid_t>(*num));
		if (pcharset == nullptr)
			pcharset = "utf-8";
	}
	mime_skeleton mime_skeleton;
	if (!oxcmail_load_mime_skeleton(pmsg, pcharset, b_tnef,
	    body_type, &mime_skeleton))
		return FALSE;
	auto phead = pmail->add_head();
	if (phead == nullptr)
		return false;
	pmime = phead;
	pplain = NULL;
	phtml = NULL;
	pmixed = NULL;
	prelated = NULL;
	pcalendar = NULL;
	switch (mime_skeleton.mail_type) {
	case oxcmail_type::dsn:
	case oxcmail_type::mdn:
	case oxcmail_type::normal:
	case oxcmail_type::calendar:
		if (mime_skeleton.mail_type == oxcmail_type::dsn) {
			pmixed = pmime;
			if (!pmime->set_content_type("multipart/report") ||
			    !pmime->set_content_param("report-type", "delivery-status") ||
			    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
				return false;
		} else if (mime_skeleton.mail_type == oxcmail_type::mdn) {
			pmixed = pmime;
			if (!pmime->set_content_type("multipart/report") ||
			    !pmime->set_content_param("report-type", "disposition-notification") ||
			    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
				return false;
		} else {
			if (mime_skeleton.b_attachment) {
				pmixed = pmime;
				if (!pmime->set_content_type("multipart/mixed") ||
				    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
					return false;
			}
		}
		if (mime_skeleton.b_inline) {
			prelated = pmime;
			if (!pmime->set_content_type("multipart/related") ||
			    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
				return false;
		}
		if (mime_skeleton.body_type == oxcmail_body::plain_and_html &&
			NULL != mime_skeleton.pplain && NULL != mime_skeleton.phtml) {
			if (!pmime->set_content_type("multipart/alternative"))
				return false;
			pplain = pmail->add_child(pmime, MIME_ADD_LAST);
			phtml = pmail->add_child(pmime, MIME_ADD_LAST);
			if (pplain == nullptr || !pplain->set_content_type("text/plain") ||
			    phtml == nullptr || !phtml->set_content_type("text/html"))
				return false;
			if (mime_skeleton.mail_type == oxcmail_type::calendar) {
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (pcalendar == nullptr ||
				    !pcalendar->set_content_type("text/calendar"))
					return false;
			}
		} else if (mime_skeleton.body_type == oxcmail_body::plain_only &&
		    mime_skeleton.pplain != nullptr) {
 PLAIN_ONLY:
			if (mime_skeleton.mail_type != oxcmail_type::calendar) {
				if (!pmime->set_content_type("text/plain"))
					return false;
				pplain = pmime;
			} else {
				if (!pmime->set_content_type("multipart/alternative"))
					return false;
				pplain = pmail->add_child(pmime, MIME_ADD_LAST);
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (pplain == nullptr || !pplain->set_content_type("text/plain") ||
				    pcalendar == nullptr || !pcalendar->set_content_type("text/calendar"))
					return false;
			}
		} else if (mime_skeleton.body_type == oxcmail_body::html_only &&
		    mime_skeleton.phtml != nullptr) {
 HTML_ONLY:
			if (mime_skeleton.mail_type != oxcmail_type::calendar) {
				if (!pmime->set_content_type("text/html"))
					return false;
				phtml = pmime;
			} else {
				if (!pmime->set_content_type("multipart/alternative"))
					return false;
				phtml = pmail->add_child(pmime, MIME_ADD_LAST);
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (phtml == nullptr || !phtml->set_content_type("text/html") ||
				    pcalendar == nullptr || !pcalendar->set_content_type("text/calendar"))
					return false;
			}
		} else if (NULL != mime_skeleton.phtml) {
			mime_skeleton.body_type = oxcmail_body::html_only;
			goto HTML_ONLY;
		} else {
			mime_skeleton.body_type = oxcmail_body::plain_only;
			goto PLAIN_ONLY;
		}
		break;
	case oxcmail_type::tnef:
		if (!pmime->set_content_type("multipart/mixed"))
			return false;
		if ((pplain = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr ||
		    !pplain->set_content_type("text/plain"))
			return false;
		break;
	case oxcmail_type::xsigned:
	case oxcmail_type::encrypted:
		break;
	}
	
	if (!oxcmail_export_mail_head(pmsg, &mime_skeleton, alloc,
	    get_propids, get_propname, phead))
		return false;
	
	if (mime_skeleton.mail_type == oxcmail_type::encrypted) {
		if (!pmime->set_content_type("application/pkcs7-mime"))
			return false;
		if (NULL == pmsg->children.pattachments ||
		    pmsg->children.pattachments->count != 1)
			return false;
		auto pbin = pmsg->children.pattachments->pplist[0]->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
		if (pbin != nullptr && !pmime->write_content(pbin->pc,
		    pbin->cb, mime_encoding::base64))
			return false;
		return TRUE;
	} else if (mime_skeleton.mail_type == oxcmail_type::xsigned) {
		auto a = pmsg->children.pattachments;
		if (a == nullptr || a->count == 0) {
			/* No idea what gives. But oh well, emit just the header then. */
			pmime->mime_type = mime_type::single;
			return TRUE;
		} else if (a->count != 1) {
			mlog(LV_DEBUG, "Signed SMIME mail with more than one attachment, what is this?!");
			return false;
		}
		auto pbin = a->pplist[0]->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
		if (!smime_signed_writeout(*pmail, *pmime, pbin, mime_field))
			return false;
		return TRUE;
	}
	
	if (NULL != pplain) {
		if (NULL == mime_skeleton.pplain ||
			'\0' == mime_skeleton.pplain[0]) {
			if (!pplain->write_content("\r\n", 2, mime_encoding::base64))
				return false;
		} else {
			auto alloc_size = worst_encoding_overhead(strlen(mime_skeleton.pplain)) + 1;
			std::unique_ptr<char[]> pbuff;
			try {
				pbuff = std::make_unique<char[]>(alloc_size);
			} catch (const std::bad_alloc &) {
				mlog(LV_ERR, "E-1508: ENOMEM");
				return false;
			}
			if (!string_from_utf8(mime_skeleton.charset,
			    mime_skeleton.pplain, pbuff.get(), alloc_size)) {
				pbuff.reset();
				if (!pplain->write_content(mime_skeleton.pplain,
				    strlen(mime_skeleton.pplain), mime_encoding::automatic))
					return false;
				strcpy(tmp_charset, "\"utf-8\"");
			} else {
				if (!pplain->write_content(pbuff.get(),
				    strlen(pbuff.get()), mime_encoding::automatic))
					return false;
				snprintf(tmp_charset, std::size(tmp_charset), "\"%s\"", mime_skeleton.charset);
			}
			if (!pplain->set_content_param("charset", tmp_charset))
				return false;
		}
	}
	
	if (mime_skeleton.mail_type == oxcmail_type::tnef) {
		pmime = pmail->add_child(pmime, MIME_ADD_LAST);
		BINARY *pbin = nullptr;
		if (pmime == nullptr || !pmime->set_content_type("application/ms-tnef"))
			return false;
		pbin = tnef_serialize(pmsg, alloc, get_propname);
		if (pbin == nullptr)
			return false;
		if (!pmime->write_content(pbin->pc, pbin->cb, mime_encoding::base64)) {
			rop_util_free_binary(pbin);
			return false;
		}
		rop_util_free_binary(pbin);
		if (!pmime->set_content_param("name", "\"winmail.dat\"") ||
		    !pmime->set_field("Content-Disposition",
			"attachment; filename=\"winmail.dat\""))
			return false;
		return TRUE;
	}
	
	if (NULL != phtml) {
		if (!phtml->write_content(mime_skeleton.phtml->pc,
		    mime_skeleton.phtml->cb, mime_encoding::automatic))
			return false;
		snprintf(tmp_charset, std::size(tmp_charset), "\"%s\"", mime_skeleton.charset);
		if (!phtml->set_content_param("charset", tmp_charset))
			return false;
	}
	
	if (NULL != pcalendar) {
		char tmp_buff[1024*1024];
		
		if (!oxcical_export(pmsg, ical, alloc,
		    get_propids, oxcmail_entryid_to_username,
		    oxcmail_essdn_to_username)) {
			mlog(LV_WARN, "W-2186: oxcical_export failed for an unspecified reason");
			return false;
		}
		tmp_method[0] = '\0';
		auto piline = ical.get_line("METHOD");
		if (NULL != piline) {
			auto str = deconst(piline->get_first_subvalue());
			if (str != nullptr)
				gx_strlcpy(tmp_method, str, std::size(tmp_method));
		}
		if (!ical.serialize(tmp_buff, std::size(tmp_buff)))
			return false;
		if (!pcalendar->write_content(tmp_buff, strlen(tmp_buff),
		    mime_encoding::automatic))
			return false;
		if (!pcalendar->set_content_param("charset", "\"utf-8\""))
			return false;
		if (*tmp_method != '\0')
			pcalendar->set_content_param("method", tmp_method);
	}
	
	if (mime_skeleton.mail_type == oxcmail_type::dsn) {
		char tmp_buff[1024*1024];
		
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (pmime == nullptr)
			return false;
		if (!pmime->set_content_type("message/delivery-status"))
			return false;
		if (!oxcmail_export_dsn(pmsg, mime_skeleton.charset,
		    mime_skeleton.pmessage_class, alloc, tmp_buff, sizeof(tmp_buff)))
			return false;
		if (!pmime->write_content(tmp_buff, strlen(tmp_buff),
		    mime_encoding::none))
			return false;
	} else if (mime_skeleton.mail_type == oxcmail_type::mdn) {
		char tmp_buff[1024*1024];
		
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (pmime == nullptr)
			return false;
		if (!pmime->set_content_type("message/disposition-notification"))
			return false;
		if (!oxcmail_export_mdn(pmsg, mime_skeleton.charset,
		    mime_skeleton.pmessage_class, alloc, tmp_buff,
		    std::size(tmp_buff)))
			return false;
		if (!pmime->write_content(tmp_buff, strlen(tmp_buff),
		    mime_encoding::none))
			return false;
	}
	
	if (NULL != mime_skeleton.pattachments) {
		for (i=0; i<mime_skeleton.pattachments->count; i++) {
			pmime = pmail->add_child(prelated, MIME_ADD_LAST);
			if (pmime == nullptr)
				return false;
			if (!oxcmail_export_attachment(mime_skeleton.pattachments->pplist[i],
			    TRUE, &mime_skeleton, alloc, get_propids,
			    get_propname, pmime))
				return false;
		}
	}
	
	if (pmsg->children.pattachments == nullptr)
		return TRUE;
	for (i=0; i<pmsg->children.pattachments->count; i++) {
		pattachment = pmsg->children.pattachments->pplist[i];
		if (NULL != pattachment->pembedded) {
			auto str = pattachment->pembedded->proplist.get<const char>(PR_MESSAGE_CLASS);
			if (str != nullptr && strcasecmp(str,
			    "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}") == 0)
				continue;
		}
		if (NULL == pattachment->pembedded &&
		    (num = pattachment->proplist.get<uint32_t>(PR_ATTACH_FLAGS)) != nullptr &&
		    (*num & ATT_MHTML_REF) &&
		    (pattachment->proplist.has(PR_ATTACH_CONTENT_ID) ||
		    pattachment->proplist.has(PR_ATTACH_CONTENT_LOCATION))) {
			b_inline = TRUE;
			pmime = pmail->add_child(prelated, MIME_ADD_LAST);
		} else {
			b_inline = FALSE;
			pmime = pmail->add_child(pmixed, MIME_ADD_LAST);
		}
		if (pmime == nullptr)
			return false;
		if (!oxcmail_export_attachment(pattachment,
		    b_inline, &mime_skeleton, alloc, get_propids,
		    get_propname, pmime))
			return false;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2181: ENOMEM");
	return false;
}

enum oxcmail_body get_override_format(const MESSAGE_CONTENT &mc)
{
	auto v = mc.proplist.get<uint32_t>(PR_INETMAIL_OVERRIDE_FORMAT);
	if (v == nullptr)
		return oxcmail_body::plain_and_html;
	else if (*v & MESSAGE_FORMAT_PLAIN_AND_HTML)
		return oxcmail_body::plain_and_html;
	else if (*v & MESSAGE_FORMAT_HTML_ONLY)
		return oxcmail_body::html_only;
	return oxcmail_body::plain_only;
}
