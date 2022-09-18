// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
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
#include <gromox/apple_util.hpp>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/html.hpp>
#include <gromox/ical.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mime_pool.hpp>
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
	FIELD_ENUM_PARAM(FIELD_ENUM_PARAM &&) = delete;
	void operator=(FIELD_ENUM_PARAM &&) = delete;

	EXT_BUFFER_ALLOC alloc{};
	MESSAGE_CONTENT *pmsg = nullptr;
	namemap &phash;
	uint16_t last_propid = 0;
	const char *charset = nullptr;
	bool b_classified = false, b_flag_del = false;
	MAIL *pmail = nullptr;
};

struct MIME_ENUM_PARAM {
	MIME_ENUM_PARAM(namemap &r) : phash(r) {}
	MIME_ENUM_PARAM(MIME_ENUM_PARAM &&) = delete;
	void operator=(MIME_ENUM_PARAM &&) = delete;

	bool b_result = false;
	int attach_id = 0;
	const char *charset = nullptr, *str_zone = nullptr;
	GET_PROPIDS get_propids{};
	EXT_BUFFER_ALLOC alloc{};
	std::shared_ptr<MIME_POOL> pmime_pool;
	MESSAGE_CONTENT *pmsg = nullptr;
	namemap phash;
	uint16_t last_propid = 0;
	uint64_t nttime_stamp = 0;
	MIME *pplain = nullptr, *phtml = nullptr, *penriched = nullptr;
	MIME *pcalendar = nullptr, *preport = nullptr;
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

struct addr_tags {
	uint32_t pr_name, pr_addrtype, pr_emaddr, pr_smtpaddr, pr_entryid;
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
	BINARY rtf_bin{};
	char *pplain = nullptr;
	BINARY *phtml = nullptr;
	const char *charset = nullptr, *pmessage_class = nullptr;
	ATTACHMENT_LIST *pattachments = nullptr;
};
using MIME_SKELETON = mime_skeleton;
}

static constexpr char
	PidNameAttachmentMacContentType[] = "AttachmentMacContentType",
	PidNameAttachmentMacInfo[] = "AttachmentMacInfo",
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
	gx_strlcpy(g_oxcmail_org_name, org_name, arsizeof(g_oxcmail_org_name));
	oxcmail_get_user_ids = get_user_ids;
	oxcmail_get_username = get_username;
	textmaps_init();
	tnef_init_library();
	if (!rtf_init_library() || !html_init_library())
		return FALSE;	
	return TRUE;
}

static BOOL oxcmail_username_to_essdn(const char *username,
    char *pessdn, enum display_type *dtpp)
{
	int user_id;
	int domain_id;
	char *pdomain;
	char tmp_name[UADDR_SIZE];
	char hex_string[16];
	char hex_string2[16];
	
	gx_strlcpy(tmp_name, username, GX_ARRAY_SIZE(tmp_name));
	pdomain = strchr(tmp_name, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	*pdomain = '\0';
	pdomain ++;
	enum display_type dtypx = DT_MAILUSER;
	if (!oxcmail_get_user_ids(username, &user_id, &domain_id, &dtypx)) {
		return FALSE;
	}
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

static BOOL oxcmail_essdn_to_username(const char *pessdn,
    char *username, size_t ulen)
{
	int user_id;
	char tmp_buff[1024];
	
	auto tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
	               "/o=%s/ou=Exchange Administrative"
		" Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=", g_oxcmail_org_name);
	if (0 != strncasecmp(pessdn, tmp_buff, tmp_len)) {
		return FALSE;
	}
	user_id = decode_hex_int(pessdn + tmp_len + 8);
	return oxcmail_get_username(user_id, username, ulen);
}

static BOOL oxcmail_entryid_to_username(const BINARY *pbin,
    EXT_BUFFER_ALLOC alloc, char *username, size_t ulen)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	FLATUID provider_uid;
	
	if (pbin->cb < 20) {
		return FALSE;
	}
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
	int status;
	EXT_PUSH ext_push;
	ONEOFF_ENTRYID tmp_entry;
	
	tmp_entry.flags = 0;
	tmp_entry.version = 0;
	tmp_entry.ctrl_flags = CTRL_FLAG_NORICH | CTRL_FLAG_UNICODE;
	tmp_entry.pdisplay_name = pdisplay_name != nullptr && *pdisplay_name != '\0' ?
	                          deconst(pdisplay_name) : deconst(username);
	tmp_entry.paddress_type = deconst("SMTP");
	tmp_entry.pmail_address = deconst(username);
	if (!ext_push.init(pbin->pb, 1280, EXT_FLAG_UTF16))
		return false;
	status = ext_push.p_oneoff_eid(tmp_entry);
	if (EXT_ERR_CHARCNV == status) {
		tmp_entry.ctrl_flags = CTRL_FLAG_NORICH;
		status = ext_push.p_oneoff_eid(tmp_entry);
	}
	if (EXT_ERR_SUCCESS != status) {
		return FALSE;
	}
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

static inline bool oxcmail_check_ascii(const char *s)
{
	return std::all_of(s, s + strlen(s),
	       [](unsigned char c) { return isascii(c); });
}

static unsigned int pick_strtype(const char *token)
{
	return oxcmail_check_ascii(token) ? PT_UNICODE : PT_STRING8;
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
	if ('\0' == value[0]) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_get_field_param(char *field,
	const char *tag, char *value, int length)
{
	char *pend;
	int tmp_len;
	char *pbegin;
	char *ptoken;
	
	ptoken = strchr(field, ';');
	if (NULL == ptoken) {
		return FALSE;
	}
	ptoken ++;
	pbegin = strcasestr(ptoken, tag);
	if (NULL == pbegin) {
		return FALSE;
	}
	pbegin += strlen(tag);
	if ('=' != *pbegin) {
		return FALSE;
	}
	pbegin ++;
	pend = strchr(pbegin, ';');
	tmp_len = pend == nullptr ? strlen(pbegin) : pend - pbegin;
	if (tmp_len >= length) {
		return FALSE;
	}
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
	if ('\0' == value[0]) {
		return FALSE;
	}
	return TRUE;
}

static void oxcmail_split_filename(char *file_name, char *extension)
{
	int i;
	int tmp_len;
	char *ptoken;
	
	tmp_len = strlen(file_name);
	for (i=0; i<tmp_len; i++) {
		if ('"' == file_name[i] || '/' == file_name[i] ||
			':' == file_name[i] || '<' == file_name[i] ||
			'>' == file_name[i] || '|' == file_name[i] ||
			'\\' == file_name[i] || (file_name[i] >= 0 &&
			file_name[i] <= 0x1F)) {
			file_name[i] = '_';
		}
	}
	for (i=0; i<tmp_len; i++) {
		if ('.' == file_name[i]) {
			file_name[i] = ' ';
			continue;
		}
		break;
	}
	HX_strltrim(file_name);
	tmp_len = strlen(file_name);
	for (i=tmp_len-1; i>=0; i--) {
		if ('.' == file_name[i]) {
			file_name[i] = ' ';
			continue;
		}
		break;
	}
	HX_strrtrim(file_name);
	ptoken = strrchr(file_name, '.');
	if (NULL == ptoken || strlen(ptoken) >= 16) {
		extension[0] = '\0';
	} else {
		strcpy(extension, ptoken);
	}
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
	if (NULL == pproplist) {
		return FALSE;
	}
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
	if (paddr->has_addr() && oxcmail_check_ascii(paddr->local_part) &&
	    oxcmail_check_ascii(paddr->domain)) {
		snprintf(username, GX_ARRAY_SIZE(username), "%s@%s", paddr->local_part, paddr->domain);
		auto dtypx = DT_MAILUSER;
		if (!oxcmail_username_to_essdn(username, essdn, &dtypx)) {
			essdn[0] = '\0';
			dtypx = DT_MAILUSER;
			tmp_bin.cb = snprintf(tmp_buff, arsizeof(tmp_buff), "SMTP:%s", username) + 1;
			HX_strupper(tmp_buff);
			if (pproplist->set(PR_ADDRTYPE, "SMTP") != 0 ||
			    pproplist->set(PR_EMAIL_ADDRESS, username) != 0)
				return FALSE;
		} else {
			tmp_bin.cb = snprintf(tmp_buff, arsizeof(tmp_buff), "EX:%s", essdn) + 1;
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
		tmp_int32 = dtypx == DT_DISTLIST ? MAPI_DISTLIST : MAPI_MAILUSER;
		if (pproplist->set(PR_OBJECT_TYPE, &tmp_int32) != 0)
			return FALSE;
		tmp_int32 = static_cast<uint32_t>(dtypx);
		if (pproplist->set(PR_DISPLAY_TYPE, &tmp_int32) != 0)
			return FALSE;
		tmp_int32 = recipSendable;
		if (pproplist->set(PR_RECIPIENT_FLAGS, &tmp_int32) != 0)
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
	fprintf(stderr, "E-2049: ENOMEM\n");
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
		fprintf(stderr, "E-2023: ENOMEM\n");
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
		snprintf(username, GX_ARRAY_SIZE(username), "%s@%s", paddr->local_part, paddr->domain);
		if (pproplist->set(pr_name, username) != 0)
			return FALSE;
	}
	bool ok = paddr->has_addr() && oxcmail_check_ascii(paddr->local_part) &&
	          oxcmail_check_ascii(paddr->domain);
	if (!ok)
		return TRUE;
	snprintf(username, GX_ARRAY_SIZE(username), "%s@%s", paddr->local_part, paddr->domain);
	if (pproplist->set(pr_addrtype, "SMTP") != 0 ||
	    pproplist->set(pr_emaddr, username) != 0 ||
	    pproplist->set(pr_smtpaddr, username) != 0)
		return FALSE;
	if (!oxcmail_username_to_essdn(username, essdn, NULL)) {
		essdn[0] = '\0';
		tmp_bin.cb = snprintf(tmp_buff, arsizeof(tmp_buff), "SMTP:%s", username) + 1;
		HX_strupper(tmp_buff);
	} else {
		tmp_bin.cb = snprintf(tmp_buff, arsizeof(tmp_buff), "EX:%s", essdn) + 1;
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
	int status;
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
		fprintf(stderr, "E-2022: ENOMEM\n");
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

		if (email_addr.has_addr() &&
		    oxcmail_check_ascii(email_addr.local_part) &&
		    oxcmail_check_ascii(email_addr.domain)) {
			uint32_t offset1 = ext_push.m_offset;
			if (ext_push.advance(sizeof(uint32_t)) != EXT_ERR_SUCCESS)
				return FALSE;
			snprintf(tmp_buff, arsizeof(tmp_buff), "%s@%s",
			         email_addr.local_part, email_addr.domain);
			tmp_entry.ctrl_flags = CTRL_FLAG_NORICH | CTRL_FLAG_UNICODE;
			status = ext_push.p_oneoff_eid(tmp_entry);
			if (EXT_ERR_CHARCNV == status) {
				ext_push.m_offset = offset1 + sizeof(uint32_t);
				tmp_entry.ctrl_flags = CTRL_FLAG_NORICH;
				status = ext_push.p_oneoff_eid(tmp_entry);
			}
			if (EXT_ERR_SUCCESS != status) {
				return FALSE;
			}
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
		if (subject_len < 0) {
			subject_len = 0;
		}
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
	if (NULL == ptoken) {
		return TRUE;
	}
	tmp_len = ptoken - tmp_buff;
	if (tmp_len < 2 || tmp_len > 6) {
		return TRUE;
	}
	for (i = 0; i < tmp_len; i += 2) {
		if ((':' == tmp_buff[i] ||
		    ' ' == tmp_buff[i] ||
		    HX_isdigit(tmp_buff[0])) &&
		    '\0' == tmp_buff[i + 1]) {
			return TRUE;
		}
	}
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
	if (decode64(field, strlen(field), tmp_buff, arsizeof(tmp_buff), &len) != 0)
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
		gx_strlcpy(tmp_buff, field, GX_ARRAY_SIZE(tmp_buff));
	} else {
		tag = PROP_TAG(PT_MV_UNICODE, propid);
	}
	strings.count = 0;
	strings.ppstr = string_buff;
	len = strlen(tmp_buff);
	tmp_buff[len] = ';';
	len ++;
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
	if (0 == strings.count) {
		return TRUE;
	}
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
	field[len] = ';';
	len ++;
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
			if (0 == strcasecmp("DR", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_DR;
			} else if (0 == strcasecmp("NDR", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_NDR;
			} else if (0 == strcasecmp("RN", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_RN;
			} else if (0 == strcasecmp("NRN", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_NRN;
			} else if (0 == strcasecmp("OOF", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_OOF;
			} else if (0 == strcasecmp("AutoReply", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_AUTOREPLY;
			}
			b_start = FALSE;
			ptoken_prev = field + i + 1;
		}
	}
	if (0 == tmp_int32) {
		return TRUE;
	}
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

static BOOL oxcmail_parse_content_class(const char *field, MAIL *pmail,
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
		if (NULL == pmime) {
			return TRUE;
		}
		if (strcasecmp(pmime->content_type, "text/html") != 0)
			return TRUE;
		pmime = pmime->get_sibling();
		if (NULL == pmime) {
			return TRUE;
		}
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
		snprintf(tmp_class, arsizeof(tmp_class), "IPM.Note.Custom.%s", field + 25);
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
		snprintf(tmp_class, arsizeof(tmp_class), "IPM.InfoPathForm.%s", field + 13);
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
	uint8_t tmp_byte;
	
	if (strcasecmp(field, "true") != 0 && strcasecmp(field, "false") != 0)
		return TRUE;
	PROPERTY_NAME propname = {MNID_ID, PSETID_COMMON, PidLidClassificationKeep};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (0 == strcasecmp(field, "true")) {
		tmp_byte = 1;
	} else if (0 == strcasecmp(field, "false")) {
		tmp_byte = 0;
	}
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
	FIELD_ENUM_PARAM *penum_param;
	
	penum_param = (FIELD_ENUM_PARAM*)pparam;
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
		uint32_t tag = oxcmail_check_ascii(field) ?
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
		uint32_t tag = oxcmail_check_ascii(field) ?
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
		uint32_t tag = oxcmail_check_ascii(field) ?
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
		uint32_t tag = oxcmail_check_ascii(field) ?
		               PR_LIST_HELP : PR_LIST_HELP_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "List-Subscribe") == 0 ||
		strcasecmp(key, "X-List-Subscribe") == 0) {
		uint32_t tag = oxcmail_check_ascii(field) ?
		               PR_LIST_SUBSCRIBE : PR_LIST_SUBSCRIBE_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "List-Unsubscribe") == 0 ||
		strcasecmp(key, "X-List-Unsubscribe") == 0) {
		uint32_t tag = oxcmail_check_ascii(field) ?
		               PR_LIST_UNSUBSCRIBE : PR_LIST_UNSUBSCRIBE_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-Payload-Class") == 0) {
		uint32_t tag = oxcmail_check_ascii(field) ?
		               PR_ATTACH_PAYLOAD_CLASS : PR_ATTACH_PAYLOAD_CLASS_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-MS-Exchange-Organization-PRD") == 0) {
		uint32_t tag = oxcmail_check_ascii(field) ?
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
		uint32_t tag = oxcmail_check_ascii(field) ?
		               PR_SENDER_TELEPHONE_NUMBER :
		               PR_SENDER_TELEPHONE_NUMBER_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-VoiceMessageSenderName") == 0) {
		uint32_t tag = oxcmail_check_ascii(field) ?
		                  PidTagVoiceMessageSenderName :
		                  PidTagVoiceMessageSenderName_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-AttachmentOrder") == 0) {
		uint32_t tag = oxcmail_check_ascii(field) ?
		               PidTagVoiceMessageAttachmentOrder :
		               PidTagVoiceMessageAttachmentOrder_A;
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
	} else if (strcasecmp(key, "X-CallID") == 0) {
		uint32_t tag = oxcmail_check_ascii(field) ?
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
			uint32_t tag = oxcmail_check_ascii(field) ?
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
		uint32_t tag = oxcmail_check_ascii(field) ?
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
		if (NULL == propname.pname) {
			return FALSE;
		}
		strcpy(propname.pname, key);
		if (namemap_add(penum_param->phash, penum_param->last_propid,
		    std::move(propname)) != 0)
			return FALSE;
		uint32_t tag = PROP_TAG(pick_strtype(field), penum_param->last_propid);
		if (penum_param->pmsg->proplist.set(tag, field) != 0)
			return FALSE;
		penum_param->last_propid ++;
	}
	return TRUE;
}

static BOOL oxcmail_parse_transport_message_header(
	MIME *pmime, TPROPVAL_ARRAY *pproplist)
{
	size_t tmp_len;
	char tmp_buff[1024*1024];
	
	tmp_len = sizeof(tmp_buff) - 1;
	if (!pmime->read_head(tmp_buff, &tmp_len))
		return TRUE;
	tmp_buff[tmp_len + 1] = '\0';
	uint32_t tag = oxcmail_check_ascii(tmp_buff) ?
	               PR_TRANSPORT_MESSAGE_HEADERS :
	               PR_TRANSPORT_MESSAGE_HEADERS_A;
	if (pproplist->set(tag, tmp_buff) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcmail_parse_message_body(const char *charset,
	MIME *pmime, TPROPVAL_ARRAY *pproplist)
{
	BINARY tmp_bin;
	char best_charset[32];
	char temp_charset[32];
	const char *content_type;
	
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
		return false;
	}
	size_t length = rdlength;
	auto content_size = 3 * length + 2;
	auto pcontent = me_alloc<char>(content_size);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (!pmime->read_content(pcontent, &length)) {
		free(pcontent);
		return TRUE;
	}
	if (oxcmail_get_content_param(pmime, "charset", temp_charset, 32))
		gx_strlcpy(best_charset, temp_charset, GX_ARRAY_SIZE(best_charset));
	else
		gx_strlcpy(best_charset, charset, GX_ARRAY_SIZE(best_charset));
	content_type = pmime->content_type;
	if (0 == strcasecmp(content_type, "text/html")) {
		uint32_t tmp_int32 = cset_to_cpid(best_charset);
		if (pproplist->set(PR_INTERNET_CPID, &tmp_int32) != 0) {
			free(pcontent);
			return FALSE;
		}
		tmp_bin.cb = length;
		tmp_bin.pc = pcontent;
		if (pproplist->set(PR_HTML, &tmp_bin) != 0) {
			free(pcontent);
			return false;
		}
	} else if (0 == strcasecmp(content_type, "text/plain")) {
		pcontent[length] = '\0';
		TAGGED_PROPVAL propval;
		if (string_to_utf8(best_charset, pcontent, pcontent + length + 1,
		    content_size - length - 1)) {
			auto s = pcontent + length + 1;
			propval.proptag = PR_BODY;
			propval.pvalue = s;
			if (!utf8_check(s))
				utf8_filter(s);
		} else {
			propval.proptag = PR_BODY_A;
			propval.pvalue = pcontent;
		}
		if (pproplist->set(propval) != 0) {
			free(pcontent);
			return false;
		}
	} else if (0 == strcasecmp(content_type, "text/enriched")) {
		pcontent[length] = '\0';
		enriched_to_html(pcontent, pcontent + length + 1, 2*length);
		uint32_t tmp_int32 = cset_to_cpid(best_charset);
		if (pproplist->set(PR_INTERNET_CPID, &tmp_int32) != 0) {
			free(pcontent);
			return FALSE;
		}
		tmp_bin.cb = strlen(pcontent + length + 1);
		tmp_bin.pc = pcontent + length + 1;
		if (pproplist->set(PR_HTML, &tmp_bin) != 0) {
			free(pcontent);
			return false;
		}
	}
	free(pcontent);
	return TRUE;
}

static void oxcmail_compose_mac_additional(
	uint32_t type, uint32_t creator, BINARY *pbin)
{
	int i, tmp_len;
	uint8_t tmp_buff[16];
	
	tmp_len = 0;
	tmp_buff[tmp_len] = ':';
	tmp_len ++;
	memcpy(tmp_buff + tmp_len, &creator, 4);
	tmp_len += 4;
	tmp_buff[tmp_len] = ':';
	tmp_len ++;
	memcpy(tmp_buff + tmp_len, &type, 4);
	tmp_len += 4;
	tmp_buff[tmp_len] = '\0';
	tmp_len ++;
	pbin->cb = 0;
	for (i=0; i<tmp_len; i++) {
		if (0 == i || 5 == i) {
			pbin->pb[pbin->cb] = ':';
			pbin->cb ++;
			continue;
		}
		if ('\\' == tmp_buff[i] || ':' == tmp_buff[i] || ';' == tmp_buff[i]) {
			pbin->pb[pbin->cb] = '\\';
			pbin->cb ++;
			pbin->pb[pbin->cb] = tmp_buff[i];
			pbin->cb ++;
		} else if (tmp_buff[i] < 32 || tmp_buff[i] > 251 || 127 == tmp_buff[i]) {
			pbin->pb[pbin->cb] = '\\';
			pbin->cb ++;
			sprintf(pbin->pc + pbin->cb, "%03o", tmp_buff[i]);
		} else {
			pbin->pb[pbin->cb] = tmp_buff[i];
			pbin->cb ++;
		}
	}
}

static BOOL oxcmail_set_mac_attachname(TPROPVAL_ARRAY *pproplist,
	BOOL b_description, char *tmp_buff)
{
	char extension[64];
	
	oxcmail_split_filename(tmp_buff, extension);
	if (!b_description && pproplist->set(PR_DISPLAY_NAME_A, tmp_buff) != 0)
		return FALSE;
	if (extension[0] != '\0' &&
	    pproplist->set(PR_ATTACH_EXTENSION_A, extension) != 0)
		return FALSE;
	if (pproplist->set(PR_ATTACH_LONG_FILENAME_A, tmp_buff) != 0)
		return FALSE;
	return TRUE;
}

static BOOL oxcmail_parse_binhex(const MIME *pmime, ATTACHMENT_CONTENT *pattachment,
    BOOL b_filename, BOOL b_description, uint16_t *plast_propid, namemap &phash)
{
	BINARY *pbin;
	BINHEX binhex;
	BINARY tmp_bin;
	char tmp_buff[256];
	
	tmp_bin.cb = sizeof(MACBINARY_ENCODING);
	tmp_bin.pb = deconst(MACBINARY_ENCODING);
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
		return FALSE;
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
		return false;
	}
	size_t content_len = rdlength;
	auto pcontent = me_alloc<char>(content_len);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (!pmime->read_content(pcontent, &content_len) ||
	    !binhex_deserialize(&binhex, pcontent, content_len)) {
		free(pcontent);
		return FALSE;
	}
	free(pcontent);
	if (!b_filename) {
		strcpy(tmp_buff, binhex.file_name);
		if (!oxcmail_set_mac_attachname(&pattachment->proplist,
		    b_description, tmp_buff)) {
			binhex_clear(&binhex);
			return FALSE;
		}
	}
	tmp_bin.cb = 0;
	tmp_bin.pc = tmp_buff;
	oxcmail_compose_mac_additional(binhex.type, binhex.creator, &tmp_bin);
	if (pattachment->proplist.set(PR_ATTACH_ADDITIONAL_INFO, &tmp_bin) != 0) {
		binhex_clear(&binhex);
		return FALSE;
	}
	pbin = apple_util_binhex_to_appledouble(&binhex);
	if (NULL == pbin) {
		binhex_clear(&binhex);
		return FALSE;
	}
	PROPERTY_NAME propname = {MNID_STRING, PSETID_ATTACHMENT,
	                         0, deconst(PidNameAttachmentMacInfo)};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0) {
		rop_util_free_binary(pbin);
		binhex_clear(&binhex);
		return FALSE;
	}
	if (pattachment->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), pbin) != 0) {
		rop_util_free_binary(pbin);
		binhex_clear(&binhex);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	(*plast_propid) ++;
	pbin = apple_util_binhex_to_macbinary(&binhex);
	if (NULL == pbin) {
		binhex_clear(&binhex);
		return FALSE;
	}
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, pbin) != 0) {
		rop_util_free_binary(pbin);
		binhex_clear(&binhex);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	binhex_clear(&binhex);
	return TRUE;
}

static BOOL oxcmail_parse_appledouble(const MIME *pmime,
    ATTACHMENT_CONTENT *pattachment, BOOL b_filename, BOOL b_description,
    EXT_BUFFER_ALLOC alloc, uint16_t *plast_propid, namemap &phash)
{
	int i;
	const MIME *phmime, *pdmime;
	BINARY *pbin;
	BINARY tmp_bin;
	EXT_PULL ext_pull;
	char tmp_buff[256];
	APPLEFILE applefile;
	
	phmime = NULL;
	pdmime = NULL;
	auto psub = pmime->get_child();
	if (NULL == psub) {
		return FALSE;
	}
	if (strcasecmp(psub->content_type, "application/applefile") == 0)
		phmime = psub;
	else
		pdmime = psub;
	psub = psub->get_sibling();
	if (NULL == psub) {
		return FALSE;
	}
	if (phmime != nullptr)
		pdmime = psub;
	else if (strcasecmp(psub->content_type, "application/applefile") == 0)
		phmime = psub;
	else
		return FALSE;

	tmp_bin.cb = sizeof(MACBINARY_ENCODING);
	tmp_bin.pb = deconst(MACBINARY_ENCODING);
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
		return FALSE;
	PROPERTY_NAME propname = {MNID_STRING, PSETID_ATTACHMENT, 0,
	                         deconst(PidNameAttachmentMacContentType)};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	if (pattachment->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid),
	    pdmime->content_type) != 0)
		return FALSE;
	(*plast_propid) ++;
	auto rdlength = phmime->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
		return false;
	}
	size_t content_len = rdlength;
	auto pcontent = me_alloc<char>(content_len);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (!phmime->read_content(pcontent, &content_len)) {
		free(pcontent);
		return FALSE;
	}
	propname = {MNID_STRING, PSETID_ATTACHMENT, 0, deconst(PidNameAttachmentMacInfo)};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0) {
		free(pcontent);
		return FALSE;
	}
	tmp_bin.cb = content_len;
	tmp_bin.pb = (uint8_t*)pcontent;
	if (pattachment->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), &tmp_bin) != 0) {
		free(pcontent);
		return FALSE;
	}
	(*plast_propid) ++;
	ext_pull.init(pcontent, content_len, alloc, 0);
	if (EXT_ERR_SUCCESS != applefile_pull_file(&ext_pull, &applefile)) {
		free(pcontent);
		return FALSE;
	}
	for (i=0; i<applefile.count; i++) {
		if (!b_filename && applefile.pentries[i].entry_id == AS_REALNAME) {
			memset(tmp_buff, 0, arsizeof(tmp_buff));
			auto bv = static_cast<BINARY *>(applefile.pentries[i].pentry);
			memcpy(tmp_buff, bv->pb, std::min(bv->cb, static_cast<uint32_t>(255)));
			if (!oxcmail_set_mac_attachname(&pattachment->proplist,
			    b_description, tmp_buff)) {
				free(pcontent);
				return FALSE;
			}
		}
		if (AS_FINDERINFO == applefile.pentries[i].entry_id) {
			tmp_bin.cb = 0;
			tmp_bin.pc = tmp_buff;
			auto as = static_cast<ASFINDERINFO *>(applefile.pentries[i].pentry);
			oxcmail_compose_mac_additional(as->finfo.fd_type,
				as->finfo.fd_creator, &tmp_bin);
			if (pattachment->proplist.set(PR_ATTACH_ADDITIONAL_INFO, &tmp_bin) != 0) {
				free(pcontent);
				return FALSE;
			}
		}
	}
	rdlength = pdmime->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
		free(pcontent);
		return false;
	}
	size_t content_len1 = rdlength;
	auto pcontent1 = me_alloc<char>(content_len1);
	if (NULL == pcontent1) {
		free(pcontent);
		return FALSE;
	}
	if (!pdmime->read_content(pcontent1, &content_len1)) {
		free(pcontent1);
		free(pcontent);
		return FALSE;
	}
	pbin = apple_util_appledouble_to_macbinary(
			&applefile, pcontent1, content_len1);
	if (NULL == pbin) {
		free(pcontent1);
		free(pcontent);
		return FALSE;
	}
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, pbin) != 0) {
		rop_util_free_binary(pbin);
		free(pcontent1);
		free(pcontent);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	free(pcontent1);
	free(pcontent);
	return TRUE;
}

static BOOL oxcmail_parse_macbinary(const MIME *pmime,
    ATTACHMENT_CONTENT *pattachment, BOOL b_filename, BOOL b_description,
    EXT_BUFFER_ALLOC alloc, uint16_t *plast_propid, namemap &phash)
{	
	BINARY *pbin;
	BINARY tmp_bin;
	MACBINARY macbin;
	EXT_PULL ext_pull;
	char tmp_buff[64];
	
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
		return false;
	}
	size_t content_len = rdlength;
	auto pcontent = me_alloc<char>(content_len);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (!pmime->read_content(pcontent, &content_len)) {
		free(pcontent);
		return FALSE;
	}
	ext_pull.init(pcontent, content_len, alloc, 0);
	if (EXT_ERR_SUCCESS != macbinary_pull_binary(&ext_pull, &macbin)) {
		free(pcontent);
		return FALSE;
	}
	tmp_bin.cb = sizeof(MACBINARY_ENCODING);
	tmp_bin.pb = deconst(MACBINARY_ENCODING);
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0) {
		free(pcontent);
		return FALSE;
	}
	if (!b_filename) {
		strcpy(tmp_buff, macbin.header.file_name);
		if (!oxcmail_set_mac_attachname(&pattachment->proplist,
		    b_description, tmp_buff)) {
			free(pcontent);
			return FALSE;
		}
	}
	pbin = apple_util_macbinary_to_appledouble(&macbin);
	if (NULL == pbin) {
		free(pcontent);
		return FALSE;
	}
	PROPERTY_NAME propname = {MNID_STRING, PSETID_ATTACHMENT,
	                         0, deconst(PidNameAttachmentMacInfo)};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0) {
		rop_util_free_binary(pbin);
		free(pcontent);
		return FALSE;
	}
	if (pattachment->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), pbin) != 0) {
		rop_util_free_binary(pbin);
		free(pcontent);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	(*plast_propid) ++;
	tmp_bin.pc = tmp_buff;
	oxcmail_compose_mac_additional(macbin.header.type,
					macbin.header.creator, &tmp_bin);
	if (pattachment->proplist.set(PR_ATTACH_ADDITIONAL_INFO, &tmp_bin) != 0) {
		free(pcontent);
		return FALSE;
	}
	tmp_bin.cb = content_len;
	tmp_bin.pc = pcontent;
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0) {
		free(pcontent);
		return FALSE;
	}
	free(pcontent);
	return TRUE;
}

static BOOL oxcmail_parse_applesingle(const MIME *pmime,
    ATTACHMENT_CONTENT *pattachment, BOOL b_filename, BOOL b_description,
    EXT_BUFFER_ALLOC alloc, uint16_t *plast_propid, namemap &phash)
{
	int i;
	BINARY *pbin;
	BINARY tmp_bin;
	EXT_PULL ext_pull;
	char tmp_buff[256];
	APPLEFILE applefile;
	
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
		return false;
	}
	size_t content_len = rdlength;
	size_t contallocsz = content_len;
	auto pcontent = me_alloc<char>(contallocsz);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (!pmime->read_content(pcontent, &content_len)) {
		free(pcontent);
		return FALSE;
	}
	ext_pull.init(pcontent, content_len, alloc, 0);
	if (EXT_ERR_SUCCESS != applefile_pull_file(&ext_pull, &applefile)) {
		free(pcontent);
		return oxcmail_parse_macbinary(pmime,
			pattachment, b_filename, b_description,
			alloc, plast_propid, phash);
	}
	tmp_bin.cb = sizeof(MACBINARY_ENCODING);
	tmp_bin.pb = deconst(MACBINARY_ENCODING);
	if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0) {
		free(pcontent);
		return FALSE;
	}
	PROPERTY_NAME propname = {MNID_STRING, PSETID_ATTACHMENT,
	                         0, deconst(PidNameAttachmentMacInfo)};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0) {
		free(pcontent);
		return FALSE;
	}
	pbin = apple_util_applesingle_to_appledouble(&applefile);
	if (NULL == pbin) {
		free(pcontent);
		return FALSE;
	}
	if (pattachment->proplist.set(PROP_TAG(PT_BINARY, *plast_propid), pbin) != 0) {
		rop_util_free_binary(pbin);
		free(pcontent);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	(*plast_propid) ++;
	for (i=0; i<applefile.count; i++) {
		if (!b_filename && applefile.pentries[i].entry_id == AS_REALNAME) {
			auto bv = static_cast<BINARY *>(applefile.pentries[i].pentry);
			memset(tmp_buff, 0, arsizeof(tmp_buff));
			memcpy(tmp_buff, bv->pb, std::min(bv->cb, static_cast<uint32_t>(255)));
			if (!oxcmail_set_mac_attachname(&pattachment->proplist,
			    b_description, tmp_buff)) {
				free(pcontent);
				return FALSE;
			}
		}
		if (AS_FINDERINFO == applefile.pentries[i].entry_id) {
			tmp_bin.cb = 0;
			tmp_bin.pc = tmp_buff;
			auto as = static_cast<ASFINDERINFO *>(applefile.pentries[i].pentry);
			oxcmail_compose_mac_additional(as->finfo.fd_type,
				as->finfo.fd_creator, &tmp_bin);
			if (pattachment->proplist.set(PR_ATTACH_ADDITIONAL_INFO, &tmp_bin) != 0) {
				free(pcontent);
				return FALSE;
			}
		}
	}
	pbin = apple_util_applesingle_to_macbinary(&applefile);
	if (NULL == pbin) {
		free(pcontent);
		return FALSE;
	}
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, pbin) != 0) {
		rop_util_free_binary(pbin);
		free(pcontent);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	free(pcontent);
	return TRUE;
}

static void oxcmail_enum_attachment(const MIME *pmime, void *pparam)
{
	const MIME *pmime1 = nullptr;
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
	if (pmime->get_parent() != nullptr &&
	    strcasecmp(pmime->get_parent()->content_type, "multipart/appledouble") == 0)
		return;
	if (pmime->mime_type == mime_type::multiple) {
		if (strcasecmp(pmime->content_type, "multipart/appledouble") != 0)
			return;
		pmime1 = pmime;
		pmime = pmime->get_child();
		if (NULL == pmime) {
			return;
		}
		if (pmime->get_sibling() == nullptr)
			pmime1 = NULL;
		else
			pmime = pmime->get_sibling();
	}
	pmime_enum->b_result = false;
	pattachment = attachment_content_init();
	if (NULL == pattachment) {
		return;
	}
	if (!attachment_list_append_internal(
		pmime_enum->pmsg->children.pattachments, pattachment)) {
		attachment_content_free(pattachment);
		return;
	}
	auto cttype = pmime->content_type;
	auto newval = strcasecmp(cttype, "application/ms-tnef") == 0 ?
	              "application/octet-stream" : cttype;
	if (pattachment->proplist.set(PR_ATTACH_MIME_TAG, newval) != 0) {
		return;
	}
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
	    pattachment->proplist.set(PR_ATTACH_EXTENSION, extension) != 0) {
		return;
	}
	if (pattachment->proplist.set(b_unifn ? PR_ATTACH_LONG_FILENAME :
	    PR_ATTACH_LONG_FILENAME_A, file_name) != 0) {
		return;
	}
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
		if (pattachment->proplist.set(tag, display_name) != 0) {
			return;
		}
	}
	bool b_inline = false;
	if (pmime->get_field("Content-Disposition", tmp_buff, 1024)) {
		b_inline = strcmp(tmp_buff, "inline") == 0 || strncasecmp(tmp_buff, "inline;", 7) == 0;
		if (oxcmail_get_field_param(tmp_buff, "create-date", date_buff, 128) &&
		    parse_rfc822_timestamp(date_buff, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (pattachment->proplist.set(PR_CREATION_TIME, &tmp_int64) != 0) {
				return;
			}
		}
		if (oxcmail_get_field_param(tmp_buff, "modification-date", date_buff, 128) &&
		    parse_rfc822_timestamp(date_buff, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (pattachment->proplist.set(PR_LAST_MODIFICATION_TIME, &tmp_int64) != 0) {
				return;
			}
		}
	}
	if (!pattachment->proplist.has(PR_CREATION_TIME) &&
	    pattachment->proplist.set(PR_CREATION_TIME, &pmime_enum->nttime_stamp) != 0) {
		return;
	}
	if (!pattachment->proplist.has(PR_LAST_MODIFICATION_TIME) &&
	    pattachment->proplist.set(PR_LAST_MODIFICATION_TIME, &pmime_enum->nttime_stamp) != 0) {
		return;
	}
	if (pmime->get_field("Content-ID", tmp_buff, 128)) {
		tmp_int32 = strlen(tmp_buff);
		if (tmp_int32 > 0) {
			if ('>' == tmp_buff[tmp_int32 - 1]) {
				tmp_buff[tmp_int32 - 1] = '\0';
			}
			if ('<' == tmp_buff[0]) {
				newval = tmp_buff + 1;
			} else {
				newval = tmp_buff;
			}
			uint32_t tag = oxcmail_check_ascii(newval) ?
			                  PR_ATTACH_CONTENT_ID : PR_ATTACH_CONTENT_ID_A;
			if (pattachment->proplist.set(tag, newval) != 0) {
				return;
			}
		}
	}
	if (pmime->get_field("Content-Location", tmp_buff, 1024)) {
		uint32_t tag = oxcmail_check_ascii(tmp_buff) ?
		                  PR_ATTACH_CONTENT_LOCATION :
		                  PR_ATTACH_CONTENT_LOCATION_A;
		if (pattachment->proplist.set(tag, tmp_buff) != 0) {
			return;
		}
	}
	if (pmime->get_field("Content-Base", tmp_buff, 1024)) {
		uint32_t tag = oxcmail_check_ascii(tmp_buff) ?
		                  PR_ATTACH_CONTENT_BASE : PR_ATTACH_CONTENT_BASE_A;
		if (pattachment->proplist.set(tag, tmp_buff) != 0) {
			return;
		}
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
		if (pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != 0) {
			return;
		}
	}
	/* Content-Type is multipart/appledouble */
	if (NULL != pmime1) {
		tmp_int32 = ATTACH_BY_VALUE;
		if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0) {
			return;
		}
		pmime_enum->b_result = oxcmail_parse_appledouble(
			pmime1, pattachment, b_filename, b_description,
			pmime_enum->alloc, &pmime_enum->last_propid,
			pmime_enum->phash);
		return;
	}
	if (strcasecmp(cttype, "text/directory") == 0) {
		auto rdlength = pmime->get_length();
		if (rdlength < 0) {
			fprintf(stderr, "%s:MIME::get_length:%u: unsuccessful\n", __func__, __LINE__);
			return;
		}
		size_t content_len = rdlength;
		if (content_len < VCARD_MAX_BUFFER_LEN) {
			auto contallocsz = 3 * content_len + 2;
			std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(contallocsz));
			if (NULL == pcontent) {
				return;
			}
			if (!pmime->read_content(pcontent.get(), &content_len)) {
				return;
			}
			pcontent[content_len] = '\0';
			if (!oxcmail_get_content_param(pmime, "charset",
			    mime_charset, arsizeof(mime_charset)))
				gx_strlcpy(mime_charset, !utf8_check(pcontent.get()) ?
					pmime_enum->charset : "utf-8", GX_ARRAY_SIZE(mime_charset));
			if (string_to_utf8(mime_charset, pcontent.get(),
			    &pcontent[content_len+1], contallocsz - content_len - 1)) {
				if (!utf8_check(pcontent.get() + content_len + 1))
					utf8_filter(pcontent.get() + content_len + 1);
				vcard vcard;
				auto ret = vcard.retrieve_single(pcontent.get() + content_len + 1);
				if (ret == ecSuccess &&
				    (pmsg = oxvcard_import(&vcard, pmime_enum->get_propids)) != nullptr) {
					attachment_content_set_embedded_internal(pattachment, pmsg);
					tmp_int32 = ATTACH_EMBEDDED_MSG;
					if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) == 0)
						pmime_enum->b_result = true;
					return;
				}
			}
			/* parsing as vcard failed */
			tmp_int32 = ATTACH_BY_VALUE;
			if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0) {
				return;
			}
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
			fprintf(stderr, "%s:MIME::get_length:%u: unsuccessful\n", __func__, __LINE__);
			return;
		}
		size_t content_len = rdlength;
		std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(content_len));
		if (NULL == pcontent) {
			return;
		}
		if (!pmime->read_content(pcontent.get(), &content_len)) {
			return;
		}
		MAIL mail(pmime_enum->pmime_pool);
		if (mail.retrieve(pcontent.get(), content_len)) {
			pattachment->proplist.erase(PR_ATTACH_LONG_FILENAME);
			pattachment->proplist.erase(PR_ATTACH_LONG_FILENAME_A);
			pattachment->proplist.erase(PR_ATTACH_EXTENSION);
			pattachment->proplist.erase(PR_ATTACH_EXTENSION_A);
			if (!b_description &&
			    mail.get_head()->get_field("Subject", tmp_buff, 256) &&
			    mime_string_to_utf8(pmime_enum->charset, tmp_buff,
			    file_name, std::size(file_name)) &&
			    pattachment->proplist.set(PR_DISPLAY_NAME, file_name) != 0) {
				return;
			}
			tmp_int32 = ATTACH_EMBEDDED_MSG;
			if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0) {
				return;
			}
			pmsg = oxcmail_import(pmime_enum->charset,
				pmime_enum->str_zone, &mail,
				pmime_enum->alloc, pmime_enum->get_propids);
			if (NULL == pmsg) {
				return;
			}
			attachment_content_set_embedded_internal(pattachment, pmsg);
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
		    mode_buff, arsizeof(mode_buff)))
			mode_buff[0] = '\0';
		if (0 == strcasecmp(mode_buff, "ascii")) {
			strcpy(mode_buff, ";type=a");
		} else if (0 == strcasecmp(mode_buff, "image")) {
			strcpy(mode_buff, ";type=i");
		}
		tmp_bin.cb = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "[InternetShortcut]\r\n"
					"URL=ftp://%s/%s/%s%s", site_buff, dir_buff,
					file_name, mode_buff);
		tmp_bin.pc = mode_buff;
		if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0) {
			return;
		}
		ptoken = strrchr(file_name, '.');
		if (NULL != ptoken) {
			strcpy(ptoken + 1, "URL");
		} else {
			strcat(file_name, ".URL");
		}
		uint32_t tag = b_unifn ? PR_ATTACH_LONG_FILENAME : PR_ATTACH_LONG_FILENAME_A;
		if (pattachment->proplist.set(tag, file_name) == 0)
			pmime_enum->b_result = true;
		return;
	}
	tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != 0) {
		return;
	}
	if (strcasecmp(cttype, "application/mac-binhex40") == 0) {
		pmime_enum->b_result = oxcmail_parse_binhex(
			pmime, pattachment, b_filename, b_description,
			&pmime_enum->last_propid, pmime_enum->phash);
		return;
	} else if (strcasecmp(cttype, "application/applefile") == 0) {
		if (oxcmail_parse_applesingle(pmime, pattachment, b_filename,
		    b_description, pmime_enum->alloc, &pmime_enum->last_propid,
		    pmime_enum->phash)) {
			pmime_enum->b_result = true;
			return;
		}
	}
	if (strncasecmp(cttype, "text/", 5) == 0 &&
	    oxcmail_get_content_param(pmime, "charset", tmp_buff, 32)) {
		uint32_t tag = oxcmail_check_ascii(tmp_buff) ?
		               PidTagTextAttachmentCharset :
		               PidTagTextAttachmentCharset_A;
		if (pattachment->proplist.set(tag, tmp_buff) != 0) {
			return;
		}
	}
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length:%u: unsuccessful\n", __func__, __LINE__);
		return;
	}
	size_t content_len = rdlength;
	std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(content_len));
	if (NULL == pcontent) {
		return;
	}
	if (!pmime->read_content(pcontent.get(), &content_len)) {
		return;
	}
	tmp_bin.cb = content_len;
	tmp_bin.pc = pcontent.get();
	pmime_enum->b_result = pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) == 0;
}

static MESSAGE_CONTENT* oxcmail_parse_tnef(MIME *pmime,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids)
{
	void *pcontent;
	MESSAGE_CONTENT *pmsg;
	
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
		return nullptr;
	}
	size_t content_len = rdlength;
	pcontent = malloc(content_len);
	if (NULL == pcontent) {
		return NULL;
	}
	if (!pmime->read_content(static_cast<char *>(pcontent), &content_len)) {
		free(pcontent);
		return NULL;
	}
	pmsg = tnef_deserialize(pcontent, content_len, alloc,
			get_propids, oxcmail_username_to_entryid);
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
	if (NULL == propids.ppropid) {
		return FALSE;
	}
	propnames.count = 0;
	propnames.ppropname = static_cast<PROPERTY_NAME *>(alloc(sizeof(PROPERTY_NAME) * phash.size()));
	if (NULL == propnames.ppropname) {
		return FALSE;
	}
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
	if (NULL != pmsg->children.prcpts) {
		for (size_t i = 0; i < pmsg->children.prcpts->count; ++i)
			oxcmail_replace_propid(pmsg->children.prcpts->pparray[i], phash1);
	}
	if (NULL != pmsg->children.pattachments) {
		for (size_t i = 0; i < pmsg->children.pattachments->count; ++i)
			oxcmail_replace_propid(
				&pmsg->children.pattachments->pplist[i]->proplist, phash1);
	}
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
	const PROPNAME_ARRAY propnames = {arsizeof(propname_buff), propname_buff};
	
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
	int i;
	
	for (i=0; i<pmsg->proplist.count; i++) {
		if (!pmsg1->proplist.has(pmsg->proplist.ppropval[i].proptag) &&
		    pmsg1->proplist.set(pmsg->proplist.ppropval[i]) != 0)
			return FALSE;
	}
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
		if (!attachment_list_append_internal(pmsg1->children.pattachments,
		    pmsg->children.pattachments->pplist[0]))
			return FALSE;
		pmsg->children.pattachments->count --;
		if (0 == pmsg->children.pattachments->count) {
			return TRUE;
		}
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
	
	if (0 != strcasecmp("Action", tag)) {
		return true;
	}
	if (0 == strcasecmp("delivered", value)) {
		severity = 0;
	} else if (0 == strcasecmp("expanded", value)) {
		severity = 1;
	} else if (0 == strcasecmp("relayed", value)) {
		severity = 2;
	} else if (0 == strcasecmp("delayed", value)) {
		severity = 3;
	} else if (0 == strcasecmp("failed", value)) {
		severity = 4;
	} else {
		return true;
	}
	if (severity > *(int*)pparam) {
		*(int*)pparam = severity;
	}
	return true;
}

static bool oxcmail_enum_dsn_action_fields(DSN_FIELDS *pfields, void *pparam)
{
	return dsn_enum_fields(pfields, oxcmail_enum_dsn_action_field, pparam);
}

static bool oxcmail_enum_dsn_rcpt_field(const char *tag,
    const char *value, void *pparam)
{
	DSN_FILEDS_INFO *pinfo;
	
	pinfo = (DSN_FILEDS_INFO*)pparam;
	if (0 == strcasecmp(tag, "Final-Recipient") &&
		0 == strncasecmp(value, "rfc822;", 7)) {
		gx_strlcpy(pinfo->final_recipient, value + 7, GX_ARRAY_SIZE(pinfo->final_recipient));
		HX_strrtrim(pinfo->final_recipient);
		HX_strltrim(pinfo->final_recipient);
	} else if (0 == strcasecmp(tag, "Action")) {
		if (0 == strcasecmp("delivered", value)) {
			pinfo->action_severity = 0;
		} else if (0 == strcasecmp("expanded", value)) {
			pinfo->action_severity = 1;
		} else if (0 == strcasecmp("relayed", value)) {
			pinfo->action_severity = 2;
		} else if (0 == strcasecmp("delayed", value)) {
			pinfo->action_severity = 3;
		} else if (0 == strcasecmp("failed", value)) {
			pinfo->action_severity = 4;
		}
	} else if (0 == strcasecmp(tag, "Status")) {
		pinfo->status = value;
	} else if (0 == strcasecmp(tag, "Diagnostic-Code")) {
		pinfo->diagnostic_code = value;
	} else if (0 == strcasecmp(tag, "Remote-MTA")) {
		gx_strlcpy(pinfo->remote_mta, value, GX_ARRAY_SIZE(pinfo->remote_mta));
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

static bool oxcmail_enum_dsn_rcpt_fields(DSN_FIELDS *pfields, void *pparam)
{
	int kind;
	int tmp_len;
	char *ptoken1;
	char *ptoken2;
	BINARY tmp_bin;
	char essdn[1280];
	char tmp_buff[1280];
	DSN_ENUM_INFO *pinfo;
	DSN_FILEDS_INFO f_info;
	char display_name[512];
	
	pinfo = (DSN_ENUM_INFO*)pparam;
	f_info.final_recipient[0] = '\0';
	f_info.action_severity = -1;
	f_info.remote_mta[0] = '\0';
	f_info.status = NULL;
	f_info.diagnostic_code = NULL;
	f_info.x_supplementary_info = NULL;
	f_info.x_display_name = NULL;
	dsn_enum_fields(pfields, oxcmail_enum_dsn_rcpt_field, &f_info);
	if (f_info.action_severity < pinfo->action_severity ||
		'\0' == f_info.final_recipient[0] || NULL == f_info.status) {
		return true;
	}
	strncpy(tmp_buff, f_info.status, 1024);
	ptoken1 = strchr(tmp_buff, '.');
	if (NULL == ptoken1) {
		return true;
	}
	*ptoken1 = '\0';
	if (1 != strlen(tmp_buff)) {
		return true;
	}
	if ('2' == tmp_buff[0]) {
		kind = 2;
	} else if ('4' == tmp_buff[0]) {
		kind = 4;
	} else if ('5' == tmp_buff[0]) {
		kind = 5;
	} else {
		return true;
	}
	ptoken1 ++;
	ptoken2 = strchr(ptoken1, '.');
	if (NULL == ptoken2) {
		return true;
	}
	*ptoken2 = '\0';
	tmp_len = strlen(ptoken1);
	if (tmp_len < 1 || tmp_len > 3) {
		return true;
	}
	int subject = strtol(ptoken1, nullptr, 0);
	if (subject > 9 || subject < 0) {
		subject = 0;
	}
	ptoken2 ++;
	tmp_len = strlen(ptoken2);
	if (tmp_len < 1 || tmp_len > 3) {
		return true;
	}
	int detail = strtol(ptoken2, nullptr, 0);
	if (detail > 9 || detail < 0) {
		detail = 0;
	}
	auto pproplist = pinfo->prcpts->emplace();
	if (NULL == pproplist) {
		return false;
	}
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
		tmp_bin.cb = snprintf(tmp_buff, arsizeof(tmp_buff), "SMTP:%s",
					f_info.final_recipient) + 1;
		HX_strupper(tmp_buff);
		if (pproplist->set(PR_ADDRTYPE, "SMTP") != 0 ||
		    pproplist->set(PR_EMAIL_ADDRESS, f_info.final_recipient) != 0)
			return false;
	} else {
		tmp_bin.cb = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "EX:%s", essdn) + 1;
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
	tmp_int32 = dtypx == DT_DISTLIST ? MAPI_DISTLIST : MAPI_MAILUSER;
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
		if (NULL == f_info.diagnostic_code) {
			snprintf(tmp_buff, 1024, "<%s #%s>",
				f_info.remote_mta, f_info.status);
		} else {
			snprintf(tmp_buff, 1024, "<%s #%s %s>",
				f_info.remote_mta, f_info.status,
				f_info.diagnostic_code);
		}
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

static MIME* oxcmail_parse_dsn(MAIL *pmail, MESSAGE_CONTENT *pmsg)
{
	DSN dsn;
	size_t content_len;
	DSN_ENUM_INFO dsn_info;
	char tmp_buff[256*1024];
	
	auto pmime = pmail->get_head();
	pmime = pmime->get_child();
	if (NULL == pmime) {
		return NULL;
	}
	do {
		if (strcasecmp(pmime->content_type, "message/delivery-status") == 0)
			break;
	} while ((pmime = pmime->get_sibling()) != nullptr);
	if (NULL == pmime) {
		return NULL;
	}
	auto mgl = pmime->get_length();
	if (mgl < 0 || static_cast<size_t>(mgl) > sizeof(tmp_buff))
		return NULL;
	content_len = sizeof(tmp_buff);
	if (!pmime->read_content(tmp_buff, &content_len))
		return NULL;
	dsn_init(&dsn);
	if (!dsn_retrieve(&dsn, tmp_buff, content_len)) {
		dsn_free(&dsn);
		return NULL;
	}
	dsn_info.action_severity = -1;
	dsn_enum_rcpts_fields(&dsn,
		oxcmail_enum_dsn_action_fields,
		&dsn_info.action_severity);
	if (-1 == dsn_info.action_severity) {
		dsn_free(&dsn);
		return NULL;
	}
	dsn_info.prcpts = tarray_set_init();
	if (NULL == dsn_info.prcpts) {
		dsn_free(&dsn);
		return NULL;
	}
	auto ts = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (ts == nullptr)
		dsn_info.submit_time = rop_util_unix_to_nttime(time(NULL));
	else
		dsn_info.submit_time = *ts;
	if (!dsn_enum_rcpts_fields(&dsn,
	    oxcmail_enum_dsn_rcpt_fields, &dsn_info)) {
		tarray_set_free(dsn_info.prcpts);
		dsn_free(&dsn);
		return NULL;
	}
	message_content_set_rcpts_internal(pmsg, dsn_info.prcpts);
	if (!dsn_enum_fields(dsn_get_message_fileds(&dsn),
	    oxcmail_enum_dsn_reporting_mta, pmsg)) {
		dsn_free(&dsn);
		return NULL;
	}
	auto as = om_actsev_to_mclass(dsn_info.action_severity);
	if (as != nullptr) {
		gx_strlcpy(tmp_buff, as, arsizeof(tmp_buff));
		if (pmsg->proplist.set(PR_MESSAGE_CLASS, tmp_buff) != 0) {
			dsn_free(&dsn);
			return NULL;
		}
	}
	dsn_free(&dsn);
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
		gx_strlcpy(tmp_buff, ptoken2, GX_ARRAY_SIZE(tmp_buff));
		HX_strltrim(tmp_buff);
		ptoken = strchr(tmp_buff, '/');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		if (0 == strcasecmp(tmp_buff, "displayed") ||
			0 == strcasecmp(tmp_buff, "dispatched") ||
			0 == strcasecmp(tmp_buff, "processed")) {
			strcpy(tmp_buff, "REPORT.IPM.Note.IPNRN");
		} else if (0 == strcasecmp(tmp_buff, "deleted") ||
			0 == strcasecmp(tmp_buff, "denied") ||
			0 == strcasecmp(tmp_buff, "failed")) {
			snprintf(tmp_buff, arsizeof(tmp_buff), "REPORT.IPM.Note.IPNNRN");
		} else {
			return true;
		}
		return mcparam->proplist.set(PR_MESSAGE_CLASS, tmp_buff) == 0 &&
		       mcparam->proplist.set(PR_REPORT_TEXT, value) == 0;
	} else if (0 == strcasecmp(tag, "X-MSExch-Correlation-Key")) {
		len = strlen(value);
		if (len <= 1024 && decode64(value, len, tmp_buff,
		    arsizeof(tmp_buff), &len) == 0) {
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

static MIME* oxcmail_parse_mdn(MAIL *pmail, MESSAGE_CONTENT *pmsg)
{
	DSN dsn;
	size_t content_len;
	char tmp_buff[256*1024];
	
	auto pmime = pmail->get_head();
	if (strcasecmp(pmime->content_type, "message/disposition-notification") != 0) {
		pmime = pmime->get_child();
		if (NULL == pmime) {
			return NULL;
		}
		do {
			if (strcasecmp(pmime->content_type, "message/disposition-notification") == 0)
				break;
		} while ((pmime = pmime->get_sibling()) != nullptr);
	}
	if (NULL == pmime) {
		return NULL;
	}
	auto mgl = pmime->get_length();
	if (mgl < 0 || static_cast<size_t>(mgl) > sizeof(tmp_buff))
		return NULL;
	content_len = sizeof(tmp_buff);
	if (!pmime->read_content(tmp_buff, &content_len))
		return NULL;
	dsn_init(&dsn);
	if (!dsn_retrieve(&dsn, tmp_buff, content_len)) {
		dsn_free(&dsn);
		return NULL;
	}
	if (!dsn_enum_fields(dsn_get_message_fileds(&dsn),
	    oxcmail_enum_mdn, pmsg)) {
		dsn_free(&dsn);
		return NULL;
	}
	dsn_free(&dsn);
	auto ts = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (pmsg->proplist.set(PR_ORIGINAL_DELIVERY_TIME, ts) != 0 ||
	    pmsg->proplist.set(PR_RECEIPT_TIME, ts) != 0)
		return NULL;
	for (size_t i = 0; i < pmsg->children.prcpts->count; ++i)
		if (pmsg->children.prcpts->pparray[i]->set(PR_REPORT_TIME, ts) != 0)
			return NULL;
	return pmime;
}

static BOOL oxcmail_parse_encrypted(MIME *phead, uint16_t *plast_propid,
    namemap &phash, MESSAGE_CONTENT *pmsg)
{
	char tmp_buff[1024];
	
	if (!phead->get_field("Content-Type", tmp_buff, arsizeof(tmp_buff)))
		return FALSE;
	PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS, 0, deconst("Content-Type")};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0 ||
	    pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), tmp_buff) != 0)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_smime_message(MAIL *pmail, MESSAGE_CONTENT *pmsg) try
{
	size_t offset;
	BINARY tmp_bin;
	uint32_t tmp_int32;
	ATTACHMENT_CONTENT *pattachment;
	
	auto phead = pmail->get_head();
	if (NULL == phead) {
		return FALSE;
	}
	auto rdlength = phead->get_length();
	if (rdlength < 0) {
		fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
		return false;
	}
	size_t content_len = rdlength;
	auto pcontent = std::make_unique<char[]>(content_len + 1024);
	auto content_type = phead->content_type;
	if (0 == strcasecmp(content_type, "multipart/signed")) {
		strcpy(pcontent.get(), "Content-Type: ");
		offset = 14;
		if (!phead->get_field("Content-Type", &pcontent[offset], 1024 - offset)) {
			return FALSE;
		}
		offset += strlen(&pcontent[offset]);
		strcpy(&pcontent[offset], "\r\n\r\n");
		offset += 4;
		if (!phead->read_content(&pcontent[offset], &content_len)) {
			return FALSE;
		}
		offset += content_len;
	} else {
		if (!phead->read_content(pcontent.get(), &content_len)) {
			return FALSE;
		}
		offset = content_len;
	}
	pattachment = attachment_content_init();
	if (NULL == pattachment) {
		return FALSE;
	}
	if (!attachment_list_append_internal(
		pmsg->children.pattachments, pattachment)) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	tmp_bin.cb = offset;
	tmp_bin.pc = pcontent.get();
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != 0) {
		return FALSE;
	}
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
	fprintf(stderr, "E-1972: ENOMEM\n");
	return false;
}

static BOOL oxcmail_try_assign_propval(TPROPVAL_ARRAY *pproplist,
    uint32_t pr_normal, uint32_t pr_representing)
{
	if (pproplist->has(pr_normal))
		return TRUE;
	auto pvalue = pproplist->getval(pr_representing);
	if (NULL == pvalue) {
		return TRUE;
	}
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

static inline bool tnef_vfy_get_field(MIME *head, char *buf, size_t z)
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

static bool smime_clearsigned(const char *head_ct, MIME *head, char (&buf)[256])
{
	if (strcasecmp(head_ct, "multipart/signed") != 0)
		return false;
	if (!oxcmail_get_content_param(head, "protocol", buf, arsizeof(buf)))
		return false;
	return strcasecmp(buf, "application/pkcs7-signature") == 0 ||
	       strcasecmp(buf, "application/x-pkcs7-signature") == 0;
}

MESSAGE_CONTENT *oxcmail_import(const char *charset, const char *str_zone,
    MAIL *pmail, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids) try
{
	int i;
	ICAL ical;
	MIME *pmime;
	MIME *pmime1;
	char *pcontent;
	uint8_t tmp_byte;
	TARRAY_SET *prcpts;
	uint32_t tmp_int32;
	char tmp_buff[256];
	PROPID_ARRAY propids;
	char mime_charset[64];
	MESSAGE_CONTENT *pmsg;
	char default_charset[64];
	namemap phash;
	MIME_ENUM_PARAM mime_enum{phash};
	FIELD_ENUM_PARAM field_param{phash};
	ATTACHMENT_LIST *pattachments;
	
	pmsg = message_content_init();
	if (NULL == pmsg) {
		return NULL;
	}
	/* set default message class */
	if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note") != 0) {
		message_content_free(pmsg);
		return NULL;
	}
	prcpts = tarray_set_init();
	if (NULL == prcpts) {
		message_content_free(pmsg);
		return NULL;
	}
	message_content_set_rcpts_internal(pmsg, prcpts);
	if (!pmail->get_charset(default_charset))
		gx_strlcpy(default_charset, charset, GX_ARRAY_SIZE(default_charset));
	field_param.alloc = alloc;
	field_param.pmail = pmail;
	field_param.pmsg = pmsg;
	field_param.charset = default_charset;
	field_param.last_propid = 0x8000;
	field_param.b_flag_del = false;
	const auto phead = pmail->get_head();
	if (NULL == phead) {
		message_content_free(pmsg);
		return NULL;
	}
	field_param.b_classified = phead->get_field("X-Microsoft-Classified", tmp_buff, 16);
	if (!phead->enum_field(oxcmail_enum_mail_head, &field_param)) {
		message_content_free(pmsg);
		return NULL;
	}
	if (!pmsg->proplist.has(PR_SENDER_NAME) &&
	    !pmsg->proplist.has(PR_SENDER_SMTP_ADDRESS)) {
		if (!oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_NAME, PR_SENT_REPRESENTING_NAME) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_SMTP_ADDRESS, PR_SENT_REPRESENTING_SMTP_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_ADDRTYPE, PR_SENT_REPRESENTING_ADDRTYPE) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_EMAIL_ADDRESS, PR_SENT_REPRESENTING_EMAIL_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_SEARCH_KEY, PR_SENT_REPRESENTING_SEARCH_KEY) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_ENTRYID, PR_SENT_REPRESENTING_ENTRYID)) {
			message_content_free(pmsg);
			return NULL;
		}
	} else if (!pmsg->proplist.has(PR_SENT_REPRESENTING_NAME) &&
	    !pmsg->proplist.has(PR_SENT_REPRESENTING_SMTP_ADDRESS)) {
		if (!oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_NAME, PR_SENDER_NAME) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_SENDER_SMTP_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_ADDRTYPE, PR_SENDER_ADDRTYPE) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENDER_EMAIL_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_SEARCH_KEY, PR_SENDER_SEARCH_KEY) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_ENTRYID, PR_SENDER_ENTRYID)) {
			message_content_free(pmsg);
			return NULL;
		}	
	}
	if (!pmsg->proplist.has(PR_IMPORTANCE)) {
		tmp_int32 = IMPORTANCE_NORMAL;
		if (pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != 0) {
			message_content_free(pmsg);
			return NULL;
		}
	}
	if (!pmsg->proplist.has(PR_SENSITIVITY)) {
		tmp_int32 = SENSITIVITY_NONE;
		if (pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != 0) {
			message_content_free(pmsg);
			return NULL;
		}
	}
	if (!oxcmail_parse_transport_message_header(phead, &pmsg->proplist)) {
		message_content_free(pmsg);
		return NULL;
	}
	auto ts = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (ts == nullptr) {
		mime_enum.nttime_stamp = rop_util_unix_to_nttime(time(NULL));
		if (pmsg->proplist.set(PR_CLIENT_SUBMIT_TIME,
		    &mime_enum.nttime_stamp) != 0) {
			message_content_free(pmsg);
			return NULL;
		}
	} else {
		mime_enum.nttime_stamp = *ts;
	}
	if (pmsg->proplist.set(PR_CREATION_TIME, &mime_enum.nttime_stamp) != 0 ||
	    pmsg->proplist.set(PR_LAST_MODIFICATION_TIME, &mime_enum.nttime_stamp) != 0) {
		message_content_free(pmsg);
		return NULL;
	}

	auto head_ct = phead->content_type;
	if (strcasecmp(head_ct, "application/ms-tnef") == 0 &&
	    tnef_vfy_get_field(phead, tmp_buff, arsizeof(tmp_buff))) {
	auto pmsg1 = oxcmail_parse_tnef(phead, alloc, get_propids);
	if (pmsg1 != nullptr) {
		auto cl_1 = make_scope_exit([&]() { message_content_free(pmsg1); });
		if (tnef_vfy_check_key(pmsg1, tmp_buff)) {
			if (!oxcmail_fetch_propname(pmsg, phash, alloc, get_propids)) {
				message_content_free(pmsg);
				return NULL;
			}
			if (!oxcmail_copy_message_proplist(pmsg, pmsg1)) {
				message_content_free(pmsg);
				return NULL;
			}
			prcpts = pmsg1->children.prcpts;
			pmsg1->children.prcpts =
				pmsg->children.prcpts;
			pmsg->children.prcpts = prcpts;
			message_content_free(pmsg);
			if (field_param.b_flag_del)
				oxcmail_remove_flag_propties(pmsg1, get_propids);
			cl_1.release();
			return pmsg1;
		}
	}
	}
	if (strcasecmp(head_ct, "multipart/report") == 0 &&
	    oxcmail_get_content_param(phead, "report-type", tmp_buff, 128) &&
	    strcasecmp("delivery-status", tmp_buff) == 0)
		mime_enum.preport = oxcmail_parse_dsn(pmail, pmsg);
	if ((strcasecmp(head_ct, "multipart/report") == 0 &&
	    oxcmail_get_content_param(phead, "report-type", tmp_buff, 128) &&
	    strcasecmp("disposition-notification", tmp_buff) == 0) ||
	    strcasecmp("message/disposition-notification", head_ct) == 0)
		mime_enum.preport = oxcmail_parse_mdn(pmail, pmsg);

	bool b_alternative = false, b_smime = false;
	if (strcasecmp(head_ct, "multipart/mixed") == 0) {
		if (phead->get_children_num() == 2 &&
		    (pmime = phead->get_child()) != nullptr &&
		    (pmime1 = pmime->get_sibling()) != nullptr &&
		    strcasecmp(pmime->content_type, "text/plain") == 0 &&
		    strcasecmp(pmime1->content_type, "application/ms-tnef") == 0 &&
		    tnef_vfy_get_field(phead, tmp_buff, arsizeof(tmp_buff))) {
		auto pmsg1 = oxcmail_parse_tnef(pmime1, alloc, get_propids);
		if (pmsg1 != nullptr) {
			auto cl_1 = make_scope_exit([&]() { message_content_free(pmsg1); });
			if (tnef_vfy_check_key(pmsg1, tmp_buff)) {
				if (!oxcmail_parse_message_body(default_charset, pmime, &pmsg->proplist) ||
				    !oxcmail_fetch_propname(pmsg, phash, alloc, get_propids)) {
					message_content_free(pmsg);
					return NULL;
				}
				if (!oxcmail_copy_message_proplist(pmsg, pmsg1)) {
					message_content_free(pmsg);
					return NULL;
				}
				prcpts = pmsg1->children.prcpts;
				pmsg1->children.prcpts =
					pmsg->children.prcpts;
				pmsg->children.prcpts = prcpts;
				message_content_free(pmsg);
				if (field_param.b_flag_del)
					oxcmail_remove_flag_propties(pmsg1, get_propids);
				cl_1.release();
				return pmsg1;
			}
		}
		}
	} else if (smime_clearsigned(head_ct, phead, tmp_buff)) {
		if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME.MultipartSigned") != 0) {
			message_content_free(pmsg);
			return NULL;
		}
		b_smime = true;
	} else if (strcasecmp(head_ct, "application/pkcs7-mime") == 0 ||
	    strcasecmp(head_ct, "application/x-pkcs7-mime") == 0) {
		if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME") != 0 ||
		    !oxcmail_parse_encrypted(phead, &field_param.last_propid, phash, pmsg)) {
			message_content_free(pmsg);
			return NULL;
		}
		b_smime = true;
	}
	mime_enum.b_result = true;
	mime_enum.attach_id = 0;
	mime_enum.charset = default_charset;
	mime_enum.str_zone = str_zone;
	mime_enum.get_propids = get_propids;
	mime_enum.alloc = alloc;
	mime_enum.pmime_pool = pmail->pmime_pool;
	mime_enum.pmsg = pmsg;
	mime_enum.phash = phash;
	pmime = phead;
	for (i=0; i<MAXIMUM_SEARCHING_DEPTH; i++) {
		pmime1 = pmime->get_child();
		if (NULL == pmime1) {
			break;
		}
		pmime = pmime1;
	}
	pmime1 = pmime->get_parent();
	if (pmime1 != nullptr &&
	    strcasecmp(pmime1->content_type, "multipart/alternative") == 0)
		b_alternative = true;
	do {
		auto cttype = pmime->content_type;
		if (strcasecmp(cttype, "text/plain") == 0 &&
		    mime_enum.pplain == nullptr)
			mime_enum.pplain = pmime;
		if (strcasecmp(cttype, "text/html") == 0 &&
		    mime_enum.phtml == nullptr)
			mime_enum.phtml = pmime;
		if (strcasecmp(cttype, "text/enriched") == 0 &&
		    mime_enum.penriched == nullptr)
			mime_enum.penriched = pmime;
		if (strcasecmp(cttype, "text/calendar") == 0 &&
		    mime_enum.pcalendar == nullptr)
			mime_enum.pcalendar = pmime;
		if (b_alternative && pmime->mime_type == mime_type::multiple) {
			pmime1 = pmime->get_child();
			while (NULL != pmime1) {
				cttype = pmime1->content_type;
				if (strcasecmp(cttype, "text/plain") == 0 &&
				    mime_enum.pplain == nullptr)
					mime_enum.pplain = pmime1;
				if (strcasecmp(cttype, "text/html") == 0 &&
				    mime_enum.phtml == nullptr)
					mime_enum.phtml = pmime1;
				if (strcasecmp(cttype, "text/enriched") == 0 &&
				    mime_enum.penriched == nullptr)
					mime_enum.penriched = pmime1;
				if (strcasecmp(cttype, "text/calendar") == 0 &&
				    mime_enum.pcalendar == nullptr)
					mime_enum.pcalendar = pmime1;
				pmime1 = pmime1->get_sibling();
			}
		}
	} while (b_alternative && (pmime = pmime->get_sibling()) != nullptr);
	
	if (NULL != mime_enum.pplain) {
		if (!oxcmail_parse_message_body(default_charset,
			mime_enum.pplain, &pmsg->proplist)) {
			message_content_free(pmsg);
			return NULL;
		}
	}
	if (NULL != mime_enum.phtml) {
		if (!oxcmail_parse_message_body(default_charset,
			mime_enum.phtml, &pmsg->proplist)) {
			message_content_free(pmsg);
			return NULL;
		}
	} else if (NULL != mime_enum.penriched) {
		if (!oxcmail_parse_message_body(default_charset,
			mime_enum.penriched, &pmsg->proplist)) {
			message_content_free(pmsg);
			return NULL;
		}
	}
	size_t content_len = 0;
	MESSAGE_CONTENT *pmsg1 = nullptr; /* ical */
	if (NULL != mime_enum.pcalendar) {
		auto rdlength = mime_enum.pcalendar->get_length();
		if (rdlength < 0) {
			fprintf(stderr, "%s:MIME::get_length: unsuccessful\n", __func__);
			message_content_free(pmsg);
			return nullptr;
		}
		content_len = rdlength;
		auto contoutsize = 3 * content_len + 2;
		pcontent = me_alloc<char>(contoutsize);
		if (NULL == pcontent) {
			message_content_free(pmsg);
			return NULL;
		}
		if (!mime_enum.pcalendar->read_content(pcontent, &content_len)) {
			free(pcontent);
			message_content_free(pmsg);
			return NULL;
		}
		pcontent[content_len] = '\0';
		if (!oxcmail_get_content_param(mime_enum.pcalendar, "charset",
		    mime_charset, arsizeof(mime_charset)))
			gx_strlcpy(mime_charset, !utf8_check(pcontent) ?
				default_charset : "utf-8", arsizeof(mime_charset));
		if (!string_to_utf8(mime_charset, pcontent,
		    &pcontent[content_len+1], contoutsize - content_len - 1)) {
			mime_enum.pcalendar = NULL;
		} else {
			if (!utf8_check(pcontent + content_len + 1))
				utf8_filter(pcontent + content_len + 1);
			if (!ical.retrieve(pcontent + content_len + 1)) {
				mime_enum.pcalendar = nullptr;
			} else {
				pmsg1 = oxcical_import_single(str_zone, ical, alloc,
				        get_propids, oxcmail_username_to_entryid).release();
				if (pmsg1 == nullptr)
					mime_enum.pcalendar = NULL;
			}
		}
		free(pcontent);
	}
	
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		message_content_free(pmsg);
		if (NULL != mime_enum.pcalendar) {
			message_content_free(pmsg1);
		}
		return NULL;
	}
	message_content_set_attachments_internal(pmsg, pattachments);
	if (b_smime) {
		if (!oxcmail_parse_smime_message(pmail, pmsg)) {
			message_content_free(pmsg);
			return NULL;
		}
	} else {
		mime_enum.last_propid = field_param.last_propid;
		pmail->enum_mime(oxcmail_enum_attachment, &mime_enum);
		if (!mime_enum.b_result) {
			message_content_free(pmsg);
			if (NULL != mime_enum.pcalendar) {
				message_content_free(pmsg1);
			}
			return NULL;
		}
	}
	if (!oxcmail_fetch_propname(pmsg, phash, alloc, get_propids)) {
		message_content_free(pmsg);
		if (NULL != mime_enum.pcalendar) {
			message_content_free(pmsg1);
		}
		return NULL;
	}
	if (NULL != mime_enum.pcalendar) {
		if (!pmsg1->proplist.has(PR_MESSAGE_CLASS)) {
			/* multiple calendar objects in attachment list */
			if (pmsg1->children.pattachments != nullptr &&
			    !oxcmail_merge_message_attachments(pmsg1, pmsg)) {
				message_content_free(pmsg);
				message_content_free(pmsg1);
				return NULL;
			}
			message_content_free(pmsg1);
		} else {
			if (!oxcmail_copy_message_proplist(pmsg, pmsg1) ||
			    !oxcmail_merge_message_attachments(pmsg, pmsg1)) {
				message_content_free(pmsg);
				message_content_free(pmsg1);
				return NULL;
			}
			message_content_free(pmsg);
			pmsg = pmsg1;
			/* calendar message object can not be displayed
				correctly without PidTagRtfCompressed convert
				PidTagHtml to PidTagRtfCompressed */
			auto phtml_bin = pmsg->proplist.get<const BINARY>(PR_HTML);
			if (NULL != phtml_bin) {
				auto num = pmsg->proplist.get<const uint32_t>(PR_INTERNET_CPID);
				tmp_int32 = num == nullptr ? 65001 : *num;
				char *rtfout = nullptr;
				if (html_to_rtf(phtml_bin->pv, phtml_bin->cb, tmp_int32,
				    &rtfout, &content_len)) {
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
			tmp_int32 = num == nullptr ? 65001 : *num;
			std::string plainbuf;
			auto ret = html_to_plain(phtml_bin->pc, phtml_bin->cb, plainbuf);
			if (ret < 0) {
				message_content_free(pmsg);
				return NULL;
			}
			if (ret == 65001) {
				pmsg->proplist.set(PR_BODY_W, plainbuf.data());
			} else {
				auto z = 3 * plainbuf.size() + 1;
				auto s = static_cast<char *>(alloc(z));
				if (s == nullptr) {
					message_content_free(pmsg);
					return NULL;
				}
				auto encoding = cpid_to_cset(tmp_int32);
				if (NULL == encoding) {
					encoding = "windows-1252";
				}
				if (string_to_utf8(encoding, plainbuf.c_str(),
				    s, z) && utf8_check(s))
					pmsg->proplist.set(PR_BODY_W, s);
			}
		}
	}
	if (!pmsg->proplist.has(PR_HTML)) {
		auto s = pmsg->proplist.get<const char>(PR_BODY);
		if (s != nullptr) {
			auto phtml_bin = static_cast<BINARY *>(alloc(sizeof(BINARY)));
			if (NULL == phtml_bin) {
				message_content_free(pmsg);
				return NULL;
			}
			phtml_bin->pc = plain_to_html(s);
			if (phtml_bin->pc == nullptr) {
				message_content_free(pmsg);
				return NULL;
			}
			phtml_bin->cb = strlen(phtml_bin->pc);
			pmsg->proplist.set(PR_HTML, phtml_bin);
			tmp_int32 = 65001;
			pmsg->proplist.set(PR_INTERNET_CPID, &tmp_int32);
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
		if (!get_propids(&propnames, &propids)) {
			message_content_free(pmsg);
			return nullptr;
		}
		tmp_byte = 1;
		if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]), &tmp_byte) != 0) {
			message_content_free(pmsg);
			return nullptr;
		}
	}
	if (field_param.b_flag_del)
		oxcmail_remove_flag_propties(pmsg, get_propids);
	return pmsg;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2182: ENOMEM\n");
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
		fprintf(stderr, "E-1539: ENOMEM\n");
		return 0;
	}

	if (oxcmail_check_ascii(pstring) && !oxcmail_check_crlf(pstring)) {
		auto string_len = strlen(pstring);
		if (string_len >= max_length) {
			return 0;
		}
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
	if (offset + 3 >= max_length) {
		return 0;
	}
	strcpy(&pout_string[offset], "?=");
	return offset + 2;
}

static BOOL oxcmail_get_smtp_address(const TPROPVAL_ARRAY *pproplist,
    EXT_BUFFER_ALLOC alloc, const addr_tags &tags,
    char *username, size_t ulen)
{
	auto s = pproplist->get<const char>(tags.pr_smtpaddr);
	if (s != nullptr) {
		gx_strlcpy(username, s, ulen);
		return TRUE;
	}
	s = pproplist->get<char>(tags.pr_addrtype);
	if (s == nullptr) {
 FIND_ENTRYID:
		auto pvalue = pproplist->get<const BINARY>(tags.pr_entryid);
		if (NULL == pvalue) {
			return FALSE;
		}
		return oxcmail_entryid_to_username(pvalue, alloc, username, ulen);
	}
	if (strcasecmp(s, "SMTP") == 0) {
		s = pproplist->get<char>(tags.pr_emaddr);
	} else if (strcasecmp(s, "EX") == 0) {
		s = pproplist->get<char>(tags.pr_emaddr);
		if (s != nullptr && oxcmail_essdn_to_username(s, username, ulen))
			return TRUE;	
	} else {
		s = nullptr;
	}
	if (s == nullptr)
		goto FIND_ENTRYID;
	gx_strlcpy(username, s, ulen);
	return TRUE;
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
			field[offset] = '"';
			offset ++;
			if (offset >= fdsize)
				return FALSE;
			auto tmp_len = oxcmail_encode_mime_string(
				charset, pdisplay_name, field + offset,
			               fdsize - offset);
			if (0 == tmp_len) {
				return FALSE;
			}
			offset += tmp_len;
			field[offset] = '"';
			offset ++;
			if (offset >= fdsize)
				return FALSE;
		}
		if (oxcmail_get_smtp_address(prcpt, alloc, tags_self,
		    username, GX_ARRAY_SIZE(username))) {
			offset += std::max(0, gx_snprintf(field + offset, fdsize - offset,
			          pdisplay_name != nullptr ? " <%s>" : "<%s>", username));
		}
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
	if (NULL == pbin) {
		return FALSE;
	}
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
			fprintf(stderr, "W-1964: skipping non-SMTP reply-to entry\n");
			continue;
		}
		if (oo.pdisplay_name != nullptr && *oo.pdisplay_name != '\0') {
			if (offset + 2 >= fieldmax)
				return false;
			strcpy(&field[offset], "\"");
			offset ++;
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
		if (strlen(pvalue) >= GX_ARRAY_SIZE(address)) {
			goto EXPORT_ADDRESS;
		}
		field[offset] = '"';
		offset ++;
		offset += oxcmail_encode_mime_string(charset,
		          pvalue, field + offset, fdsize - offset);
		field[offset++] = '"';
		field[offset++] = ' ';
		field[offset] = '\0';
	}
 EXPORT_ADDRESS:
	if (oxcmail_get_smtp_address(&pmsg->proplist, alloc, tags,
	    address, arsizeof(address))) {
		offset += gx_snprintf(field + offset, fdsize - offset, "<%s>", address);
	} else {
		/*
		 * RFC 5322 §3.4's ABNF mandates an address at all times.
		 * If we only emitted "Display Name", parsers can
		 * preferentially treat that as the email address, so let's add
		 * <> to nudge them.
		 */
		offset += gx_snprintf(field + offset, fdsize - offset, "<>");
	}
	if (0 == offset) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_export_content_class(
	const char *pmessage_class, char *field)
{
	if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Fax")) {
		strcpy(field, "fax");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Fax.CA")) {
		strcpy(field, "fax-ca");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Missed.Voice")) {
		strcpy(field, "missedcall");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Conversation.Voice")) {
		strcpy(field, "voice-uc");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Voicemail.UM.CA")) {
		strcpy(field, "voice-ca");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Voicemail.UM")) {
		strcpy(field, "voice");
	} else if (0 == strncasecmp(pmessage_class,
		"IPM.Note.Custom.", 16)) {
		snprintf(field, 1024,
			"urn:content-class:custom.%s",
			pmessage_class + 16);
	} else {
		return FALSE;
	}
	return TRUE;
}

static enum oxcmail_type oxcmail_get_mail_type(const char *pmessage_class)
{
	int tmp_len;
	
	tmp_len = strlen(pmessage_class);
	if (0 == strcasecmp( pmessage_class,
		"IPM.Note.SMIME.MultipartSigned")) {
		return oxcmail_type::xsigned;
	}
	if (0 == strncasecmp(pmessage_class, "IPM.InfoPathForm.",
		17) && 0 == strcasecmp(pmessage_class + tmp_len - 22,
		".SMIME.MultipartSigned")) {
		return oxcmail_type::xsigned;
	}
	if (0 == strcasecmp(pmessage_class, "IPM.Note.SMIME")) {
		return oxcmail_type::encrypted;
	}
	if (0 == strncasecmp(pmessage_class, "IPM.InfoPathForm.",
		17) && 0 == strcasecmp(pmessage_class + tmp_len - 6,
		".SMIME")) {
		return oxcmail_type::encrypted;
	}
	if (0 == strcasecmp(pmessage_class, "IPM.Note") ||
		0 == strncasecmp(pmessage_class, "IPM.Note.", 9) ||
		0 == strncasecmp(pmessage_class, "IPM.InfoPathForm.", 17)) {
		return oxcmail_type::normal;
	}
	if (0 == strncasecmp(pmessage_class, "REPORT.", 7) &&
		(0 == strcasecmp(pmessage_class + tmp_len - 3, ".DR") ||
		0 == strcasecmp(pmessage_class + tmp_len - 12, ".Expanded.DR") ||
		0 == strcasecmp(pmessage_class + tmp_len - 11, ".Relayed.DR") ||
		0 == strcasecmp(pmessage_class + tmp_len - 11, ".Delayed.DR") ||
		0 == strcasecmp(pmessage_class + tmp_len - 4, ".NDR"))) {
		return oxcmail_type::dsn;
	}
	if (0 == strncasecmp(pmessage_class, "REPORT.", 7) &&
		(0 == strcasecmp(pmessage_class + tmp_len - 6, ".IPNRN") ||
		0 == strcasecmp(pmessage_class + tmp_len - 7, ".IPNNRN"))) {
		return oxcmail_type::mdn;
	}
	if (0 == strcasecmp(pmessage_class, "IPM.Appointment") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Request") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Pos") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Tent") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Neg") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Canceled")) {
		return oxcmail_type::calendar;
	}
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
	if (NULL == pskeleton->pmessage_class) {
		pskeleton->pmessage_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	}
	if (NULL == pskeleton->pmessage_class) {
		debug_info("[oxcmail]: missing message class for exporting");
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
		auto pvalue = pmsg->proplist.get<uint32_t>(PR_NATIVE_BODY_INFO);
		if (NULL != pvalue && NATIVE_BODY_RTF == *pvalue &&
		    ((pvalue = pmsg->proplist.get<uint32_t>(PR_RTF_IN_SYNC)) == nullptr ||
		    *pvalue == 0)) {
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
					size_t tmp_len = SIZE_MAX;
					char *htmlout = nullptr;
					if (rtf_to_html(pbuff, rtf_len, pcharset, &htmlout,
					    &tmp_len, pskeleton->pattachments)) {
						pskeleton->rtf_bin.pv = htmlout;
						free(pbuff);
						pskeleton->rtf_bin.cb = tmp_len;
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
			if (NULL == pskeleton->phtml) {
				goto FIND_RTF;
			}
		}
	}
	if (NULL == pmsg->children.pattachments) {
		return TRUE;
	}
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
	if (NULL != pskeleton->rtf_bin.pb) {
		free(pskeleton->rtf_bin.pb);
		pskeleton->rtf_bin.pb = nullptr;
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
	char tmp_buff[MIME_FIELD_LEN];
	char tmp_field[MIME_FIELD_LEN];
	
	if (!phead->set_field("MIME-Version", "1.0"))
		return FALSE;
	
	auto str  = pmsg->proplist.get<const char>(PR_SENDER_SMTP_ADDRESS);
	auto str1 = pmsg->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr && str1 != nullptr) {
		if (strcasecmp(str, str1) != 0) {
			oxcmail_export_address(pmsg, alloc, tags_sender,
				pskeleton->charset, tmp_field,
				GX_ARRAY_SIZE(tmp_field));
			if (!phead->set_field("Sender", tmp_field))
				return FALSE;
		}
	} else {
		str  = pmsg->proplist.get<char>(PR_SENDER_ADDRTYPE);
		str1 = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_ADDRTYPE);
		if (str != nullptr && str1 != nullptr &&
		    strcasecmp(str, "SMTP") == 0 &&
		    strcasecmp(str1, "SMTP") == 0) {
			str  = pmsg->proplist.get<char>(PR_SENDER_EMAIL_ADDRESS);
			str1 = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr && str1 != nullptr &&
			    strcasecmp(str, str1) != 0) {
				oxcmail_export_address(pmsg, alloc, tags_sender,
					pskeleton->charset, tmp_field,
					GX_ARRAY_SIZE(tmp_field));
				if (!phead->set_field("Sender", tmp_field))
					return FALSE;
			}
		}
	}
	if (oxcmail_export_address(pmsg, alloc, tags_sent_repr,
	    pskeleton->charset, tmp_field, GX_ARRAY_SIZE(tmp_field))) {
		if (!phead->set_field("From", tmp_field))
			return FALSE;
	} else if (oxcmail_export_address(pmsg, alloc, tags_sender,
	    pskeleton->charset, tmp_field, GX_ARRAY_SIZE(tmp_field)) &&
	    !phead->set_field("Sender", tmp_field)) {
		return FALSE;
	}
	auto flag = pmsg->proplist.get<uint8_t>(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED);
	if (flag != nullptr && *flag != 0) {
		if (oxcmail_export_address(pmsg, alloc, tags_read_rcpt,
		    pskeleton->charset, tmp_field, GX_ARRAY_SIZE(tmp_field)) ||

		    oxcmail_export_address(pmsg, alloc, tags_sender,
		    pskeleton->charset, tmp_field, GX_ARRAY_SIZE(tmp_field)) ||

		    oxcmail_export_address(pmsg, alloc, tags_sent_repr,
		    pskeleton->charset, tmp_field, GX_ARRAY_SIZE(tmp_field))) {
			if (!phead->set_field("Return-Receipt-To", tmp_field))
				return FALSE;
		}
	}
	
	flag = pmsg->proplist.get<uint8_t>(PR_READ_RECEIPT_REQUESTED);
	if (flag != nullptr && *flag != 0) {
		if (oxcmail_export_address(pmsg, alloc, tags_read_rcpt,
		    pskeleton->charset, tmp_field, GX_ARRAY_SIZE(tmp_field)) ||

		    oxcmail_export_address(pmsg, alloc, tags_sent_repr,
		    pskeleton->charset, tmp_field, GX_ARRAY_SIZE(tmp_field))) {
			if (!phead->set_field("Disposition-Notification-To", tmp_field))
				return FALSE;
		}
	}
	
	if (oxcmail_export_reply_to(pmsg, pskeleton->charset, alloc, tmp_field) &&
	    !phead->set_field("Reply-To", tmp_field))
		return FALSE;
	if (NULL == pmsg->children.prcpts) {
		goto EXPORT_CONTENT_CLASS;
	}
	if (oxcmail_export_addresses(pskeleton->charset, pmsg->children.prcpts,
	    MAPI_TO, alloc, tmp_field, arsizeof(tmp_field)) &&
	    !phead->set_field("To", tmp_field))
		return FALSE;
	if (oxcmail_export_addresses(pskeleton->charset, pmsg->children.prcpts,
	    MAPI_CC, alloc, tmp_field, arsizeof(tmp_field)) &&
	    !phead->set_field("Cc", tmp_field))
		return FALSE;
	
	if (0 == strncasecmp(pskeleton->pmessage_class,
		"IPM.Schedule.Meeting.", 21) ||
		0 == strcasecmp(pskeleton->pmessage_class,
		"IPM.Task") || 0 == strncasecmp(
		pskeleton->pmessage_class, "IPM.Task.", 9)) {
		if (oxcmail_export_addresses(pskeleton->charset,
		    pmsg->children.prcpts, MAPI_BCC, alloc,
		    tmp_field, arsizeof(tmp_field)) &&
		    !phead->set_field("Bcc", tmp_field))
			return FALSE;
	}
	
 EXPORT_CONTENT_CLASS:
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
		str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids.ppropid[0]));
		if (str != nullptr) {
			str1 = strrchr(str, '.');
			if (str1 != nullptr)
				str = str1 + 1;
			snprintf(tmp_field, 1024, "InfoPathForm.%s", str);
			if (!phead->set_field("Content-Class", tmp_field))
				return FALSE;
		}
	}
	str = pmsg->proplist.get<char>(PR_SENDER_TELEPHONE_NUMBER);
	if (str != nullptr && !phead->set_field("X-CallingTelephoneNumber", str))
		return FALSE;
	auto num = pmsg->proplist.get<const uint32_t>(PidTagVoiceMessageDuration);
	if (num != nullptr) {
		snprintf(tmp_field, arsizeof(tmp_field), "%ld", static_cast<long>(*num));
		if (!phead->set_field("X-VoiceMessageDuration", tmp_field))
			return FALSE;
	}
	str = pmsg->proplist.get<char>(PidTagVoiceMessageSenderName);
	if (str != nullptr && !phead->set_field("X-VoiceMessageSenderName", str))
		return FALSE;
	num = pmsg->proplist.get<uint32_t>(PidTagFaxNumberOfPages);
	if (num != nullptr) {
		snprintf(tmp_field, arsizeof(tmp_field), "%lu", static_cast<unsigned long>(*num));
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
	if (lnum == nullptr)
		time(&tmp_time);
	else
		tmp_time = rop_util_nttime_to_unix(*lnum);
	strftime(tmp_field, 128, "%a, %d %b %Y %H:%M:%S %z",
					localtime_r(&tmp_time, &time_buff));
	if (!phead->set_field("Date", tmp_field))
		return FALSE;
	
	str  = pmsg->proplist.get<char>(PR_SUBJECT_PREFIX);
	str1 = pmsg->proplist.get<char>(PR_NORMALIZED_SUBJECT);
	if (str != nullptr && str1 != nullptr) {
		snprintf(tmp_buff, MIME_FIELD_LEN, "%s%s", str, str1);
		if (oxcmail_encode_mime_string(pskeleton->charset,
		    tmp_buff, tmp_field, arsizeof(tmp_field)) > 0 &&
		    !phead->set_field("Subject", tmp_field))
			return FALSE;
	} else {
		str = pmsg->proplist.get<char>(PR_SUBJECT);
		if (str != nullptr && oxcmail_encode_mime_string(pskeleton->charset,
		    str, tmp_field, arsizeof(tmp_field)) > 0 &&
		    !phead->set_field("Subject", tmp_field))
			return FALSE;
	}
	str = pmsg->proplist.get<char>(PR_CONVERSATION_TOPIC);
	if (str != nullptr && oxcmail_encode_mime_string(pskeleton->charset,
	    str, tmp_field, arsizeof(tmp_field)) > 0 &&
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
			if (tmp_len >= MIME_FIELD_LEN) {
				break;
			}
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
	flag = pmsg->proplist.get<uint8_t>(PROP_TAG(PT_BOOLEAN, propids.ppropid[0]));
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
		snprintf(tmp_field, arsizeof(tmp_field), "%ld", static_cast<long>(*inum));
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
	DSN dsn;
	int tmp_len;
	char action[16];
	TARRAY_SET *prcpts;
	char tmp_buff[1024];
	DSN_FIELDS *pdsn_fields;
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
	
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	auto str = pmsg->proplist.get<const char>(PidTagReportingMessageTransferAgent);
	if (str == nullptr) {
		strcpy(tmp_buff, "dns; ");
		gethostname(tmp_buff + 5, sizeof(tmp_buff) - 5);
		tmp_buff[arsizeof(tmp_buff)-1] = '\0';
		if (!dsn_append_field(pdsn_fields, "Reporting-MTA", tmp_buff)) {
			dsn_free(&dsn);
			return FALSE;
		}
	} else {
		if (!dsn_append_field(pdsn_fields, "Reporting-MTA", str)) {
			dsn_free(&dsn);
			return FALSE;
		}
	}
	
	tmp_len = strlen(pmessage_class);
	if (0 == strcasecmp(pmessage_class
		+ tmp_len - 3, ".DR")) {
		strcpy(action, "delivered");
	} else if (0 == strcasecmp(pmessage_class
		+ tmp_len - 12, ".Expanded.DR")) {
		strcpy(action, "expanded");
	} else if (0 == strcasecmp(pmessage_class
		+ tmp_len - 11, ".Relayed.DR")) {
		strcpy(action, "relayed");
	} else if (0 == strcasecmp(pmessage_class
		+ tmp_len - 11, ".Delayed.DR")) {
		strcpy(action, "delayed");
	} else if (0 == strcasecmp(pmessage_class
		+ tmp_len - 4, ".NDR")) {
		strcpy(action, "failed");
	} else {
		*action = '\0';
	}
	if (NULL == pmsg->children.prcpts) {
		goto SERIALIZE_DSN;
	}
	prcpts = pmsg->children.prcpts;
	for (size_t i = 0; i < prcpts->count; ++i) {
		pdsn_fields = dsn_new_rcpt_fields(&dsn);
		if (NULL == pdsn_fields) {
			dsn_free(&dsn);
			return FALSE;
		}
		strcpy(tmp_buff, "rfc822;");
		if (!oxcmail_get_smtp_address(prcpts->pparray[i], alloc,
		    tags_self, tmp_buff + 7, arsizeof(tmp_buff) - 7)) {
			dsn_free(&dsn);
			return FALSE;
		}
		if (!dsn_append_field(pdsn_fields, "Final-Recipient", tmp_buff)) {
			dsn_free(&dsn);
			return FALSE;
		}
		if (*action != '\0' &&
		    !dsn_append_field(pdsn_fields, "Action", action)) {
			dsn_free(&dsn);
			return FALSE;
		}
		auto num = prcpts->pparray[i]->get<const uint32_t>(PR_NDR_DIAG_CODE);
		if (num != nullptr) {
			if (*num == MAPI_DIAG_NO_DIAGNOSTIC) {
				num = prcpts->pparray[i]->get<uint32_t>(PR_NDR_REASON_CODE);
				if (num != nullptr) {
					strcpy(tmp_buff, *num > 6 ? "5.4.0" :
					       status_strings1[*num]);
					if (!dsn_append_field(pdsn_fields, "Status", tmp_buff)) {
						dsn_free(&dsn);
						return FALSE;
					}
				}
			} else {
				num = prcpts->pparray[i]->get<uint32_t>(PR_NDR_REASON_CODE);
				if (num != nullptr) {
					strcpy(tmp_buff, *num > 48 ? "5.0.0" :
					       status_strings2[*num]);
					if (!dsn_append_field(pdsn_fields, "Status", tmp_buff)) {
						dsn_free(&dsn);
						return FALSE;
					}
				}
			}
		}
		str = prcpts->pparray[i]->get<char>(PR_DSN_REMOTE_MTA);
		if (str != nullptr && !dsn_append_field(pdsn_fields,
		    "Remote-MTA", str)) {
			dsn_free(&dsn);
			return FALSE;
		}
		str = prcpts->pparray[i]->get<char>(PR_SUPPLEMENTARY_INFO);
		if (str != nullptr && !dsn_append_field(pdsn_fields,
		    "X-Supplementary-Info", str)) {
			dsn_free(&dsn);
			return FALSE;
		}
		str = prcpts->pparray[i]->get<char>(PR_DISPLAY_NAME);
		if (str != nullptr && oxcmail_encode_mime_string(charset,
		    str, tmp_buff, arsizeof(tmp_buff)) > 0 &&
		    !dsn_append_field(pdsn_fields, "X-Display-Name", tmp_buff)) {
			dsn_free(&dsn);
			return FALSE;
		}
	}
 SERIALIZE_DSN:
	if (!dsn_serialize(&dsn, pdsn_content, max_length)) {
		dsn_free(&dsn);
		return FALSE;
	}
	dsn_free(&dsn);
	return TRUE;
}

static BOOL oxcmail_export_mdn(const MESSAGE_CONTENT *pmsg,
	const char *charset, const char *pmessage_class,
	EXT_BUFFER_ALLOC alloc, char *pmdn_content,
	int max_length)
{
	DSN dsn;
	int tmp_len;
	size_t base64_len;
	char tmp_buff[1024];
	char tmp_address[UADDR_SIZE];
	DSN_FIELDS *pdsn_fields;
	
	tmp_address[0] = '\0';
	auto str = pmsg->proplist.get<const char>(PR_SENDER_SMTP_ADDRESS);
	auto pdisplay_name = pmsg->proplist.get<const char>(PR_SENDER_NAME);
	if (str != nullptr) {
		gx_strlcpy(tmp_address, str, arsizeof(tmp_address));
	} else {
		str = pmsg->proplist.get<char>(PR_SENDER_ADDRTYPE);
		if (str != nullptr && strcasecmp(str, "SMTP") == 0) {
			str = pmsg->proplist.get<char>(PR_SENDER_EMAIL_ADDRESS);
			if (str != nullptr)
				gx_strlcpy(tmp_address, str, arsizeof(tmp_address));
		}
	}
	if ('\0' != tmp_address[0]) {
		goto EXPORT_MDN_CONTENT;
	}
	str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	pdisplay_name = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_NAME);
	if (str != nullptr) {
		gx_strlcpy(tmp_address, str, arsizeof(tmp_address));
	} else {
		str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_ADDRTYPE);
		if (str != nullptr && strcasecmp(str, "SMTP") == 0) {
			str = pmsg->proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
			if (str != nullptr)
				gx_strlcpy(tmp_address, str, arsizeof(tmp_address));
		}
	}
 EXPORT_MDN_CONTENT:
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	snprintf(tmp_buff, arsizeof(tmp_buff), "rfc822;%s", tmp_address);
	if (!dsn_append_field(pdsn_fields, "Final-Recipient", tmp_buff)) {
		dsn_free(&dsn);
		return FALSE;
	}
	tmp_len = strlen(pmessage_class);
	strcpy(tmp_buff, strcasecmp(pmessage_class + tmp_len - 6, ".IPNRN") == 0 ?
	       "manual-action/MDN-sent-automatically; displayed" :
	       "manual-action/MDN-sent-automatically; deleted");
	if (!dsn_append_field(pdsn_fields, "Disposition", tmp_buff)) {
		dsn_free(&dsn);
		return FALSE;
	}
	auto bv = pmsg->proplist.get<const BINARY>(PR_PARENT_KEY);
	if (bv != nullptr && encode64(bv->pb, bv->cb, tmp_buff,
	    arsizeof(tmp_buff), &base64_len) == 0) {
		tmp_buff[base64_len] = '\0';
		if (!dsn_append_field(pdsn_fields, "X-MSExch-Correlation-Key", tmp_buff)) {
			dsn_free(&dsn);
			return FALSE;
		}
	}
	str = pmsg->proplist.get<char>(PidTagOriginalMessageId);
	if (str != nullptr && !dsn_append_field(pdsn_fields,
	    "Original-Message-ID", str)) {
		dsn_free(&dsn);
		return FALSE;
	}
	if (pdisplay_name != nullptr && oxcmail_encode_mime_string(charset,
	    pdisplay_name, tmp_buff, arsizeof(tmp_buff)) > 0 &&
	    !dsn_append_field(pdsn_fields, "X-Display-Name", tmp_buff)) {
		dsn_free(&dsn);
		return FALSE;
	}
	if (!dsn_serialize(&dsn, pmdn_content, max_length)) {
		dsn_free(&dsn);
		return FALSE;
	}
	dsn_free(&dsn);
	return TRUE;
}

static bool select_octet_stream(const char *s)
{
	return s == nullptr || strcasecmp(s, "message/rfc822") == 0 ||
	       strcasecmp(s, "application/applefile") == 0 ||
	       strcasecmp(s, "application/mac-binhex40") == 0 ||
	       strncasecmp(s, "multipart/", 10) == 0;
}

static BOOL oxcmail_export_appledouble(MAIL *pmail,
	BOOL b_inline, ATTACHMENT_CONTENT *pattachment,
	MIME_SKELETON *pskeleton, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, MIME *pmime)
{
	int tmp_len;
	MACBINARY macbin;
	EXT_PULL ext_pull;
	char tmp_field[1024];
	PROPID_ARRAY propids;
	
	auto pbin = pattachment->proplist.get<const BINARY>(PR_ATTACH_DATA_BIN);
	if (NULL == pbin) {
		return FALSE;
	}
	ext_pull.init(pbin->pb, pbin->cb, alloc, 0);
	if (EXT_ERR_SUCCESS != macbinary_pull_binary(
		&ext_pull, &macbin)) {
		return FALSE;
	}
	PROPERTY_NAME propname_buff[] = {
		{MNID_STRING, PSETID_ATTACHMENT, 0, deconst(PidNameAttachmentMacInfo)},
		{MNID_STRING, PSETID_ATTACHMENT, 0, deconst(PidNameAttachmentMacContentType)},
	};
	const PROPNAME_ARRAY propnames = {arsizeof(propname_buff), propname_buff};
	if (!get_propids(&propnames, &propids))
		return FALSE;
	pbin = pattachment->proplist.get<BINARY>(PROP_TAG(PT_BINARY, propids.ppropid[0]));
	auto str = pattachment->proplist.get<const char>(PROP_TAG(PT_UNICODE, propids.ppropid[1]));
	if (select_octet_stream(str))
		str = "application/octet-stream";
	if (!pmime->set_content_type("multipart/appledouble"))
		return FALSE;
	auto pmime1 = pmail->add_child(pmime, MIME_ADD_LAST);
	if (NULL == pmime1) {
		return FALSE;
	}
	if (!pmime1->set_content_type("application/applefile"))
		return FALSE;
	auto pmime2 = pmail->add_child(pmime, MIME_ADD_LAST);
	if (NULL == pmime2) {
		return FALSE;
	}
	if (!pmime2->set_content_type(str))
		return FALSE;
	if (NULL == pbin) {
		auto b2 = apple_util_macbinary_to_appledouble(&macbin);
		if (b2 == nullptr)
			return FALSE;
		if (!pmime1->write_content(b2->pc, b2->cb, mime_encoding::base64)) {
			rop_util_free_binary(b2);
			return FALSE;
		}
		rop_util_free_binary(b2);
	} else if (!pmime1->write_content(pbin->pc, pbin->cb, mime_encoding::base64)) {
			return FALSE;
	}
	str = pattachment->proplist.get<char>(PR_ATTACH_LONG_FILENAME);
	if (str == nullptr)
		str = pattachment->proplist.get<char>(PR_ATTACH_FILENAME);
	if (str != nullptr) {
		tmp_field[0] = '"';
		tmp_len = oxcmail_encode_mime_string(pskeleton->charset,
		          str, tmp_field + 1, 512);
		if (tmp_len > 0) {
			strcpy(&tmp_field[tmp_len+1], "\"");
			if (!pmime2->set_content_param("name", tmp_field))
				return FALSE;
		}
		if (!b_inline) {
			strcpy(tmp_field, "attachment; filename=\"");
			tmp_len = 22;
		} else {
			strcpy(tmp_field, "inline; filename=\"");
			tmp_len = 18;
		}
		tmp_len += oxcmail_encode_mime_string(pskeleton->charset,
		           str, tmp_field + tmp_len, arsizeof(tmp_field) - tmp_len);
		strcpy(&tmp_field[tmp_len], "\"");
		if (!pmime2->set_field("Content-Disposition", tmp_field))
			return FALSE;
	}
	str = pattachment->proplist.get<char>(PR_DISPLAY_NAME);
	if (str != nullptr) {
		tmp_len = oxcmail_encode_mime_string(pskeleton->charset,
		          str, tmp_field, arsizeof(tmp_field));
		if (tmp_len > 0 && !pmime2->set_field("Content-Description", tmp_field))
			return FALSE;
	}
	return pmime2->write_content(reinterpret_cast<const char *>(macbin.pdata),
	       macbin.header.data_len, mime_encoding::base64);
}

static BOOL oxcmail_export_attachment(ATTACHMENT_CONTENT *pattachment,
    BOOL b_inline, MIME_SKELETON *pskeleton, EXT_BUFFER_ALLOC alloc,
    GET_PROPIDS get_propids, GET_PROPNAME get_propname,
    std::shared_ptr<MIME_POOL> ppool, MIME *pmime)
{
	int tmp_len;
	BOOL b_vcard;
	size_t offset;
	time_t tmp_time;
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
		if (NULL == pfile_name) {
			pfile_name = pattachment->proplist.get<char>(PR_ATTACH_FILENAME);
		}
		if (NULL == pcontent_type) {
			auto str = pattachment->proplist.get<const char>(PR_ATTACH_EXTENSION);
			if (str != nullptr)
				pcontent_type = extension_to_mime(str + 1);
			if (NULL == pcontent_type) {
				pcontent_type = "application/octet-stream";
			}
		}
		if (0 == strncasecmp(pcontent_type, "multipart/", 10)) {
			pcontent_type = "application/octet-stream";
		}
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
		if (NULL == pfile_name) {
			pfile_name = pattachment->proplist.get<char>(PR_ATTACH_FILENAME);
		}
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
		          str, tmp_field, arsizeof(tmp_field));
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
	time(&tmp_time);
	if (NULL != pctime) {
		tmp_time = rop_util_nttime_to_unix(*pctime);
	}
	gmtime_r(&tmp_time, &time_buff);
	tmp_len += strftime(tmp_field + tmp_len, 1024 - tmp_len,
		"creation-date=\"%a, %d %b %Y %H:%M:%S GMT\";\r\n\t",
		&time_buff);
	if (NULL != pmtime) {
		tmp_time = rop_util_nttime_to_unix(*pmtime);
	}
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
			    strlen(pbuff.get()), mime_encoding::automatic)) {
				return FALSE;
			}
			return TRUE;
		}
	}
	}
	
	if (NULL != pattachment->pembedded) {
		auto b_tnef = pskeleton->mail_type == oxcmail_type::tnef;
		MAIL imail;
		if (!oxcmail_export(pattachment->pembedded,
		    b_tnef ? TRUE : false, pskeleton->body_type, ppool, &imail,
		    alloc, get_propids, get_propname))
			return FALSE;
		auto mail_len = imail.get_length();
		if (mail_len < 0)
			return false;
		alloc_limiter<stream_block> pallocator(mail_len / STREAM_BLOCK_SIZE + 1,
			"oxcmail_export_attachment");
		STREAM tmp_stream(&pallocator);
		if (!imail.serialize(&tmp_stream)) {
			return FALSE;
		}
		imail.clear();
		std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(mail_len + 128));
		if (NULL == pbuff) {
			return FALSE;
		}
				
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
    const BINARY *hdrs, MIME_FIELD &f)
{
	if (hdrs == nullptr || hdrs->cb == 0)
		return false;
	auto sec = origmail.pmime_pool->get_mime();
	if (sec == nullptr)
		return false;
	auto cl_0 = make_scope_exit([&]() { origmail.pmime_pool->put_mime(sec); });
	char buf[512];
	if (!sec->retrieve(nullptr, hdrs->pc, hdrs->cb))
		return false;
	if (!sec->get_field("Content-Type", buf, arsizeof(buf)))
		return false;
	if (strncasecmp(buf, "multipart/signed", 16) != 0)
		return false;
	if (buf[16] != '\0' && buf[16] != ';')
		return false;
	sec->f_type_params.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	size_t rd;
	while ((rd = sec->f_type_params.read(buf, arsizeof(buf))) != MEM_END_OF_FILE)
		origmime.f_type_params.write(buf, rd);
	sec->f_other_fields.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while ((rd = sec->f_other_fields.read(buf, arsizeof(buf))) != MEM_END_OF_FILE)
		origmime.f_other_fields.write(buf, rd);

	auto content = static_cast<char *>(HX_memdup(sec->content_begin, sec->content_length));
	if (content == nullptr)
		return false;
	free(origmime.content_begin);
	origmime.content_begin = content;
	origmime.content_length = sec->content_length;
	origmime.mime_type = mime_type::single;
	gx_strlcpy(origmime.content_type, "multipart/signed", arsizeof(origmime.content_type));
	origmime.head_touched = origmime.content_touched = TRUE;
	return true;
}

BOOL oxcmail_export(const MESSAGE_CONTENT *pmsg, BOOL b_tnef,
    enum oxcmail_body body_type, std::shared_ptr<MIME_POOL> ppool,
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
	
	*pmail = MAIL(ppool);
	auto num = pmsg->proplist.get<uint32_t>(PR_INTERNET_CPID);
	if (num == nullptr || *num == 1200) {
		pcharset = "utf-8";
	} else {
		pcharset = cpid_to_cset(*num);
		if (NULL == pcharset) {
			pcharset = "utf-8";
		}
	}
	mime_skeleton mime_skeleton;
	if (!oxcmail_load_mime_skeleton(pmsg, pcharset, b_tnef,
	    body_type, &mime_skeleton))
		return FALSE;
	auto phead = pmail->add_head();
	if (NULL == phead) {
		goto EXPORT_FAILURE;
	}
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
				goto EXPORT_FAILURE;
		} else if (mime_skeleton.mail_type == oxcmail_type::mdn) {
			pmixed = pmime;
			if (!pmime->set_content_type("multipart/report") ||
			    !pmime->set_content_param("report-type", "disposition-notification") ||
			    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
				goto EXPORT_FAILURE;
		} else {
			if (mime_skeleton.b_attachment) {
				pmixed = pmime;
				if (!pmime->set_content_type("multipart/mixed") ||
				    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
					goto EXPORT_FAILURE;
			}
		}
		if (mime_skeleton.b_inline) {
			prelated = pmime;
			if (!pmime->set_content_type("multipart/related") ||
			    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
				goto EXPORT_FAILURE;
		}
		if (mime_skeleton.body_type == oxcmail_body::plain_and_html &&
			NULL != mime_skeleton.pplain && NULL != mime_skeleton.phtml) {
			if (!pmime->set_content_type("multipart/alternative"))
				goto EXPORT_FAILURE;
			pplain = pmail->add_child(pmime, MIME_ADD_LAST);
			phtml = pmail->add_child(pmime, MIME_ADD_LAST);
			if (pplain == nullptr || !pplain->set_content_type("text/plain") ||
			    phtml == nullptr || !phtml->set_content_type("text/html"))
				goto EXPORT_FAILURE;
			if (mime_skeleton.mail_type == oxcmail_type::calendar) {
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (pcalendar == nullptr ||
				    !pcalendar->set_content_type("text/calendar"))
					goto EXPORT_FAILURE;
			}
		} else if (mime_skeleton.body_type == oxcmail_body::plain_only &&
		    mime_skeleton.pplain != nullptr) {
 PLAIN_ONLY:
			if (mime_skeleton.mail_type != oxcmail_type::calendar) {
				if (!pmime->set_content_type("text/plain"))
					goto EXPORT_FAILURE;
				pplain = pmime;
			} else {
				if (!pmime->set_content_type("multipart/alternative"))
					goto EXPORT_FAILURE;
				pplain = pmail->add_child(pmime, MIME_ADD_LAST);
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (pplain == nullptr || !pplain->set_content_type("text/plain") ||
				    pcalendar == nullptr || !pcalendar->set_content_type("text/calendar"))
					goto EXPORT_FAILURE;
			}
		} else if (mime_skeleton.body_type == oxcmail_body::html_only &&
		    mime_skeleton.phtml != nullptr) {
 HTML_ONLY:
			if (mime_skeleton.mail_type != oxcmail_type::calendar) {
				if (!pmime->set_content_type("text/html"))
					goto EXPORT_FAILURE;
				phtml = pmime;
			} else {
				if (!pmime->set_content_type("multipart/alternative"))
					goto EXPORT_FAILURE;
				phtml = pmail->add_child(pmime, MIME_ADD_LAST);
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (phtml == nullptr || !phtml->set_content_type("text/html") ||
				    pcalendar == nullptr || !pcalendar->set_content_type("text/calendar"))
					goto EXPORT_FAILURE;
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
			goto EXPORT_FAILURE;
		if ((pplain = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr ||
		    !pplain->set_content_type("text/plain"))
			goto EXPORT_FAILURE;
		break;
	case oxcmail_type::xsigned:
	case oxcmail_type::encrypted:
		break;
	}
	
	if (!oxcmail_export_mail_head(pmsg, &mime_skeleton, alloc,
	    get_propids, get_propname, phead))
		goto EXPORT_FAILURE;
	
	if (mime_skeleton.mail_type == oxcmail_type::encrypted) {
		if (!pmime->set_content_type("application/pkcs7-mime"))
			goto EXPORT_FAILURE;
		if (NULL == pmsg->children.pattachments ||
			1 != pmsg->children.pattachments->count) {
			goto EXPORT_FAILURE;
		}
		auto pbin = pmsg->children.pattachments->pplist[0]->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
		if (NULL == pbin) {
			goto EXPORT_FAILURE;
		}
		if (!pmime->write_content(pbin->pc, pbin->cb, mime_encoding::base64))
			goto EXPORT_FAILURE;
		return TRUE;
	} else if (mime_skeleton.mail_type == oxcmail_type::xsigned) {
		auto a = pmsg->children.pattachments;
		if (a == nullptr || a->count != 1)
			goto EXPORT_FAILURE;
		auto pbin = a->pplist[0]->proplist.get<const BINARY>(PR_ATTACH_DATA_BIN);
		if (!smime_signed_writeout(*pmail, *pmime, pbin, mime_field))
			goto EXPORT_FAILURE;
		return TRUE;
	}
	
	if (NULL != pplain) {
		if (NULL == mime_skeleton.pplain ||
			'\0' == mime_skeleton.pplain[0]) {
			if (!pplain->write_content("\r\n", 2, mime_encoding::base64))
				goto EXPORT_FAILURE;
		} else {
			auto alloc_size = worst_encoding_overhead(strlen(mime_skeleton.pplain)) + 1;
			std::unique_ptr<char[]> pbuff;
			try {
				pbuff = std::make_unique<char[]>(alloc_size);
			} catch (const std::bad_alloc &) {
				fprintf(stderr, "E-1508: ENOMEM\n");
				goto EXPORT_FAILURE;
			}
			if (!string_from_utf8(mime_skeleton.charset,
			    mime_skeleton.pplain, pbuff.get(), alloc_size)) {
				pbuff.reset();
				if (!pplain->write_content(mime_skeleton.pplain,
				    strlen(mime_skeleton.pplain), mime_encoding::automatic))
					goto EXPORT_FAILURE;
				strcpy(tmp_charset, "\"utf-8\"");
			} else {
				if (!pplain->write_content(pbuff.get(),
				    strlen(pbuff.get()), mime_encoding::automatic))
					goto EXPORT_FAILURE;
				snprintf(tmp_charset, arsizeof(tmp_charset), "\"%s\"", mime_skeleton.charset);
			}
			if (!pplain->set_content_param("charset", tmp_charset))
				goto EXPORT_FAILURE;
		}
	}
	
	if (mime_skeleton.mail_type == oxcmail_type::tnef) {
		pmime = pmail->add_child(pmime, MIME_ADD_LAST);
		BINARY *pbin = nullptr;
		if (pmime == nullptr || !pmime->set_content_type("application/ms-tnef"))
			goto EXPORT_FAILURE;
		pbin = tnef_serialize(pmsg, alloc, get_propname);
		if (pbin == nullptr)
			goto EXPORT_FAILURE;
		if (!pmime->write_content(pbin->pc, pbin->cb, mime_encoding::base64)) {
			rop_util_free_binary(pbin);
			goto EXPORT_FAILURE;
		}
		rop_util_free_binary(pbin);
		if (!pmime->set_content_param("name", "\"winmail.dat\"") ||
		    !pmime->set_field("Content-Disposition",
			"attachment; filename=\"winmail.dat\""))
			goto EXPORT_FAILURE;
		return TRUE;
	}
	
	if (NULL != phtml) {
		if (!phtml->write_content(mime_skeleton.phtml->pc,
		    mime_skeleton.phtml->cb, mime_encoding::automatic))
			goto EXPORT_FAILURE;
		snprintf(tmp_charset, arsizeof(tmp_charset), "\"%s\"", mime_skeleton.charset);
		if (!phtml->set_content_param("charset", tmp_charset))
			goto EXPORT_FAILURE;
	}
	
	if (NULL != pcalendar) {
		char tmp_buff[1024*1024];
		
		if (!oxcical_export(pmsg, ical, alloc,
		    get_propids, oxcmail_entryid_to_username,
		    oxcmail_essdn_to_username)) {
			fprintf(stderr, "W-2186: oxcical_export failed for an unspecified reason\n");
			goto EXPORT_FAILURE;
		}
		tmp_method[0] = '\0';
		auto piline = ical.get_line("METHOD");
		if (NULL != piline) {
			auto str = deconst(piline->get_first_subvalue());
			if (str != nullptr)
				gx_strlcpy(tmp_method, str, arsizeof(tmp_method));
		}
		if (!ical.serialize(tmp_buff, arsizeof(tmp_buff)))
			goto EXPORT_FAILURE;
		if (!pcalendar->write_content(tmp_buff, strlen(tmp_buff),
		    mime_encoding::automatic))
			goto EXPORT_FAILURE;
		if (!pcalendar->set_content_param("charset", "\"utf-8\""))
			goto EXPORT_FAILURE;
		if ('\0' != tmp_method[0]) {
			pcalendar->set_content_param("method", tmp_method);
		}
	}
	
	if (mime_skeleton.mail_type == oxcmail_type::dsn) {
		char tmp_buff[1024*1024];
		
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL == pmime) {
			goto EXPORT_FAILURE;
		}
		if (!pmime->set_content_type("message/delivery-status"))
			goto EXPORT_FAILURE;
		if (!oxcmail_export_dsn(pmsg, mime_skeleton.charset,
		    mime_skeleton.pmessage_class, alloc, tmp_buff, sizeof(tmp_buff)))
			goto EXPORT_FAILURE;
		if (!pmime->write_content(tmp_buff, strlen(tmp_buff),
		    mime_encoding::none))
			goto EXPORT_FAILURE;
	} else if (mime_skeleton.mail_type == oxcmail_type::mdn) {
		char tmp_buff[1024*1024];
		
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL == pmime) {
			goto EXPORT_FAILURE;
		}
		if (!pmime->set_content_type("message/disposition-notification"))
			goto EXPORT_FAILURE;
		if (!oxcmail_export_mdn(pmsg, mime_skeleton.charset,
		    mime_skeleton.pmessage_class, alloc, tmp_buff,
		    arsizeof(tmp_buff)))
			goto EXPORT_FAILURE;
		if (!pmime->write_content(tmp_buff, strlen(tmp_buff),
		    mime_encoding::none))
			goto EXPORT_FAILURE;
	}
	
	if (NULL != mime_skeleton.pattachments) {
		for (i=0; i<mime_skeleton.pattachments->count; i++) {
			pmime = pmail->add_child(prelated, MIME_ADD_LAST);
			if (NULL == pmime) {
				goto EXPORT_FAILURE;
			}
			if (!oxcmail_export_attachment(mime_skeleton.pattachments->pplist[i],
			    TRUE, &mime_skeleton, alloc, get_propids,
			    get_propname, nullptr, pmime))
				goto EXPORT_FAILURE;
		}
	}
	
	if (NULL == pmsg->children.pattachments) {
		return TRUE;
	}
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
		if (NULL == pmime) {
			goto EXPORT_FAILURE;
		}
		const BINARY *pbin = nullptr;
		if (NULL == pattachment->pembedded &&
		    (num = pattachment->proplist.get<uint32_t>(PR_ATTACH_METHOD)) != nullptr &&
		    *num == ATTACH_BY_VALUE &&
		    (pbin = pattachment->proplist.get<BINARY>(PR_ATTACH_ENCODING)) != nullptr &&
		    pbin->cb == sizeof(MACBINARY_ENCODING) &&
		    memcmp(pbin->pb, MACBINARY_ENCODING, sizeof(MACBINARY_ENCODING)) == 0) {
			if (oxcmail_export_appledouble(pmail, b_inline,
			    pattachment, &mime_skeleton, alloc, get_propids, pmime))
				continue;
		}
		if (!oxcmail_export_attachment(pattachment,
		    b_inline, &mime_skeleton, alloc, get_propids,
		    get_propname, ppool, pmime))
			goto EXPORT_FAILURE;
	}
	return TRUE;
 EXPORT_FAILURE:
	return FALSE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2181: ENOMEM\n");
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
