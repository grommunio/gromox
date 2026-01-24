// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2026 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cassert>
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
#include <fmt/core.h>
#include <libHX/ctype_helper.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <vmime/addressList.hpp>
#include <vmime/constants.hpp>
#include <vmime/mailbox.hpp>
#include <vmime/mailboxList.hpp>
#include <vmime/text.hpp>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/ical.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tnef.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>
#include "oxcmail_int.hpp"

/* uncomment below macro if you need system to verify X-MS-TNEF-Correlator */
/* #define VERIFY_TNEF_CORRELATOR */

/*
	Caution. If any errors in parsing any sub type, ignore this sub type.
	for example, if an error appears when parsing tnef attachment, treat
	this tnef sub type as normal attachment. there will be no error for
	parsing email object into message object!
*/

using namespace std::string_literals;
using namespace oxcmail;
using namespace gromox;
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

/**
 * @have_orig_fn: a filename was found in MIME header
 * @tag:          _A or _W mapitag for new filename
 * @fn:           new filename
 * @ext:          new extension
 */
struct gmf_output {
	bool have_orig_fn = false;
	uint32_t tag = PR_ATTACH_LONG_FILENAME_A;
	std::string fn, ext;
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

static constexpr char
	PidNameContentClass[] = "Content-Class",
	PidNameKeywords[] = "Keywords";
static constexpr size_t namemap_limit = 0x1000;
static char g_oxcmail_org_name[256];
static GET_USER_IDS oxcmail_get_user_ids;
static GET_DOMAIN_IDS oxcmail_get_domain_ids;
static GET_USERNAME oxcmail_get_username;

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

BOOL oxcmail_init_library(const char *org_name, GET_USER_IDS get_user_ids,
    GET_DOMAIN_IDS get_domain_ids, GET_USERNAME get_username)
{
	gx_strlcpy(g_oxcmail_org_name, org_name, std::size(g_oxcmail_org_name));
	oxcmail_get_user_ids = get_user_ids;
	oxcmail_get_domain_ids = get_domain_ids;
	oxcmail_get_username = get_username;
	textmaps_init();
	return TRUE;
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
	if (status == pack_result::charconv) {
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
	EMSAB_ENTRYID_view tmp_entryid;
	
	tmp_entryid.flags = 0;
	tmp_entryid.type = DT_MAILUSER;
	tmp_entryid.px500dn = deconst(pessdn);
	if (!ext_push.init(pbin->pb, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != pack_result::ok)
		return false;
	pbin->cb = ext_push.m_offset;
	return TRUE;
}

BOOL oxcmail_username_to_entryid(const char *username,
    const char *pdisplay_name, BINARY *pbin, enum display_type *dtpp)
{
	std::string essdn;

	if (oxcmail_get_user_ids != nullptr &&
	    oxcmail_get_user_ids(username, nullptr, nullptr, dtpp) &&
	    cvt_username_to_essdn(username, g_oxcmail_org_name,
	    oxcmail_get_user_ids, oxcmail_get_domain_ids,
	    essdn) == ecSuccess)
		return oxcmail_essdn_to_entryid(essdn.c_str(), pbin);
	if (dtpp != nullptr)
		*dtpp = DT_MAILUSER;
	return oxcmail_username_to_oneoff(
	       username, pdisplay_name, pbin);
}

static unsigned int pick_strtype(const char *token)
{
	/*
	 * This will recur throughout oxcmail.cpp: If it is pure
	 * ASCII, we can upgrade it to Unicode. But if it is some
	 * locale-specific encoding, just mark it as 8-bit and don't
	 * worry about eager upconversion.
	 */
	return str_isascii(token) ? PT_UNICODE : PT_STRING8;
}

static inline bool oxcmail_check_crlf(const char *s)
{
	return std::any_of(s, s + strlen(s),
	       [](char c) { return c == '\n' || c == '\r'; });
}

bool oxcmail_get_content_param(const MIME *pmime,
    const char *tag, std::string &value)
{
	if (!pmime->get_content_param(tag, value))
		return false;
	auto tmp_len = value.size();
	if (('"' == value[0] && '"' == value[tmp_len - 1]) ||
		('\'' == value[0] && '\'' == value[tmp_len - 1])) {
		value.pop_back();
		value.erase(0, 1);
	}
	return !value.empty();
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

/**
 * @paddr:	always has UTF-8 display name in it
 */
static BOOL oxcmail_parse_recipient(const EMAIL_ADDR *paddr,
    uint32_t rcpt_type, TARRAY_SET *pset) try
{
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	
	if (!paddr->has_value())
		return TRUE;
	auto pproplist = pset->emplace();
	if (pproplist == nullptr)
		return FALSE;
	if (paddr->has_dispname()) {
		if (pproplist->set(PR_DISPLAY_NAME, paddr->display_name) != ecSuccess ||
		    pproplist->set(PR_TRANSMITABLE_DISPLAY_NAME, paddr->display_name) != ecSuccess)
			return FALSE;
	} else {
		if (pproplist->set(PR_DISPLAY_NAME, paddr->addr) != ecSuccess ||
		    pproplist->set(PR_TRANSMITABLE_DISPLAY_NAME, paddr->addr) != ecSuccess)
			return FALSE;
	}
	if (paddr->has_addr()) {
		auto dtypx = DT_MAILUSER;
		std::string essdn, skb;
		if (!oxcmail_get_user_ids(paddr->addr, nullptr, nullptr, &dtypx) ||
		    cvt_username_to_essdn(paddr->addr, g_oxcmail_org_name,
		    oxcmail_get_user_ids, oxcmail_get_domain_ids, essdn) != ecSuccess) {
			dtypx = DT_MAILUSER;
			skb = "SMTP:"s + paddr->addr;
			if (pproplist->set(PR_ADDRTYPE, "SMTP") != ecSuccess ||
			    pproplist->set(PR_EMAIL_ADDRESS, paddr->addr) != ecSuccess)
				return FALSE;
		} else {
			skb = "EX:" + essdn;
			if (pproplist->set(PR_ADDRTYPE, "EX") != ecSuccess ||
			    pproplist->set(PR_EMAIL_ADDRESS, essdn.c_str()) != ecSuccess)
				return FALSE;
		}
		HX_strupper(skb.data());
		BINARY srchkey;
		srchkey.cb = skb.size() + 1;
		srchkey.pc = deconst(skb.c_str());
		if (pproplist->set(PR_SMTP_ADDRESS, paddr->addr) != ecSuccess ||
		    pproplist->set(PR_SEARCH_KEY, &srchkey) != ecSuccess)
			return FALSE;
		char tmp_buff[1280];
		BINARY tmp_bin{};
		tmp_bin.pc = tmp_buff;
		if ('\0' == essdn[0]) {
			if (!oxcmail_username_to_oneoff(paddr->addr, paddr->display_name, &tmp_bin))
				return FALSE;
		} else {
			if (!oxcmail_essdn_to_entryid(essdn.c_str(), &tmp_bin))
				return FALSE;
		}
		if (pproplist->set(PR_ENTRYID, &tmp_bin) != ecSuccess ||
		    pproplist->set(PR_RECIPIENT_ENTRYID, &tmp_bin) != ecSuccess ||
		    pproplist->set(PR_RECORD_KEY, &tmp_bin) != ecSuccess)
			return FALSE;
		tmp_int32 = static_cast<uint32_t>(dtypx == DT_DISTLIST ? MAPI_DISTLIST : MAPI_MAILUSER);
		if (pproplist->set(PR_OBJECT_TYPE, &tmp_int32) != ecSuccess)
			return FALSE;
		tmp_int32 = static_cast<uint32_t>(dtypx);
		if (pproplist->set(PR_DISPLAY_TYPE, &tmp_int32) != ecSuccess)
			return FALSE;
	}
	tmp_byte = 1;
	if (pproplist->set(PR_RESPONSIBILITY, &tmp_byte) != ecSuccess)
		return FALSE;
	tmp_int32 = recipSendable;
	if (pproplist->set(PR_RECIPIENT_FLAGS, &tmp_int32) != ecSuccess)
		return FALSE;
	return pproplist->set(PR_RECIPIENT_TYPE, &rcpt_type) == ecSuccess ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_parse_addresses(const char *field, uint32_t rcpt_type,
    TARRAY_SET *pset) try
{
	vmime::mailboxList mblist;
	mblist.parse(field);
	for (const auto &compo : mblist.getChildComponents()) {
		auto mb = vmime::dynamicCast<vmime::mailbox>(compo);
		if (mb == nullptr)
			continue;
		EMAIL_ADDR email_addr(*mb);
		if (!email_addr.has_addr())
			continue;
		if (!oxcmail_parse_recipient(&email_addr, rcpt_type, pset))
			return FALSE;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_parse_address(const char *field, uint32_t pr_name,
    uint32_t pr_addrtype, uint32_t pr_emaddr, uint32_t pr_smtpaddr,
    uint32_t pr_searchkey, uint32_t pr_entryid, TPROPVAL_ARRAY *pproplist) try
{
	EMAIL_ADDR email_addr(field), *paddr = &email_addr;
	
	if (paddr->has_dispname()) {
		if (pproplist->set(pr_name, paddr->display_name) != ecSuccess)
			return false;
	} else if (paddr->has_addr()) {
		if (pproplist->set(pr_name, paddr->addr) != ecSuccess)
			return FALSE;
	}
	bool ok = paddr->has_addr();
	if (!ok)
		return TRUE;
	if (pproplist->set(pr_addrtype, "SMTP") != ecSuccess ||
	    pproplist->set(pr_emaddr, paddr->addr) != ecSuccess ||
	    pproplist->set(pr_smtpaddr, paddr->addr) != ecSuccess)
		return FALSE;
	std::string essdn, skb;
	if (cvt_username_to_essdn(paddr->addr, g_oxcmail_org_name,
	    oxcmail_get_user_ids, oxcmail_get_domain_ids, essdn) != ecSuccess)
		skb = "SMTP:"s + paddr->addr;
	else
		skb = "EX:"s + essdn;
	HX_strupper(skb.data());
	BINARY srchkey;
	srchkey.cb = skb.size() + 1;
	srchkey.pc = deconst(skb.c_str());
	if (pproplist->set(pr_searchkey, &srchkey) != ecSuccess)
		return FALSE;
	char tmp_buff[1280];
	BINARY tmp_bin{};
	tmp_bin.pc = tmp_buff;
	if ('\0' == essdn[0]) {
		if (!oxcmail_username_to_oneoff(paddr->addr, paddr->display_name, &tmp_bin))
			return FALSE;
	} else {
		if (!oxcmail_essdn_to_entryid(essdn.c_str(), &tmp_bin))
			return FALSE;
	}
	return pproplist->set(pr_entryid, &tmp_bin) == ecSuccess ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_parse_reply_to(const char *field, TPROPVAL_ARRAY *pproplist) try
{
	uint32_t count;
	BINARY tmp_bin;
	uint8_t pad_len;
	EXT_PUSH ext_push;
	EMAIL_ADDR email_addr;
	ONEOFF_ENTRYID tmp_entry;
	auto bin_buff = std::make_unique<uint8_t[]>(256 * 1024);
	static constexpr uint8_t pad_bytes[3]{};
	
	count = 0;
	if (!ext_push.init(bin_buff.get(), 256 * 1024, EXT_FLAG_UTF16))
		return false;
	if (ext_push.advance(sizeof(uint32_t)) != pack_result::ok)
		return FALSE;
	uint32_t offset = ext_push.m_offset;
	if (ext_push.advance(sizeof(uint32_t)) != pack_result::ok)
		return FALSE;
	tmp_entry.flags = 0;
	tmp_entry.version = 0;
	tmp_entry.paddress_type = deconst("SMTP");
	/* Ensure the fields are a classic array and thus do not change address */
	static_assert(std::size(email_addr.display_name) > 0);
	static_assert(std::size(email_addr.addr) > 0);

	vmime::mailboxList mblist;
	std::string names;
	mblist.parse(field);
	for (const auto &compo : mblist.getChildComponents()) {
		auto mb = vmime::dynamicCast<vmime::mailbox>(compo);
		if (mb == nullptr)
			continue;
		email_addr.set(*mb);
		if (!email_addr.has_addr())
			continue;
		if (names.size() > 0)
			names += ';';
		if (*email_addr.display_name != '\0') {
			auto oldsize = names.size();
			names += email_addr.display_name;
			names.erase(std::remove(names.begin() + oldsize, names.end(), ';'), names.end());
		} else {
			names += email_addr.addr;
		}

		uint32_t offset1 = ext_push.m_offset;
		if (ext_push.advance(sizeof(uint32_t)) != pack_result::ok)
			return FALSE;
		tmp_entry.pmail_address = email_addr.addr;
		tmp_entry.pdisplay_name = email_addr.display_name;
		tmp_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_UNICODE;
		auto status = ext_push.p_oneoff_eid(tmp_entry);
		if (status == pack_result::charconv) {
			ext_push.m_offset = offset1 + sizeof(uint32_t);
			tmp_entry.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO;
			status = ext_push.p_oneoff_eid(tmp_entry);
		}
		if (status != pack_result::success)
			return FALSE;
		uint32_t offset2 = ext_push.m_offset;
		uint32_t bytes = offset2 - (offset1 + sizeof(uint32_t));
		ext_push.m_offset = offset1;
		if (ext_push.p_uint32(bytes) != pack_result::ok)
			return FALSE;
		ext_push.m_offset = offset2;
		pad_len = ((bytes + 3) & ~3) - bytes;
		if (ext_push.p_bytes(pad_bytes, pad_len) != pack_result::ok)
			return FALSE;
		count++;
	}
	if (count == 0)
		return TRUE;
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pb = bin_buff.get();
	uint32_t bytes = ext_push.m_offset - (offset + sizeof(uint32_t));
	ext_push.m_offset = 0;
	if (ext_push.p_uint32(count) != pack_result::ok)
		return FALSE;
	ext_push.m_offset = offset;
	if (ext_push.p_uint32(bytes) != pack_result::ok)
		return FALSE;
	if (pproplist->set(PR_REPLY_RECIPIENT_ENTRIES, &tmp_bin) != ecSuccess)
		return FALSE;
	if (names.size() > 0 &&
	    pproplist->set(PR_REPLY_RECIPIENT_NAMES, names.c_str()) != ecSuccess)
		return FALSE;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_parse_subject(const char *charset, const char *field,
    TPROPVAL_ARRAY *pproplist) try
{
	char prefix_buff[32];
	static constexpr uint8_t seperator[] = {':', 0x00, ' ', 0x00};

	static constexpr size_t utf8_field_size = MIME_FIELD_LEN;
	auto utf8_field = std::make_unique<char[]>(utf8_field_size);
	if (!mime_string_to_utf8(charset, field, utf8_field.get(), utf8_field_size))
		return pproplist->set(PR_SUBJECT_A, field) == ecSuccess ? TRUE : false;

	static constexpr size_t tmp_buff_size = utf8_field_size;
	auto tmp_buff = std::make_unique<char[]>(tmp_buff_size);
	auto subject_len = utf8_to_utf16le(utf8_field.get(),
	              tmp_buff.get(), tmp_buff_size);
	if (subject_len < 0) {
		utf8_truncate(utf8_field.get(), 255);
		subject_len = utf8_to_utf16le(utf8_field.get(),
		              tmp_buff.get(), tmp_buff_size);
		if (subject_len < 0)
			subject_len = 0;
	}
	if (subject_len > 512) {
		subject_len = 512;
		tmp_buff[510] = '\0';
		tmp_buff[511] = '\0';
	}

	static constexpr size_t tmp_buff1_size = 4096;
	auto tmp_buff1 = std::make_unique<char[]>(tmp_buff1_size);
	utf16le_to_utf8(tmp_buff.get(), subject_len, tmp_buff1.get(), tmp_buff1_size);
	if (pproplist->set(PR_SUBJECT, tmp_buff1.get()) != ecSuccess)
		return FALSE;
	auto ptoken = static_cast<char *>(memmem(tmp_buff.get(), subject_len, seperator, 4));
	if (ptoken == nullptr)
		return TRUE;
	size_t tmp_len = ptoken - tmp_buff.get();
	if (tmp_len < 2 || tmp_len > 6)
		return TRUE;
	for (size_t i = 0; i < tmp_len; i += 2)
		if ((tmp_buff[i] == ':' || tmp_buff[i] == ' ' || HX_isdigit(tmp_buff[0])) &&
		    tmp_buff[i+1] == '\0')
			return TRUE;
	tmp_len += sizeof(seperator);
	memcpy(tmp_buff1.get(), tmp_buff.get(), tmp_len);
	tmp_buff1[tmp_len] = '\0';
	tmp_buff1[tmp_len + 1] = '\0';
	utf16le_to_utf8(tmp_buff1.get(), tmp_len + 2,
		prefix_buff, sizeof(prefix_buff));
	if (pproplist->set(PR_SUBJECT_PREFIX, prefix_buff) != ecSuccess)
		return FALSE;
	utf16le_to_utf8(&tmp_buff[tmp_len], subject_len - tmp_len,
		tmp_buff1.get(), tmp_buff1_size);
	return pproplist->set(PR_NORMALIZED_SUBJECT, tmp_buff1.get()) == ecSuccess ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_parse_thread_topic(const char *charset,
    const char *field, TPROPVAL_ARRAY *pproplist) try
{
	static constexpr size_t utf8_field_size = MIME_FIELD_LEN;
	auto utf8_field = std::make_unique<char[]>(utf8_field_size);
	
	if (mime_string_to_utf8(charset, field, utf8_field.get(), utf8_field_size))
		return pproplist->set(PR_CONVERSATION_TOPIC, utf8_field.get()) == ecSuccess;
	return pproplist->set(PR_CONVERSATION_TOPIC_A, field) == ecSuccess ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_parse_thread_index(const char *charset, const char *field,
    TPROPVAL_ARRAY *pproplist) try
{
	static constexpr size_t len = MIME_FIELD_LEN;
	auto tmp_buff = std::make_unique<char[]>(len);
	
	if (!mime_string_to_utf8(charset, field, tmp_buff.get(), len))
		return TRUE;
	auto raw = base64_decode(tmp_buff.get());
	BINARY tmp_bin;
	tmp_bin.pc = raw.data();
	tmp_bin.cb = std::min(raw.size(), static_cast<size_t>(UINT32_MAX));
	return pproplist->set(PR_CONVERSATION_INDEX, &tmp_bin) == ecSuccess ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
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
				PROPERTY_NAME propname = {MNID_ID, PSETID_Common,
				                         PidLidInfoPathFromName};
				if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
					return FALSE;
				uint32_t tag = PROP_TAG(pick_strtype(ptoken), *plast_propid);
				if (pproplist->set(tag, ptoken) != ecSuccess)
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
		if (pproplist->set(tag, field) != ecSuccess)
			return FALSE;
		(*plast_propid) ++;
		return TRUE;
	}
	return pproplist->set(PR_MESSAGE_CLASS, mclass) == ecSuccess ? TRUE : false;
}

static BOOL oxcmail_parse_message_flag(const char *field,
    uint16_t *plast_propid, namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	BOOL b_unicode;
	uint8_t tmp_byte;
	double tmp_double;
	uint32_t tmp_int32;
	
	PROPERTY_NAME propname = {MNID_ID, PSETID_Common, PidLidFlagRequest};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
	if (pproplist->set(tag, field) != ecSuccess)
		return FALSE;
	(*plast_propid) ++;
	tmp_int32 = followupFlagged;
	if (pproplist->set(PR_FLAG_STATUS, &tmp_int32) != ecSuccess)
		return FALSE;
	
	auto str = pproplist->get<const char>(PR_SUBJECT);
	if (str != nullptr) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
		str = pproplist->get<char>(PR_SUBJECT_A);
	}
	if (str != nullptr) {
		propname = {MNID_ID, PSETID_Common, PidLidFlagRequest};
		if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
			return FALSE;
		tag = PROP_TAG(b_unicode ? PT_UNICODE : PT_STRING8, *plast_propid);
		if (pproplist->set(tag, str) != ecSuccess)
			return FALSE;
		(*plast_propid) ++;
	}
	
	propname = {MNID_ID, PSETID_Task, PidLidTaskStatus};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_int32 = 0;
	if (pproplist->set(PROP_TAG(PT_LONG, *plast_propid), &tmp_int32) != ecSuccess)
		return FALSE;
	(*plast_propid) ++;
	
	propname = {MNID_ID, PSETID_Task, PidLidTaskComplete};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_byte = 0;
	if (pproplist->set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != ecSuccess)
		return FALSE;
	(*plast_propid) ++;
	
	propname = {MNID_ID, PSETID_Task, PidLidPercentComplete};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_double = 0.0;
	if (pproplist->set(PROP_TAG(PT_DOUBLE, *plast_propid), &tmp_double) != ecSuccess)
		return FALSE;
	(*plast_propid) ++;
	tmp_int32 = todoRecipientFlagged;
	return pproplist->set(PR_TODO_ITEM_FLAGS, &tmp_int32) == ecSuccess ? TRUE : false;
}

static BOOL oxcmail_parse_classified(const char *field, uint16_t *plast_propid,
    namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	uint8_t tmp_byte;
	
	if (strcasecmp(field, "true") != 0 && strcasecmp(field, "false") != 0)
		return TRUE;
	PROPERTY_NAME propname = {MNID_ID, PSETID_Common, PidLidClassified};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	tmp_byte = 1;
	if (pproplist->set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != ecSuccess)
		return FALSE;
	(*plast_propid)++;
	return TRUE;
}

static BOOL oxcmail_parse_classkeep(const char *field, uint16_t *plast_propid,
    namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	if (strcasecmp(field, "true") != 0 && strcasecmp(field, "false") != 0)
		return TRUE;
	PROPERTY_NAME propname = {MNID_ID, PSETID_Common, PidLidClassificationKeep};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint8_t tmp_byte = strcasecmp(field, "true") == 0;
	if (pproplist->set(PROP_TAG(PT_BOOLEAN, *plast_propid), &tmp_byte) != ecSuccess)
		return FALSE;
	(*plast_propid)++;
	return TRUE;
}

static BOOL oxcmail_parse_classification(const char *field,
    uint16_t *plast_propid, namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	PROPERTY_NAME propname = {MNID_ID, PSETID_Common, PidLidClassification};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
	if (pproplist->set(tag, field) != ecSuccess)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_classdesc(const char *field, uint16_t *plast_propid,
    namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	PROPERTY_NAME propname = {MNID_ID, PSETID_Common, PidLidClassificationDescription};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
	if (pproplist->set(tag, field) != ecSuccess)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_classid(const char *field, uint16_t *plast_propid,
    namemap &phash, TPROPVAL_ARRAY *pproplist)
{
	PROPERTY_NAME propname = {MNID_ID, PSETID_Common, PidLidClassificationGuid};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0)
		return FALSE;
	uint32_t tag = PROP_TAG(pick_strtype(field), *plast_propid);
	if (pproplist->set(tag, field) != ecSuccess)
		return FALSE;
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_enum_mail_head(const char *key, const char *field, void *pparam)
{
	if (*field == '\0')
		return TRUE;
	time_t tmp_time;
	uint8_t tmp_byte;
	uint64_t tmp_int64;
	
	auto penum_param = static_cast<FIELD_ENUM_PARAM *>(pparam);
	if (strcasecmp(key, "From") == 0) {
		if (!oxcmail_parse_address(field,
		    PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_ADDRTYPE,
		    PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENT_REPRESENTING_SMTP_ADDRESS,
		    PR_SENT_REPRESENTING_SEARCH_KEY, PR_SENT_REPRESENTING_ENTRYID,
		    &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Sender") == 0) {
		if (!oxcmail_parse_address(field,
		    PR_SENDER_NAME, PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS,
		    PR_SENDER_SMTP_ADDRESS, PR_SENDER_SEARCH_KEY,
		    PR_SENDER_ENTRYID, &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Reply-To") == 0) {
		if (!oxcmail_parse_reply_to(field, &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "To") == 0) {
		if (!oxcmail_parse_addresses(field, MAPI_TO,
		    penum_param->pmsg->children.prcpts))
			return FALSE;
	} else if (strcasecmp(key, "Cc") == 0) {
		if (!oxcmail_parse_addresses(field, MAPI_CC,
		    penum_param->pmsg->children.prcpts))
			return FALSE;
	} else if (strcasecmp(key, "Bcc") == 0) {
		if (!oxcmail_parse_addresses(field, MAPI_BCC,
		    penum_param->pmsg->children.prcpts))
			return FALSE;
	} else if (strcasecmp(key, "Return-Receipt-To") == 0) {
		tmp_byte = 1;
		if (penum_param->pmsg->proplist.set(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED, &tmp_byte) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Disposition-Notification-To") == 0) {
		tmp_byte = 1;
		if (penum_param->pmsg->proplist.set(PR_READ_RECEIPT_REQUESTED, &tmp_byte) != ecSuccess)
			return FALSE;
		tmp_byte = 1;
		if (penum_param->pmsg->proplist.set(PR_NON_RECEIPT_NOTIFICATION_REQUESTED, &tmp_byte) != ecSuccess)
			return FALSE;
		if (!oxcmail_parse_address(field, PidTagReadReceiptName,
		    PidTagReadReceiptAddressType, PidTagReadReceiptEmailAddress,
		    PidTagReadReceiptSmtpAddress, PR_READ_RECEIPT_SEARCH_KEY,
		    PR_READ_RECEIPT_ENTRYID, &penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Message-ID") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PR_INTERNET_MESSAGE_ID : PR_INTERNET_MESSAGE_ID_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Date") == 0) {
		if (parse_rfc822_timestamp(field, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (penum_param->pmsg->proplist.set(PR_CLIENT_SUBMIT_TIME, &tmp_int64) != ecSuccess)
				return FALSE;
		}
	} else if (strcasecmp(key, "References") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PR_INTERNET_REFERENCES : PR_INTERNET_REFERENCES_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Sensitivity") == 0) {
		uint32_t tmp_int32 = om_parse_sensitivity(field);
		if (penum_param->pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Importance") == 0 ||
		strcasecmp(key, "X-MSMail-Priority") == 0) {
		uint32_t tmp_int32 = om_parse_importance(field);
		if (penum_param->pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Priority") == 0) {
		uint32_t tmp_int32 = om_parse_priority(field);
		if (penum_param->pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-Priority") == 0) {
		uint32_t tmp_int32 = om_parse_xpriority(field);
		if (penum_param->pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Subject") == 0) {
		if (!oxcmail_parse_subject(penum_param->charset, field,
		    &penum_param->pmsg->proplist))
			return FALSE;
		if (!penum_param->pmsg->proplist.has(PR_SUBJECT_PREFIX)) {
			tmp_byte = '\0';
			if (penum_param->pmsg->proplist.set(PR_SUBJECT_PREFIX, &tmp_byte) != ecSuccess)
				return FALSE;
			auto str = penum_param->pmsg->proplist.get<const char>(PR_SUBJECT);
			if (str == nullptr) {
				str = penum_param->pmsg->proplist.get<char>(PR_SUBJECT_A);
				if (str != nullptr &&
				    penum_param->pmsg->proplist.set(PR_NORMALIZED_SUBJECT_A, str) != ecSuccess)
					return FALSE;
			} else if (penum_param->pmsg->proplist.set(PR_NORMALIZED_SUBJECT, str) != ecSuccess) {
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
		uint32_t tag = str_isascii(field) ?
		               PR_IN_REPLY_TO_ID : PR_IN_REPLY_TO_ID_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Reply-By") == 0) {
		if (parse_rfc822_timestamp(field, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (penum_param->pmsg->proplist.set(PR_REPLY_TIME, &tmp_int64) != ecSuccess)
				return FALSE;
		}
	} else if (strcasecmp(key, "Content-Language") == 0) {
		uint32_t tmp_int32 = ltag_to_lcid(field);
		if (tmp_int32 != 0 &&
		    penum_param->pmsg->proplist.set(PR_MESSAGE_LOCALE_ID, &tmp_int32) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Accept-Language") == 0 ||
		strcasecmp(key, "X-Accept-Language") == 0) {
		PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS,
		                         0, deconst("Accept-Language")};
		if (namemap_add(penum_param->phash, penum_param->last_propid,
		    std::move(propname)) != 0)
			return FALSE;
		uint32_t tag = PROP_TAG(pick_strtype(field), penum_param->last_propid);
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
		penum_param->last_propid ++;
	} else if (strcasecmp(key, "Keywords") == 0) {
		PROPERTY_NAME propname = {MNID_STRING, PS_PUBLIC_STRINGS,
		                         0, deconst(PidNameKeywords)};
		if (namemap_add(penum_param->phash, penum_param->last_propid,
		    std::move(propname)) != 0)
			return FALSE;
		if (!oxcmail::parse_keywords(penum_param->charset, field,
		    penum_param->last_propid, penum_param->pmsg->proplist))
			return FALSE;
		penum_param->last_propid ++;
	} else if (strcasecmp(key, "Expires") == 0 ||
		strcasecmp(key, "Expiry-Date") == 0) {
		if (parse_rfc822_timestamp(field, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (penum_param->pmsg->proplist.set(PR_EXPIRY_TIME, &tmp_int64) != ecSuccess)
				return FALSE;
		}
	} else if (strcasecmp(key, "X-Auto-Response-Suppress") == 0) {
		if (!oxcmail::parse_response_suppress(field,
		    penum_param->pmsg->proplist))
			return FALSE;
	} else if (strcasecmp(key, "Precedence") == 0) {
		if (penum_param->pmsg->proplist.set(PR_INTERNET_PRECEDENCE, field) != ecSuccess)
			return false;
	} else if (strcasecmp(key, "Auto-Submitted") == 0 &&
	    strcasecmp(field, "no") != 0) {
		static constexpr uint32_t val = AUTO_RESPONSE_SUPPRESS_AUTOREPLY | AUTO_RESPONSE_SUPPRESS_OOF;
		if (!penum_param->pmsg->proplist.has(PR_AUTO_RESPONSE_SUPPRESS) &&
		    penum_param->pmsg->proplist.set(PR_AUTO_RESPONSE_SUPPRESS, &val) != ecSuccess)
			return false;
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
		uint32_t tag = str_isascii(field) ?
		               PR_LIST_HELP : PR_LIST_HELP_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "List-Subscribe") == 0 ||
		strcasecmp(key, "X-List-Subscribe") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PR_LIST_SUBSCRIBE : PR_LIST_SUBSCRIBE_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "List-Unsubscribe") == 0 ||
		strcasecmp(key, "X-List-Unsubscribe") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PR_LIST_UNSUBSCRIBE : PR_LIST_UNSUBSCRIBE_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-Payload-Class") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PR_ATTACH_PAYLOAD_CLASS : PR_ATTACH_PAYLOAD_CLASS_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-MS-Exchange-Organization-PRD") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PR_PURPORTED_SENDER_DOMAIN : PR_PURPORTED_SENDER_DOMAIN_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-MS-Exchange-Organization-SenderIdResult") == 0) {
		uint32_t tmp_int32 = om_parse_senderidresult(field);
		if (tmp_int32 != 0 &&
		    penum_param->pmsg->proplist.set(PR_SENDER_ID_STATUS, &tmp_int32) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-MS-Exchange-Organization-SCL") == 0) {
		int32_t tmp_int32 = strtol(field, nullptr, 0);
		if (penum_param->pmsg->proplist.set(PR_CONTENT_FILTER_SCL, &tmp_int32) != ecSuccess)
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
		uint32_t tag = str_isascii(field) ?
		               PR_SENDER_TELEPHONE_NUMBER :
		               PR_SENDER_TELEPHONE_NUMBER_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-VoiceMessageSenderName") == 0) {
		uint32_t tag = str_isascii(field) ?
		                  PidTagVoiceMessageSenderName :
		                  PidTagVoiceMessageSenderName_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-AttachmentOrder") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PidTagVoiceMessageAttachmentOrder :
		               PidTagVoiceMessageAttachmentOrder_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-CallID") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PidTagCallId : PidTagCallId_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-VoiceMessageDuration") == 0) {
		uint32_t tmp_int32 = strtoul(field, nullptr, 0);
		if (penum_param->pmsg->proplist.set(PidTagVoiceMessageDuration, &tmp_int32) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "X-FaxNumberOfPages") == 0) {
		uint32_t tmp_int32 = strtoul(field, nullptr, 0);
		if (penum_param->pmsg->proplist.set(PidTagFaxNumberOfPages, &tmp_int32) != ecSuccess)
			return FALSE;
	} else if (strcasecmp(key, "Content-ID") == 0) {
		uint32_t tag = str_isascii(field) ?
			       PR_BODY_CONTENT_ID : PR_BODY_CONTENT_ID_A;
		if (field[0] == '<' && field[1] != '\0') {
			std::string rw = field + 1;
			if (rw.back() == '>')
				rw.pop_back();
			if (penum_param->pmsg->proplist.set(tag, rw.c_str()) != ecSuccess)
				return FALSE;
		} else {
			if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
				return FALSE;
		}
	} else if (strcasecmp(key, "Content-Base") == 0) {
		PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS,
		                         0, deconst("Content-Base")};
		if (namemap_add(penum_param->phash, penum_param->last_propid,
		    std::move(propname)) != 0)
			return FALSE;
		uint32_t tag = PROP_TAG(pick_strtype(field), penum_param->last_propid);
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
			return FALSE;
		penum_param->last_propid ++;
	} else if (strcasecmp(key, "Content-Location") == 0) {
		uint32_t tag = str_isascii(field) ?
		               PR_BODY_CONTENT_LOCATION : PR_BODY_CONTENT_LOCATION_A;
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
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
		if (penum_param->pmsg->proplist.set(tag, field) != ecSuccess)
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
			if (penum_param->pmsg->proplist.set(PR_MESSAGE_DELIVERY_TIME, &tmp_int64) != ecSuccess)
				return false;
		}
	}
	return TRUE;
}

static bool oxcmail_parse_transport_message_header(const MIME *pmime,
    TPROPVAL_ARRAY *pproplist) try
{
	size_t tmp_len = pmime->head_length + 3; /* weird behavior of read_head needs 2 extra */
	auto tmp_buff = std::make_unique<char[]>(tmp_len);
	if (!pmime->read_head(tmp_buff.get(), &tmp_len))
		return TRUE;
	tmp_buff[tmp_len] = '\0';
	uint32_t tag = str_isascii(tmp_buff.get()) ?
	               PR_TRANSPORT_MESSAGE_HEADERS :
	               PR_TRANSPORT_MESSAGE_HEADERS_A;
	return pproplist->set(tag, tmp_buff.get()) == ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static bool oxcmail_parse_message_body(const char *charset, const MIME *pmime,
    TPROPVAL_ARRAY *pproplist) try
{
	auto rdlength = pmime->get_length();
	if (rdlength < 0) {
		mlog(LV_ERR, "%s:MIME::get_length: unsuccessful", __func__);
		return false;
	}
	std::string rawbody;
	rawbody.resize(rdlength);
	size_t length = rdlength;
	if (!pmime->read_content(rawbody.data(), &length))
		return TRUE;
	rawbody.resize(length);

	std::string best_charset;
	if (!oxcmail_get_content_param(pmime, "charset", best_charset))
		best_charset = charset;
	if (strcasecmp(pmime->content_type, "text/html") == 0)
		return bodyset_html(*pproplist, std::move(rawbody),
		       best_charset.c_str()) == ecSuccess;
	else if (strcasecmp(pmime->content_type, "text/plain") == 0)
		return bodyset_plain(*pproplist, std::move(rawbody),
		       best_charset.c_str()) == ecSuccess;
	else if (strcasecmp(pmime->content_type, "text/enriched") == 0)
		return bodyset_enriched(*pproplist, std::move(rawbody),
		       best_charset.c_str()) == ecSuccess;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static gmf_output oxcmail_get_massaged_filename(const MIME *mime,
    MIME_ENUM_PARAM &ei, const char *cttype)
{
	gmf_output ret;
	std::string raw_fn;
	auto have_fn = mime->get_filename(raw_fn);

	if (have_fn) {
		char cooked_fn[1024];
		auto uni = mime_string_to_utf8(ei.charset, raw_fn.c_str(),
		           cooked_fn, std::size(cooked_fn));
		if (uni) {
			ret.tag = PR_ATTACH_LONG_FILENAME;
			ret.fn  = cooked_fn;
		} else {
			ret.fn  = std::move(raw_fn);
		}
		replace_reserved_chars(ret.fn.data());
		replace_trailing_dots(ret.fn.data());
		replace_leading_dots(ret.fn.data());
		auto pos = ret.fn.find_last_of('.');
		if (pos != ret.fn.npos && ret.fn.size() - pos < 16)
			ret.ext = ret.fn.substr(pos);
	} else {
		ret.fn = "attachment" + std::to_string(++ei.attach_id);
	}
	if (ret.ext.size() > 0)
		return ret;
	auto proposal = mime_to_extension(cttype);
	if (proposal == nullptr)
		proposal = "dat";
	ret.ext = "."s + proposal;
	ret.fn += ret.ext;
	return ret;
}

static void oxcmail_enum_attachment(const MIME *pmime, void *pparam)
{
	BINARY tmp_bin;
	time_t tmp_time;
	uint64_t tmp_int64;
	uint32_t tmp_int32;
	char tmp_buff[1024];
	char date_buff[128];
	char display_name[512];
	ATTACHMENT_CONTENT *pattachment;
	
	assert(pmime != nullptr);
	auto pmime_enum = static_cast<MIME_ENUM_PARAM *>(pparam);
	if (!pmime_enum->b_result)
		return;
	if (std::find(pmime_enum->htmls.cbegin(), pmime_enum->htmls.cend(),
	    pmime) != pmime_enum->htmls.cend() ||
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
	if (pattachment->proplist.set(PR_ATTACH_MIME_TAG, newval) != ecSuccess)
		return;
	auto gmf = oxcmail_get_massaged_filename(pmime, *pmime_enum, cttype);
	if (gmf.ext.size() > 0 &&
	    pattachment->proplist.set(PR_ATTACH_EXTENSION, gmf.ext.c_str()) != ecSuccess)
		return;
	if (pattachment->proplist.set(gmf.tag, gmf.fn.c_str()) != ecSuccess)
		return;
	auto b_description = pmime->get_field("Content-Description", tmp_buff, 256);
	if (b_description) {
		uint32_t tag;
		if (mime_string_to_utf8(pmime_enum->charset, tmp_buff,
		    display_name, std::size(display_name))) {
			tag = PR_DISPLAY_NAME;
		} else {
			tag = PR_DISPLAY_NAME_A;
			gx_strlcpy(display_name, tmp_buff, std::size(display_name));
		}
		if (pattachment->proplist.set(tag, display_name) != ecSuccess)
			return;
	}
	bool b_inline = false;
	if (pmime->get_field("Content-Disposition", tmp_buff, 1024)) {
		b_inline = strcmp(tmp_buff, "inline") == 0 || strncasecmp(tmp_buff, "inline;", 7) == 0;
		if (oxcmail_get_field_param(tmp_buff, "create-date", date_buff, 128) &&
		    parse_rfc822_timestamp(date_buff, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (pattachment->proplist.set(PR_CREATION_TIME, &tmp_int64) != ecSuccess)
				return;
		}
		if (oxcmail_get_field_param(tmp_buff, "modification-date", date_buff, 128) &&
		    parse_rfc822_timestamp(date_buff, &tmp_time)) {
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (pattachment->proplist.set(PR_LAST_MODIFICATION_TIME, &tmp_int64) != ecSuccess)
				return;
		}
	}
	if (!pattachment->proplist.has(PR_CREATION_TIME) &&
	    pattachment->proplist.set(PR_CREATION_TIME, &pmime_enum->nttime_stamp) != ecSuccess)
		return;
	if (!pattachment->proplist.has(PR_LAST_MODIFICATION_TIME) &&
	    pattachment->proplist.set(PR_LAST_MODIFICATION_TIME, &pmime_enum->nttime_stamp) != ecSuccess)
		return;
	if (pmime->get_field("Content-ID", tmp_buff, 128)) {
		tmp_int32 = strlen(tmp_buff);
		if (tmp_int32 > 0) {
			if (tmp_buff[tmp_int32-1] == '>')
				tmp_buff[tmp_int32 - 1] = '\0';
			newval = tmp_buff[0] == '<' ? tmp_buff + 1 : tmp_buff;
			uint32_t tag = str_isascii(newval) ?
			                  PR_ATTACH_CONTENT_ID : PR_ATTACH_CONTENT_ID_A;
			if (pattachment->proplist.set(tag, newval) != ecSuccess)
				return;
		}
	} else {
		auto ct_iter = pmime_enum->new_ctids.find(pmime);
		if (ct_iter != pmime_enum->new_ctids.end() &&
		    pattachment->proplist.set(PR_ATTACH_CONTENT_ID, ct_iter->second.c_str()) != ecSuccess)
			return;
	}
	if (pmime->get_field("Content-Location", tmp_buff, 1024)) {
		uint32_t tag = str_isascii(tmp_buff) ?
		                  PR_ATTACH_CONTENT_LOCATION :
		                  PR_ATTACH_CONTENT_LOCATION_A;
		if (pattachment->proplist.set(tag, tmp_buff) != ecSuccess)
			return;
	}
	if (pmime->get_field("Content-Base", tmp_buff, 1024)) {
		uint32_t tag = str_isascii(tmp_buff) ?
		                  PR_ATTACH_CONTENT_BASE : PR_ATTACH_CONTENT_BASE_A;
		if (pattachment->proplist.set(tag, tmp_buff) != ecSuccess)
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
		if (pattachment->proplist.set(PR_ATTACH_FLAGS, &tmp_int32) != ecSuccess)
			return;
	}
	if (strcasecmp(cttype, "text/directory") == 0) {
		auto rdlength = pmime->get_length();
		if (rdlength < 0) {
			mlog(LV_ERR, "%s:MIME::get_length:%u: unsuccessful", __func__, __LINE__);
			return;
		}
		size_t content_len = rdlength;
		auto contallocsz = mb_to_utf8_xlen(content_len) + 1;
		std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(contallocsz));
		if (pcontent == nullptr)
			return;
		if (!pmime->read_content(pcontent.get(), &content_len))
			return;
		pcontent[content_len] = '\0';

		std::string mime_charset;
		if (!oxcmail_get_content_param(pmime, "charset", mime_charset))
			mime_charset = utf8_valid(pcontent.get()) ?
				       "utf-8" : pmime_enum->charset;

		if (string_mb_to_utf8(mime_charset.c_str(), pcontent.get(),
		    &pcontent[content_len+1], contallocsz - content_len - 1)) {
			utf8_filter(&pcontent[content_len+1]);
			oxvcard_converter vc_cvt;
			vc_cvt.get_propids = pmime_enum->get_propids;
			vcard vcard;
			std::unique_ptr<message_content, mc_delete> pmsg;
			auto ret = vcard.load_single_from_str_move(pcontent.get() + content_len + 1);
			if (ret == ecSuccess &&
			    (pmsg = vc_cvt.vcard_to_mapi(vcard)) != nullptr) {
				pattachment->set_embedded_internal(pmsg.release());
				tmp_int32 = ATTACH_EMBEDDED_MSG;
				if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) == ecSuccess)
					pmime_enum->b_result = true;
				return;
			}
		}
		/* parsing as vcard failed */
		tmp_int32 = ATTACH_BY_VALUE;
		if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != ecSuccess)
			return;
		tmp_bin.cb = content_len;
		tmp_bin.pc = pcontent.get();
		pmime_enum->b_result = pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) == ecSuccess;
		return;
	}
	if (strcasecmp(cttype, "message/rfc822") == 0 ||
	    (gmf.have_orig_fn && strcasecmp(gmf.ext.c_str(), ".eml") == 0)) {
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
		if (mail.refonly_parse(pcontent.get(), content_len)) {
			pattachment->proplist.erase(PR_ATTACH_LONG_FILENAME);
			pattachment->proplist.erase(PR_ATTACH_LONG_FILENAME_A);
			pattachment->proplist.erase(PR_ATTACH_EXTENSION);
			pattachment->proplist.erase(PR_ATTACH_EXTENSION_A);
			char sbbf[512];
			if (!b_description &&
			    mail.get_head()->get_field("Subject", tmp_buff, std::size(tmp_buff)) &&
			    mime_string_to_utf8(pmime_enum->charset, tmp_buff,
			    sbbf, std::size(sbbf)) &&
			    pattachment->proplist.set(PR_DISPLAY_NAME, sbbf) != ecSuccess)
				return;
			tmp_int32 = ATTACH_EMBEDDED_MSG;
			if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != ecSuccess)
				return;
			oxcmail_converter cvt;
			cvt.alloc = pmime_enum->alloc;
			cvt.get_propids = pmime_enum->get_propids;
			auto pmsg = cvt.inet_to_mapi(mail);
			if (pmsg == nullptr)
				return;
			pattachment->set_embedded_internal(pmsg.release());
			pmime_enum->b_result = true;
			return;
		}
	}

	std::string tmp_str, site_buff, dir_buff;
	if (gmf.have_orig_fn != 0 && strcasecmp(cttype, "message/external-body") == 0 &&
	    oxcmail_get_content_param(pmime, "access-type", tmp_str) &&
	    strcasecmp(tmp_str.c_str(), "anon-ftp") == 0 &&
	    oxcmail_get_content_param(pmime, "site", site_buff) &&
	    oxcmail_get_content_param(pmime, "directory", dir_buff)) {
		std::string mode_buff;
		if (oxcmail_get_content_param(pmime, "mode", mode_buff))
			/* mode_buff.clear() - already empty */;
		if (strcasecmp(mode_buff.c_str(), "ascii") == 0)
			mode_buff = ";type=a";
		else if (strcasecmp(mode_buff.c_str(), "image") == 0)
			mode_buff = ";type=i";
		tmp_bin.cb = gx_snprintf(tmp_buff, std::size(tmp_buff), "[InternetShortcut]\r\n"
		                         "URL=ftp://%s/%s/%s%s", site_buff.c_str(), dir_buff.c_str(),
		                         gmf.fn.c_str(), mode_buff.c_str());
		tmp_bin.pc = deconst(mode_buff.c_str());
		if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != ecSuccess)
			return;
		gmf.fn += ".url";
		if (pattachment->proplist.set(gmf.tag, gmf.fn.c_str()) == ecSuccess)
			pmime_enum->b_result = true;
		return;
	}
	tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != ecSuccess)
		return;
	if (strncasecmp(cttype, "text/", 5) == 0 &&
	    oxcmail_get_content_param(pmime, "charset", tmp_str)) {
		uint32_t tag = str_isascii(tmp_str.c_str()) ?
		               PidTagTextAttachmentCharset :
		               PidTagTextAttachmentCharset_A;
		if (pattachment->proplist.set(tag, tmp_str.c_str()) != ecSuccess)
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
	pmime_enum->b_result = pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) == ecSuccess;
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
	
	for (i=0; i<pproplist->count; i++) {
		auto proptag = pproplist->ppropval[i].proptag;
		auto propid = PROP_ID(proptag);
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
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids) try
{
	PROPID_ARRAY propids;
	PROPID_ARRAY propids1;
	PROPNAME_ARRAY propnames;
	
	propnames.count = 0;
	propnames.ppropname = static_cast<PROPERTY_NAME *>(alloc(sizeof(PROPERTY_NAME) * phash.size()));
	if (propnames.ppropname == nullptr)
		return FALSE;
	for (const auto &pair : phash) {
		propids.push_back(pair.first);
		propnames.ppropname[propnames.count++] = pair.second;
	}
	if (!get_propids(&propnames, &propids1) ||
	    propids1.size() != propnames.size())
		return FALSE;
	propididmap_t phash1;
	for (size_t i = 0; i < propids.size(); ++i)
		phash1.emplace(propids[i], propids1[i]);
	oxcmail_replace_propid(&pmsg->proplist, phash1);
	if (pmsg->children.prcpts != nullptr)
		for (auto &rcpt : *pmsg->children.prcpts)
			oxcmail_replace_propid(&rcpt, phash1);
	if (pmsg->children.pattachments != nullptr)
		for (auto &at : *pmsg->children.pattachments)
			oxcmail_replace_propid(&at.proplist, phash1);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static void oxcmail_remove_flag_properties(
	MESSAGE_CONTENT *pmsg, GET_PROPIDS get_propids)
{
	PROPID_ARRAY propids;
	const PROPERTY_NAME propname_buff[] = {
		{MNID_ID, PSETID_Task, PidLidTaskDueDate},
		{MNID_ID, PSETID_Task, PidLidTaskStartDate},
		{MNID_ID, PSETID_Task, PidLidTaskDateCompleted},
	};
	enum { l_duedate = 0, l_startdate, l_datecompl };
	static_assert(l_datecompl + 1 == std::size(propname_buff));
	const PROPNAME_ARRAY propnames = {std::size(propname_buff), deconst(propname_buff)};
	
	pmsg->proplist.erase(PR_FLAG_COMPLETE_TIME);
	if (!get_propids(&propnames, &propids) ||
	    propids.size() != 3)
		return;
	pmsg->proplist.erase(PROP_TAG(PT_SYSTIME, propids[l_duedate]));
	pmsg->proplist.erase(PROP_TAG(PT_SYSTIME, propids[l_startdate]));
	pmsg->proplist.erase(PROP_TAG(PT_SYSTIME, propids[l_datecompl]));
}

static BOOL oxcmail_copy_message_proplist(
	MESSAGE_CONTENT *pmsg, MESSAGE_CONTENT *pmsg1)
{
	for (unsigned int i = 0; i < pmsg->proplist.count; ++i)
		if (!pmsg1->proplist.has(pmsg->proplist.ppropval[i].proptag) &&
		    pmsg1->proplist.set(pmsg->proplist.ppropval[i]) != ecSuccess)
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

static bool oxcmail_enum_dsn_rcpt_fields(const std::vector<dsn_field> &pfields,
    void *pparam) try
{
	int kind;
	int tmp_len;
	char *ptoken1;
	char *ptoken2;
	DSN_FILEDS_INFO f_info;
	
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
	char tmp_buff[1280];
	gx_strlcpy(tmp_buff, f_info.status, std::size(tmp_buff));
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
	if (pproplist->set(PR_RECIPIENT_TYPE, &tmp_int32) != ecSuccess)
		return false;

	char display_name[512]{};
	if (f_info.x_display_name != nullptr &&
	    strlen(f_info.x_display_name) < 256 &&
	    mime_string_to_utf8("utf-8", f_info.x_display_name, display_name,
	    std::size(display_name)) &&
	    pproplist->set(PR_DISPLAY_NAME, display_name) != ecSuccess)
		return false;
	auto dtypx = DT_MAILUSER;
	std::string essdn, skb;
	if (!oxcmail_get_user_ids(f_info.final_recipient, nullptr, nullptr, &dtypx) ||
	    cvt_username_to_essdn(f_info.final_recipient, g_oxcmail_org_name,
	    oxcmail_get_user_ids, oxcmail_get_domain_ids, essdn) != ecSuccess) {
		dtypx = DT_MAILUSER;
		skb = "SMTP:"s + f_info.final_recipient;
		if (pproplist->set(PR_ADDRTYPE, "SMTP") != ecSuccess ||
		    pproplist->set(PR_EMAIL_ADDRESS, f_info.final_recipient) != ecSuccess)
			return false;
	} else {
		skb = "EX:"s + essdn;
		if (pproplist->set(PR_ADDRTYPE, "EX") != ecSuccess ||
		    pproplist->set(PR_EMAIL_ADDRESS, essdn.c_str()) != ecSuccess)
			return false;
	}
	HX_strupper(skb.data());
	BINARY srchkey;
	srchkey.cb = skb.size() + 1;
	srchkey.pc = deconst(skb.c_str());
	if (pproplist->set(PR_SMTP_ADDRESS, f_info.final_recipient) != ecSuccess ||
	    pproplist->set(PR_SEARCH_KEY, &srchkey) != ecSuccess)
		return false;
	BINARY tmp_bin{};
	tmp_bin.pc = tmp_buff;
	if ('\0' == essdn[0]) {
		if (!oxcmail_username_to_oneoff(f_info.final_recipient,
		    display_name, &tmp_bin))
			return false;
	} else {
		if (!oxcmail_essdn_to_entryid(essdn.c_str(), &tmp_bin))
			return false;
	}
	if (pproplist->set(PR_ENTRYID, &tmp_bin) != ecSuccess ||
	    pproplist->set(PR_RECIPIENT_ENTRYID, &tmp_bin) != ecSuccess ||
	    pproplist->set(PR_RECORD_KEY, &tmp_bin) != ecSuccess)
		return false;
	tmp_int32 = static_cast<uint32_t>(dtypx == DT_DISTLIST ? MAPI_DISTLIST : MAPI_MAILUSER);
	if (pproplist->set(PR_OBJECT_TYPE, &tmp_int32) != ecSuccess)
		return false;
	tmp_int32 = static_cast<uint32_t>(dtypx);
	if (pproplist->set(PR_DISPLAY_TYPE, &tmp_int32) != ecSuccess)
		return false;
	tmp_int32 = recipSendable;
	if (pproplist->set(PR_RECIPIENT_FLAGS, &tmp_int32) != ecSuccess)
		return false;
	if (f_info.remote_mta[0] != '\0' &&
	    pproplist->set(PR_DSN_REMOTE_MTA, f_info.remote_mta) != ecSuccess)
		return false;
	if (pproplist->set(PR_REPORT_TIME, &pinfo->submit_time) != ecSuccess)
		return false;
	if (NULL != f_info.x_supplementary_info) {
		if (pproplist->set(PR_SUPPLEMENTARY_INFO, f_info.x_supplementary_info) != ecSuccess)
			return false;
	} else {
		if (f_info.diagnostic_code == nullptr)
			snprintf(tmp_buff, 1024, "<%s #%s>",
				f_info.remote_mta, f_info.status);
		else
			snprintf(tmp_buff, 1024, "<%s #%s %s>",
				f_info.remote_mta, f_info.status,
				f_info.diagnostic_code);
		if (pproplist->set(PR_SUPPLEMENTARY_INFO, tmp_buff) != ecSuccess)
			return false;
	}
	uint32_t status_code = 100 * kind + 10 * subject + detail;
	if (pproplist->set(PR_NDR_STATUS_CODE, &status_code) != ecSuccess)
		return false;
	auto [diagnostic_code, reason_code] = status_code_to_diag(subject, detail);
	if (pproplist->set(PR_NDR_DIAG_CODE, &diagnostic_code) != ecSuccess ||
	    pproplist->set(PR_NDR_REASON_CODE, &reason_code) != ecSuccess)
		return false;
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static bool oxcmail_enum_dsn_reporting_mta(const char *tag,
    const char *value, void *pparam)
{
	if (strcasecmp(tag, "Reporting-MTA") != 0)
		return true;
	auto &pl = static_cast<MESSAGE_CONTENT *>(pparam)->proplist;
	return pl.set(PidTagReportingMessageTransferAgent, value) == ecSuccess;
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

static const MIME *oxcmail_parse_dsn(const MAIL *pmail, MESSAGE_CONTENT *pmsg) try
{
	DSN_ENUM_INFO dsn_info;
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
	if (mgl < 0)
		return nullptr;

	auto content_len = static_cast<size_t>(mgl) + 1;
	auto tmp_buff = std::make_unique<char[]>(content_len);
	if (!pmime->read_content(tmp_buff.get(), &content_len))
		return NULL;

	DSN dsn;
	if (!dsn.load_from_str(tmp_buff.get(), content_len))
		return NULL;
	tmp_buff.reset();
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
	if (as != nullptr &&
	    pmsg->proplist.set(PR_MESSAGE_CLASS, as) != ecSuccess)
		return nullptr;
	return pmime;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return nullptr;
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
		    mcparam->proplist.set(PR_ORIGINAL_DISPLAY_TO, value + 7) != ecSuccess)
			return false;
	} else if (0 == strcasecmp(tag, "Final-Recipient")) {
		if (strncasecmp(value, "rfc822;", 7) == 0 &&
		    !static_cast<MESSAGE_CONTENT *>(pparam)->proplist.has(PR_ORIGINAL_DISPLAY_TO))
			return mcparam->proplist.set(PR_ORIGINAL_DISPLAY_TO, value + 7) == ecSuccess;
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
		return mcparam->proplist.set(PR_MESSAGE_CLASS, tmp_buff) == ecSuccess &&
		       mcparam->proplist.set(PR_REPORT_TEXT, value) == ecSuccess;
	} else if (0 == strcasecmp(tag, "X-MSExch-Correlation-Key")) {
		len = strlen(value);
		if (len <= 1024 && decode64(value, len, tmp_buff,
		    std::size(tmp_buff), &len) == 0) {
			tmp_bin.pc = tmp_buff;
			tmp_bin.cb = len;
			return mcparam->proplist.set(PR_PARENT_KEY, &tmp_bin) == ecSuccess;
		}
	} else if (0 == strcasecmp(tag, "Original-Message-ID")) {
		return mcparam->proplist.set(PidTagOriginalMessageId, value) == ecSuccess &&
		       mcparam->proplist.set(PR_INTERNET_REFERENCES, value) == ecSuccess;
	} else if (0 == strcasecmp(tag, "X-Display-Name")) {
		if (mime_string_to_utf8("utf-8", value, tmp_buff,
		    std::size(tmp_buff)))
			return mcparam->proplist.set(PR_DISPLAY_NAME, tmp_buff) == ecSuccess;
		return mcparam->proplist.set(PR_DISPLAY_NAME_A, value) == ecSuccess;
	}
	return true;
}

static const MIME *oxcmail_parse_mdn(const MAIL *pmail, MESSAGE_CONTENT *pmsg) try
{
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
	if (mgl < 0)
		return nullptr;

	auto content_len = static_cast<size_t>(mgl) + 1;
	auto tmp_buff = std::make_unique<char[]>(content_len);
	if (!pmime->read_content(tmp_buff.get(), &content_len))
		return NULL;

	DSN dsn;
	if (!dsn.load_from_str(tmp_buff.get(), content_len) ||
	    !dsn.enum_fields(*dsn.get_message_fields(), oxcmail_enum_mdn, pmsg))
		return NULL;
	dsn.clear();
	tmp_buff.reset();
	auto ts = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (pmsg->proplist.set(PR_ORIGINAL_DELIVERY_TIME, ts) != ecSuccess ||
	    pmsg->proplist.set(PR_RECEIPT_TIME, ts) != ecSuccess)
		return NULL;
	for (auto &rcpt : *pmsg->children.prcpts)
		if (rcpt.set(PR_REPORT_TIME, ts) != ecSuccess)
			return NULL;
	return pmime;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return nullptr;
}

static BOOL oxcmail_parse_encrypted(const MIME *phead, uint16_t *plast_propid,
    namemap &phash, MESSAGE_CONTENT *pmsg)
{
	char tmp_buff[1024];
	
	if (!phead->get_field("Content-Type", tmp_buff, std::size(tmp_buff)))
		return FALSE;
	PROPERTY_NAME propname = {MNID_STRING, PS_INTERNET_HEADERS, 0, deconst("Content-Type")};
	if (namemap_add(phash, *plast_propid, std::move(propname)) != 0 ||
	    pmsg->proplist.set(PROP_TAG(PT_UNICODE, *plast_propid), tmp_buff) != ecSuccess)
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
	if (pattachment->proplist.set(PR_ATTACH_DATA_BIN, &tmp_bin) != ecSuccess)
		return FALSE;
	tmp_int32 = ATTACH_BY_VALUE;
	if (pattachment->proplist.set(PR_ATTACH_METHOD, &tmp_int32) != ecSuccess ||
	    pattachment->proplist.set(PR_ATTACH_MIME_TAG, content_type) != ecSuccess ||
	    pattachment->proplist.set(PR_ATTACH_EXTENSION, ".p7m") != ecSuccess ||
	    pattachment->proplist.set(PR_ATTACH_FILENAME, "SMIME.p7m") != ecSuccess ||
	    pattachment->proplist.set(PR_ATTACH_LONG_FILENAME, "SMIME.p7m") != ecSuccess ||
	    pattachment->proplist.set(PR_DISPLAY_NAME, "SMIME.p7m") != ecSuccess)
		return FALSE;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
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
	return pproplist->set(pr_normal, pvalue) == ecSuccess ? TRUE : false;
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

static bool smime_clearsigned(const char *head_ct, const MIME *head)
{
	if (strcasecmp(head_ct, "multipart/signed") != 0)
		return false;
	std::string buf;
	if (!oxcmail_get_content_param(head, "protocol", buf))
		return false;
	return strcasecmp(buf.c_str(), "application/pkcs7-signature") == 0 ||
	       strcasecmp(buf.c_str(), "application/x-pkcs7-signature") == 0;
}

static BOOL xlog_bool(const char *func, unsigned int line)
{
	mlog(LV_ERR, "%s:%u returned false; see surrounding log messages", func, line);
	return false;
}

static std::nullptr_t xlog_null(const char *func, unsigned int line)
{
	mlog(LV_ERR, "%s:%u returned false; see surrounding log messages and those of gromox-http for unexpected shutdowns or absence of the mailbox directory", func, line);
	return nullptr;
}

#define imp_null xlog_null(__func__, __LINE__)
std::unique_ptr<message_content, mc_delete> oxcmail_converter::inet_to_mapi(const MAIL &imail) try
{
	auto pmail = &imail;
	namemap phash;
	MIME_ENUM_PARAM mime_enum{phash};
	FIELD_ENUM_PARAM field_param{phash};
	
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> pmsg(message_content_init());
	if (pmsg == nullptr)
		return imp_null;
	/* set default message class */
	if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note") != ecSuccess)
		return imp_null;
	auto prcpts = tarray_set_init();
	if (prcpts == nullptr)
		return imp_null;
	pmsg->set_rcpts_internal(prcpts);

	std::string default_charset;
	if (!pmail->get_charset(default_charset))
		default_charset = "us-ascii";
	field_param.alloc = alloc;
	field_param.pmail = pmail;
	field_param.pmsg = pmsg.get();
	field_param.charset = default_charset.c_str();
	field_param.last_propid = 0x8000;
	field_param.b_flag_del = false;
	const MIME *phead = pmail->get_head();
	if (phead == nullptr)
		return imp_null;

	char tmp_buff[256];
	field_param.b_classified = phead->get_field("X-Microsoft-Classified", tmp_buff, 16);
	if (!phead->enum_field(oxcmail_enum_mail_head, &field_param))
		return imp_null;
	if (!pmsg->proplist.has(PR_SENDER_NAME) &&
	    !pmsg->proplist.has(PR_SENDER_SMTP_ADDRESS)) {
		if (!oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_NAME, PR_SENT_REPRESENTING_NAME) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_SMTP_ADDRESS, PR_SENT_REPRESENTING_SMTP_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_ADDRTYPE, PR_SENT_REPRESENTING_ADDRTYPE) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_EMAIL_ADDRESS, PR_SENT_REPRESENTING_EMAIL_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_SEARCH_KEY, PR_SENT_REPRESENTING_SEARCH_KEY) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENDER_ENTRYID, PR_SENT_REPRESENTING_ENTRYID))
			return imp_null;
	} else if (!pmsg->proplist.has(PR_SENT_REPRESENTING_NAME) &&
	    !pmsg->proplist.has(PR_SENT_REPRESENTING_SMTP_ADDRESS)) {
		if (!oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_NAME, PR_SENDER_NAME) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_SENDER_SMTP_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_ADDRTYPE, PR_SENDER_ADDRTYPE) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENDER_EMAIL_ADDRESS) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_SEARCH_KEY, PR_SENDER_SEARCH_KEY) ||
		    !oxcmail_try_assign_propval(&pmsg->proplist, PR_SENT_REPRESENTING_ENTRYID, PR_SENDER_ENTRYID))
			return imp_null;
	}
	if (!pmsg->proplist.has(PR_IMPORTANCE)) {
		uint32_t tmp_int32 = IMPORTANCE_NORMAL;
		if (pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != ecSuccess)
			return imp_null;
	}
	if (!pmsg->proplist.has(PR_SENSITIVITY)) {
		uint32_t tmp_int32 = SENSITIVITY_NONE;
		if (pmsg->proplist.set(PR_SENSITIVITY, &tmp_int32) != ecSuccess)
			return imp_null;
	}
	if (!oxcmail_parse_transport_message_header(phead, &pmsg->proplist))
		return imp_null;
	auto ts = pmsg->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (ts == nullptr) {
		mime_enum.nttime_stamp = rop_util_unix_to_nttime(time(NULL));
		if (pmsg->proplist.set(PR_CLIENT_SUBMIT_TIME,
		    &mime_enum.nttime_stamp) != ecSuccess)
			return imp_null;
	} else {
		mime_enum.nttime_stamp = *ts;
	}
	if (pmsg->proplist.set(PR_CREATION_TIME, &mime_enum.nttime_stamp) != ecSuccess
/*	    pmsg->proplist.set(PR_LAST_MODIFICATION_TIME, &mime_enum.nttime_stamp) != ecSuccess */)
		return imp_null;

	if (add_rcvd_timestamp &&
	    !pmsg->proplist.has(PR_MESSAGE_DELIVERY_TIME) &&
	    pmsg->proplist.set(PR_MESSAGE_DELIVERY_TIME, &mime_enum.nttime_stamp) != ecSuccess)
		return imp_null;

	auto head_ct = phead->content_type;
	if (strcasecmp(head_ct, "application/ms-tnef") == 0 &&
	    tnef_vfy_get_field(phead, tmp_buff, std::size(tmp_buff))) {
		std::unique_ptr<message_content, mc_delete> pmsg1(oxcmail_parse_tnef(phead, alloc, get_propids));
		if (pmsg1 != nullptr && tnef_vfy_check_key(pmsg1.get(), tmp_buff)) {
			if (!oxcmail_fetch_propname(pmsg.get(), phash, alloc, get_propids))
				return imp_null;
			if (!oxcmail_copy_message_proplist(pmsg.get(), pmsg1.get()))
				return imp_null;
			std::swap(pmsg->children.prcpts, pmsg1->children.prcpts);
			if (field_param.b_flag_del)
				oxcmail_remove_flag_properties(pmsg1.get(), std::move(get_propids));
			return pmsg1;
		}
	}

	std::string tmp_str;
	if (strcasecmp(head_ct, "multipart/report") == 0 &&
	    oxcmail_get_content_param(phead, "report-type", tmp_str) &&
	    strcasecmp(tmp_str.c_str(), "delivery-status") == 0)
		mime_enum.preport = oxcmail_parse_dsn(pmail, pmsg.get());
	if ((strcasecmp(head_ct, "multipart/report") == 0 &&
	    oxcmail_get_content_param(phead, "report-type", tmp_str) &&
	    strcasecmp(tmp_str.c_str(), "disposition-notification") == 0) ||
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
				if (!oxcmail_parse_message_body(default_charset.c_str(), pmime, &pmsg->proplist) ||
				    !oxcmail_fetch_propname(pmsg.get(), phash, alloc, get_propids))
					return imp_null;
				if (!oxcmail_copy_message_proplist(pmsg.get(), pmsg1.get()))
					return imp_null;
				std::swap(pmsg->children.prcpts, pmsg1->children.prcpts);
				if (field_param.b_flag_del)
					oxcmail_remove_flag_properties(pmsg1.get(), std::move(get_propids));
				return pmsg1;
			}
		}
	} else if (smime_clearsigned(head_ct, phead)) {
		if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME.MultipartSigned") != ecSuccess)
			return imp_null;
		b_smime = true;
	} else if (strcasecmp(head_ct, "application/pkcs7-mime") == 0 ||
	    strcasecmp(head_ct, "application/x-pkcs7-mime") == 0) {
		if (pmsg->proplist.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME") != ecSuccess ||
		    !oxcmail_parse_encrypted(phead, &field_param.last_propid, phash, pmsg.get()))
			return imp_null;
		b_smime = true;
	}
	mime_enum.b_result = true;
	mime_enum.attach_id = 0;
	mime_enum.charset = default_charset.c_str();
	mime_enum.get_propids = get_propids;
	mime_enum.alloc = alloc;
	mime_enum.pmsg = pmsg.get();
	mime_enum.phash = phash;
	select_parts(phead, mime_enum, 0);

	if (mime_enum.pplain != nullptr &&
	    !oxcmail_parse_message_body(default_charset.c_str(),
	    mime_enum.pplain, &pmsg->proplist))
		return imp_null;
	if (mime_enum.htmls.size() > 1) {
		assert(mime_enum.hjoin.size() >= mime_enum.htmls.size());
		auto err = bodyset_multi(mime_enum, pmsg->proplist,
		           default_charset.c_str());
		if (err != ecSuccess)
			return imp_null;
	} else if (mime_enum.htmls.size() > 0) {
		if (!oxcmail_parse_message_body(default_charset.c_str(),
		    mime_enum.htmls.front(), &pmsg->proplist))
			return imp_null;
	} else if (NULL != mime_enum.penriched) {
		if (!oxcmail_parse_message_body(default_charset.c_str(),
		    mime_enum.penriched, &pmsg->proplist))
			return imp_null;
	}
	size_t content_len = 0;
	std::unique_ptr<message_content, mc_delete> pmsg1; /* ical */
	if (NULL != mime_enum.pcalendar) {
		auto rdlength = mime_enum.pcalendar->get_length();
		if (rdlength < 0) {
			mlog(LV_ERR, "%s:MIME::get_length: unsuccessful", __func__);
			return imp_null;
		}
		content_len = rdlength;
		auto contoutsize = mb_to_utf8_xlen(content_len) + 1;
		std::unique_ptr<char[], stdlib_delete> pcontent(me_alloc<char>(contoutsize));
		if (pcontent == nullptr)
			return imp_null;
		if (!mime_enum.pcalendar->read_content(pcontent.get(), &content_len))
			return imp_null;
		pcontent[content_len] = '\0';

		std::string mime_charset;
		if (!oxcmail_get_content_param(mime_enum.pcalendar, "charset",
		    mime_charset))
			mime_charset = utf8_valid(pcontent.get()) ?
			               "utf-8" : default_charset;
		if (!string_mb_to_utf8(mime_charset.c_str(), pcontent.get(),
		    &pcontent[content_len+1], contoutsize - content_len - 1)) {
			mime_enum.pcalendar = NULL;
		} else {
			utf8_filter(&pcontent[content_len+1]);
			ical ical;
			if (!ical.load_from_str_move(&pcontent[content_len+1])) {
				mime_enum.pcalendar = nullptr;
			} else {
				oxcical_converter ical_cvt;
				ical_cvt.alloc = alloc;
				ical_cvt.get_propids = get_propids;
				ical_cvt.username_to_entryid = oxcmail_username_to_entryid;
				pmsg1 = ical_cvt.ical_to_mapi_single(ical);
				if (pmsg1 == nullptr) {
					mlog(LV_WARN, "W-2728: oxcmail_import_single returned no object (parse error?); placing ical as attachment instead");
					mime_enum.pcalendar = NULL;
				}
			}
		}
	}
	assert((mime_enum.pcalendar != nullptr) == (pmsg1 != nullptr)); /* (pcalendar ^ pmsg1) == 0 */
	
	auto pattachments = attachment_list_init();
	if (pattachments == nullptr)
		return imp_null;
	pmsg->set_attachments_internal(pattachments);
	if (b_smime) {
		if (!oxcmail_parse_smime_message(pmail, pmsg.get()))
			return imp_null;
	} else {
		mime_enum.last_propid = field_param.last_propid;
		pmail->enum_mime(oxcmail_enum_attachment, &mime_enum);
		if (!mime_enum.b_result)
			return imp_null;
	}
	if (!oxcmail_fetch_propname(pmsg.get(), phash, alloc, get_propids))
		return imp_null;
	if (NULL != mime_enum.pcalendar) {
		if (!pmsg1->proplist.has(PR_MESSAGE_CLASS)) {
			/* multiple calendar objects in attachment list */
			if (pmsg1->children.pattachments != nullptr &&
			    !oxcmail_merge_message_attachments(pmsg1.get(), pmsg.get()))
				return imp_null;
			pmsg1.reset();
		} else {
			if (!oxcmail_copy_message_proplist(pmsg.get(), pmsg1.get()) ||
			    !oxcmail_merge_message_attachments(pmsg.get(), pmsg1.get()))
				return imp_null;
			pmsg = std::move(pmsg1);
		}
	}
	if (!pmsg->proplist.has(PR_BODY_W) && !pmsg->proplist.has(PR_BODY_A)) {
		auto phtml_bin = pmsg->proplist.get<const BINARY>(PR_HTML);
		if (NULL != phtml_bin) {
			auto num = pmsg->proplist.get<const uint32_t>(PR_INTERNET_CPID);
			auto cpid = num != nullptr ? static_cast<cpid_t>(*num) : CP_OEMCP;
			std::string plainbuf;
			auto ret = html_to_plain(*phtml_bin, cpid, plainbuf);
			if (ret < 0)
				return imp_null;
			else if (ret == CP_OEMCP)
				ret = CP_UTF8;
			if (ret == CP_UTF8) {
				if (pmsg->proplist.set(PR_BODY_W, plainbuf.data()) != ecSuccess)
					return imp_null;
			} else {
				auto z = 3 * plainbuf.size() + 1;
				auto s = static_cast<char *>(alloc(z));
				if (s == nullptr)
					return imp_null;
				auto encoding = cpid_to_cset(cpid);
				if (encoding == nullptr)
					encoding = "windows-1252";
				if (string_mb_to_utf8(encoding, plainbuf.c_str(),
				    s, z) && utf8_valid(s) && pmsg->proplist.set(PR_BODY_W, s) != ecSuccess)
					return imp_null;
			}
		}
	}
	if (!pmsg->proplist.has(PR_HTML)) {
		auto s = pmsg->proplist.get<const char>(PR_BODY);
		if (s != nullptr) {
			std::string html_repr;
			auto err = plain_to_html(s, html_repr);
			if (err != ecSuccess)
				return imp_null;
			BINARY bv;
			bv.pc = html_repr.data();
			bv.cb = html_repr.size();
			if (pmsg->proplist.set(PR_HTML, &bv) != ecSuccess)
				return imp_null;
			uint32_t tmp_int32 = CP_UTF8;
			if (pmsg->proplist.set(PR_INTERNET_CPID, &tmp_int32) != ecSuccess)
				return imp_null;
		}
	}

	if (atxlist_all_hidden(pmsg->children.pattachments)) {
		/*
		 * You know the data model sucks when you cannot determine
		 * all-hidden in O(1) without creating redundant information
		 * like this property.
		 */
		const PROPERTY_NAME namequeries[] = {{MNID_ID, PSETID_Common, PidLidSmartNoAttach}};
		const PROPNAME_ARRAY propnames = {std::size(namequeries), deconst(namequeries)};
		PROPID_ARRAY propids;
		if (!get_propids(&propnames, &propids) || propids.size() != 1)
			return imp_null;
		uint8_t tmp_byte = 1;
		if (pmsg->proplist.set(PROP_TAG(PT_BOOLEAN, propids[0]), &tmp_byte) != ecSuccess)
			return imp_null;
	}
	if (field_param.b_flag_del)
		oxcmail_remove_flag_properties(pmsg.get(), std::move(get_propids));
	return pmsg;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return nullptr;
}
#undef imp_null

template<typename T> static inline std::string enc_text(T &&s)
{
	return vmime::text(s, vmime::charsets::UTF_8).generate();
}

BOOL oxcmail_get_smtp_address(const TPROPVAL_ARRAY &props,
    const addr_tags *ptags, const char *org, cvt_id2user id2user,
    std::string &username) try
{
	auto pproplist = &props;
	const auto &tags = ptags != nullptr ? *ptags : tags_self;
	auto s = pproplist->get<const char>(tags.pr_smtpaddr);
	if (s != nullptr) {
		username = s;
		return TRUE;
	}
	auto addrtype = pproplist->get<const char>(tags.pr_addrtype);
	auto emaddr   = pproplist->get<const char>(tags.pr_emaddr);
	if (addrtype != nullptr) {
		auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr, org,
		           id2user, username);
		if (ret == ecSuccess)
			return TRUE;
		else if (ret != ecNullObject)
			return false;
	}
	auto ret = cvt_entryid_to_smtpaddr(pproplist->get<const BINARY>(tags.pr_entryid),
	           org, std::move(id2user), username);
	return ret == ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

/**
 * Only useful for DSN generation.
 */
static bool oxcmail_get_rcpt_address(const TPROPVAL_ARRAY &props,
    const addr_tags &tags, const char *org, cvt_id2user id2user,
    std::string &username) try
{
	auto em = props.get<const char>(tags.pr_smtpaddr);
	if (em != nullptr) {
		username = "rfc822;"s + em;
		return true;
	}
	auto at = props.get<const char>(tags.pr_addrtype);
	em = props.get<char>(tags.pr_emaddr);
	if (at != nullptr) {
		auto ret = cvt_genaddr_to_smtpaddr(at, em, org,
		           id2user, username);
		if (ret == ecSuccess) {
			username.insert(0, "rfc822;");
			return true;
		} else if (ret != ecNullObject) {
			return false;
		}
	}
	auto v = props.get<const BINARY>(tags.pr_entryid);
	if (v != nullptr) {
		auto ret = cvt_entryid_to_smtpaddr(v, org, std::move(id2user), username);
		if (ret == ecSuccess) {
			username.insert(0, "rfc822;");
			return true;
		} else if (ret != ecNullObject) {
			return false;
		}
	}
	if (at != nullptr) {
		username = at + ";"s + znul(em);
		return true;
	}
	return false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_export_addresses(const TARRAY_SET &rcpt_list,
    uint32_t rcpt_type, vmime::mailboxList &mblist) try
{
	for (const auto &rcpt : rcpt_list) {
		auto pvalue = rcpt.get<uint32_t>(PR_RECIPIENT_TYPE);
		if (pvalue == nullptr || *pvalue != rcpt_type)
			continue;
		auto mb = vmime::make_shared<vmime::mailbox>("");
		auto pdisplay_name = rcpt.get<char>(PR_DISPLAY_NAME);
		if (pdisplay_name != nullptr)
			mb->setName(vmime::text(pdisplay_name, vmime::charsets::UTF_8));
		std::string username;
		if (oxcmail_get_smtp_address(rcpt, &tags_self,
		    g_oxcmail_org_name, oxcmail_get_username, username))
			mb->setEmail(username);
		mblist.appendMailbox(mb);
	}
	return !mblist.isEmpty();
} catch (...) {
	return false;
}

static bool genentryid_to_smtpaddr(const BINARY &bin, std::string &dispname,
    std::string &emaddr)
{
	EXT_PULL ep;
	EMSAB_ENTRYID ems;
	ep.init(bin.pb, bin.cb, malloc, EXT_FLAG_UTF16);
	if (ep.g_abk_eid(&ems) == pack_result::ok &&
	    cvt_essdn_to_username(ems.x500dn.c_str(), g_oxcmail_org_name,
	    oxcmail_get_username, emaddr) == ecSuccess)
		return true;

	ONEOFF_ENTRYID oo;
	ep.init(bin.pb, bin.cb, malloc, EXT_FLAG_UTF16);
	if (ep.g_oneoff_eid(&oo) == pack_result::ok) {
		dispname = std::move(oo.pdisplay_name);
		if (cvt_genaddr_to_smtpaddr(oo.paddress_type.c_str(),
		    oo.pmail_address.c_str(), g_oxcmail_org_name,
		    oxcmail_get_username, emaddr) == ecSuccess)
			return true;
	}

	mlog(LV_WARN, "W-1964: skipping unrecognizable entry in PR_REPLY_RECIPIENTS_TO");
	return false;
}

static bool oxcmail_export_reply_to(const MESSAGE_CONTENT *pmsg,
    vmime::addressList &adrlist) try
{
	EXT_PULL ext_pull;
	BINARY_ARRAY address_array{};
	auto cl_0 = HX::make_scope_exit([&]() {
		for (unsigned int i = 0; i < address_array.count; ++i)
			free(address_array.pbin[i].pb);
		free(address_array.pbin);
	});
	
	auto pbin = pmsg->proplist.get<BINARY>(PR_REPLY_RECIPIENT_ENTRIES);
	if (pbin == nullptr)
		return FALSE;
	/*
	 * PR_REPLY_RECIPIENT_NAMES is semicolon-separated, but there is no way
	 * to distinguish between semicolon as a separator and semicolon as
	 * part of a name. So we ignore that property altogether.
	 */
	ext_pull.init(pbin->pb, pbin->cb, malloc, EXT_FLAG_WCOUNT);
	if (ext_pull.g_flatentry_a(&address_array) != pack_result::ok)
		return FALSE;
	for (size_t i = 0; i < address_array.count; ++i) {
		std::string dispname, emaddr;
		if (!genentryid_to_smtpaddr(address_array.pbin[i], dispname, emaddr))
			continue;
		auto mb = vmime::make_shared<vmime::mailbox>("");
		if (!emaddr.empty()) {
			mb->setEmail(std::move(emaddr));
			if (!dispname.empty())
				mb->setName(vmime::text(std::move(dispname), vmime::charsets::UTF_8));
		}
		adrlist.appendAddress(mb);
	}
	return true;
} catch (...) {
	return false;
}

static BOOL oxcmail_export_address(const MESSAGE_CONTENT *pmsg,
    const addr_tags &tags, vmime::mailbox &mb) try
{
	auto pvalue = pmsg->proplist.get<char>(tags.pr_name);
	if (pvalue != nullptr && *pvalue != '\0')
		mb.setName(vmime::text(pvalue, vmime::charsets::UTF_8));
	std::string address;
	if (oxcmail_get_smtp_address(pmsg->proplist, &tags, g_oxcmail_org_name,
	    oxcmail_get_username, address)) {
		mb.setEmail(address);
		return true;
	}
	return false;
	/*
	 * RFC 5322 §3.4's ABNF mandates an address at all times.
	 * If we only emitted "Display Name", parsers can
	 * preferentially treat that as the email address.
	 * (vmime ensures that won't happen.)
	 */
} catch (...) {
	return false;
}

static bool oxcmail_export_content_class(const char *pmessage_class, std::string &field)
{
	if (class_match_prefix(pmessage_class, "IPM.Note.Microsoft.Fax") == 0)
		field = "fax";
	else if (class_match_prefix(pmessage_class, "IPM.Note.Microsoft.Fax.CA") == 0)
		field = "fax-ca";
	else if (class_match_prefix(pmessage_class, "IPM.Note.Microsoft.Missed.Voice") == 0)
		field = "missedcall";
	else if (class_match_prefix(pmessage_class, "IPM.Note.Microsoft.Conversation.Voice") == 0)
		field = "voice-uc";
	else if (class_match_prefix(pmessage_class, "IPM.Note.Microsoft.Voicemail.UM.CA") == 0)
		field = "voice-ca";
	else if (class_match_prefix(pmessage_class, "IPM.Note.Microsoft.Voicemail.UM") == 0)
		field = "voice";
	else if (strncasecmp(pmessage_class, "IPM.Note.Custom.", 16) == 0)
		field = "urn:content-class:custom."s + pmessage_class;
	else
		return FALSE;
	return TRUE;
}

static enum oxcmail_type oxcmail_get_mail_type(const char *pmessage_class)
{
	if (class_match_prefix( pmessage_class, "IPM.Note.SMIME.MultipartSigned") == 0)
		return oxcmail_type::xsigned;
	if (class_match_prefix(pmessage_class, "IPM.InfoPathForm") == 0) {
		if (class_match_suffix(pmessage_class, ".SMIME.MultipartSigned") == 0)
			return oxcmail_type::xsigned;
		if (class_match_suffix(pmessage_class, ".SMIME") == 0)
			return oxcmail_type::encrypted;
	}
	if (class_match_prefix(pmessage_class, "IPM.Note.SMIME") == 0)
		return oxcmail_type::encrypted;
	if (class_match_prefix(pmessage_class, "IPM.Note") == 0 ||
	    class_match_prefix(pmessage_class, "IPM.InfoPathForm") == 0)
		return oxcmail_type::normal;
	if (class_match_prefix(pmessage_class, "REPORT") == 0) {
		if (class_match_suffix(pmessage_class, ".DR") == 0 ||
		    class_match_suffix(pmessage_class, ".Expanded.DR") == 0 ||
		    class_match_suffix(pmessage_class, ".Relayed.DR") == 0 ||
		    class_match_suffix(pmessage_class, ".Delayed.DR") == 0 ||
		    class_match_suffix(pmessage_class, ".NDR") == 0)
			return oxcmail_type::dsn;
		if (class_match_suffix(pmessage_class, ".IPNRN") == 0 ||
		    class_match_suffix(pmessage_class, ".IPNNRN") == 0)
			return oxcmail_type::mdn;
	}
	if (class_match_prefix(pmessage_class, "IPM.Appointment") == 0 ||
	    class_match_prefix(pmessage_class, "IPM.Schedule.Meeting.Request") == 0 ||
	    class_match_prefix(pmessage_class, "IPM.Schedule.Meeting.Resp.Pos") == 0 ||
	    class_match_prefix(pmessage_class, "IPM.Schedule.Meeting.Resp.Tent") == 0 ||
	    class_match_prefix(pmessage_class, "IPM.Schedule.Meeting.Resp.Neg") == 0 ||
	    class_match_prefix(pmessage_class, "IPM.Schedule.Meeting.Canceled") == 0)
		return oxcmail_type::calendar;
	return oxcmail_type::tnef;
}

static bool skel_prefer_rtf_body(const MESSAGE_CONTENT &msg)
{
	auto v = msg.proplist.get<const uint32_t>(PR_NATIVE_BODY_INFO);
	if (v == nullptr || *v != NATIVE_BODY_RTF)
		return false;
	auto flag = msg.proplist.get<const uint8_t>(PR_RTF_IN_SYNC);
	return flag == nullptr || *flag == 0;
}

static bool skel_grab_rtf(mime_skeleton &skel, const message_content &msg,
    const char *charset) try
{
	auto rtf = msg.proplist.get<const BINARY>(PR_RTF_COMPRESSED);
	if (rtf == nullptr)
		return true;
	auto err = rtfcp_uncompress(*rtf, skel.rtf);
	if (err != ecSuccess) {
		skel.mail_type = oxcmail_type::tnef;
		return true;
	}
	skel.pattachments = attachment_list_init();
	if (skel.pattachments == nullptr)
		return false;
	err = rtf_to_html(skel.rtf, charset, skel.rtf, skel.pattachments);
	if (err != ecSuccess) {
		skel.mail_type = oxcmail_type::tnef;
		return true;
	}
	skel.rtf_bin.pv = skel.rtf.data();
	skel.rtf_bin.cb = skel.rtf.size();
	skel.phtml = &skel.rtf_bin;
	if (skel.pattachments->count > 0)
		skel.b_inline = TRUE;
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

/***
 * Populate pskeleton with condensed information about the message.
 */
static BOOL oxcmail_load_mime_skeleton(const MESSAGE_CONTENT *pmsg,
    const char *pcharset, BOOL b_tnef, enum oxcmail_body body_type,
    MIME_SKELETON *pskeleton)
{
	pskeleton->clear();
	pskeleton->charset = pcharset;
	pskeleton->pmessage_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS);
	if (pskeleton->pmessage_class == nullptr)
		pskeleton->pmessage_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS_A);
	if (pskeleton->pmessage_class == nullptr)
		pskeleton->pmessage_class = "IPM.Note";
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
	} else if (skel_prefer_rtf_body(*pmsg)) {
		if (!skel_grab_rtf(*pskeleton, *pmsg, pcharset))
			return false;
	} else {
		pskeleton->phtml = pmsg->proplist.get<BINARY>(PR_HTML);
		if (pskeleton->phtml == nullptr &&
		    !skel_grab_rtf(*pskeleton, *pmsg, pcharset))
			return false;
	}
	if (pmsg->children.pattachments == nullptr)
		return TRUE;
	for (auto &at : *pmsg->children.pattachments) {
		if (at.pembedded != nullptr)
			pskeleton->b_attachment = TRUE;
		else if (attachment_is_inline(at))
			pskeleton->b_inline = TRUE;
		else
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

static bool oxcmail_export_sender(const MESSAGE_CONTENT *pmsg,
    MIME *phead, bool sched) try
{
	if (sched)
		return true;
	auto str  = pmsg->proplist.get<const char>(PR_SENDER_SMTP_ADDRESS);
	auto str1 = pmsg->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr && str1 != nullptr) {
		if (strcasecmp(str, str1) == 0)
			return true; /* field not needed */
		auto mb = vmime::make_shared<vmime::mailbox>("");
		if (!oxcmail_export_address(pmsg, tags_sender, *mb))
			return true; /* not present */
		auto mg = mb->generate();
		if (!phead->set_field("Sender", std::move(mg)))
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
	auto mb = vmime::make_shared<vmime::mailbox>("");
	if (oxcmail_export_address(pmsg, tags_sender, *mb)) {
		auto mg = mb->generate();
		if (!phead->set_field("Sender", std::move(mg)))
			return false;
	}
	return true;
} catch (...) {
	return false;
}

static bool oxcmail_export_fromsender(const MESSAGE_CONTENT *pmsg,
    MIME *phead, bool sched) try
{
	auto mb = vmime::make_shared<vmime::mailbox>("");
	if (sched) {
		if (oxcmail_export_address(pmsg, tags_sender, *mb)) {
			auto mg = mb->generate();
			if (!phead->set_field("From", std::move(mg)))
				return false;
		}
		return true;
	}
	if (oxcmail_export_address(pmsg, tags_sent_repr, *mb)) { {
		auto mg = mb->generate();
		if (!phead->set_field("From", std::move(mg)))
			return FALSE;
	}
	} else if (oxcmail_export_address(pmsg, tags_sender, *mb)) {
		auto mg = mb->generate();
		if (!phead->set_field("Sender", std::move(mg)))
			return FALSE;
	}
	return true;
} catch (...) {
	return false;
}

static bool oxcmail_export_receiptto(const MESSAGE_CONTENT *pmsg,
    MIME *phead, bool sched) try
{
	auto flag = pmsg->proplist.get<uint8_t>(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED);
	if (flag == nullptr || *flag == 0)
		return true;
	auto mb = vmime::make_shared<vmime::mailbox>("");
	if (oxcmail_export_address(pmsg, tags_read_rcpt, *mb))
		/* ok */;
	else if (oxcmail_export_address(pmsg, tags_sender, *mb))
		/* ok */;
	else if (sched && oxcmail_export_address(pmsg, tags_sent_repr, *mb))
		/* ok */;
	else
		return true; /* No recipient */
	auto mg = mb->generate();
	return phead->set_field("Return-Receipt-To", std::move(mg));
} catch (...) {
	return false;
}

static bool oxcmail_export_receiptflg(const MESSAGE_CONTENT *pmsg,
    MIME *phead, bool sched) try
{
	auto flag = pmsg->proplist.get<uint8_t>(PR_READ_RECEIPT_REQUESTED);
	if (flag == nullptr || *flag == 0)
		return true;
	auto mb = vmime::make_shared<vmime::mailbox>("");
	if (oxcmail_export_address(pmsg, tags_read_rcpt, *mb))
		/* ok */;
	else if (oxcmail_export_address(pmsg, tags_sender, *mb))
		/* ok */;
	else if (!sched && oxcmail_export_address(pmsg, tags_sent_repr, *mb))
		/* ok */;
	else
		return true; /* No recipient */
	auto mg = mb->generate();
	return phead->set_field("Disposition-Notification-To", std::move(mg));
} catch (...) {
	return false;
}

static bool oxcmail_export_tocc(const MESSAGE_CONTENT *pmsg,
    const MIME_SKELETON *pskeleton, MIME *phead) try
{
	if (pmsg->children.prcpts == nullptr)
		return true;
	auto mblist = vmime::make_shared<vmime::mailboxList>();
	if (oxcmail_export_addresses(*pmsg->children.prcpts, MAPI_TO, *mblist)) {
		auto mg = mblist->generate();
		if (!phead->set_field("To", std::move(mg)))
			return FALSE;
	}
	mblist = vmime::make_shared<vmime::mailboxList>();
	if (oxcmail_export_addresses(*pmsg->children.prcpts, MAPI_CC, *mblist)) {
		auto mg = mblist->generate();
		if (!phead->set_field("Cc", std::move(mg)))
			return FALSE;
	}
	if (class_match_prefix(pskeleton->pmessage_class, "IPM.Schedule.Meeting") == 0 ||
	    class_match_prefix(pskeleton->pmessage_class, "IPM.Task") == 0)
		return true;
	mblist = vmime::make_shared<vmime::mailboxList>();
	if (oxcmail_export_addresses(*pmsg->children.prcpts, MAPI_BCC, *mblist)) {
		auto mg = mblist->generate();
		if (!phead->set_field("Bcc", std::move(mg)))
			return FALSE;
	}
	return true;
} catch (...) {
	return false;
}

static bool oxcmail_export_mail_head(const message_content &imsg, const mime_skeleton &skel,
    EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids, GET_PROPNAME get_propname, MIME *phead) try
{
	auto pmsg = &imsg;
	auto pskeleton = &skel;
	time_t tmp_time;
	struct tm time_buff;
	PROPID_ARRAY propids;

	auto sched = pskeleton->mail_type == oxcmail_type::calendar;
	if (!phead->set_field("MIME-Version", "1.0") ||
	    !oxcmail_export_sender(pmsg, phead, sched) ||
	    !oxcmail_export_fromsender(pmsg, phead, sched) ||
	    !oxcmail_export_receiptto(pmsg, phead, sched) ||
	    !oxcmail_export_receiptflg(pmsg, phead, sched) ||
	    !oxcmail_export_tocc(pmsg, pskeleton, phead))
		return false;
	auto adrlist = vmime::make_shared<vmime::addressList>();
	if (oxcmail_export_reply_to(pmsg, *adrlist)) {
		auto mg = adrlist->generate();
		if (!phead->set_field("Reply-To", std::move(mg)))
			return FALSE;
	}

	const PROPERTY_NAME namequeries[] = {
		{MNID_ID, PSETID_Common, PidLidInfoPathFromName},
		{MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameKeywords)},
		{MNID_ID, PSETID_Common, PidLidClassified},
		{MNID_ID, PSETID_Common, PidLidClassification},
		{MNID_ID, PSETID_Common, PidLidClassificationKeep},
		{MNID_ID, PSETID_Common, PidLidClassificationDescription},
		{MNID_ID, PSETID_Common, PidLidClassificationGuid},
		{MNID_ID, PSETID_Common, PidLidFlagRequest},
	};
	enum {
		l_infopath = 0, l_keywords, l_classified, l_classification,
		l_classkeep, l_classdesc, l_classguid, l_flagreq,
	};
	static_assert(l_flagreq + 1 == std::size(namequeries));
	const PROPNAME_ARRAY propnames = {std::size(namequeries), deconst(namequeries)};
	if (!get_propids(&propnames, &propids) || propids.size() != propnames.size())
		return false;

	std::string ostr;
	if (oxcmail_export_content_class(pskeleton->pmessage_class, ostr)) {
		if (!phead->set_field("Content-Class", std::move(ostr)))
			return FALSE;
	} else if (0 == strncasecmp(
		pskeleton->pmessage_class,
		"IPM.InfoPathForm.", 17)) {
		auto str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_infopath]));
		if (str != nullptr) {
			auto str1 = strrchr(str, '.');
			if (str1 != nullptr)
				str = str1 + 1;
			if (!phead->set_field("Content-Class", "InfoPathForm."s + str))
				return FALSE;
		}
	}
	auto str = pmsg->proplist.get<const char>(PR_SENDER_TELEPHONE_NUMBER);
	if (str != nullptr && !phead->set_field("X-CallingTelephoneNumber", str))
		return FALSE;
	auto num = pmsg->proplist.get<const uint32_t>(PidTagVoiceMessageDuration);
	if (num != nullptr &&
	    !phead->set_field("X-VoiceMessageDuration", std::to_string(*num)))
		return FALSE;
	str = pmsg->proplist.get<char>(PidTagVoiceMessageSenderName);
	if (str != nullptr && !phead->set_field("X-VoiceMessageSenderName", str))
		return FALSE;
	num = pmsg->proplist.get<uint32_t>(PidTagFaxNumberOfPages);
	if (num != nullptr &&
	    !phead->set_field("X-FaxNumberOfPages", std::to_string(*num)))
		return FALSE;
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
	static constexpr size_t tmp_field_size = MIME_FIELD_LEN;
	auto tmp_field = std::make_unique<char[]>(tmp_field_size);
	strftime(tmp_field.get(), tmp_field_size, "%a, %d %b %Y %H:%M:%S %z",
					localtime_r(&tmp_time, &time_buff));
	if (!phead->set_field("Date", tmp_field.get()))
		return FALSE;
	
	str  = pmsg->proplist.get<char>(PR_SUBJECT_PREFIX);
	auto str1 = pmsg->proplist.get<const char>(PR_NORMALIZED_SUBJECT);
	if (str != nullptr && str1 != nullptr) {
		if (!phead->set_field("Subject", enc_text(std::string(str) + str1)))
			return FALSE;
	} else {
		str = pmsg->proplist.get<char>(PR_SUBJECT);
		if (str != nullptr && !phead->set_field("Subject", enc_text(str)))
			return FALSE;
	}
	str = pmsg->proplist.get<char>(PR_CONVERSATION_TOPIC);
	if (str != nullptr &&
	    !phead->set_field("Thread-Topic", enc_text(str)))
		return FALSE;
	auto bv = pmsg->proplist.get<BINARY>(PR_CONVERSATION_INDEX);
	if (bv != nullptr &&
	    !phead->set_field("Thread-Index", base64_encode(*bv)))
		return FALSE;
	str = pmsg->proplist.get<char>(PR_INTERNET_MESSAGE_ID);
	if (str != nullptr && !phead->set_field("Message-ID", str))
		return FALSE;
	str = pmsg->proplist.get<char>(PR_INTERNET_REFERENCES);
	if (str != nullptr && !phead->set_field("References", str))
		return FALSE;
	auto sa = pmsg->proplist.get<STRING_ARRAY>(PROP_TAG(PT_MV_UNICODE, propids[l_keywords]));
	if (sa != nullptr) {
		ostr.clear();
		for (size_t i = 0; i < sa->count; ++i) {
			if (sa->ppstr[i] == nullptr)
				continue;
			if (!ostr.empty())
				ostr += ", ";
			ostr += enc_text(sa->ppstr[i]);
		}
		if (!phead->set_field("Keywords", std::move(ostr)))
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
	auto flag = pmsg->proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_classified]));
	if (flag != nullptr && *flag != 0 &&
	    !phead->set_field("X-Microsoft-Classified", "true"))
		return FALSE;
	flag = pmsg->proplist.get<uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_classkeep]));
	if (flag != nullptr && *flag != 0 &&
	    !phead->set_field("X-Microsoft-ClassKeep", "true"))
		return FALSE;
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_classification]));
	if (str != nullptr && !phead->set_field("X-Microsoft-Classification", str))
		return FALSE;
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_classdesc]));
	if (str != nullptr && !phead->set_field("X-Microsoft-ClassDesc", str))
		return FALSE;
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_classguid]));
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
			ostr.clear();
			if (*num & AUTO_RESPONSE_SUPPRESS_DR)
				ostr += "DR";
			if (*num & AUTO_RESPONSE_SUPPRESS_NDR)
				ostr += ostr.empty() ? "NDR" : ",NDR";
			if (*num & AUTO_RESPONSE_SUPPRESS_RN)
				ostr += ostr.empty() ? "RN" : ",RN";
			if (*num & AUTO_RESPONSE_SUPPRESS_NRN)
				ostr += ostr.empty() ? "NRN" : ",NRN";
			if (*num & AUTO_RESPONSE_SUPPRESS_OOF)
				ostr += ostr.empty() ? "OOF" : ",OOF";
			if (*num & AUTO_RESPONSE_SUPPRESS_AUTOREPLY)
				ostr += ostr.empty() ? "AutoReply" : ",AutoReply";
			if (ostr.size() > 0 &&
			    !phead->set_field("X-Auto-Response-Suppress", std::move(ostr)))
				return FALSE;
		}
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
	if (inum != nullptr &&
	    !phead->set_field("X-MS-Exchange-Organization-SCL", std::to_string(*inum)))
		return FALSE;
	
	str = pmsg->proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_flagreq]));
	if (str != nullptr && *str != '\0') {
		if (!phead->set_field("X-Message-Flag", str))
			return FALSE;
		lnum = pmsg->proplist.get<uint64_t>(PR_REPLY_TIME);
		if (lnum != nullptr) {
			char buf[64];
			tmp_time = rop_util_nttime_to_unix(*lnum);
			strftime(buf, std::size(buf), "%a, %d %b %Y %H:%M:%S %z",
							localtime_r(&tmp_time, &time_buff));
			if (!phead->set_field("Reply-By", buf))
				return FALSE;
		}
	}
	
	if (pskeleton->mail_type == oxcmail_type::tnef) {
		ostr.clear();
		bv = pmsg->proplist.get<BINARY>(PR_TNEF_CORRELATION_KEY);
		if (bv == nullptr) {
			str = pmsg->proplist.get<char>(PR_INTERNET_MESSAGE_ID);
			if (str != nullptr)
				ostr = str;
		} else if (bv->cb < 1024) {
			ostr.assign(bv->pc, bv->cb);
		}
		if (!phead->set_field("X-MS-TNEF-Correlator", std::move(ostr)))
			return FALSE;
	}
	
	str = pmsg->proplist.get<char>(PR_BODY_CONTENT_ID);
	if (str != nullptr &&
	    !phead->set_field("Content-ID", "<"s + str + ">"))
		return FALSE;
	
	str = pmsg->proplist.get<char>(PR_BODY_CONTENT_LOCATION);
	if (str != nullptr && !phead->set_field("Content-Location", str))
		return FALSE;
	
	if (!phead->set_field("X-Mailer", "gromox-oxcmail " PACKAGE_VERSION))
		/* ignore */;
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
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_export_dsn(const MESSAGE_CONTENT *pmsg, const char *charset,
    const char *pmessage_class, const char *org,
    cvt_id2user id2user, char *pdsn_content, int max_length) try
{
	char action[16];
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
		std::string hn;
		auto ret = canonical_hostname(hn);
		if (ret == 0) {
			hn.insert(0, "dsn; ");
			if (!dsn.append_field(pdsn_fields, "Reporting-MTA", hn))
				return FALSE;
		}
	} else {
		if (!dsn.append_field(pdsn_fields, "Reporting-MTA", str))
			return FALSE;
	}
	
	if (class_match_suffix(pmessage_class, ".DR") == 0)
		strcpy(action, "delivered");
	else if (class_match_suffix(pmessage_class, ".Expanded.DR") == 0)
		strcpy(action, "expanded");
	else if (class_match_suffix(pmessage_class, ".Relayed.DR") == 0)
		strcpy(action, "relayed");
	else if (class_match_suffix(pmessage_class, ".Delayed.DR") == 0)
		strcpy(action, "delayed");
	else if (class_match_suffix(pmessage_class, ".NDR") == 0)
		strcpy(action, "failed");
	else
		*action = '\0';
	if (pmsg->children.prcpts == nullptr)
		goto SERIALIZE_DSN;
	for (const auto &rcpt : *pmsg->children.prcpts) {
		pdsn_fields = dsn.new_rcpt_fields();
		if (pdsn_fields == nullptr)
			return FALSE;
		std::string username;
		if (!oxcmail_get_rcpt_address(rcpt, tags_self, org, id2user, username))
			username.clear();
		if (!dsn.append_field(pdsn_fields, "Final-Recipient", username.c_str()))
			return FALSE;
		if (*action != '\0' &&
		    !dsn.append_field(pdsn_fields, "Action", action))
			return FALSE;
		auto num = rcpt.get<const uint32_t>(PR_NDR_DIAG_CODE);
		if (num != nullptr) {
			if (*num == MAPI_DIAG_NO_DIAGNOSTIC) {
				num = rcpt.get<uint32_t>(PR_NDR_REASON_CODE);
				if (num != nullptr && !dsn.append_field(pdsn_fields,
				    "Status", *num > 6 ? "5.4.0" : status_strings1[*num]))
					return FALSE;
			} else {
				num = rcpt.get<uint32_t>(PR_NDR_REASON_CODE);
				if (num != nullptr && !dsn.append_field(pdsn_fields,
				    "Status", *num > 48 ? "5.0.0" : status_strings2[*num]))
					return FALSE;
			}
		}
		str = rcpt.get<char>(PR_DSN_REMOTE_MTA);
		if (str != nullptr && !dsn.append_field(pdsn_fields,
		    "Remote-MTA", str))
			return FALSE;
		str = rcpt.get<char>(PR_SUPPLEMENTARY_INFO);
		if (str != nullptr && !dsn.append_field(pdsn_fields,
		    "X-Supplementary-Info", str))
			return FALSE;
		str = rcpt.get<char>(PR_DISPLAY_NAME);
		if (str != nullptr &&
		    !dsn.append_field(pdsn_fields, "X-Display-Name", enc_text(str)))
			return FALSE;
	}
 SERIALIZE_DSN:
	return dsn.serialize(pdsn_content, max_length);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static BOOL oxcmail_export_mdn(const MESSAGE_CONTENT *pmsg, const char *charset,
    const char *pmessage_class, char *pmdn_content, int max_length) try
{
	int tmp_len;
	size_t base64_len;
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
	auto t_addr = "rfc822;"s + tmp_address;
	if (!dsn.append_field(pdsn_fields, "Final-Recipient", t_addr.c_str()))
		return FALSE;
	tmp_len = strlen(pmessage_class);
	char tmp_buff[1024];
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
	if (pdisplay_name != nullptr &&
	    !dsn.append_field(pdsn_fields, "X-Display-Name", enc_text(pdisplay_name)))
		return FALSE;
	return dsn.serialize(pmdn_content, max_length);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

bool oxcmail_converter::export_attachment(const attachment_content &atc,
    bool b_inline, const mime_skeleton &skel, MIME &mimeout,
    unsigned int mail_depth) try
{
	auto pattachment = &atc;
	auto pskeleton = &skel;
	auto pmime = &mimeout;
	BOOL b_vcard;
	size_t offset;
	struct tm time_buff;
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
		if (class_match_prefix(str, "IPM.Contact") == 0)
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
		if (pfile_name != nullptr && *pfile_name != '\0' &&
		    !pmime->set_content_param("name", ("\"" + enc_text(pfile_name) + "\"").c_str()))
			return FALSE;
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
	if (str != nullptr && *str != '\0' &&
	    !pmime->set_field("Content-Description", enc_text(str)))
		return FALSE;
	
	auto pctime = pattachment->proplist.get<uint64_t>(PR_CREATION_TIME);
	auto pmtime = pattachment->proplist.get<uint64_t>(PR_LAST_MODIFICATION_TIME);
	std::string ostr = b_inline ? "inline; " : "attachment; ";
	if (pfile_name != nullptr)
		ostr += "filename=\"" + enc_text(pfile_name) + "\";\r\n\t";
	if (pctime != nullptr) {
		auto tmp_time = rop_util_nttime_to_unix(*pctime);
		if (gmtime_r(&tmp_time, &time_buff) != nullptr) {
			char buf[64];
			strftime(buf, std::size(buf),
				"creation-date=\"%a, %d %b %Y %H:%M:%S GMT\";\r\n\t",
				&time_buff);
			ostr += buf;
		}
	}
	if (pmtime != nullptr) {
		auto tmp_time = rop_util_nttime_to_unix(*pmtime);
		if (gmtime_r(&tmp_time, &time_buff) != nullptr) {
			char buf[64];
			strftime(buf, std::size(buf),
				"modification-date=\"%a, %d %b %Y %H:%M:%S GMT\"",
				&time_buff);
			ostr += buf;
		}
	}
	if (!pmime->set_field("Content-Disposition", std::move(ostr)))
		return FALSE;
	
	str = pattachment->proplist.get<char>(PR_ATTACH_CONTENT_ID);
	if (str != nullptr &&
	    !pmime->set_field("Content-ID", "<"s + str + ">"))
		return FALSE;
	str = pattachment->proplist.get<char>(PR_ATTACH_CONTENT_LOCATION);
	if (str != nullptr && !pmime->set_field("Content-Location", str))
		return FALSE;
	str = pattachment->proplist.get<char>(PR_ATTACH_CONTENT_BASE);
	if (str != nullptr && !pmime->set_field("Content-Base", str))
		return FALSE;
	
	{
	oxvcard_converter vc_cvt;
	vc_cvt.log_id = log_id;
	vc_cvt.get_propids = get_propids;
	vcard vcard;
	if (b_vcard && vc_cvt.mapi_to_vcard(*pattachment->pembedded, vcard)) {
		std::string vcout;
		if (vcard.serialize(vcout)) {
			if (!pmime->write_content(vcout.c_str(),
			    vcout.size(), mime_encoding::automatic))
				return FALSE;
			return TRUE;
		}
	}
	}
	
	if (pattachment->pembedded != nullptr &&
	    mail_depth >= m_max_attach_depth) {
		auto msg = fmt::format("Content-Type: text/plain\r\n\r\n"
		           "This embedded attachment was suppressed upon sending "
		           "because it is nested too deeply (maximum {})\r\n\r\n",
		           m_max_attach_depth);
		return pmime->write_content(msg.c_str(), msg.size(), mime_encoding::none);
	}
	if (NULL != pattachment->pembedded) {
		auto b_tnef = pskeleton->mail_type == oxcmail_type::tnef;
		MAIL imail;
		if (!do_export(*pattachment->pembedded, b_tnef, imail, mail_depth + 1))
			return FALSE;
		auto mail_len = imail.get_length();
		if (mail_len < 0)
			return false;
		STREAM tmp_stream;
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
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
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
	if (!sec->load_from_str(nullptr, hdrs->pc, hdrs->cb))
		return false;
	if (!sec->get_field("Content-Type", buf, std::size(buf)))
		return false;
	if (strncasecmp(buf, "multipart/signed", 16) != 0) {
		origmime.mime_type = mime_type::single;
		auto s = fmt::format("[Message is not a valid OXOSMIME message. "
			 "The attachment object is not of type multipart/signed.]");
		origmime.write_content(s.c_str(), s.size(), mime_encoding::none);
		if (!origmime.set_content_type("text/plain"))
			/* ignore */;
		return TRUE;
	}
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
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

#define exp_false xlog_bool(__func__, __LINE__)
bool oxcmail_converter::do_export(const message_content &imsg,
    bool b_tnef, MAIL &imail, unsigned int mail_depth) try
{
	const auto pmsg = &imsg;
	auto pmail = &imail;
	ical ical;
	MIME *phtml;
	MIME *pmime;
	MIME *pplain;
	MIME *pmixed;
	MIME *prelated;
	MIME *pcalendar;
	char tmp_method[32];
	char tmp_charset[32];
	const char *pcharset = nullptr;
	MIME_FIELD mime_field;
	
	pmail->clear();
	auto num = pmsg->proplist.get<uint32_t>(PR_INTERNET_CPID);
	if (num != nullptr && *num != CP_UTF16)
		pcharset = cpid_to_cset(static_cast<cpid_t>(*num));
	if (pcharset == nullptr)
		pcharset = "utf-8";
	mime_skeleton skel;
	if (!oxcmail_load_mime_skeleton(pmsg, pcharset, b_tnef,
	    body_type, &skel))
		return exp_false;
	auto phead = pmail->add_head();
	if (phead == nullptr)
		return exp_false;
	pmime = phead;
	pplain = NULL;
	phtml = NULL;
	pmixed = NULL;
	prelated = NULL;
	pcalendar = NULL;
	switch (skel.mail_type) {
	case oxcmail_type::dsn:
	case oxcmail_type::mdn:
	case oxcmail_type::normal:
	case oxcmail_type::calendar:
		if (skel.mail_type == oxcmail_type::dsn) {
			pmixed = pmime;
			if (!pmime->set_content_type("multipart/report") ||
			    !pmime->set_content_param("report-type", "delivery-status") ||
			    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
				return exp_false;
		} else if (skel.mail_type == oxcmail_type::mdn) {
			pmixed = pmime;
			if (!pmime->set_content_type("multipart/report") ||
			    !pmime->set_content_param("report-type", "disposition-notification") ||
			    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
				return exp_false;
		} else {
			if (skel.b_attachment) {
				pmixed = pmime;
				if (!pmime->set_content_type("multipart/mixed") ||
				    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
					return exp_false;
			}
		}
		if (skel.b_inline) {
			prelated = pmime;
			if (!pmime->set_content_type("multipart/related") ||
			    (pmime = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr)
				return exp_false;
		}
		if (skel.body_type == oxcmail_body::plain_and_html &&
		    skel.pplain != nullptr && skel.phtml != nullptr) {
			if (!pmime->set_content_type("multipart/alternative"))
				return exp_false;
			pplain = pmail->add_child(pmime, MIME_ADD_LAST);
			phtml = pmail->add_child(pmime, MIME_ADD_LAST);
			if (pplain == nullptr || !pplain->set_content_type("text/plain") ||
			    phtml == nullptr || !phtml->set_content_type("text/html"))
				return exp_false;
			if (skel.mail_type == oxcmail_type::calendar) {
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (pcalendar == nullptr ||
				    !pcalendar->set_content_type("text/calendar"))
					return exp_false;
			}
		} else if (skel.body_type == oxcmail_body::plain_only &&
		    skel.pplain != nullptr) {
 PLAIN_ONLY:
			if (skel.mail_type != oxcmail_type::calendar) {
				if (!pmime->set_content_type("text/plain"))
					return exp_false;
				pplain = pmime;
			} else {
				if (!pmime->set_content_type("multipart/alternative"))
					return exp_false;
				pplain = pmail->add_child(pmime, MIME_ADD_LAST);
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (pplain == nullptr || !pplain->set_content_type("text/plain") ||
				    pcalendar == nullptr || !pcalendar->set_content_type("text/calendar"))
					return exp_false;
			}
		} else if (skel.body_type == oxcmail_body::html_only &&
		    skel.phtml != nullptr) {
 HTML_ONLY:
			if (skel.mail_type != oxcmail_type::calendar) {
				if (!pmime->set_content_type("text/html"))
					return exp_false;
				phtml = pmime;
			} else {
				if (!pmime->set_content_type("multipart/alternative"))
					return exp_false;
				phtml = pmail->add_child(pmime, MIME_ADD_LAST);
				pcalendar = pmail->add_child(pmime, MIME_ADD_LAST);
				if (phtml == nullptr || !phtml->set_content_type("text/html") ||
				    pcalendar == nullptr || !pcalendar->set_content_type("text/calendar"))
					return exp_false;
			}
		} else if (skel.phtml != nullptr) {
			skel.body_type = oxcmail_body::html_only;
			goto HTML_ONLY;
		} else {
			skel.body_type = oxcmail_body::plain_only;
			goto PLAIN_ONLY;
		}
		break;
	case oxcmail_type::tnef:
		if (!pmime->set_content_type("multipart/mixed"))
			return exp_false;
		if ((pplain = pmail->add_child(pmime, MIME_ADD_LAST)) == nullptr ||
		    !pplain->set_content_type("text/plain"))
			return exp_false;
		break;
	case oxcmail_type::xsigned:
	case oxcmail_type::encrypted:
		break;
	}
	
	if (!oxcmail_export_mail_head(imsg, skel, alloc,
	    get_propids, get_propname, phead))
		return exp_false;
	
	if (skel.mail_type == oxcmail_type::encrypted ||
	    skel.mail_type == oxcmail_type::xsigned) {
		if (skel.mail_type == oxcmail_type::encrypted &&
		    !pmime->set_content_type("application/pkcs7-mime"))
			return exp_false;
		auto a = pmsg->children.pattachments;
		if (a == nullptr || a->count != 1) {
			pmime->mime_type = mime_type::single;
			auto s = fmt::format("[Message is not a valid OXOSMIME message. "
			         "Found {} attachment objects, but exactly one is required.]", a->count);
			pmime->write_content(s.c_str(), s.size(), mime_encoding::none);
			pmime->set_content_type("text/plain");
			return TRUE;
		}
		auto pbin = a->pplist[0]->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
		if (skel.mail_type == oxcmail_type::encrypted) {
			if (pbin != nullptr && !pmime->write_content(pbin->pc,
			    pbin->cb, mime_encoding::base64))
				return exp_false;
		} else {
			if (!smime_signed_writeout(*pmail, *pmime, pbin, mime_field))
				return false;
		}
		return TRUE;
	}
	
	if (NULL != pplain) {
		if (skel.pplain == nullptr || *skel.pplain == '\0') {
			if (!pplain->write_content("\r\n", 2, mime_encoding::base64))
				return exp_false;
		} else {
			auto alloc_size = utf8_to_mb_len(skel.pplain);
			auto pbuff = std::make_unique<char[]>(alloc_size);
			if (!string_utf8_to_mb(skel.charset,
			    skel.pplain, pbuff.get(), alloc_size)) {
				pbuff.reset();
				if (!pplain->write_content(skel.pplain,
				    strlen(skel.pplain), mime_encoding::automatic))
					return exp_false;
				strcpy(tmp_charset, "\"utf-8\"");
			} else {
				if (!pplain->write_content(pbuff.get(),
				    strlen(pbuff.get()), mime_encoding::automatic))
					return exp_false;
				snprintf(tmp_charset, std::size(tmp_charset), "\"%s\"", skel.charset);
			}
			if (!pplain->set_content_param("charset", tmp_charset))
				return exp_false;
		}
	}
	
	if (skel.mail_type == oxcmail_type::tnef) {
		pmime = pmail->add_child(pmime, MIME_ADD_LAST);
		BINARY *pbin = nullptr;
		if (pmime == nullptr || !pmime->set_content_type("application/ms-tnef"))
			return exp_false;
		pbin = tnef_serialize(pmsg, log_id, alloc, std::move(get_propname));
		if (pbin == nullptr)
			return exp_false;
		if (!pmime->write_content(pbin->pc, pbin->cb, mime_encoding::base64)) {
			rop_util_free_binary(pbin);
			return exp_false;
		}
		rop_util_free_binary(pbin);
		if (!pmime->set_content_param("name", "\"winmail.dat\"") ||
		    !pmime->set_field("Content-Disposition",
			"attachment; filename=\"winmail.dat\""))
			return exp_false;
		return TRUE;
	}
	
	if (NULL != phtml) {
		if (!phtml->write_content(skel.phtml->pc,
		    skel.phtml->cb, mime_encoding::automatic))
			return exp_false;
		snprintf(tmp_charset, std::size(tmp_charset), "\"%s\"", skel.charset);
		if (!phtml->set_content_param("charset", tmp_charset))
			return exp_false;
	}
	
	if (NULL != pcalendar) {
		oxcical_converter cvt;
		cvt.log_id = log_id;
		cvt.org_name = g_oxcmail_org_name;
		cvt.alloc = alloc;
		cvt.get_propids = get_propids;
		cvt.id2user = oxcmail_get_username;
		
		if (!cvt.mapi_to_ical(*pmsg, ical)) {
			mlog(LV_WARN, "W-2186: oxcical_export %s failed (unspecified reason)", log_id);
			return exp_false;
		}
		tmp_method[0] = '\0';
		auto piline = ical.get_line("METHOD");
		if (NULL != piline) {
			auto str = deconst(piline->get_first_subvalue());
			if (str != nullptr)
				gx_strlcpy(tmp_method, str, std::size(tmp_method));
		}
		std::string tmp_buff;
		auto err = ical.serialize(tmp_buff);
		if (err != ecSuccess) {
			mlog(LV_ERR, "E-2361: %s", mapi_strerror(err));
			return exp_false;
		}
		if (!pcalendar->write_content(tmp_buff.c_str(), tmp_buff.size(),
		    mime_encoding::automatic))
			return exp_false;
		if (!pcalendar->set_content_param("charset", "\"utf-8\""))
			return exp_false;
		if (*tmp_method != '\0')
			pcalendar->set_content_param("method", tmp_method);
	}
	
	if (skel.mail_type == oxcmail_type::dsn) {
		static constexpr size_t tmp_buff_size = 1024 * 1024;
		auto tmp_buff = std::make_unique<char[]>(tmp_buff_size);
		
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (pmime == nullptr)
			return exp_false;
		if (!pmime->set_content_type("message/delivery-status"))
			return exp_false;
		if (!oxcmail_export_dsn(pmsg, skel.charset,
		    skel.pmessage_class, g_oxcmail_org_name,
		    oxcmail_get_username, tmp_buff.get(), tmp_buff_size))
			return exp_false;
		if (!pmime->write_content(tmp_buff.get(), strlen(tmp_buff.get()),
		    mime_encoding::none))
			return exp_false;
	} else if (skel.mail_type == oxcmail_type::mdn) {
		static constexpr size_t tmp_buff_size = 1024 * 1024;
		auto tmp_buff = std::make_unique<char[]>(tmp_buff_size);
		
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (pmime == nullptr)
			return exp_false;
		if (!pmime->set_content_type("message/disposition-notification"))
			return exp_false;
		if (!oxcmail_export_mdn(pmsg, skel.charset,
		    skel.pmessage_class, tmp_buff.get(), tmp_buff_size))
			return exp_false;
		if (!pmime->write_content(tmp_buff.get(), strlen(tmp_buff.get()),
		    mime_encoding::none))
			return exp_false;
	}

	auto err = export_tnef_body(skel, *pmail, prelated, mail_depth);
	if (err != ecSuccess) {
		mlog(LV_ERR, "E-2941: %s", mapi_strerror(err));
		return false;
	}
	err = export_attachments(*pmsg, skel, *pmail, prelated, pmixed, mail_depth);
	if (err != ecSuccess) {
		mlog(LV_ERR, "E-2940: %s", mapi_strerror(err));
		return false;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}
#undef exp_false

/* automatic format selection */
void oxcmail_converter::use_format_override(const message_content &mc)
{
	auto v = mc.proplist.get<uint32_t>(PR_INETMAIL_OVERRIDE_FORMAT);
	if (v == nullptr)
		body_type = oxcmail_body::plain_and_html;
	else if (*v & MESSAGE_FORMAT_PLAIN_AND_HTML)
		body_type = oxcmail_body::plain_and_html;
	else if (*v & MESSAGE_FORMAT_HTML_ONLY)
		body_type = oxcmail_body::html_only;
	else
		body_type = oxcmail_body::plain_only;
}

bool oxcmail_converter::mapi_to_inet(const message_content &mc, MAIL &out)
{
	return do_export(mc, false, out, 0);
}
