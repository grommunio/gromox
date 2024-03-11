// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023-2024 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <fmt/core.h>
#include <libHX/string.h>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/scope.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>

using namespace std::string_literals;

namespace gromox {

/*
 * As per MS-OXOABK v18 §2.2.1.1, the maximum DN length is roughly 1072 bytes
 * (16 pieces of "/cn=<63 chars>")
 */

ec_error_t cvt_essdn_to_username(const char *idn, const char *org,
    cvt_id2user id2user, std::string &username) try
{
	auto prefix = "/o="s + org + "/" + EAG_RCPTS "/cn=";
	if (strncasecmp(idn, prefix.c_str(), prefix.size()) != 0)
		return ecUnknownUser;
	auto len = strlen(idn);
	if (len < prefix.size() + 16 || idn[prefix.size()+16] != '-')
		return ecUnknownUser;
	auto local_part = &idn[prefix.size()+17];
	auto user_id = decode_hex_int(&idn[prefix.size()+8]);
	auto ret = id2user(user_id, username);
	if (ret != ecSuccess)
		return ret;
	auto pos = username.find('@');
	if (pos == username.npos ||
	    strncasecmp(username.c_str(), local_part, pos) != 0)
		return ecUnknownUser;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-5208: ENOMEM");
	return ecServerOOM;
}

ec_error_t cvt_essdn_to_username(const char *idn, const char *org,
    cvt_id2user id2user, char *username, size_t ulen)
{
	std::string es_result;
	auto ret = cvt_essdn_to_username(idn, org, std::move(id2user), es_result);
	if (ret == ecSuccess)
		gx_strlcpy(username, es_result.c_str(), ulen);
	return ret;
}

/**
 * ecNullObject is returned to signify that a situation was encountered that is
 * equivalent to addrtype not having been present in the first place.
 */
ec_error_t cvt_genaddr_to_smtpaddr(const char *addrtype, const char *emaddr,
    const char *org, cvt_id2user id2user, std::string &smtpaddr)
{
	if (*addrtype == '\0') {
		/* OL 2013 */
		return ecNullObject;
	} else if (strcasecmp(addrtype, "SMTP") == 0) {
		if (emaddr != nullptr)
			smtpaddr = emaddr;
		return emaddr != nullptr ? ecSuccess : ecNullObject;
	} else if (strcasecmp(addrtype, "EX") == 0) {
		if (emaddr == nullptr)
			return ecNullObject;
		return cvt_essdn_to_username(emaddr, org, std::move(id2user), smtpaddr);
	} else if (strcmp(addrtype, "0") == 0) {
		/*
		 * When MFCMAPI 21.2.21207.01 imports a .msg file, PR_SENT_*
		 * gets reset to this odd combo.
		 */
		return ecNullObject;
	}
	return ecUnknownUser;
}

ec_error_t cvt_genaddr_to_smtpaddr(const char *addrtype, const char *emaddr,
    const char *org, cvt_id2user id2user, char *smtpaddr, size_t slen)
{
	std::string es_result;
	auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr, org,
	           std::move(id2user), es_result);
	if (ret == ecSuccess)
		gx_strlcpy(smtpaddr, es_result.c_str(), slen);
	return ret;
}

static ec_error_t emsab_to_email2(EXT_PULL &ser, const char *org, cvt_id2user id2user,
    std::string &smtpaddr)
{
	EMSAB_ENTRYID eid{};
	auto cl_0 = make_scope_exit([&]() { free(eid.px500dn); });
	if (ser.g_abk_eid(&eid) != pack_result::success)
		return ecInvalidParam;
	/*
	 * The preconditions to get here are convoluted: an object must have no
	 * usable $pr_smtpaddr, no usable $pr_addrtype/$pr_emaddr, but must
	 * have $pr_entryid. Message recipients have no PR_ENTRYID at least in
	 * exmdb, which leaves e.g. sender (PR_SENDER_ENTRYID), sent_repr and
	 * PR_READ_RECEIPT_ENTRYID.
	 *
	 * The entryid type (EMSAB_ENTRYID::type) is set based on the
	 * NSP-provided PR_DISPLAY_TYPE value. Even though PR_DISPLAY_TYPE_EX
	 * may be DT_ROOM, rooms have PR_DISPLAY_TYPE=DT_MAILUSER. This might
	 * explain the historic DT_MAILUSER check.
	 */
	/*
	if (eid.type != DT_MAILUSER)
		return ecInvalidParam;
	*/
	return cvt_essdn_to_username(eid.px500dn, org, std::move(id2user), smtpaddr);
}

ec_error_t cvt_emsab_to_essdn(const BINARY *bin, std::string &essdn) try
{
	if (bin == nullptr)
		return ecInvalidParam;
	EXT_PULL ep;
	EMSAB_ENTRYID eid{};
	auto cl_0 = make_scope_exit([&]() { free(eid.px500dn); });
	ep.init(bin->pb, bin->cb, malloc, EXT_FLAG_UTF16);
	if (ep.g_abk_eid(&eid) != pack_result::success)
		return ecInvalidParam;
	essdn = eid.px500dn;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

static ec_error_t cvt_oneoff_to_smtpaddr(EXT_PULL &ser, const char *org,
    cvt_id2user id2user, std::string &smtpaddr)
{
	ONEOFF_ENTRYID eid{};
	auto cl_0 = make_scope_exit([&]() {
		free(eid.pdisplay_name);
		free(eid.paddress_type);
		free(eid.pmail_address);
	});
	if (ser.g_oneoff_eid(&eid) != pack_result::success)
		return ecInvalidParam;
	return cvt_genaddr_to_smtpaddr(eid.paddress_type, eid.pmail_address,
	       org, std::move(id2user), smtpaddr);
}

ec_error_t cvt_entryid_to_smtpaddr(const BINARY *bin, const char *org,
    cvt_id2user id2user, std::string &smtpaddr)
{
	if (bin == nullptr)
		return ecNullObject;
	if (bin->cb < 20)
		return ecInvalidParam;

	uint32_t flags;
	EXT_PULL ext_pull;
	FLATUID provider_uid;
	ext_pull.init(bin->pb, bin->cb, malloc, EXT_FLAG_UTF16);
	if (ext_pull.g_uint32(&flags) != pack_result::success || flags != 0 ||
	    ext_pull.g_guid(&provider_uid) != pack_result::success)
		return ecInvalidParam;
	/* Tail functions will use EXT_PULL::*_eid, which parse a full EID */
	ext_pull.m_offset = 0;
	if (provider_uid == muidEMSAB)
		return emsab_to_email2(ext_pull, org, std::move(id2user), smtpaddr);
	if (provider_uid == muidOOP)
		return cvt_oneoff_to_smtpaddr(ext_pull, org, std::move(id2user), smtpaddr);
	return ecUnknownUser;
}

ec_error_t cvt_username_to_essdn(const char *username, const char *org,
    unsigned int user_id, unsigned int domain_id, std::string &essdn) try
{
	const char *at = strchr(username, '@');
	essdn = fmt::format("/o={}/" EAG_RCPTS "/cn={:08x}{:08x}-",
	        org, __builtin_bswap32(domain_id), __builtin_bswap32(user_id));
	if (at == nullptr)
		essdn += "public.folder.root";
	else
		essdn += std::string_view(username, at - username);
	/*
	 * In EXC, the ESSDN is normally mixed-case, but appears upper-case in:
	 *
	 * - message objects
	 *   - CreatorEmailAddress (0x4023001f), PR_CREATOR_ENTRYID
	 *   - LastModifierEmailAddress (0x4025001f), PR_LAST_MODIFIER_ENTRYID
	 *   - PR_SENDER_EMAIL_ADDRESS, PR_SENDER_ENTRYID [delivery only]
	 *   - PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENT_REPRESENTING_ENTRYID
	 *   - PR_RECEIVED_BY_EMAIL_ADDRESS, PR_RECEIVED_BY_ENTRYID
	 *   - PR_RCVD_REPRESENTING_EMAIL_ADDRESS, PR_RCVD_REPRESENTING_ENTRYID
	 *   - PR_SEARCH_KEY, PR_*_SEARCH_KEY
	 * - GAB objects
	 *   - PR_SEARCH_KEY
	 */
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

ec_error_t cvt_username_to_essdn(const char *username, const char *org,
    GET_USER_IDS get_uids, GET_DOMAIN_IDS get_dids, std::string &essdn) try
{
	unsigned int user_id = 0, domain_id = 0;
	const char *ps_domain = nullptr, *at = nullptr;
	if (strncmp(username, "public.folder.root@", 19) == 0)
		ps_domain = username + 19;
	else if ((at = strchr(username, '@')) == nullptr)
		ps_domain = username;
	if (ps_domain != nullptr) {
		if (!get_dids(ps_domain, &domain_id, nullptr))
			return ecError;
		return cvt_username_to_essdn(ps_domain, org, 0, domain_id, essdn);
	}
	if (!get_uids(username, &user_id, &domain_id, nullptr))
		return ecError;
	return cvt_username_to_essdn(username, org, user_id, domain_id, essdn);
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

ec_error_t cvt_username_to_abkeid(const char *username, const char *org,
    enum display_type dtx, GET_USER_IDS get_uids, GET_DOMAIN_IDS get_dids,
    std::string &eidbuf) try
{
	std::string essdn;
	auto err = cvt_username_to_essdn(username, org, get_uids, get_dids, essdn);
	if (err != ecSuccess)
		return err;
	EMSAB_ENTRYID te;
	te.flags = 0;
	te.type = dtx;
	te.px500dn = deconst(essdn.c_str());
	eidbuf.resize(1280);
	EXT_PUSH ep;
	if (!ep.init(eidbuf.data(), eidbuf.size(), EXT_FLAG_UTF16) ||
	    ep.p_abk_eid(te) != pack_result::ok)
		return ecError;
	eidbuf.resize(ep.m_offset);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

ec_error_t cvt_username_to_mailboxid(const char *username, unsigned int id,
    std::string &mailboxid)
{
	FLATUID f{};
	strncpy(reinterpret_cast<char *>(&f.ab[0]), username, 12);
	GUID g = f;
	g.time_low = __builtin_bswap32(g.time_low);
	g.time_mid = __builtin_bswap16(g.time_mid);
	g.time_hi_and_version = __builtin_bswap16(g.time_hi_and_version);
	cpu_to_le32p(&g.node[2], id);
	char txt[37];
	g.to_str(txt, std::size(txt), 36);
	mailboxid = txt;
	return ecSuccess;
}

ec_error_t cvt_username_to_serverdn(const char *username, const char *org,
    unsigned int id, std::string &out) try
{
	const char *at = strchr(username, '@');
	if (at == nullptr)
		return ecInvalidParam;
	auto err = cvt_username_to_mailboxid(username, id, out);
	if (err != ecSuccess)
		return err;
	out = fmt::format("/o={}/" EAG_SERVERS "/cn={}@{}", org, out, at + 1);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

ec_error_t cvt_username_to_mdbdn(const char *username, const char *org,
    unsigned int id, std::string &out) try
{
	auto err = cvt_username_to_serverdn(username, org, id, out);
	if (err == ecSuccess)
		out += "/cn=Microsoft Private MDB";
	return err;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

const char *cvt_serverdn_to_domain(const char *essdn, const char *org) try
{
	auto prefix = fmt::format("/o={}/" EAG_SERVERS "/cn=", org);
	if (strncasecmp(essdn, prefix.c_str(), prefix.size()) != 0) {
		errno = 0;
		return nullptr;
	}
	auto at = strchr(&essdn[prefix.size()], '@');
	if (at != nullptr)
		return at + 1;
	errno = 0;
	return nullptr;
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return nullptr;
}

}
