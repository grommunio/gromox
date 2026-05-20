// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <json/value.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/json.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapitags.hpp>

namespace gromox {

using namespace std::string_literals;

struct kdb_user_map {
	using base_type = std::map<std::string, std::string>;
	errno_t read(const char *);
	base_type uid_to_email;
	base_type login_to_email;
	base_type login_to_guid;
};

errno_t kdb_user_map::read(const char *file)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(file, &slurp_len));
	if (slurp_data == nullptr) {
		int se = errno;
		fprintf(stderr, "Could not read %s: %s\n", file, strerror(se));
		return se;
	}
	Json::Value jval;
	if (!str_to_json({slurp_data.get(), slurp_len}, jval) ||
	    !jval.isArray()) {
		fprintf(stderr, "%s: JSON parse error.\n"
			"Try using a utility like jq(1) to discover details.\n", file);
		return EINVAL;
	}

	for (unsigned int i = 0; i < jval.size(); ++i) {
		auto &row = jval[i];
		const std::string &kuid = !row["id"].isNull() ? row["id"].asString() : "";
		auto srv_guid = !row["sv"].isNull() ? row["sv"].asString() : "";
		HX_strlower(srv_guid.data());
		auto f_na = !row["na"].isNull() ? row["na"].asCString() : "";
		auto f_em = !row["em"].isNull() ? row["em"].asCString() : "";
		auto f_to = !row["to"].isNull() ? row["to"].asCString() : "";
		if (kuid.size() > 0 && srv_guid.size() > 0 &&
		    *f_to != '\0' && strchr(f_to, '@') != nullptr)
			uid_to_email.emplace(kuid + "@" + srv_guid + ".kopano.invalid", f_to);
		if (*f_na != '\0' && !row["st"].isNull()) {
			auto store_guid = row["st"].asString();
			HX_strlower(store_guid.data());
			auto p = std::move(srv_guid) + "/" + f_na;
			login_to_guid.emplace(std::move(p), std::move(store_guid));
		}
		if (*f_na != '\0' && *f_to != '\0')
			login_to_email.emplace(f_na, f_to);
		if (*f_em != '\0' && *f_to != '\0')
			login_to_email.emplace(f_em, f_to);
	}
	fprintf(stderr, "usermap %s: %zu x kuid -> (new) emailaddr\n", file, uid_to_email.size());
	fprintf(stderr, "usermap %s: %zu x name -> storeguid\n", file, login_to_guid.size());
	fprintf(stderr, "usermap %s: %zu x name -> emailaddr\n", file, login_to_email.size());
	return 0;
}

/**
 * Returns 0 when no property was changed, >0 when any property was changed,
 * or <0 on error.
 */
static int subst_addrs_entryids(const kdb_user_map &umap, TPROPVAL_ARRAY *ar)
{
	bool changed_anything = false;
	static constexpr struct {
		proptag_t addrtype, emaddr, entryid, srchkey, smtpaddr;
	} propsets[] = {
		{PR_SENT_REPRESENTING_ADDRTYPE, PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENT_REPRESENTING_ENTRYID, PR_SENT_REPRESENTING_SEARCH_KEY, PR_SENT_REPRESENTING_SMTP_ADDRESS},
		{PR_ORIGINAL_SENDER_ADDRTYPE, PR_ORIGINAL_SENDER_EMAIL_ADDRESS, PR_ORIGINAL_SENDER_ENTRYID, PR_ORIGINAL_SENDER_SEARCH_KEY},
		{PR_ORIGINAL_SENT_REPRESENTING_ADDRTYPE, PR_ORIGINAL_SENT_REPRESENTING_EMAIL_ADDRESS, PR_ORIGINAL_SENT_REPRESENTING_ENTRYID, PR_ORIGINAL_SENT_REPRESENTING_SEARCH_KEY},
		{PR_RECEIVED_BY_ADDRTYPE, PR_RECEIVED_BY_EMAIL_ADDRESS, PR_RECEIVED_BY_ENTRYID, PR_RECEIVED_BY_SEARCH_KEY},
		{PR_RCVD_REPRESENTING_ADDRTYPE, PR_RCVD_REPRESENTING_EMAIL_ADDRESS, PR_RCVD_REPRESENTING_ENTRYID, PR_RCVD_REPRESENTING_SEARCH_KEY},
		{PR_ORIGINAL_AUTHOR_ADDRTYPE, PR_ORIGINAL_AUTHOR_EMAIL_ADDRESS, PR_ORIGINAL_AUTHOR_ENTRYID, PR_ORIGINAL_AUTHOR_SEARCH_KEY},
		{PR_ORIGINALLY_INTENDED_RECIP_ADDRTYPE, PR_ORIGINALLY_INTENDED_RECIP_EMAIL_ADDRESS, PR_ORIGINALLY_INTENDED_RECIP_ENTRYID, 0},
		{PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS, PR_SENDER_ENTRYID, PR_SENDER_SEARCH_KEY, PR_SENDER_SMTP_ADDRESS},
		{PR_ADDRTYPE, PR_EMAIL_ADDRESS, PR_ENTRYID, PR_SEARCH_KEY, PR_SMTP_ADDRESS},
	};
	for (const auto &tags : propsets) {
		const char *smtpaddr = nullptr;
		/* If we already have PR.*SMTP_ADDRESS, just use that */
		if (tags.smtpaddr != 0)
			smtpaddr = ar->get<const char>(tags.smtpaddr);
		if (smtpaddr == nullptr) {
			auto at = ar->get<const char>(tags.addrtype);
			if (at == nullptr || strcasecmp(at, "ZARAFA") != 0)
				continue;
			auto em = ar->get<const char>(tags.emaddr);
			if (em == nullptr)
				continue;
			auto repl = umap.login_to_email.find(em);
			if (repl == umap.login_to_email.cend())
				continue;
			smtpaddr = repl->second.c_str();
		}

		ONEOFF_ENTRYID e{};
		e.ctrl_flags    = MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_UNICODE;
		e.pdisplay_name = smtpaddr;
		e.paddress_type = "SMTP";
		e.pmail_address = smtpaddr;
		std::string out;
		out.resize(1280);
		EXT_PUSH ep;
		if (!ep.init(out.data(), out.size(), EXT_FLAG_UTF16) ||
		    ep.p_oneoff_eid(e) != pack_result::success)
			continue;
		BINARY ebin;
		ebin.cb = ep.m_offset;
		ebin.pb = ep.m_udata;
		std::string srchkey = "SMTP:"s + smtpaddr;
		HX_strupper(srchkey.data());
		BINARY sbin;
		sbin.cb = srchkey.size() + 1;
		sbin.pc = deconst(srchkey.c_str());

		/*
		 * No need to set PR_SMTP_ADDRESS:
		 * - if it existed, it is the source truth (and is not changing)
		 * - it did not exist before, don't add redundant
		 *   data (PR_EMAIL_ADDRESS already contains everything)
		 */
		changed_anything = true;
		if (ar->set(TAGGED_PROPVAL{tags.addrtype, deconst("SMTP")}) == ecServerOOM ||
		    ar->set(TAGGED_PROPVAL{tags.emaddr, deconst(smtpaddr)}) == ecServerOOM)
			throw std::bad_alloc();
		if (tags.entryid != 0 &&
		    ar->set(TAGGED_PROPVAL{tags.entryid, &ebin}) == ecServerOOM)
			throw std::bad_alloc();
		if (tags.srchkey != 0 &&
		    ar->set(TAGGED_PROPVAL{tags.srchkey, &sbin}) == ecServerOOM)
			throw std::bad_alloc();
	}
	return changed_anything;
}

}
