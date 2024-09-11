// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <string>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mime.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "oxcmail_int.hpp"

using namespace gromox;

namespace oxcmail {

/**
 * @level: how often to recurse into multiparts.
 *         If level==0, a top-level multipart/ will not be analyzed.
 * Returns: indicator if something usable was found
 */
unsigned int select_parts(const MIME *part, MIME_ENUM_PARAM &info,
    unsigned int level)
{
	info.plain_count = info.html_count = 0;
	info.enriched_count = info.calendar_count = 0;

	if (part->mime_type == mime_type::single) {
		if (strcasecmp(part->content_type, "text/plain") == 0) {
			info.pplain = part;
			return info.plain_count = 1;
		} else if (strcasecmp(part->content_type, "text/html") == 0) {
			info.phtml = part;
			return info.html_count = 1;
		} else if (strcasecmp(part->content_type, "text/enriched") == 0) {
			info.penriched = part;
			return info.enriched_count = 1;
		} else if (strcasecmp(part->content_type, "text/calendar") == 0) {
			info.pcalendar = part;
			return info.calendar_count = 1;
		}
		return 0;
	}
	/*
	 * At level 0, we are inspecting the root (the mail itself, only one of
	 * these tests will succeed)
	 */
	if (level >= MAXIMUM_SEARCHING_DEPTH)
		return 0;
	++level;
	bool alt = strcasecmp(part->content_type, "multipart/alternative") == 0;

	for (auto child = part->get_child(); child != nullptr;
	     child = child->get_sibling()) {
		MIME_ENUM_PARAM cld_info{info.phash};
		auto cld_alt = strcasecmp(child->content_type, "multipart/alternative") == 0;
		bool found = select_parts(child, cld_info, level);
		if (!found)
			continue;
		if (!cld_alt && (cld_info.plain_count > 1 ||
		    cld_info.html_count > 1 || cld_info.enriched_count > 1 ||
		    cld_info.calendar_count > 1)) {
			/*
			 * @child is a /mixed or so, and has multiple
			 * bodies of the same type, which is a bad
			 * sign (AppleMail splitting one HTML body
			 * into multiple MIME parts).
			 */
			continue;
		}
		info.plain_count    += cld_info.pplain != nullptr;
		info.html_count     += cld_info.phtml != nullptr;
		info.enriched_count += cld_info.penriched != nullptr;
		info.calendar_count += cld_info.pcalendar != nullptr;
		if (alt) {
			/* Parts within a /alternative container override one another */
			if (cld_info.pplain != nullptr)
				info.pplain = cld_info.pplain;
			if (cld_info.phtml != nullptr)
				info.phtml = cld_info.phtml;
			if (cld_info.penriched != nullptr)
				info.penriched = cld_info.penriched;
			if (cld_info.pcalendar != nullptr)
				info.pcalendar = cld_info.pcalendar;
			continue;
		}
		/* Parts within a /related don't */
		if (cld_info.pplain != nullptr && info.pplain == nullptr)
			info.pplain = cld_info.pplain;
		if (cld_info.phtml != nullptr && info.phtml == nullptr)
			info.phtml = cld_info.phtml;
		if (cld_info.penriched != nullptr && info.penriched == nullptr)
			info.penriched = cld_info.penriched;
		if (cld_info.pcalendar != nullptr && info.pcalendar == nullptr)
			info.pcalendar = cld_info.pcalendar;
	}
	return info.plain_count + info.html_count + info.enriched_count +
	       info.calendar_count;
}

errno_t bodyset_html(TPROPVAL_ARRAY &props, std::string &&rawbody,
    const char *charset)
{
	uint32_t id = cset_to_cpid(charset);
	auto err = props.set(PR_INTERNET_CPID, &id);
	if (err < 0)
		return -err;
	BINARY bin;
	bin.cb = std::min(rawbody.size(), static_cast<size_t>(UINT32_MAX));
	bin.pc = rawbody.data();
	err = props.set(PR_HTML, &bin);
	return err >= 0 ? 0 : -err;
}

errno_t bodyset_plain(TPROPVAL_ARRAY &props, std::string &&rawbody,
    const char *charset) try
{
	std::string utfbody;
	utfbody.resize(mb_to_utf8_xlen(rawbody.size()));
	TAGGED_PROPVAL pv;
	/*
	 * string_to_utf8() may or may not(!) call iconv. Thus, we have
	 * an unconditional utf8_filter call in case the message
	 * declared charset=utf-8 and still included garbage.
	 */
	if (string_to_utf8(charset, rawbody.c_str(),
	    utfbody.data(), utfbody.size() + 1)) {
		utf8_filter(utfbody.data());
		pv.proptag = PR_BODY;
		pv.pvalue  = utfbody.data();
	} else {
		pv.proptag = PR_BODY_A;
		pv.pvalue  = rawbody.data();
	}
	auto err = props.set(pv);
	return err >= 0 ? 0 : -err;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1746: ENOMEM");
	return ENOMEM;
}

errno_t bodyset_enriched(TPROPVAL_ARRAY &props,
    std::string &&rawbody, const char *charset) try
{
	uint32_t id = cset_to_cpid(charset);
	auto err = props.set(PR_INTERNET_CPID, &id);
	if (err < 0)
		return -err;
	std::string utfbody;
	utfbody.resize(mb_to_utf8_xlen(rawbody.size()));
	enriched_to_html(rawbody.c_str(), utfbody.data(), utfbody.size() + 1);
	BINARY bin;
	bin.cb = utfbody.size();
	bin.pc = utfbody.data();
	err = props.set(PR_HTML, &bin);
	return err >= 0 ? 0 : -err;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1747: ENOMEM");
	return ENOMEM;
}

}
