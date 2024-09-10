// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <string>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "oxcmail_int.hpp"

using namespace gromox;

namespace oxcmail {

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
