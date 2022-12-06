// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstring>
#include <string>
#include <gromox/bounce_gen.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mime.hpp>
#include <gromox/util.hpp>

namespace {
struct enum_parts {
	std::string &result;
	const char *charset, *sep;
};
};

namespace gromox {

static void bp_enum_parts(const MIME *mime, void *arg)
{
	auto &param = *static_cast<enum_parts *>(arg);
	char rawname[256], u8name[512];

	if (!mime->get_filename(rawname, std::size(rawname)) ||
	    !mime_string_to_utf8(param.charset, rawname, u8name, std::size(u8name)))
		return;
	auto &sep = bounce_gen_sep();
	if (!param.result.empty() && !sep.empty())
		param.result += sep;
	param.result += u8name;
}

std::string bounce_gen_attachs(const MAIL &m, const char *charset)
{
	std::string result;
	enum_parts param{result, charset};
	m.enum_mime(bp_enum_parts, &param);
	return result;
}

std::string bounce_gen_thrindex(const MAIL &m) try
{
	auto h = m.get_head();
	if (h == nullptr)
		return {};
	char b[128];
	if (!h->get_field("Thread-Index", b, std::size(b)))
		return {};
	return b;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1218: ENOMEM");
	return {};
}

static void bp_enum_charset(const MIME *mime, void *arg)
{
	auto &result = *static_cast<std::string *>(arg);
	char buf[32];
	if (!result.empty() || !mime->get_content_param("charset",
	    buf, std::size(buf)))
		return;
	auto z = strlen(buf);
	if (z <= 2)
		return;
	auto start = strchr(buf, '"');
	if (start == nullptr) {
		result = buf;
		return;
	}
	auto end = strchr(start + 1, '"');
	if (end != nullptr)
		result.assign(start + 1, end - start - 1);
}

std::string bounce_gen_charset(const MAIL &m)
{
	std::string result;
	m.enum_mime(bp_enum_charset, &result);
	if (result.empty())
		result = "ascii";
	return result;
}

std::string bounce_gen_subject(const MAIL &m, const char *cset)
{
	std::string r;
	char buf[1024], b2[1024];
	auto &mi = *m.get_head();
	if (!mi.get_field("Subject", buf, std::size(buf)) ||
	    !mime_string_to_utf8(cset, buf, b2, std::size(b2)))
		/* also just return r */;
	return r;
}

}
