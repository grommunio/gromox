// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2026 grommunio GmbH
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

std::string bounce_gen_thrindex(const vmime::message &msg) try
{
	auto &hdr = *msg.getHeader();
	if (auto field = hdr.findField("Thread-Index"))
		return field->getValue()->generate();
	return {};
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return {};
}

std::string bounce_gen_charset(const vmime::message &msg)
{
	return msg.getBody()->getCharset().getName();
}

std::string bounce_gen_subject(const vmime::message &msg)
{
	auto hdr = &*msg.getHeader();
	auto field = hdr->findField(vmime::fields::SUBJECT);
	if (field == nullptr)
		return {};
	auto txt = vmime::dynamicCast<vmime::text>(field->getValue());
	if (txt == nullptr)
		return {};
	return txt->getConvertedText(vmime::charsets::UTF_8);
}

}
