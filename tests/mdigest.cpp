// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
#include <cstdlib>
#include <string>
#include <json/value.h>
#include <vmime/message.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;

static Json::Value vdigest(const std::string &eml)
{
	vmime::message vmsg;
	auto vpctx = vmail_default_parsectx();
	vmsg.parse(vpctx, eml);
	Json::Value d;
	assert(vmail_to_digest(eml, vmsg, d) > 0);
	return d;
}

static Json::Value odigest(const std::string &eml)
{
	MAIL m;
	assert(m.refonly_parse(eml.c_str(), eml.size()));
	Json::Value d;
	assert(m.make_digest(d) > 0);
	return d;
}

/* MAIL emits UInt64, vmail_to_digest Int64; the JSON consumers do not care. */
static bool same(const Json::Value &a, const Json::Value &b)
{
	return a.isNumeric() && b.isNumeric() ? a.asUInt64() == b.asUInt64() : a == b;
}

static std::string slice(const std::string &eml, const Json::Value &m)
{
	return eml.substr(m["begin"].asUInt(), m["length"].asUInt());
}

static void single_part()
{
	const auto head = "From: a@b.c\r\nSubject: s\r\nX-Priority: High\r\n"
	                  "Content-Type: text/plain; charset=\"us-ascii\"\r\n\r\n"s;
	const auto body = "hello\r\nworld\r\n"s;
	auto d = vdigest(head + body);
	assert(d["mimes"].size() == 1);
	const auto &m = d["mimes"][0];
	assert(m["id"].asString().empty());
	assert(m["ctype"].asString() == "text/plain");
	assert(m["charset"].asString() == "us-ascii");
	assert(m["encoding"].asString() == "7bit");
	assert(m["head"].asUInt() == 0);
	assert(m["begin"].asUInt() == head.size());
	assert(slice(head + body, m) == body);
	assert(m["lines"].asUInt() == 2);
	assert(d["priority"].asUInt() == 3);
	assert(d["size"].asUInt() == head.size() + body.size());
	assert(!d.isMember("signed") && !d.isMember("encrypt"));
}

static void name_param_and_sanitizing()
{
	const auto eml =
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
		"--b\r\nContent-Type: te\"xt/pl\"ain\r\n"
		"Content-Transfer-Encoding: \xc3\xbcmlaut\r\n\r\nx\r\n"
		"--b\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\n"
		"Content-Transfer-Encoding: BASE64\r\n"
		"Content-Disposition: attachment\r\n\r\nQUJD\r\n"
		"--b--\r\n"s;
	auto d = vdigest(eml);
	assert(d["mimes"].size() == 2);
	assert(d["mimes"][0]["ctype"].asString() == "te\"xt/pl\"ain");
	assert(!d["mimes"][0].isMember("filename"));
	assert(d["mimes"][1]["encoding"].asString() == "base64");
	assert(d["mimes"][1]["cntdspn"].asString() == "attachment");
	assert(base64_decode(d["mimes"][1]["filename"].asString()) == "report.pdf");
}

static void smime_flags()
{
	auto d = vdigest("Content-Type: multipart/signed; "
	           "protocol=\"application/pkcs7-signature\"; boundary=b\r\n\r\n"
	           "--b\r\nContent-Type: text/plain\r\n\r\nx\r\n"
	           "--b\r\nContent-Type: application/pkcs7-signature\r\n\r\nQUJD\r\n"
	           "--b--\r\n"s);
	assert(d["signed"].asUInt() == 1);
	assert(!d.isMember("encrypt"));
	d = vdigest("Content-Type: application/pkcs7-mime; "
	    "smime-type=enveloped-data; name=smime.p7m\r\n"
	    "Content-Transfer-Encoding: base64\r\n\r\nQUJD\r\n"s);
	assert(d["encrypt"].asUInt() == 1);
	assert(!d.isMember("signed"));
	assert(d["mimes"].size() == 1);
	assert(base64_decode(d["mimes"][0]["filename"].asString()) == "smime.p7m");
}

static void digest_default()
{
	auto d = vdigest("Content-Type: multipart/digest; boundary=b\r\n\r\n"
	           "--b\r\n\r\nFrom: x@y.z\r\n\r\ninner\r\n"
	           "--b\r\nContent-Type: text/plain\r\n\r\nx\r\n"
	           "--b--\r\n"s);
	assert(d["mimes"].size() == 2);
	assert(d["mimes"][0]["ctype"].asString() == "message/rfc822");
	assert(d["mimes"][1]["ctype"].asString() == "text/plain");
}

static void empty_tail_part()
{
	auto d = vdigest("Content-Type: multipart/mixed; boundary=b\r\n\r\n"
	           "--b\r\nContent-Type: text/plain\r\n\r\n"s);
	assert(d["mimes"].size() == 1);
	assert(d["mimes"][0]["length"].asUInt() == 0);
	assert(d["mimes"][0]["lines"].asUInt() == 0);
}

/* Offsets must match what MAIL::make_digest produced for the same bytes. */
static void parity_with_mail()
{
	const auto eml =
		"From: a@b.c\r\nTo: d@e.f\r\nSubject: t\r\n"
		"Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n"
		"--outer\r\nContent-Type: multipart/alternative; boundary=\"inner\"\r\n\r\n"
		"--inner\r\nContent-Type: text/plain; charset=utf-8\r\n"
		"Content-Transfer-Encoding: 7bit\r\n\r\nplain\r\n"
		"--inner\r\nContent-Type: text/html; charset=utf-8\r\n"
		"Content-Transfer-Encoding: 7bit\r\n\r\n<p>html</p>\r\n"
		"--inner--\r\n"
		"--outer\r\nContent-Type: application/octet-stream\r\n"
		"Content-Transfer-Encoding: base64\r\n"
		"Content-Disposition: attachment; filename=\"a.bin\"\r\n"
		"Content-ID: <cid1@x>\r\n\r\nQUJD\r\n"
		"--outer--\r\n"s;
	auto nd = vdigest(eml), od = odigest(eml);
	assert(nd["mimes"].size() == od["mimes"].size());
	for (unsigned int i = 0; i < nd["mimes"].size(); ++i)
		for (const char *k : {"id", "ctype", "head", "begin", "length",
		     "encoding", "charset", "filename", "cid", "cntdspn", "lines"})
			assert(same(nd["mimes"][i][k], od["mimes"][i][k]));
	/*
	 * Container lengths differ by design: MAIL counted the CRLF that
	 * belongs to the following boundary delimiter.
	 */
	assert(nd["structure"].size() == od["structure"].size());
	for (unsigned int i = 0; i < nd["structure"].size(); ++i)
		for (const char *k : {"id", "ctype", "head", "begin"})
			assert(same(nd["structure"][i][k], od["structure"][i][k]));
	assert(same(nd["size"], od["size"]));
	assert(slice(eml, nd["mimes"][0]) == "plain");
	assert(nd["mimes"][2]["id"].asString() == "2");
	assert(base64_decode(nd["mimes"][2]["cid"].asString()) == "<cid1@x>");
}

int main()
{
	single_part();
	name_param_and_sanitizing();
	smime_flags();
	digest_default();
	empty_tail_part();
	parity_with_mail();
	return EXIT_SUCCESS;
}
