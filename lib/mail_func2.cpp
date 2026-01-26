// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <memory>
#include <string>
#include <libHX/string.h>
#include <vmime/generationContext.hpp>
#include <vmime/utility/outputStreamStringAdapter.hpp>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

using namespace gromox;

/**
 * Render HTML document as plaintext.
 *
 * @inbuf:  input data
 * @cpid:   character set of input data (overriding any <meta> tag
 *          inside the data); use %CP_OEMCP to indicate "guess".
 * @outbuf: result variable for caller
 *
 * Returns %CP_UTF8 to indicate conversion to UTF-8 happened.
 * Returns @cpid to indicate no charset conversion happened.
 * Thus it is possible for %CP_OEMCP to be returned again if the input cpid was
 * %CP_OEMCP, which creates a situation where html_to_plain's caller may need
 * to postprocess the output.
 * Returns a negative number on error.
 */
int html_to_plain(std::string_view inbuf, cpid_t cpid, std::string &outbuf)
{
	auto s = getenv("AVOID_W3M"); /* for testing */
	if (s == nullptr || parse_bool(s) == 0) {
		auto ret = feed_w3m(inbuf, cpid_to_cset(cpid), outbuf);
		if (ret >= 0)
			return CP_UTF8;
	}
	auto ret = html_to_plain_boring(inbuf, outbuf);
	if (ret < 0)
		return ret;
	return cpid;
}

/**
 * @rbuf: input buffer; must be UTF-8
 *        (this is normally the case, since props.get<char>(PR_BODY) is UTF-8)
 * @out:  output buffer; will be filled with UTF-8
 *        (caller may need to set PR_INTERNET_CPID=65001 [CP_UTF8] if not
 *        already done).
 *
 * It is allowed for @rbuf to point to the same object as @out.
 */
ec_error_t plain_to_html(const char *rbuf, std::string &out) try
{
	static constexpr char head[] =
		"<html><head><meta name=\"Generator\" content=\"gromox-texttohtml"
		"\">\r\n</head>\r\n<body>\r\n<pre>";
	static constexpr char footer[] = "</pre>\r\n</body>\r\n</html>";

	std::unique_ptr<char[], stdlib_delete> body(HX_strquote(rbuf, HXQUOTE_HTML, nullptr));
	if (body == nullptr)
		return ecMAPIOOM;
	out = std::string(head) + body.get() + footer;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecMAPIOOM;
}

namespace gromox {

vmime::generationContext vmail_default_genctx()
{
	vmime::generationContext c;
	/* Outlook is unable to read RFC 2231. */
	c.setEncodedParameterValueMode(vmime::generationContext::EncodedParameterValueModes::PARAMETER_VALUE_RFC2231_AND_RFC2047);
	/* Outlook is also unable to parse Content-ID:\n id... */
	c.setWrapMessageId(false);
	return c;
}

std::string vmail_to_string(const vmime::message &msg)
{
	std::string ss;
	vmime::utility::outputStreamStringAdapter adap(ss);
	msg.generate(vmail_default_genctx(), adap);
	return ss;
}

}
