// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/element_data.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static const std::string lortf_head =
"\x7b\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fswiss\\fprq0\\fcharset128 Arial;}{\\f1\\fswiss\\fprq0\\fcharset0 Arial;}}\\plain ";
static const std::string lortf_foot = "\x7d";

static int rp_thtml(const std::string &complete, const char *expout)
{
	std::string outdoc;
	auto at = attachment_list_init();
	auto cl_0 = HX::make_scope_exit([&]() { attachment_list_free(at); });
	if (rtf_to_html(complete, "utf-8", outdoc, at) != ecSuccess) {
		fprintf(stderr, "rtf_to_html failed on:\n%s\n", complete.c_str());
		return -1;
	} else if (*expout == '\0') {
		fprintf(stderr, "expout cannot be empty\n");
		return -1;
	} else if (strstr(outdoc.c_str(), expout) == nullptr) {
		fprintf(stderr, "== Input ==\n%s\n\n== Expected needle ==\n%s\n\n== Actual output ==\n%s\n",
			complete.c_str(), expout, outdoc.c_str());
		return 1;
	}
	return 0;
}

static int rp_test(const std::string &complete, const char *expout)
{
	std::string outdoc;
	auto at = attachment_list_init();
	auto cl_0 = HX::make_scope_exit([&]() { attachment_list_free(at); });
	if (rtf_to_html(complete, "utf-8", outdoc, at) != ecSuccess) {
		fprintf(stderr, "rtf_to_html failed on:\n%s\n", complete.c_str());
		return -1;
	} else if (html_to_plain(outdoc, CP_UTF8, outdoc) < 0) {
		fprintf(stderr, "rtf+html_to_plain failed on:\n%s\n", complete.c_str());
		return -1;
	}
	/*
	 * html_to_plain output is CRLF-based when no external renderer
	 * (chawan/pandoc/w3m) is installed. Normalize for comparison.
	 */
	std::erase(outdoc, '\r');
	HX_chomp(outdoc.data());
	if (strcmp(outdoc.c_str(), expout) != 0) {
		fprintf(stderr, "== Input ==\n%s\n\n== Expected ==\n%s\n\n== Actual output ==\n%s\n",
			complete.c_str(), expout, outdoc.c_str());
		return 1;
	}
	return 0;
}

#define rp_assert(x, y) do { auto kldfgv = rp_test((x), (y)); if (kldfgv != 0) return kldfgv; } while (false)
static int t_rtf_reader()
{
	std::string uncomp;

	rp_assert(lortf_head + "\\dbch\\'89\\'bd" + lortf_foot, "何");
	rp_assert(lortf_head + "\\ansicpg932\\dbch \x89\xbd" + lortf_foot, "何");

	/*
	 * Multi-byte sequences that span an RTF group are handled differently
	 * by various implementations.
	 */
	rp_assert(lortf_head + "\\dbch{\\'89}{\\'bd}" + lortf_foot, "何"); // MSWord
	// rp_assert(lortf_head + "\\dbch{\\'89}{\\'bd}" + lortf_foot, "�ｽ"); // SvxRTF

	/* Character set switch */
	rp_assert(lortf_head + "\\dbch{\\f0\\'89\\f0\\'bd}" + lortf_foot, "何"); // MSWord
	// rp_assert(lortf_head + "\\dbch{\\f0\\'89\\f0\\'bd}" + lortf_foot, "�ｽ"); // SvxRTF
	// rp_assert(lortf_head + "\\dbch{\\f0\\'89\\f1\\f0\\'bd}" + lortf_foot, "何"); // MSWord
	rp_assert(lortf_head + "\\dbch{\\f0\\'89\\f1\\f0\\'bd}" + lortf_foot, "ｽ");

	rp_assert(lortf_head + "A\\emspace\\enspace\\qmspace B\\_C\\zwj\\zwnj D\\rtlmark\\ltrmark E" + lortf_foot,
		"A   B‑C‍‌D‏‎E");
	rp_assert(lortf_head + "{\\field{\\*\\fldinst {\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\cf0\\lang1033\\langfe1033\\langnp1033\\insrsid10112218\\charrsid10112218  HYPERLINK \"https://grommunio.com\" }}{\\fldrslt {\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\cs15\\ul\\cf17\\lang1033\\langfe1033\\langnp1033\\insrsid10112218\\charrsid10112218 https://grommunio.com}}}" + lortf_foot,
		"https://grommunio.com");
	rp_assert(lortf_head + "before {\\field{\\*\\fldinst HYPERLINK \"https://grommunio.com\"}{\\fldrslt https://grommunio.com}} after" + lortf_foot,
		"before https://grommunio.com after");
	rp_assert(lortf_head + "{First line with link }{\\field{\\*\\fldinst HYPERLINK \"https://grommunio.com\"}{\\fldrslt https://grommunio.com}}{ and the link goes on}{ and on! And On!}\\par\\par {more notes}" + lortf_foot,
		"First line with link https://grommunio.com and the link goes on and on! And On!\n\nmore notes");
	/*
	 * w3m is a formatter (renderer), and thus does not necessarily
	 * preserve controlling characters verbatim. So we need to test the
	 * pre-w3m output for some of the RTF control words.
	 */
	auto ret = rp_thtml(lortf_head + "A\\-\\emspace\\enspace\\qmspace B\\zwbo\\zwnbo C" + lortf_foot,
	           "A&shy;&emsp;&ensp;&emsp14;B​﻿C");
	if (ret != 0)
		return ret;
	ret = rp_thtml(lortf_head + "@@\\u127\\'3f@@\\u2047\\'3f@@\\u32767\\'3f@@\\u-1\\'3f@@" + lortf_foot,
	      "@@\x7f@@߿@@翿@@￿@@");
	if (ret != 0)
		return ret;
	ret = rp_thtml(lortf_head + "{\\field{\\*\\fldinst {\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\cf0\\lang1033\\langfe1033\\langnp1033\\insrsid10112218\\charrsid10112218  HYPERLINK \"https://grommunio.com\" }}{\\fldrslt {\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\cs15\\ul\\cf17\\lang1033\\langfe1033\\langnp1033\\insrsid10112218\\charrsid10112218 https://grommunio.com}}}" + lortf_foot,
		"<a href=\"https://grommunio.com\">");
	if (ret != 0)
		return ret;
	return 0;
}

static const char rtf_native_angles[] =
"{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}}"
"\\plain Von: Katja Test <katja@dev.local>}";

static const char rtf_fromhtml_conformant[] =
"{\\rtf1\\ansi\\ansicpg1252\\fromhtml1\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}}"
"{\\*\\htmltag19 <html>}{\\*\\htmltag34 <body>}{\\*\\htmltag64 <p>}"
"Von: Katja Test {\\*\\htmltag84 &lt;}\\htmlrtf <\\htmlrtf0 katja@dev.local"
"{\\*\\htmltag84 &gt;}\\htmlrtf >\\htmlrtf0 {\\*\\htmltag72 </p>}"
"{\\*\\htmltag41 </body>}{\\*\\htmltag27 </html>}}";

static const char rtf_fromhtml_srctext[] =
"{\\rtf1\\ansi\\ansicpg1252\\fromhtml1\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}}"
"{\\*\\htmltag19 <html>}{\\*\\htmltag34 <body>}{\\*\\htmltag64 <p>}"
"Von: Katja Test &lt;katja@dev.local&gt;{\\*\\htmltag72 </p>}"
"{\\*\\htmltag41 </body>}{\\*\\htmltag27 </html>}}";

static const char rtf_fromhtml_srctext_anchor[] =
"{\\rtf1\\ansi\\ansicpg1252\\fromhtml1\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}}"
"{\\*\\htmltag19 <html>}{\\*\\htmltag34 <body>}{\\*\\htmltag64 <p>}"
"{\\*\\htmltag84 <b>}Von:{\\*\\htmltag92 </b>} Katja Test &lt;"
"{\\*\\htmltag84 <a href=\"mailto:katja@dev.local\">}katja@dev.local{\\*\\htmltag92 </a>}"
"&gt;{\\*\\htmltag72 </p>}{\\*\\htmltag41 </body>}{\\*\\htmltag27 </html>}}";

static const char rtf_fromhtml_numeric[] =
"{\\rtf1\\ansi\\ansicpg1252\\fromhtml1\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}}"
"{\\*\\htmltag19 <html>}{\\*\\htmltag34 <body>}{\\*\\htmltag64 <p>}"
"a&#33;b&#x2014;c{\\*\\htmltag72 </p>}{\\*\\htmltag41 </body>}{\\*\\htmltag27 </html>}}";

static const char rtf_fromhtml_bare_amp[] =
"{\\rtf1\\ansi\\ansicpg1252\\fromhtml1\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}}"
"{\\*\\htmltag19 <html>}{\\*\\htmltag34 <body>}{\\*\\htmltag64 <p>}"
"Meier & Sohn, A&B, 100&#37, x&y;{\\*\\htmltag72 </p>}{\\*\\htmltag41 </body>}"
"{\\*\\htmltag27 </html>}}";

/*
 * Text runs of a \\fromhtml1 document are HTML source in some producers and
 * decoded text in others; markup always lives in \\*\\htmltag destinations and
 * is emitted verbatim. Escaping has to leave character references alone
 * without letting a bare ampersand through.
 */
static int t_fromhtml_entities()
{
	auto ret = rp_thtml(rtf_native_angles, "&lt;katja@dev.local&gt;");
	if (ret != 0)
		return ret;
	ret = rp_thtml(rtf_fromhtml_conformant, "Von: Katja Test &lt;katja@dev.local&gt;");
	if (ret != 0)
		return ret;
	ret = rp_thtml(rtf_fromhtml_srctext, "Von: Katja Test &lt;katja@dev.local&gt;");
	if (ret != 0)
		return ret;
	ret = rp_thtml(rtf_fromhtml_srctext_anchor,
	      "&lt;<a href=\"mailto:katja@dev.local\">katja@dev.local</a>&gt;");
	if (ret != 0)
		return ret;
	ret = rp_thtml(rtf_fromhtml_numeric, "a&#33;b&#x2014;c");
	if (ret != 0)
		return ret;
	ret = rp_thtml(rtf_fromhtml_bare_amp,
	      "Meier &amp; Sohn, A&amp;B, 100&amp;#37, x&amp;y;");
	if (ret != 0)
		return ret;
	return 0;
}

static int t_html_plain()
{
	std::string obuf;
	if (html_to_plain("&lt;&gt;&quot;&amp;&#33;", CP_UTF8, obuf) != CP_UTF8)
		return -1;
	if (strncmp(obuf.c_str(), "<>\"&!", 5) != 0) {
		fprintf(stderr, "output: >%s<\n", obuf.c_str());
		return -1;
	}
	return 0;
}

static int t_htmltortf()
{
	std::string out;
	auto err = html_to_rtf("", static_cast<cpid_t>(1252), out);
	if (err != ecSuccess) {
		fprintf(stderr, "html_to_rtf failed\n");
		return EXIT_FAILURE;
	}
	err = html_to_rtf("1", static_cast<cpid_t>(1252), out);
	if (err != ecSuccess) {
		fprintf(stderr, "html_to_rtf failed\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main()
{
	textmaps_init(getenv("TEST_PATH"));
	setenv("GROMOX_RTFTOHTML", "internal", true);
	setenv("GROMOX_HTMLTOPLAIN", "internal", true);
	if (t_html_plain() != 0)
		return EXIT_FAILURE;
	if (t_rtf_reader() != 0)
		return EXIT_FAILURE;
	if (t_fromhtml_entities() != 0)
		return EXIT_FAILURE;
	if (t_htmltortf() != 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
