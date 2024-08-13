// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
#include <cstdlib>
#include <libHX/string.h>
#include <gromox/element_data.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/util.hpp>
#include "../tools/staticnpmap.cpp"
#undef assert
#define assert(x) do { if (!(x)) { printf("%s failed\n", #x); return EXIT_FAILURE; } } while (false)

using namespace gromox;
using namespace gi_dump;

static alloc_context g_alloc_mgr;

static void *g_alloc(size_t z) { return g_alloc_mgr.alloc(z); }

static constexpr char appl_header[] =
	"Content-Type: multipart/alternative;\r\n"
	"	boundary=\"Apple-Mail=_DB070322-3ADF-45C2-BA0A-580CF7CD6ACA\"\r\n"
	"Mime-Version: 1.0 (Mac OS X Mail 16.0 (3696.120.41.1.8))\r\n"
	"X-Mailer: Apple Mail (2.3696.120.41.1.8)\r\n"
	"\r\n"
	"\r\n";
static constexpr char appl_plain[] =
	"--Apple-Mail=_DB070322-3ADF-45C2-BA0A-580CF7CD6ACA\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"ZplainZ\r\n";
static constexpr char appl_mixed[] =
	"--Apple-Mail=_DB070322-3ADF-45C2-BA0A-580CF7CD6ACA\r\n"
	"Content-Type: multipart/mixed;\r\n"
	"	boundary=\"Apple-Mail=_1D3088EC-33DB-413D-B7F8-D50FC6A5658E\"\r\n"
	"\r\n"
	"\r\n";
static constexpr char appl_html1[] =
	"--Apple-Mail=_1D3088EC-33DB-413D-B7F8-D50FC6A5658E\r\n"
	"Content-Type: text/html;\r\n"
	"\r\n"
	"Zhtml1Z\r\n";
static constexpr char appl_zip[] =
	"--Apple-Mail=_1D3088EC-33DB-413D-B7F8-D50FC6A5658E\r\n"
	"Content-Disposition: attachment; filename=text.txt.zip\r\n"
	"Content-Type: application/zip; x-unix-mode=0644; name=\"text.txt.zip\"\r\n"
	"\r\n"
	"PKCD\r\n";
static constexpr char appl_html2[] =
	"--Apple-Mail=_1D3088EC-33DB-413D-B7F8-D50FC6A5658E\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"Zhtml2Z\r\n";
static constexpr char appl_mixed_footer[] =
	"--Apple-Mail=_1D3088EC-33DB-413D-B7F8-D50FC6A5658E--\r\n"
	"\r\n";
static constexpr char appl_alt_footer[] =
	"--Apple-Mail=_DB070322-3ADF-45C2-BA0A-580CF7CD6ACA--\r\n";

static int select_parts_1()
{
	/*
	 * Apple's generation of mails is just messed up. Non-inline
	 * attachments are _not_ an alternative to a text part. It also splits
	 * the HTML body into multiple parts (and the first one may be blank,
	 * therefore we should not even try to pick out one HTML part as an
	 * alternative to the plain part.)
	 *
	 * What it does:
	 * 	alternative { text, mixed { html, zip, html, png, html } }
	 * What it should do:
	 * 	mixed { alternative { text, html }, zip, png }
	 */
	auto data = std::string(appl_header) + appl_plain + appl_mixed +
	            appl_html1 + appl_zip + appl_html2 +
	            appl_mixed_footer + appl_alt_footer;
	MAIL m;
	assert(m.load_from_str_move(data.data(), data.size()));
	auto mc = oxcmail_import("us-ascii", "UTC", &m, g_alloc, ee_get_propids);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	if (atl->count != 3)
		gi_print(0, *mc);
	assert(atl->count == 3);
	auto v = atl->pplist[0]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "text/html") == 0);
	v = atl->pplist[1]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "application/zip") == 0);
	v = atl->pplist[2]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "text/html") == 0);
	v = mc->proplist.get<const char>(PR_BODY);
	assert(v != nullptr && strcmp(v, "ZplainZ") == 0);
	auto bin = mc->proplist.get<BINARY>(PR_HTML);
	if (bin != nullptr)
		assert(HX_memmem(bin->pv, bin->cb, "ZplainZ", 7) != nullptr);
	return 0;
}

static int select_parts_2()
{
	auto data = std::string(appl_header) + appl_plain + appl_mixed +
	            appl_html1 + appl_zip + appl_mixed_footer + appl_alt_footer;
	MAIL m;
	assert(m.load_from_str_move(data.data(), data.size()));
	auto mc = oxcmail_import("us-ascii", "UTC", &m, g_alloc, ee_get_propids);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	if (atl->count != 1)
		gi_print(0, *mc);
	assert(atl->count == 1);
	auto v = atl->pplist[0]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "application/zip") == 0);
	v = mc->proplist.get<const char>(PR_BODY);
	assert(v != nullptr && strcmp(v, "ZplainZ") == 0);
	auto bin = mc->proplist.get<BINARY>(PR_HTML);
	if (bin != nullptr)
		assert(HX_memmem(bin->pv, bin->cb, "Zhtml1Z", 7) != nullptr);
	return 0;
}

static int select_parts_3()
{
	/* Exchange V6 and M365 generate weird alternative containers. */
	char data[] =
		"Content-Type: multipart/mixed;\r\n"
		"	boundary=\"_007D\"\r\n"
		"MIME-Version: 1.0\r\n"
		"\r\n"
		"--_007D\r\n"
		"Content-Type: multipart/related;\r\n"
		"	boundary=\"_006D\";\r\n"
		"	type=\"multipart/alternative\"\r\n"
		"\r\n"
		"--_006D\r\n"
		"Content-Type: multipart/alternative;\r\n"
		"	boundary=\"_000D\"\r\n"
		"\r\n"
		"--_000D\r\n"
		"Content-Type: text/plain; charset=\"utf-8\"\r\n"
		"\r\n"
		"ZplainZ\r\n"
		"--_000D\r\n"
		"Content-Type: text/html; charset=\"utf-8\"\r\n"
		"\r\n"
		"Zhtml1Z\r\n"
		"--_000D--\r\n"
		"\r\n"
		"--_006D\r\n"
		"Content-Type: image/png; name=\"image001.png\"\r\n"
		"\r\n"
		"PNG\r\n"
		"--_006D\r\n"
		"Content-Type: image/gif; name=\"image001.gif\"\r\n"
		"\r\n"
		"GIF\r\n"
		"--_006D--\r\n"
		"\r\n"
		"--_007D\r\n"
		"Content-Type: application/pdf; name=\"RE-20249303.pdf\"\r\n"
		"\r\n"
		"PDF\r\n"
		"--_007D--\r\n";

	MAIL m;
	assert(m.load_from_str_move(data, std::size(data)));
	auto mc = oxcmail_import("us-ascii", "UTC", &m, g_alloc, ee_get_propids);
	assert(mc != nullptr);
	gi_print(0, *mc);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	if (atl->count != 3)
		gi_print(0, *mc);
	assert(atl->count == 3);
	auto v = atl->pplist[2]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "application/pdf") == 0);
	v = mc->proplist.get<const char>(PR_BODY);
	assert(v != nullptr && strcmp(v, "ZplainZ") == 0);
	auto bin = mc->proplist.get<BINARY>(PR_HTML);
	if (bin != nullptr)
		assert(HX_memmem(bin->pv, bin->cb, "Zhtml1Z", 7) != nullptr);
	return 0;
}

int main()
{
	auto ee_get_user_ids = [](const char *, unsigned int *, unsigned int *, enum display_type *) -> BOOL { return false; };
	auto ee_get_domain_ids = [](const char *, unsigned int *, unsigned int *) -> BOOL { return false; };
	auto ee_get_username_from_id = [](unsigned int, char *, size_t) -> BOOL { return false; };
	g_show_tree = g_show_props = true;
	if (!oxcmail_init_library("x500", ee_get_user_ids, ee_get_domain_ids, ee_get_username_from_id)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}
	select_parts_1();
	select_parts_2();
	select_parts_3();
	return EXIT_SUCCESS;
}
