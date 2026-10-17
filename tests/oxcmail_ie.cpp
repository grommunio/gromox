// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <deque>
#include <libHX/string.h>
#include <vmime/contentTypeField.hpp>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>
#include "../tools/staticnpmap.cpp"
#undef assert
#define assert(x) do { if (!(x)) { printf("%s failed\n", #x); return EXIT_FAILURE; } } while (false)

namespace {
struct ie_name_entry {
	uint16_t proptag;
	PROPERTY_NAME pn;
};
}

using namespace gromox;
using namespace gi_dump;
using mptr = std::unique_ptr<message_content, mc_delete>;

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
static constexpr char appl_png[] =
	"--Apple-Mail=_1D3088EC-33DB-413D-B7F8-D50FC6A5658E\r\n"
	"Content-Disposition: inline\r\n"
	"Content-Type: image/png\r\n"
	"\r\n"
	"iPNG\r\n";
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
static char data_4[] =
	"Content-Type: multipart/alternative; boundary=\"0\"\r\n"
	"MIME-Version: 1.0\r\n"
	"\r\n"
	"--0\r\n"
	"Content-Type: multipart/mixed; boundary=\"1\";\r\n"
	"\r\n"
	"--1\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"Zplain1Z\r\n"
	"--1\r\n"
	"Content-Type: image/png\r\n"
	"\r\n"
	"///1\r\n"
	"--1--\r\n"
	"--0\r\n"
	"Content-Type: multipart/mixed; boundary=\"1\";\r\n"
	"\r\n"
	"--1\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"Zplain2Z\r\n"
	"--1\r\n"
	"Content-Type: image/png\r\n"
	"\r\n"
	"///2\r\n"
	"--1--\r\n"
	"--0\r\n"
	"Content-Type: multipart/mixed; boundary=\"1\";\r\n"
	"\r\n"
	"--1\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"Zhtml3Z\r\n"
	"--1\r\n"
	"Content-Type: text/html\r\n"
	"Content-Disposition: attachment\r\n"
	"\r\n"
	"dontjoin\r\n"
	"--1\r\n"
	"Content-Type: image/png\r\n"
	"\r\n"
	"///3\r\n"
	"--1--\r\n"
	"--0--\r\n";
static char data_5[] =
	"Content-Type: multipart/related; boundary=\"0\"\r\n"
	"\r\n"
	"--0\r\n"
	"Content-Type: multipart/alternative; boundary=\"--=1\"\r\n"
	"\r\n"
	"----=1\r\n"
	"Content-Transfer-Encoding: quoted-printable\r\n"
	"Content-Type: text/plain; charset=\"iso-8859-1\"\r\n"
	"\r\n"
	"ZplainZ\r\n"
	"----=1\r\n"
	"Content-Transfer-Encoding: quoted-printable\r\n"
	"Content-Type: text/html; charset=\"iso-8859-1\"\r\n"
	"\r\n"
	"ZhtmlZ=E4\r\n"
	"----=1--\r\n"
	"--0\r\n"
	"Content-Disposition: inline\r\n"
	"Content-ID: <image001.png@01DB05E8.3DF68800>\r\n"
	"Content-Transfer-Encoding: base64\r\n"
	"Content-Type: image/png\r\n"
	"\r\n"
	"///1\r\n"
	"--0\r\n"
	"Content-Disposition: inline\r\n"
	"Content-ID: <image002.png@01DB05E8.3DF68800>\r\n"
	"Content-Transfer-Encoding: base64\r\n"
	"Content-Type: image/png\r\n"
	"\r\n"
	"///2\r\n"
	"--0--\r\n";

static bool ie_get_propids(const ie_name_entry *map, size_t mapsize,
    const PROPNAME_ARRAY *pna, PROPID_ARRAY *idp)
{
	auto &id = *idp;
	id.resize(pna->size());
	for (size_t i = 0; i < pna->size(); ++i) {
		auto row = std::find_if(&map[0], &map[mapsize],
		           [&](const ie_name_entry &r) -> bool { return r.pn == (*pna)[i]; });
		id[i] = row != &map[mapsize] ? row->proptag : 0;
	}
	return TRUE;
}

static int excess_attachment()
{
	static char data[] = "Content-Type: message/rfc822\n";
	MAIL m;
	assert(m.refonly_parse(data, strlen(data)));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	assert(atl->count == 1);
	auto atx = atl->pplist[0];
	assert(atx != nullptr);
	assert(atx->pembedded != nullptr);
	atl = atx->pembedded->children.pattachments;
	assert(atl == nullptr || atl->count == 0);
	return 0;
}

static int nested_boundary_prefix()
{
	/* GXL-714 */
	static char data[] =
		"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
		"--B\r\nContent-Type: multipart/alternative; boundary=\"B-1\"\r\n\r\n"
		"--B-1\r\nContent-Type: text/plain\r\n\r\nplain\r\n"
		"--B-1\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n"
		"--B-1--\r\n"
		"--B\r\nContent-Type: application/octet-stream\r\n"
		"Content-Disposition: attachment; filename=\"a.bin\"\r\n\r\nx\r\n"
		"--B--\r\n";
	MAIL m;
	assert(m.refonly_parse(data, strlen(data)));
	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr && atl->count == 1);
	return EXIT_SUCCESS;
}

static int select_parts_1()
{
	/*
	 * Apple's generation of mails is just messed up. Non-inline
	 * attachments are _not_ an alternative to a text part. It also splits
	 * the HTML body into multiple parts.
	 */
	fprintf(stderr, "== T1\n");
	auto data = std::string(appl_header) + appl_plain + appl_mixed +
	            appl_html1 + appl_zip + appl_html2 +
	            appl_mixed_footer + appl_alt_footer;
	MAIL m;
	assert(m.refonly_parse(data.data(), data.size()));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	if (atl->count != 1)
		gi_print(0, *mc);
	assert(atl->count == 1);
	auto v = atl->pplist[0]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "application/zip") == 0);
	v = atl->pplist[0]->proplist.get<char>(PR_ATTACH_LONG_FILENAME);
	assert(v != nullptr && strcasecmp(v, "text.txt.zip") == 0);
	v = mc->proplist.get<const char>(PR_BODY);
	assert(v != nullptr && strcmp(v, "ZplainZ") == 0);
	auto bin = mc->proplist.get<BINARY>(PR_HTML);
	if (bin != nullptr)
		assert(HX_memmem(bin->pv, bin->cb, "Zhtml2Z", 7) != nullptr);
	return 0;
}

static int select_parts_1a()
{
	fprintf(stderr, "== T1a\n");
	auto data = std::string(appl_header) + appl_plain + appl_mixed +
	            appl_html1 + appl_png + appl_html2 +
	            appl_mixed_footer + appl_alt_footer;
	MAIL m;
	assert(m.refonly_parse(data.data(), data.size()));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	if (atl->count != 1)
		gi_print(0, *mc);
	assert(atl->count == 1);
	auto v = atl->pplist[0]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "image/png") == 0);
	auto bin = mc->proplist.get<BINARY>(PR_HTML);
	if (bin != nullptr)
		assert(HX_memmem(bin->pv, bin->cb, "cid:", 4) != nullptr);
	return 0;
}

static int select_parts_2()
{
	fprintf(stderr, "== T2\n");
	auto data = std::string(appl_header) + appl_plain + appl_mixed +
	            appl_html1 + appl_zip + appl_mixed_footer + appl_alt_footer;
	MAIL m;
	assert(m.refonly_parse(data.data(), data.size()));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
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
	fprintf(stderr, "== T3\n");
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
	assert(m.refonly_parse(data, std::size(data)));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
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

/* Test retention of alternative-discarded attachments */
static int select_parts_4()
{
	fprintf(stderr, "== T4\n");
	MAIL m;
	assert(m.refonly_parse(data_4, std::size(data_4)));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	if (atl->count != 5)
		gi_print(0, *mc);
	assert(atl->count == 5);
	auto v = atl->pplist[1]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "image/png") == 0);
	v = atl->pplist[2]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "image/png") == 0);
	v = atl->pplist[3]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "text/html") == 0);
	v = atl->pplist[4]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "image/png") == 0);
	v = mc->proplist.get<const char>(PR_BODY);
	assert(v != nullptr && strcmp(v, "Zplain2Z") == 0);
	auto bin = mc->proplist.get<const BINARY>(PR_HTML);
	assert(bin != nullptr && HX_memmem(bin->pv, bin->cb, "Zhtml3Z", 7) != nullptr);
	assert(HX_memmem(bin->pv, bin->cb, "dontjoin", 8) == nullptr);
	return 0;
}

/**
 * Ensure high bytes are properly handled by hjoin;
 * Ensure Content-ID angled brackets are stripped when spliced into img src="".
 */
static int select_parts_5()
{
	fprintf(stderr, "== T5\n");
	MAIL m;
	assert(m.refonly_parse(data_5, std::size(data_5)));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	if (atl->count != 2)
		gi_print(0, *mc);
	assert(atl->count == 2);
	auto bin = mc->proplist.get<const BINARY>(PR_HTML);
	assert(bin != nullptr);
	assert(HX_memmem(bin->pv, bin->cb, "ZhtmlZ", 6) != nullptr);
	return 0;
}

static char data_6[] =
	"Content-Type: multipart/mixed; boundary=\"0\"\r\n"
	"MIME-Version: 1.0\r\n"
	"\r\n"
	"--0\r\n"
	"Content-Type: application/pdf; name=\"a.pdf\"\r\n"
	"Content-Disposition: attachment; filename=\"a.pdf\"\r\n"
	"\r\n"
	"PDF\r\n"
	"--0\r\n"
	"Content-Type: multipart/alternative; boundary=\"1\"\r\n"
	"\r\n"
	"--1\r\n"
	"Content-Type: text/plain; charset=\"utf-8\"\r\n"
	"\r\n"
	"ZplainZ\r\n"
	"--1\r\n"
	"Content-Type: text/html; charset=\"utf-8\"\r\n"
	"\r\n"
	"Zhtml1Z\r\n"
	"--1--\r\n"
	"--0--\r\n";
static char data_7[] =
	"Content-Type: multipart/mixed; boundary=\"0\"\r\n"
	"MIME-Version: 1.0\r\n"
	"\r\n"
	"--0\r\n"
	"Content-Type: application/pdf; name=\"a.pdf\"\r\n"
	"Content-Disposition: attachment; filename=\"a.pdf\"\r\n"
	"\r\n"
	"PDF\r\n"
	"--0\r\n"
	"Content-Type: text/html; charset=\"utf-8\"\r\n"
	"\r\n"
	"Zhtml1Z\r\n"
	"--0--\r\n";

/**
 * The HTML body may be preceded by other parts. Ensure it is still used as
 * the body.
 */
static int select_parts_6()
{
	fprintf(stderr, "== T6\n");
	MAIL m;
	assert(m.refonly_parse(data_6, std::size(data_6)));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	if (atl == nullptr || atl->count != 1)
		gi_print(0, *mc);
	assert(atl != nullptr && atl->count == 1);
	auto v = atl->pplist[0]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "application/pdf") == 0);
	v = mc->proplist.get<const char>(PR_BODY);
	assert(v != nullptr && strcmp(v, "ZplainZ") == 0);
	auto bin = mc->proplist.get<const BINARY>(PR_HTML);
	assert(bin != nullptr);
	assert(HX_memmem(bin->pv, bin->cb, "Zhtml1Z", 7) != nullptr);
	return 0;
}

/* Same as _6, but without any text/plain alternative to fall back to. */
static int select_parts_7()
{
	fprintf(stderr, "== T7\n");
	MAIL m;
	assert(m.refonly_parse(data_7, std::size(data_7)));

	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	auto mc = cvt.inet_to_mapi(m);
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	if (atl == nullptr || atl->count != 1)
		gi_print(0, *mc);
	assert(atl != nullptr && atl->count == 1);
	auto v = atl->pplist[0]->proplist.get<const char>(PR_ATTACH_MIME_TAG);
	assert(v != nullptr && strcasecmp(v, "application/pdf") == 0);
	auto bin = mc->proplist.get<const BINARY>(PR_HTML);
	assert(bin != nullptr);
	assert(HX_memmem(bin->pv, bin->cb, "Zhtml1Z", 7) != nullptr);
	return 0;
}

static int ical_meeting_attendees()
{
	static constexpr char data[] =
		"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\n"
		"UID:mtg\r\nDTSTAMP:20261005T100000Z\r\nSUMMARY:meeting\r\n"
		"ORGANIZER;CN=Org:mailto:org@example.org\r\n"
		"ATTENDEE;CN=Org;PARTSTAT=ACCEPTED;ROLE=CHAIR:mailto:org@example.org\r\n"
		"ATTENDEE;CN=Two;PARTSTAT=TENTATIVE;ROLE=REQ-PARTICIPANT:mailto:two@example.org\r\n"
		"ATTENDEE;CN=Three;PARTSTAT=NEEDS-ACTION;ROLE=OPT-PARTICIPANT:mailto:three@example.org\r\n"
		"DTSTART:20261030T090000Z\r\nDTEND:20261030T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
	static constexpr char plain[] =
		"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\n"
		"UID:plain\r\nDTSTAMP:20261005T100000Z\r\nSUMMARY:plain\r\n"
		"ATTENDEE:mailto:two@example.org\r\n"
		"DTSTART:20261030T090000Z\r\nDTEND:20261030T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
	fprintf(stderr, "=== ical_meeting_attendees\n");
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.org_name = "x500org";
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	cvt.username_to_entryid = [](const char *, const char *, BINARY *bin, enum display_type *dt) -> BOOL {
		bin->cb = 0;
		if (dt != nullptr)
			*dt = DT_MAILUSER;
		return TRUE;
	};
	std::string str = data;
	ical ic;
	assert(ic.load_from_str_move(str.data()));
	auto msg = cvt.ical_to_mapi_single(ic);
	assert(msg != nullptr);
	auto rcpts = msg->children.prcpts;
	/* organizer once, plus two attendees */
	if (rcpts == nullptr || rcpts->count != 3) {
		fprintf(stderr, "%u recipients\n", rcpts != nullptr ? rcpts->count : 0);
		return EXIT_FAILURE;
	}
	ical icalout;
	assert(cvt.mapi_to_ical(*msg, icalout));
	std::string icstr;
	assert(icalout.serialize(icstr) == ecSuccess);
	for (size_t pos; (pos = icstr.find("\r\n ")) != icstr.npos; )
		icstr.erase(pos, 3);
	if (icstr.find("ORGANIZER;CN=Org:MAILTO:org@example.org") == icstr.npos ||
	    icstr.find("PARTSTAT=TENTATIVE;RSVP=TRUE;CN=Two:MAILTO:two@example.org") == icstr.npos ||
	    icstr.find("ROLE=OPT-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=Three") == icstr.npos ||
	    icstr.find("MAILTO:org@example.org", icstr.find("ATTENDEE")) != icstr.npos) {
		fprintf(stderr, "%s", icstr.c_str());
		return EXIT_FAILURE;
	}

	/* no organizer: not a meeting, nothing changes */
	str = plain;
	ical ic2;
	assert(ic2.load_from_str_move(str.data()));
	msg = cvt.ical_to_mapi_single(ic2);
	assert(msg != nullptr);
	if (msg->children.prcpts != nullptr && msg->children.prcpts->count != 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

static int ical_export_1()
{
	/*
	 * DESK-2104: Old Zarafa imports (which lack some TZ fields) shifted by
	 * one day in some MUA, attributed to DTSTART not containing any TZID
	 * but just UTC.
	 */
	const ie_name_entry ie_map[] = {
		{0x809d, {MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole}},
		{0x809e, {MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole}},
		{0x80b8, {MNID_ID, PSETID_Appointment, PidLidTimeZoneStruct}},
		{0x80b9, {MNID_ID, PSETID_Appointment, PidLidTimeZoneDescription}},
	};
	auto get_propids = [&](const PROPNAME_ARRAY *a, PROPID_ARRAY *i) {
		return ie_get_propids(ie_map, std::size(ie_map), a, i);
	};
	static constexpr uint64_t v_time = 0x1dabd02f773da00;
	const BINARY bin_48{48, {deconst("\304\377\377\377\0\0\0\0\304\377\377\377\0\0\0\0\n\0\0\0\5\0\3\0\0\0\0\0\0\0\0\0\0\0\3\0\0\0\5\0\2\0\0\0\0\0\0\0")}};
	const TAGGED_PROPVAL props[] = {
		{PR_MESSAGE_CLASS, deconst("IPM.Appointment")},
		{PR_START_DATE, deconst(&v_time)},
		{PR_END_DATE, deconst(&v_time)},
		{0x809d0040, deconst(&v_time)},
		{0x809e0040, deconst(&v_time)},
		{0x80b80102, deconst(&bin_48)},
		{0x80b9001f, deconst("Europe/Vienna")},
	};
	const MESSAGE_CONTENT msgctnt = {{std::size(props), deconst(props)}};
	ical icalout;
	fprintf(stderr, "=== ical_export_1\n");
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.org_name = "x500org";
	cvt.alloc = malloc;
	cvt.get_propids = get_propids;
	if (!cvt.mapi_to_ical(msgctnt, icalout)) {
		fprintf(stderr, "oxcical_export failed\n");
		return EXIT_FAILURE;
	}
	std::string icstr;
	if (icalout.serialize(icstr) != ecSuccess) {
		fprintf(stderr, "ical_serialize failed\n");
		return EXIT_FAILURE;
	}
	constexpr char needle[] = "DTSTART;TZID=Europe/Vienna:20240612T215900";
	auto ptr = strstr(icstr.c_str(), needle);
	if (ptr == nullptr) {
		printf("%s\n", icstr.c_str());
		fprintf(stderr, "FAILED. Substrings Europe/215900 not found.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int ical_export_2()
{
	/* GXF-1819 */
	const ie_name_entry ie_map[] = {
		{0x809d, {MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole}},
		{0x809e, {MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole}},
		{0x80a5, {MNID_ID, PSETID_Appointment, PidLidAppointmentSubType}},
		{0x80d2, {MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionStartDisplay}},
		{0x80d3, {MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionEndDisplay}},
	};
	auto get_propids = [&](const PROPNAME_ARRAY *a, PROPID_ARRAY *i) {
		return ie_get_propids(ie_map, std::size(ie_map), a, i);
	};
	static constexpr uint64_t v_start = 0x1db0f96441fb000, v_end = 0x1db105f6e897000;
	static const BINARY v_122 = {122, {deconst("\x02\x01\x34\x00\x02\x00\x17\x00\x57\x00\x2e\x00\x20\x00\x45\x00\x75\x00\x72\x00\x6f\x00\x70\x00\x65\x00\x20\x00\x53\x00\x74\x00\x61\x00\x6e\x00\x64\x00\x61\x00\x72\x00\x64\x00\x20\x00\x54\x00\x69\x00\x6d\x00\x65\x00\x01\x00\x02\x01\x3e\x00\x02\x00\x41\x06\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc4\xff\xff\xff\x00\x00\x00\x00\xc4\xff\xff\xff\x00\x00\x0a\x00\x00\x00\x05\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00\x00\x00")}};
	const TAGGED_PROPVAL props[] = {
		{PR_MESSAGE_CLASS, deconst("IPM.Appointment")},
		{0x809d0040, deconst(&v_start)},
		{0x809e0040, deconst(&v_end)},
		{0x80a5000b, deconst(&byte_value_one)},
		{0x80d20102, deconst(&v_122)},
		{0x80d30102, deconst(&v_122)},
	};
	fprintf(stderr, "=== ical_export_2\n");
	const MESSAGE_CONTENT msgctnt = {{std::size(props), deconst(props)}};
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.org_name = "x500org";
	cvt.alloc = malloc;
	cvt.get_propids = get_propids;
	ical icalout;
	if (!cvt.mapi_to_ical(msgctnt, icalout)) {
		fprintf(stderr, "oxcical_export failed\n");
		return EXIT_FAILURE;
	}
	std::string icstr;
	if (icalout.serialize(icstr) != ecSuccess) {
		fprintf(stderr, "ical_serialize failed\n");
		return EXIT_FAILURE;
	}
	if (strstr(icstr.c_str(), "DTSTART;VALUE=DATE:20240926") == nullptr ||
	    strstr(icstr.c_str(), "DTEND;VALUE=DATE:20240927") == nullptr) {
		printf("%s\n", icstr.c_str());
		fprintf(stderr, "FAILED. Substrings DTSTART/20240926 and DTEND/20240927 not found.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static std::unique_ptr<message_content, mc_delete> ical_load(std::string &&str)
{
	ical ic;
	if (!ic.load_from_str_move(str.data()))
		return nullptr;
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	return cvt.ical_to_mapi_single(ic);
}

static bool ical_recur(const message_content &msg, APPOINTMENT_RECUR_PAT &apr)
{
	static const PROPERTY_NAME namelist[] = {
		{MNID_ID, PSETID_Appointment, PidLidAppointmentRecur},
	};
	PROPNAME_ARRAY na = {1, deconst(namelist)};
	PROPID_ARRAY pids;
	if (!ee_get_propids(&na, &pids))
		return false;
	auto bin = msg.proplist.get<const BINARY>(PROP_TAG(PT_BINARY, pids[0]));
	if (bin == nullptr)
		return false;
	EXT_PULL ep;
	ep.init(bin->pb, bin->cb, g_alloc, EXT_FLAG_UTF16);
	return ep.g_apptrecpat(&apr) == pack_result::ok;
}

static int ical_exception_roundtrip()
{
	static constexpr char data[] =
		"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n"
		"BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n"
		"BEGIN:DAYLIGHT\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\n"
		"DTSTART:19700329T020000\r\nRRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\nEND:DAYLIGHT\r\n"
		"BEGIN:STANDARD\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n"
		"DTSTART:19701025T030000\r\nRRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\n"
		"END:VTIMEZONE\r\n"
		"BEGIN:VEVENT\r\nUID:exc-rt\r\nDTSTAMP:20261005T100000Z\r\nSUMMARY:daily\r\n"
		"RRULE:FREQ=DAILY;COUNT=5\r\nEXDATE;TZID=Europe/Berlin:20261021T100000\r\n"
		"DTSTART;TZID=Europe/Berlin:20261020T100000\r\nDTEND;TZID=Europe/Berlin:20261020T110000\r\n"
		"END:VEVENT\r\n"
		"BEGIN:VEVENT\r\nUID:exc-rt\r\nDTSTAMP:20261005T100000Z\r\nSUMMARY:moved\r\n"
		"RECURRENCE-ID;TZID=Europe/Berlin:20261022T100000\r\n"
		"DTSTART;TZID=Europe/Berlin:20261022T140000\r\nDTEND;TZID=Europe/Berlin:20261022T150000\r\n"
		"END:VEVENT\r\nEND:VCALENDAR\r\n";
	fprintf(stderr, "=== ical_exception_roundtrip\n");
	auto msg1 = ical_load(data);
	assert(msg1 != nullptr);
	APPOINTMENT_RECUR_PAT apr1{};
	assert(ical_recur(*msg1, apr1));
	assert(apr1.pexceptioninfo.size() == 1);

	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.org_name = "x500org";
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	ical icalout;
	assert(cvt.mapi_to_ical(*msg1, icalout));
	std::string icstr;
	assert(icalout.serialize(icstr) == ecSuccess);
	/* only the real deletion, given in local time; the moved one is a VEVENT */
	if (icstr.find("EXDATE;TZID=Europe/Berlin:20261021T100000\r\n") == std::string::npos ||
	    icstr.find("EXDATE;TZID=Europe/Berlin:\r\n") != std::string::npos ||
	    icstr.find("RDATE") != std::string::npos) {
		fprintf(stderr, "%s", icstr.c_str());
		return EXIT_FAILURE;
	}

	/* the export writes the exception in UTC; the local time must survive */
	auto msg2 = ical_load(std::move(icstr));
	assert(msg2 != nullptr);
	APPOINTMENT_RECUR_PAT apr2{};
	assert(ical_recur(*msg2, apr2));
	assert(apr2.pexceptioninfo.size() == 1);
	if (apr2.pexceptioninfo[0].startdatetime != apr1.pexceptioninfo[0].startdatetime ||
	    apr2.pexceptioninfo[0].enddatetime != apr1.pexceptioninfo[0].enddatetime) {
		fprintf(stderr, "exception moved from %u to %u\n",
		        apr1.pexceptioninfo[0].startdatetime, apr2.pexceptioninfo[0].startdatetime);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/*
 * A meeting response identifies the responder through
 * PR_SENT_REPRESENTING_SMTP_ADDRESS (the iCalendar ATTENDEE) and through
 * PR_SENDER_* (the From: header, which a scheduling mail takes from the sender
 * tags). RFC 5546 §3.2.3 requires the ATTENDEE: it is the whole content of a
 * REPLY. Anything that generates a response -- lib/ruleproc.cpp does -- has to
 * put both on the message, so pin what the export needs.
 */
static int ical_reply_identity()
{
	static const PROPERTY_NAME namelist[] = {
		{MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole},
	};
	PROPNAME_ARRAY na = {static_cast<uint16_t>(std::size(namelist)), deconst(namelist)};
	PROPID_ARRAY pids;
	assert(ee_get_propids(&na, &pids));
	static constexpr uint64_t v_time = 0x1dabd02f773da00;
	static constexpr uint32_t v_rcpttype = MAPI_TO;
	fprintf(stderr, "=== ical_reply_identity\n");

	TAGGED_PROPVAL rcpt_props[] = {
		{PR_ADDRTYPE, deconst("SMTP")},
		{PR_EMAIL_ADDRESS, deconst("sender@example.org")},
		{PR_SMTP_ADDRESS, deconst("sender@example.org")},
		{PR_RECIPIENT_TYPE, deconst(&v_rcpttype)},
	};
	TPROPVAL_ARRAY rcpt_row = {static_cast<uint16_t>(std::size(rcpt_props)), rcpt_props};
	TPROPVAL_ARRAY *rows[] = {&rcpt_row};
	TARRAY_SET rcpts = {1, rows};
	const TAGGED_PROPVAL props[] = {
		{PR_MESSAGE_CLASS, deconst("IPM.Schedule.Meeting.Resp.Pos")},
		{PR_SUBJECT_PREFIX, deconst("Accepted: ")},
		{PR_NORMALIZED_SUBJECT, deconst("appointment")},
		{PR_START_DATE, deconst(&v_time)},
		{PR_END_DATE, deconst(&v_time)},
		{PROP_TAG(PT_SYSTIME, pids[0]), deconst(&v_time)},
		{PROP_TAG(PT_SYSTIME, pids[1]), deconst(&v_time)},
		{PR_SENT_REPRESENTING_ADDRTYPE, deconst("SMTP")},
		{PR_SENT_REPRESENTING_EMAIL_ADDRESS, deconst("u@d.at")},
		{PR_SENT_REPRESENTING_SMTP_ADDRESS, deconst("u@d.at")},
		{PR_SENDER_ADDRTYPE, deconst("SMTP")},
		{PR_SENDER_EMAIL_ADDRESS, deconst("u@d.at")},
		{PR_SENDER_SMTP_ADDRESS, deconst("u@d.at")},
	};
	MESSAGE_CONTENT msgctnt{};
	msgctnt.proplist = {static_cast<uint16_t>(std::size(props)), deconst(props)};
	msgctnt.children.prcpts = &rcpts;

	ical icalout;
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.org_name = "x500org";
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	assert(cvt.mapi_to_ical(msgctnt, icalout));
	std::string icstr;
	assert(icalout.serialize(icstr) == ecSuccess);
	assert(icstr.find("METHOD:REPLY") != std::string::npos);
	assert(icstr.find("ATTENDEE;PARTSTAT=ACCEPTED:MAILTO:u@d.at") != std::string::npos);

	oxcmail_converter mcvt;
	mcvt.alloc = g_alloc;
	mcvt.get_propids = ee_get_propids;
	mcvt.get_propname = [](uint16_t id, PROPERTY_NAME **out) -> BOOL {
		auto entry = static_namedprop_map.fwd.find(PROP_TAG(PT_UNSPECIFIED, id));
		if (entry == static_namedprop_map.fwd.end())
			return false;
		*out = static_cast<PROPERTY_NAME *>(g_alloc(sizeof(PROPERTY_NAME)));
		if (*out == nullptr)
			return false;
		**out = static_cast<PROPERTY_NAME>(entry->second);
		return true;
	};
	auto out = vmime::make_shared<vmime::message>();
	assert(mcvt.mapi_to_inet(msgctnt, out) == ecSuccess);
	auto head = out->getHeader();
	assert(head != nullptr);
	auto from = head->findField(vmime::fields::FROM);
	assert(from != nullptr && from->getValue()->generate().find("u@d.at") != std::string::npos);
	return EXIT_SUCCESS;
}

static int ical_export_exception()
{
	/* GXL-796 */
	const ie_name_entry ie_map[] = {
		{0x809d, {MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole}},
		{0x809e, {MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole}},
		{0x8228, {MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime}},
	};
	auto get_propids = [&](const PROPNAME_ARRAY *a, PROPID_ARRAY *i) {
		return ie_get_propids(ie_map, std::size(ie_map), a, i);
	};
	static constexpr uint64_t v_start = 0x1db0f96441fb000,
		v_end = v_start + 18000000000, v_xrt = v_start - 36000000000;
	const TAGGED_PROPVAL props[] = {
		{PR_MESSAGE_CLASS, deconst("IPM.Appointment")},
		{0x809d0040, deconst(&v_start)},
		{0x809e0040, deconst(&v_end)},
		{0x82280040, deconst(&v_xrt)},
	};
	fprintf(stderr, "=== ical_export_exception\n");
	const MESSAGE_CONTENT msgctnt = {{std::size(props), deconst(props)}};
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.org_name = "x500org";
	cvt.alloc = malloc;
	cvt.get_propids = get_propids;
	ical icalout;
	assert(cvt.mapi_to_ical(msgctnt, icalout));
	std::string icstr;
	assert(icalout.serialize(icstr) == ecSuccess);
	assert(icstr.find("RECURRENCE-ID:") != std::string::npos);
	assert(icstr.find("X-MICROSOFT-CDO-INSTTYPE:3") != std::string::npos);
	return EXIT_SUCCESS;
}

static int ical_export_allday_exception()
{
	/*
	 * An all-day occurrence of 2026-11-19 in UTC+1 without timezone
	 * information: the original start is the local midnight, 2026-11-18
	 * 23:00 UTC, and the occurrence was moved to 2026-11-20.
	 */
	const ie_name_entry ie_map[] = {
		{0x809d, {MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole}},
		{0x809e, {MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole}},
		{0x8228, {MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime}},
		{0x8215, {MNID_ID, PSETID_Appointment, PidLidAppointmentSubType}},
	};
	auto get_propids = [&](const PROPNAME_ARRAY *a, PROPID_ARRAY *i) {
		return ie_get_propids(ie_map, std::size(ie_map), a, i);
	};
	static constexpr uint64_t v_xrt = 0x1dd77b089c01800,
		v_start = 0x1dd7879b429d800, v_end = 0x1dd7942de939800;
	static constexpr uint8_t v_allday = 1;
	const TAGGED_PROPVAL props[] = {
		{PR_MESSAGE_CLASS, deconst("IPM.Appointment")},
		{0x809d0040, deconst(&v_start)},
		{0x809e0040, deconst(&v_end)},
		{0x82280040, deconst(&v_xrt)},
		{0x8215000b, deconst(&v_allday)},
	};
	fprintf(stderr, "=== ical_export_allday_exception\n");
	const MESSAGE_CONTENT msgctnt = {{std::size(props), deconst(props)}};
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.org_name = "x500org";
	cvt.alloc = malloc;
	cvt.get_propids = get_propids;
	ical icalout;
	assert(cvt.mapi_to_ical(msgctnt, icalout));
	std::string icstr;
	assert(icalout.serialize(icstr) == ecSuccess);
	if (icstr.find("DTSTART;VALUE=DATE:20261120") == std::string::npos ||
	    icstr.find("RECURRENCE-ID;VALUE=DATE:20261119") == std::string::npos) {
		fprintf(stderr, "%s\n", icstr.c_str());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static std::unique_ptr<message_content, mc_delete> ical_import_str(const char *body)
{
	std::string str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n"
		"BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n"
		"BEGIN:DAYLIGHT\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\n"
		"DTSTART:19700329T020000\r\nRRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\nEND:DAYLIGHT\r\n"
		"BEGIN:STANDARD\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n"
		"DTSTART:19701025T030000\r\nRRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\n"
		"END:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:allday-hint\r\nDTSTAMP:20261005T100000Z\r\n";
	str += body;
	str += "END:VEVENT\r\nEND:VCALENDAR\r\n";
	ical ic;
	if (!ic.load_from_str_move(str.data()))
		return nullptr;
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	return cvt.ical_to_mapi_single(ic);
}

static int ical_allday_hint()
{
	static const PROPERTY_NAME namelist[] = {
		{MNID_ID, PSETID_Appointment, PidLidAppointmentSubType},
	};
	PROPNAME_ARRAY na = {static_cast<uint16_t>(std::size(namelist)), deconst(namelist)};
	PROPID_ARRAY pids;
	assert(ee_get_propids(&na, &pids));
	const auto subtype = PROP_TAG(PT_BOOLEAN, pids[0]);
	static constexpr struct {
		const char *body;
		bool allday;
	} cases[] = {
		/* allday event made timed by Thunderbird, hint left behind */
		{"DTSTART;TZID=Europe/Berlin:20261019T160000\r\nDTEND;TZID=Europe/Berlin:20261019T170000\r\n"
		 "X-MICROSOFT-CDO-ALLDAYEVENT:TRUE\r\n", false},
		{"DTSTART;VALUE=DATE:20261019\r\nDTEND;VALUE=DATE:20261020\r\n"
		 "X-MICROSOFT-CDO-ALLDAYEVENT:TRUE\r\n", true},
		{"DTSTART;TZID=Europe/Berlin:20261019T000000\r\nDTEND;TZID=Europe/Berlin:20261020T000000\r\n"
		 "X-MICROSOFT-CDO-ALLDAYEVENT:TRUE\r\n", true},
		{"DTSTART;TZID=Europe/Berlin:20261019T000000\r\nDTEND;TZID=Europe/Berlin:20261020T000000\r\n", true},
		/* older Exchange exports allday events in UTC */
		{"DTSTART:20261018T220000Z\r\nDTEND:20261019T220000Z\r\n"
		 "X-MICROSOFT-CDO-ALLDAYEVENT:TRUE\r\n", true},
		{"DTSTART;TZID=Europe/Berlin:20261019T160000\r\nDTEND;TZID=Europe/Berlin:20261019T170000\r\n", false},
	};
	fprintf(stderr, "=== ical_allday_hint\n");
	for (const auto &c : cases) {
		auto msg = ical_import_str(c.body);
		assert(msg != nullptr);
		auto v = msg->proplist.get<const uint8_t>(subtype);
		bool allday = v != nullptr && *v != 0;
		if (allday != c.allday) {
			fprintf(stderr, "allday=%d expected %d for:\n%s", allday, c.allday, c.body);
			return EXIT_FAILURE;
		}
	}

	/* a sub-day allday appointment must still export a non-empty DATE range */
	auto msg = ical_import_str("DTSTART;TZID=Europe/Berlin:20261019T160000\r\n"
	           "DTEND;TZID=Europe/Berlin:20261019T170000\r\n");
	assert(msg != nullptr);
	static constexpr uint8_t v_true = 1;
	assert(msg->proplist.set(subtype, &v_true) == ecSuccess);
	oxcical_converter cvt;
	cvt.log_id = "-";
	cvt.org_name = "x500org";
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	ical icalout;
	assert(cvt.mapi_to_ical(*msg, icalout));
	std::string icstr;
	assert(icalout.serialize(icstr) == ecSuccess);
	if (icstr.find("DTSTART;VALUE=DATE:20261020") == std::string::npos ||
	    icstr.find("DTEND;VALUE=DATE:20261021") == std::string::npos) {
		fprintf(stderr, "%s", icstr.c_str());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int hdrparse_1()
{
	static const char data[] =
		"\r\n"
		"Bodytext\r\n";
	MAIL m;
	assert(m.refonly_parse(data, strlen(data)));
	auto part = m.get_head();
	assert(part->head_begin != nullptr);
	return EXIT_SUCCESS;
}

static std::unique_ptr<message_content, mc_delete> vcf_import(const char *body)
{
	std::string str = "BEGIN:VCARD\r\n";
	str += body;
	str += "END:VCARD\r\n";
	vcard vc;
	if (vc.load_single_from_str_move(str.data()) != ecSuccess)
		return nullptr;
	oxvcard_converter cvt;
	cvt.log_id = "-";
	cvt.get_propids = ee_get_propids;
	return cvt.vcard_to_mapi(vc);
}

static std::string vcf_export(const message_content &msg)
{
	oxvcard_converter cvt;
	cvt.log_id = "-";
	cvt.get_propids = ee_get_propids;
	vcard vc;
	std::string out;
	if (!cvt.mapi_to_vcard(msg, vc) || !vc.serialize(out))
		return {};
	return out;
}

static proptag_t vcf_namedtag(uint16_t type, const PROPERTY_NAME &pn)
{
	PROPNAME_ARRAY na = {1, deconst(&pn)};
	PROPID_ARRAY pids;
	assert(ee_get_propids(&na, &pids));
	return PROP_TAG(type, pids[0]);
}

static bool vcf_has(const message_content &m, proptag_t tag, const char *want)
{
	auto v = m.proplist.get<const char>(tag);
	if (v != nullptr && strcmp(v, want) == 0)
		return true;
	fprintf(stderr, "%08x: \"%s\", expected \"%s\"\n", tag, znul(v), want);
	return false;
}

static int vcard_tel_types()
{
	fprintf(stderr, "=== vcard_tel_types\n");
	/* Thunderbird */
	auto m = vcf_import("VERSION:4.0\r\nFN:T\r\n"
	         "TEL;TYPE=work;VALUE=TEXT:1\r\nTEL;TYPE=home;VALUE=TEXT:2\r\n"
	         "TEL;TYPE=cell;VALUE=TEXT:3\r\nTEL;TYPE=fax;VALUE=TEXT:4\r\n"
	         "TEL;VALUE=TEXT:5\r\n");
	assert(m != nullptr);
	if (!vcf_has(*m, PR_BUSINESS_TELEPHONE_NUMBER, "1") ||
	    !vcf_has(*m, PR_HOME_TELEPHONE_NUMBER, "2") ||
	    !vcf_has(*m, PR_MOBILE_TELEPHONE_NUMBER, "3") ||
	    !vcf_has(*m, PR_PRIMARY_FAX_NUMBER, "4") ||
	    !vcf_has(*m, PR_OTHER_TELEPHONE_NUMBER, "5"))
		return EXIT_FAILURE;
	/* Apple, DAVx5, Evolution */
	m = vcf_import("VERSION:3.0\r\nFN:A\r\n"
	    "TEL;type=CELL;type=VOICE;type=pref:1\r\nTEL;type=WORK;type=VOICE:2\r\n"
	    "TEL;TYPE=\"home,voice\":3\r\nTEL;TYPE=WORK,FAX:4\r\nTEL;TYPE=HOME;FAX:5\r\n"
	    "item1.ADR;type=WORK;type=pref:;;Street 1;City;;1010;AT\r\nitem1.X-ABADR:at\r\n");
	assert(m != nullptr);
	if (!vcf_has(*m, PR_MOBILE_TELEPHONE_NUMBER, "1") ||
	    !vcf_has(*m, PR_BUSINESS_TELEPHONE_NUMBER, "2") ||
	    !vcf_has(*m, PR_HOME_TELEPHONE_NUMBER, "3") ||
	    !vcf_has(*m, PR_BUSINESS_FAX_NUMBER, "4") ||
	    !vcf_has(*m, PR_HOME_FAX_NUMBER, "5") ||
	    !vcf_has(*m, vcf_namedtag(PT_UNICODE, {MNID_ID, PSETID_Address, PidLidWorkAddressCity}), "City"))
		return EXIT_FAILURE;
	auto out = vcf_export(*m);
	if (out.find("TEL;TYPE=WORK;FAX:4") == out.npos ||
	    out.find("ADR;TYPE=WORK:;;Street 1;City;;1010;AT") == out.npos) {
		fprintf(stderr, "%s", out.c_str());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int vcard_escaped_values()
{
	fprintf(stderr, "=== vcard_escaped_values\n");
	auto m = vcf_import("VERSION:3.0\r\nFN:E\r\nN:Doe\\, Jr.;John;;;\r\n"
	         "ORG:Smith\\; Partners;Sales\r\n");
	assert(m != nullptr);
	if (!vcf_has(*m, PR_SURNAME, "Doe, Jr.") ||
	    !vcf_has(*m, PR_GIVEN_NAME, "John") ||
	    !vcf_has(*m, PR_COMPANY_NAME, "Smith; Partners") ||
	    !vcf_has(*m, PR_DEPARTMENT_NAME, "Sales"))
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

static int vcard_photo()
{
	fprintf(stderr, "=== vcard_photo\n");
	static constexpr char png[] = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
	auto hasphoto = vcf_namedtag(PT_BOOLEAN, {MNID_ID, PSETID_Address, PidLidHasPicture});
	for (auto fmt : {"VERSION:4.0\r\nFN:P\r\nPHOTO:data:image/png;base64,%s\r\n",
	     "VERSION:4.0\r\nFN:P\r\nPHOTO;VALUE=URI:data:image/png;base64,%s\r\n",
	     "VERSION:3.0\r\nFN:P\r\nPHOTO;ENCODING=b;TYPE=PNG:%s\r\n"}) {
		char buf[512];
		snprintf(buf, sizeof(buf), fmt, png);
		auto m = vcf_import(buf);
		assert(m != nullptr);
		auto flag = m->proplist.get<const uint8_t>(hasphoto);
		auto atl = m->children.pattachments;
		if (flag == nullptr || *flag == 0 || atl == nullptr || atl->count != 1) {
			fprintf(stderr, "no photo from %s", buf);
			return EXIT_FAILURE;
		}
		auto at = atl->pplist[0];
		auto cp = at->proplist.get<const uint8_t>(PR_ATTACHMENT_CONTACTPHOTO);
		auto meth = at->proplist.get<const uint32_t>(PR_ATTACH_METHOD);
		if (cp == nullptr || *cp == 0 || meth == nullptr || *meth != ATTACH_BY_VALUE)
			return EXIT_FAILURE;
		auto out = vcf_export(*m);
		if (out.find("PHOTO:data:image/png;base64,iVBORw0KGgo") == out.npos) {
			fprintf(stderr, "%s", out.c_str());
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

static int vcard_dates()
{
	fprintf(stderr, "=== vcard_dates\n");
	auto m = vcf_import("VERSION:4.0\r\nFN:D\r\nBDAY;VALUE=DATE:19800102\r\nANNIVERSARY:2005-06-07\r\n");
	assert(m != nullptr);
	auto b = m->proplist.get<const uint64_t>(PR_BIRTHDAY);
	auto w = m->proplist.get<const uint64_t>(PR_WEDDING_ANNIVERSARY);
	if (b == nullptr || rop_util_nttime_to_unix(*b) != 315619200 ||
	    w == nullptr || rop_util_nttime_to_unix(*w) != 1118102400)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

static int vcard_fileas_categories()
{
	fprintf(stderr, "=== vcard_fileas_categories\n");
	auto fileas = vcf_namedtag(PT_UNICODE, {MNID_ID, PSETID_Address, PidLidFileAs});
	auto fileasid = vcf_namedtag(PT_LONG, {MNID_ID, PSETID_Address, PidLidFileUnderId});
	auto keywords = vcf_namedtag(PT_MV_UNICODE, {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst("Keywords")});
	auto m = vcf_import("VERSION:3.0\r\nFN:Eve Olution\r\nN:Olution;Eve;;;\r\n"
	         "X-EVOLUTION-FILE-AS:Olution\\, Eve (Gnome)\r\nCATEGORIES:Friends,Work\r\n");
	assert(m != nullptr);
	if (!vcf_has(*m, fileas, "Olution, Eve (Gnome)"))
		return EXIT_FAILURE;
	auto cats = m->proplist.get<const STRING_ARRAY>(keywords);
	if (cats == nullptr || cats->count != 2 || strcmp(cats->ppstr[1], "Work") != 0)
		return EXIT_FAILURE;
	auto out = vcf_export(*m);
	if (out.find("X-EVOLUTION-FILE-AS:Olution\\, Eve (Gnome)\r\n") == out.npos ||
	    out.find("CATEGORIES:Friends,Work\r\n") == out.npos) {
		fprintf(stderr, "%s", out.c_str());
		return EXIT_FAILURE;
	}
	/* no file-as given: Outlook's default */
	m = vcf_import("VERSION:4.0\r\nFN:John Doe\r\nN:Doe;John;;;\r\n");
	assert(m != nullptr);
	auto id = m->proplist.get<const uint32_t>(fileasid);
	if (!vcf_has(*m, fileas, "Doe, John") || id == nullptr || *id != 0x8017)
		return EXIT_FAILURE;
	m = vcf_import("VERSION:4.0\r\nFN:ACME\r\nORG:ACME;\r\n");
	assert(m != nullptr);
	if (!vcf_has(*m, fileas, "ACME"))
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

static int vexport_head()
{
	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;

	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;

	/* Blank message */
	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	if (err != ecSuccess)
		return EXIT_FAILURE;
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Date: ") != nullptr);
	assert(strstr(ostr.c_str(), "MIME-Version: 1.0") != nullptr);
	assert(strstr(ostr.c_str(), "X-Mailer: gromox") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: ") == nullptr);

	/* Now with some props */
#define XFE "\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe"
#define XFE4 XFE XFE XFE XFE
	BINARY conv_index = {uint32_t(strlen(XFE4)), {deconst(XFE4)}};
#undef XFE4
#undef XFE
	static const unsigned int loc_x409 = 0x409;
	props.set(PR_CONVERSATION_INDEX, &conv_index);
	props.set(PR_READ_RECEIPT_REQUESTED, &byte_value_one);
	props.set(PidTagReadReceiptName, "Foo Bar");
	props.set(PidTagReadReceiptAddressType, "SMTP");
	props.set(PidTagReadReceiptEmailAddress, "foobar@localhost");
	props.set(PR_SUBJECT_PREFIX, "Re: ");
	props.set(PR_NORMALIZED_SUBJECT, "Le subjäkt");
	props.set(PR_IMPORTANCE, &uint_value_zero);
	props.set(PR_MESSAGE_LOCALE_ID, &loc_x409);
	err = cvt.mapi_to_inet(*mct, vmsg);
	if (err != ecSuccess)
		return EXIT_FAILURE;
	ostr = vmsg->generate();

	/* Important checks, like... */
	/* ...that PR_SUBJECT with Unicode is encoded right */
	assert(strstr(ostr.c_str(), "Subject: Re: Le =?utf-8?Q?") != nullptr);
	/* ...that overly long header lines wrap (requires =? ?=) */
	assert(strstr(ostr.c_str(), "Thread-Index: =?us-ascii?Q?") != nullptr);
	/* ...that Sender/From/Dispo is composed ok */
	assert(strstr(ostr.c_str(), "Disposition-Notification-To: \"Foo Bar\" <foobar@localhost>") != nullptr);

	return EXIT_SUCCESS;
}

static int vexport_simple_body()
{
	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;

	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;

	/* Just plaintext mail */
	auto vmsg = vmime::make_shared<vmime::message>();
#define HSTR "Ä very long long long long long long long long long long long long long long long long line"
	props.set(PR_BODY, HSTR);
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	if (err != ecSuccess)
		return EXIT_FAILURE;
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: text/plain") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: multipart/") == nullptr);

	/* Message with two body types */
#define HSTR2 "<p>" HSTR "</p>"
	const BINARY bin_html = {static_cast<uint32_t>(strlen(HSTR2)), {deconst(HSTR2)}};
	props.set(PR_HTML, &bin_html);
	err = cvt.mapi_to_inet(*mct, vmsg);
	if (err != ecSuccess)
		return EXIT_FAILURE;
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/alt") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: text/plain") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: text/html") != nullptr);
	printf("%s\n", ostr.c_str());

	return EXIT_SUCCESS;
#undef HSTR2
#undef HSTR
}

static attachment_content *ve_new_attachment(MESSAGE_CONTENT *mct)
{
	if (mct->children.pattachments == nullptr) {
		mct->children.pattachments = attachment_list_init();
		if (mct->children.pattachments == nullptr)
			return nullptr;
	}
	auto atx = attachment_content_init();
	if (atx == nullptr)
		return nullptr;
	if (!mct->children.pattachments->append_internal(atx)) {
		attachment_content_free(atx);
		return nullptr;
	}
	return atx;
}

static TPROPVAL_ARRAY *ve_new_rcpt(MESSAGE_CONTENT *mct, uint32_t type,
    const char *name, const char *smtp)
{
	if (mct->children.prcpts == nullptr)
		mct->set_rcpts_internal(tarray_set_init());
	auto row = mct->children.prcpts->emplace();
	if (row == nullptr)
		return nullptr;
	row->set(PR_RECIPIENT_TYPE, &type);
	if (name != nullptr)
		row->set(PR_DISPLAY_NAME, name);
	if (smtp != nullptr) {
		row->set(PR_ADDRTYPE, "SMTP");
		row->set(PR_SMTP_ADDRESS, smtp);
	}
	return row;
}

static BOOL ve_get_propname(propid_t propid, PROPERTY_NAME **name)
{
	auto xn = ee_get_propname(propid);
	if (xn == nullptr)
		return false;
	/* deque for address stability; TNEF keeps the pointers around */
	static std::deque<PROPERTY_NAME> keep;
	keep.emplace_back(static_cast<PROPERTY_NAME>(*xn));
	*name = &keep.back();
	return TRUE;
}

/* Undo quoted-printable soft line breaks so substring checks are stable */
static std::string ve_qp_unwrap(std::string s)
{
	size_t pos;
	while ((pos = s.find("=\r\n")) != std::string::npos)
		s.erase(pos, 3);
	return s;
}

static oxcmail_converter ve_converter()
{
	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	cvt.get_propname = ve_get_propname;
	return cvt;
}

static int vexport_image()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto atx = ve_new_attachment(mct.get());
	const BINARY almost_empty = {1, {deconst(" ")}};
	uint32_t method = ATTACH_BY_VALUE;
	atx->proplist.set(PR_ATTACH_METHOD, &method);
	atx->proplist.set(PR_ATTACH_DATA_BIN, &almost_empty);

	/* Attachment-only message: still a multipart/mixed container */
	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/mixed") != nullptr);
	assert(strstr(ostr.c_str(), "X-MS-Has-Attach: yes") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Disposition: attachment") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Transfer-Encoding: base64") != nullptr);
	assert(strstr(ostr.c_str(), "\r\nIA==") != nullptr);
	/* No charset parameter on binary content */
	assert(strstr(ostr.c_str(), "Content-Type: application/octet-stream\r\n") != nullptr);
	/* The body-less first part is a proper empty text/plain */
	assert(strstr(ostr.c_str(), "Content-Type: text/plain") != nullptr);

	/* Same with bodies present */
	auto &props = mct->proplist;
	props.set(PR_BODY, "bodyline");
	const BINARY bin_html = {12, {deconst("<p>etext</p>")}};
	props.set(PR_HTML, &bin_html);
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/mixed") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: multipart/alternative") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: application/octet-stream") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_inline_image()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;
	props.set(PR_BODY, "see image");
	const BINARY bin_html = {26, {deconst("<img src=\"cid:img1@ex\">   ")}};
	props.set(PR_HTML, &bin_html);

	auto atx = ve_new_attachment(mct.get());
	const BINARY pngish = {4, {deconst("\x89PNG")}};
	uint32_t method = ATTACH_BY_VALUE, flags = ATT_MHTML_REF;
	atx->proplist.set(PR_ATTACH_METHOD, &method);
	atx->proplist.set(PR_ATTACH_DATA_BIN, &pngish);
	atx->proplist.set(PR_ATTACH_FLAGS, &flags);
	atx->proplist.set(PR_ATTACH_CONTENT_ID, "img1@ex");
	atx->proplist.set(PR_ATTACH_MIME_TAG, "image/png");

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/related") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: image/png") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Id: <img1@ex>") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Disposition: inline") != nullptr);
	/* No plain attachments, so no multipart/mixed level */
	assert(strstr(ostr.c_str(), "Content-Type: multipart/mixed") == nullptr);

	/* Adding a regular attachment brings in the mixed container, too */
	auto atx2 = ve_new_attachment(mct.get());
	const BINARY blob = {3, {deconst("abc")}};
	atx2->proplist.set(PR_ATTACH_METHOD, &method);
	atx2->proplist.set(PR_ATTACH_DATA_BIN, &blob);
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/mixed") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: multipart/related") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Disposition: attachment") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_recipients()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;
	props.set(PR_BODY, "x");
	assert(ve_new_rcpt(mct.get(), MAPI_TO, "Tö Wan", "to@ex.de") != nullptr);
	assert(ve_new_rcpt(mct.get(), MAPI_TO, nullptr, "to2@ex.de") != nullptr);
	assert(ve_new_rcpt(mct.get(), MAPI_CC, "Ccpt", "cc@ex.de") != nullptr);
	assert(ve_new_rcpt(mct.get(), MAPI_BCC, "Bcpt", "bcc@ex.de") != nullptr);
	props.set(PR_SENDER_NAME, "Sunder");
	props.set(PR_SENDER_SMTP_ADDRESS, "sender@ex.de");
	props.set(PR_SENT_REPRESENTING_NAME, "Riprezenting");
	props.set(PR_SENT_REPRESENTING_SMTP_ADDRESS, "boss@ex.de");

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "To: =?utf-8?B?VMO2?=") != nullptr);
	assert(strstr(ostr.c_str(), "<to@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "to2@ex.de") != nullptr);
	assert(strstr(ostr.c_str(), "Cc: \"Ccpt\" <cc@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "Bcc: \"Bcpt\" <bcc@ex.de>") != nullptr);
	/* Sender and From differ -> both emitted */
	assert(strstr(ostr.c_str(), "From: \"Riprezenting\" <boss@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "Sender: \"Sunder\" <sender@ex.de>") != nullptr);

	/* Sender == From -> Sender suppressed */
	props.set(PR_SENT_REPRESENTING_SMTP_ADDRESS, "sender@ex.de");
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Sender: ") == nullptr);
	return EXIT_SUCCESS;
}

static int vexport_headers()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;
	static const uint32_t imp_high = 2, sens_conf = 3, scl = 4;
	props.set(PR_IMPORTANCE, &imp_high);
	props.set(PR_SENSITIVITY, &sens_conf);
	props.set(PR_CONTENT_FILTER_SCL, &scl);
	props.set(PR_AUTO_FORWARDED, &byte_value_one);
	props.set(PR_INTERNET_MESSAGE_ID, "<self@ex.de>");
	props.set(PR_IN_REPLY_TO_ID, "<parent@ex.de>");
	props.set(PR_INTERNET_REFERENCES, "<grandparent@ex.de> <parent@ex.de>");
	props.set(PR_CONVERSATION_TOPIC, "talk");
	props.set(PR_LIST_HELP, "<mailto:help@ex.de>");
	props.set(PR_LIST_SUBSCRIBE, "<mailto:sub@ex.de>");
	props.set(PR_LIST_UNSUBSCRIBE, "<mailto:unsub@ex.de>");
	props.set(PR_BODY_CONTENT_ID, "body@ex.de");
	props.set(PR_BODY_CONTENT_LOCATION, "http://ex.de/b");
	static const uint32_t ars_all = UINT32_MAX;
	props.set(PR_AUTO_RESPONSE_SUPPRESS, &ars_all);

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Importance: High") != nullptr);
	assert(strstr(ostr.c_str(), "Sensitivity: Company-Confidential") != nullptr);
	assert(strstr(ostr.c_str(), "X-MS-Exchange-Organization-SCL: 4") != nullptr);
	assert(strstr(ostr.c_str(), "X-MS-Exchange-Organization-AutoForwarded: true") != nullptr);
	assert(strstr(ostr.c_str(), "Message-Id: <self@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "In-Reply-To: <parent@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "References: <grandparent@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "Thread-Topic: talk") != nullptr);
	assert(strstr(ostr.c_str(), "List-Help: <mailto:help@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "List-Subscribe: <mailto:sub@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "List-Unsubscribe: <mailto:unsub@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Id: <body@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Location: http://ex.de/b") != nullptr);
	assert(strstr(ostr.c_str(), "X-Auto-Response-Suppress: ALL") != nullptr);

	static const uint32_t ars_some = 0x2 | 0x10; /* NDR, OOF */
	props.set(PR_AUTO_RESPONSE_SUPPRESS, &ars_some);
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "X-Auto-Response-Suppress: NDR,OOF") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_internet_headers()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;
	props.set(PR_BODY, "x");
	/*
	 * Transport headers stored as PS_INTERNET_HEADERS named props must be
	 * re-emitted even for header names vmime has a typed value class for
	 * (setValue(text) would throw bad_field_value_type at runtime).
	 */
	const PROPERTY_NAME pn[] = {
		{MNID_STRING, PS_INTERNET_HEADERS, 0, deconst("X-Funky")},
		{MNID_STRING, PS_INTERNET_HEADERS, 0, deconst("Return-Path")},
		{MNID_STRING, PS_INTERNET_HEADERS, 0, deconst("Received")},
	};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	PROPID_ARRAY ids;
	assert(ee_get_propids(&pna, &ids));
	props.set(PROP_TAG(PT_UNICODE, ids[0]), "hello");
	props.set(PROP_TAG(PT_UNICODE, ids[1]), "<bounce@ex.de>");
	props.set(PROP_TAG(PT_UNICODE, ids[2]), "from a.ex.de by b.ex.de; Mon, 1 Jul 2026 00:00:00 +0000");

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "X-Funky: hello") != nullptr);
	assert(strstr(ostr.c_str(), "Return-Path: <bounce@ex.de>") != nullptr);
	assert(strstr(ostr.c_str(), "Received: from a.ex.de") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_report(const char *msgclass, const char *rpttype,
    const char *stpart, const char *needle)
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;
	props.set(PR_MESSAGE_CLASS, msgclass);
	props.set(PR_BODY, "report body");
	props.set(PR_SENDER_SMTP_ADDRESS, "orig@ex.de");
	/* keep the test independent of the build host's name resolution */
	props.set(PidTagReportingMessageTransferAgent, "dns;mta.ex.de");
	auto rcpt = ve_new_rcpt(mct.get(), MAPI_TO, "Rcpt", "rcpt@ex.de");
	assert(rcpt != nullptr);

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/report") != nullptr);
	assert(strstr(ostr.c_str(), rpttype) != nullptr);
	assert(strstr(ostr.c_str(), stpart) != nullptr);
	assert(strstr(ostr.c_str(), needle) != nullptr);
	/* The status part is a sibling of the body part, under the root */
	auto body = vmsg->getBody();
	assert(body->getPartCount() == 2);
	assert(body->getPartAt(1)->getBody()->getContentType().generate().find(stpart + 14) != std::string::npos);
	return EXIT_SUCCESS;
}

static int vexport_dsn()
{
	return vexport_report("REPORT.IPM.Note.NDR",
	       "report-type=delivery-status",
	       "Content-Type: message/delivery-status",
	       "Reporting-MTA: dns;mta.ex.de");
}

static int vexport_mdn()
{
	return vexport_report("REPORT.IPM.Note.IPNRN",
	       "report-type=disposition-notification",
	       "Content-Type: message/disposition-notification",
	       "Disposition: manual-action/MDN-sent-automatically;displayed");
}

static int vexport_smime()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;
	props.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME");

	/* No attachment: placeholder text, and no crash */
	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = ve_qp_unwrap(vmsg->generate());
	assert(strstr(ostr.c_str(), "Found 0 attachment objects") != nullptr);

	/* Encrypted blob */
	auto atx = ve_new_attachment(mct.get());
	const BINARY blob = {8, {deconst("PKCS#7!!")}};
	atx->proplist.set(PR_ATTACH_DATA_BIN, &blob);
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: application/pkcs7-mime\r\n") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Transfer-Encoding: base64") != nullptr);

	/* Signed: the stored message is folded into the output */
	static const char signed_blob[] =
		"Content-Type: multipart/signed; boundary=\"sig\"; "
			"protocol=\"application/pkcs7-signature\"\r\n"
		"\r\n"
		"--sig\r\n"
		"Content-Type: text/plain; charset=\"utf-8\"\r\n"
		"\r\n"
		"signed text\r\n"
		"--sig\r\n"
		"Content-Type: application/pkcs7-signature\r\n"
		"\r\n"
		"SIGSIG\r\n"
		"--sig--\r\n";
	const BINARY sbin = {static_cast<uint32_t>(strlen(signed_blob)), {deconst(signed_blob)}};
	atx->proplist.set(PR_ATTACH_DATA_BIN, &sbin);
	props.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME.MultipartSigned");
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/signed") != nullptr);
	/* the signed entity must come out byte-for-byte */
	assert(strstr(ostr.c_str(), strstr(signed_blob, "--sig\r\n")) != nullptr);

	/* Signed, but the blob is not multipart/signed: placeholder */
	const BINARY nbin = {5, {deconst("hello")}};
	atx->proplist.set(PR_ATTACH_DATA_BIN, &nbin);
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = ve_qp_unwrap(vmsg->generate());
	assert(strstr(ostr.c_str(), "not of type multipart/signed") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_embedded()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	mct->proplist.set(PR_BODY, "outer");

	auto inner = message_content_init();
	inner->proplist.set(PR_MESSAGE_CLASS, "IPM.Note");
	inner->proplist.set(PR_SUBJECT, "inner subject");
	inner->proplist.set(PR_BODY, "inner body");
	auto atx = ve_new_attachment(mct.get());
	uint32_t method = ATTACH_EMBEDDED_MSG;
	atx->proplist.set(PR_ATTACH_METHOD, &method);
	atx->proplist.set(PR_DISPLAY_NAME, "fwddesc");
	atx->set_embedded_internal(inner);

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: message/rfc822") != nullptr);
	assert(strstr(ostr.c_str(), "Subject: inner subject") != nullptr);
	assert(strstr(ostr.c_str(), "inner body") != nullptr);
	/* Part headers built before the recursion must survive it */
	assert(strstr(ostr.c_str(), "Content-Description: fwddesc") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Disposition: attachment") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_depth_cap()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	mct->proplist.set(PR_BODY, "level0");
	auto cur = mct.get();
	for (unsigned int i = 0; i < 9; ++i) {
		auto inner = message_content_init();
		inner->proplist.set(PR_MESSAGE_CLASS, "IPM.Note");
		inner->proplist.set(PR_BODY, "deeper");
		auto atx = ve_new_attachment(cur);
		uint32_t method = ATTACH_EMBEDDED_MSG;
		atx->proplist.set(PR_ATTACH_METHOD, &method);
		atx->set_embedded_internal(inner);
		cur = inner;
	}
	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "suppressed upon sending") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_tnef()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;
	/* IPM.TaskRequest has no MIME representation -> winmail.dat */
	props.set(PR_MESSAGE_CLASS, "IPM.TaskRequest");
	props.set(PR_BODY, "task text");
	static const char correl[] = "<correl@ex.de>";
	const BINARY ckey = {std::size(correl), {deconst(correl)}}; /* incl. NUL */
	props.set(PR_TNEF_CORRELATION_KEY, &ckey);

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/mixed") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: application/ms-tnef") != nullptr);
	assert(strstr(ostr.c_str(), "name=winmail.dat") != nullptr ||
	       strstr(ostr.c_str(), "name=\"winmail.dat\"") != nullptr);
	assert(strstr(ostr.c_str(), "filename=winmail.dat") != nullptr ||
	       strstr(ostr.c_str(), "filename=\"winmail.dat\"") != nullptr);
	/* Trailing NUL of the correlation key must not leak into the header */
	assert(strstr(ostr.c_str(), "X-MS-TNEF-Correlator: <correl@ex.de>\r\n") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_dataless_attachment()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	mct->proplist.set(PR_BODY, "x");
	auto atx = ve_new_attachment(mct.get());
	uint32_t method = ATTACH_BY_REFERENCE;
	atx->proplist.set(PR_ATTACH_METHOD, &method);
	atx->proplist.set(PR_ATTACH_MIME_TAG, "application/pdf");
	atx->proplist.set(PR_ATTACH_LONG_FILENAME, "ref.pdf");

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	/* No content, but the part still says what it would have been */
	assert(strstr(ostr.c_str(), "Content-Type: application/pdf") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Disposition: attachment; filename=ref.pdf") != nullptr ||
	       strstr(ostr.c_str(), "filename=ref.pdf") != nullptr);
	return EXIT_SUCCESS;
}

static int vexport_filename_utf8()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	mct->proplist.set(PR_BODY, "x");
	auto atx = ve_new_attachment(mct.get());
	const BINARY blob = {3, {deconst("abc")}};
	uint32_t method = ATTACH_BY_VALUE;
	atx->proplist.set(PR_ATTACH_METHOD, &method);
	atx->proplist.set(PR_ATTACH_DATA_BIN, &blob);
	atx->proplist.set(PR_ATTACH_LONG_FILENAME, "Grüße.txt");
	atx->proplist.set(PR_DISPLAY_NAME, "Grüße");

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	/* Non-ASCII metadata must be labeled UTF-8, not the process locale */
	assert(strstr(ostr.c_str(), "utf-8''Gr%C3%BC%C3%9Fe.txt") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Description: =?utf-8?") != nullptr);
	assert(strstr(ostr.c_str(), "ANSI_X3.4") == nullptr);
	return EXIT_SUCCESS;
}

static int vexport_body_fallback()
{
	auto cvt = ve_converter();
	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;

	/* html_only requested, but only plaintext available */
	props.set(PR_BODY, "plain only");
	cvt.body_type = oxcmail_body::html_only;
	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: text/plain") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: multipart/") == nullptr);

	/* plain_only requested, but only HTML available */
	props.erase(PR_BODY);
	const BINARY bin_html = {11, {deconst("<p>htm</p> ")}};
	props.set(PR_HTML, &bin_html);
	cvt.body_type = oxcmail_body::plain_only;
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: text/html") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: multipart/") == nullptr);
	return EXIT_SUCCESS;
}

static int vexport_calendar()
{
	auto cvt = ve_converter();
	/* Same appointment shape as ical_export_1, ids via staticnpmap */
	const PROPERTY_NAME pn[] = {
		{MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole},
	};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	PROPID_ARRAY ids;
	assert(ee_get_propids(&pna, &ids));

	message_content_ptr mct(message_content_init());
	auto &props = mct->proplist;
	static constexpr uint64_t v_time = 0x1dabd02f773da00;
	props.set(PR_MESSAGE_CLASS, "IPM.Appointment");
	props.set(PR_BODY, "appt text");
	props.set(PR_START_DATE, &v_time);
	props.set(PR_END_DATE, &v_time);
	props.set(PROP_TAG(PT_SYSTIME, ids[0]), &v_time);
	props.set(PROP_TAG(PT_SYSTIME, ids[1]), &v_time);

	auto vmsg = vmime::make_shared<vmime::message>();
	auto err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	auto ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/alternative") != nullptr);
	assert(strstr(ostr.c_str(), "Content-Type: text/calendar") != nullptr);
	/* The part must carry the serialized iCal, not just the method */
	assert(strstr(ostr.c_str(), "BEGIN:VCALENDAR") != nullptr);
	assert(strstr(ostr.c_str(), "END:VCALENDAR") != nullptr);
	return EXIT_SUCCESS;
}

namespace {
struct pgp_block {
	char ct_type[20]{}, ct_protocol[28]{}, msg_class[36]{};
	char gpgol_class[36]{}, infopath_class[51]{};
	const char *payload = nullptr;
};
}

static int openpgp_roundtrip3(message_content &mc, oxcmail_converter &cvt,
    const pgp_block &ct_info, const char *out_class)
{
	assert(mc.proplist.set(PR_MESSAGE_CLASS, ct_info.msg_class) == ecSuccess);
	auto output = vmime::make_shared<vmime::message>();
	assert(cvt.mapi_to_inet(mc, output) == ecSuccess);
	auto &vhdr = *output->getHeader();
	auto phf = vmime::dynamicCast<vmime::contentTypeField>(vhdr.ContentType());
	assert(phf->getValue()->generate() == ct_info.ct_type);
	assert(vhdr.findField("Bcc") == nullptr);
	auto param = phf->findParameter("protocol");
	assert(param != nullptr && param->getValue().generate() == ct_info.ct_protocol);
	return EXIT_SUCCESS;
}

static int openpgp_roundtrip2(const pgp_block &ct_info)
{
	const std::string payload = ct_info.payload;
	auto data = std::string("From: sender@example.org\r\nTo: recipient@example.org\r\nBcc: hidden@example.org\r\n"
		"Subject: OpenPGP transport\r\nMIME-Version: 1.0\r\nContent-Type: ") +
		ct_info.ct_type + "; protocol=\"" + ct_info.ct_protocol +
		"\"; boundary=\"pgp-boundary\"\r\n\r\n" + payload;
	MAIL source;
	assert(source.refonly_parse(data.data(), data.size()));
	oxcmail_converter cvt;
	cvt.alloc = g_alloc;
	cvt.get_propids = ee_get_propids;
	cvt.get_propname = [](uint16_t id, PROPERTY_NAME **out) STATIC_IN_CXX23 -> BOOL {
		auto entry = static_namedprop_map.fwd.find(PROP_TAG(PT_UNSPECIFIED, id));
		if (entry == static_namedprop_map.fwd.end())
			return false;
		*out = static_cast<PROPERTY_NAME *>(g_alloc(sizeof(PROPERTY_NAME)));
		if (*out == nullptr)
			return false;
		**out = static_cast<PROPERTY_NAME>(entry->second);
		return true;
	};
	auto mc = cvt.inet_to_mapi(source);
	assert(mc != nullptr);
	auto actual_class = mc->proplist.get<const char>(PR_MESSAGE_CLASS);
	assert(actual_class != nullptr && strcmp(actual_class, ct_info.msg_class) == 0);
	bool found_override = false;
	for (const auto &[tag, name] : static_namedprop_map.fwd) {
		if (name.kind != MNID_STRING || name.name != "GpgOL Msg Class")
			continue;
		auto value = mc->proplist.get<const char>(CHANGE_PROP_TYPE(tag, PT_STRING8));
		assert(value != nullptr && strcmp(value, ct_info.gpgol_class) == 0);
		found_override = true;
	}
	assert(found_override);
	bool has_bcc = false;
	for (const auto &recipient : *mc->children.prcpts) {
		auto type = recipient.get<const uint32_t>(PR_RECIPIENT_TYPE);
		has_bcc |= type != nullptr && *type == MAPI_BCC;
	}
	assert(has_bcc);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr && atl->count == 1);
	auto &aprops = atl->pplist[0]->proplist;
	auto tag = aprops.get<const char>(PR_ATTACH_MIME_TAG);
	assert(tag != nullptr && strcmp(tag, ct_info.ct_type) == 0);
	auto bin = aprops.get<const BINARY>(PR_ATTACH_DATA_BIN);
	assert(bin != nullptr && bin->cb > payload.size());
	assert(memcmp(bin->pc + bin->cb - payload.size(), payload.data(), payload.size()) == 0);

	auto ret = openpgp_roundtrip3(*mc, cvt, ct_info, ct_info.msg_class);
	if (ret != EXIT_SUCCESS)
		return ret;
	return openpgp_roundtrip3(*mc, cvt, ct_info, ct_info.infopath_class);
}

static int openpgp_roundtrip()
{
	/*
	 * Packet contents are opaque here. Verify byte preservation, MIME
	 * mapping and GpgOL's transport classes independently of a crypto
	 * engine.
	 */
	static constexpr pgp_block info[] = {{
		"multipart/signed", "application/pgp-signature",
		"IPM.Note.SMIME.MultipartSigned",
		"IPM.Note.GpgOL.MultipartSigned",
		"IPM.Note.InfoPathForm.GpgOL.SMIME.MultipartSigned",

		"--pgp-boundary\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"
		"--pgp-boundary\r\nContent-Type: application/octet-stream\r\n\r\n"
		"-----BEGIN PGP MESSAGE-----\r\n\r\nopaque-ciphertext\r\n-----END PGP MESSAGE-----\r\n"
		"--pgp-boundary--\r\n",
	},
	{
		"multipart/encrypted", "application/pgp-encrypted",
		"IPM.Note.GpgOL.MultipartEncrypted",
		"IPM.Note.GpgOL.MultipartEncrypted",
		"IPM.Note.InfoPathForm.GpgOLS.SMIME.MultipartSigned",

		"--pgp-boundary\r\nContent-Type: text/plain;\r\n\tcharset=utf-8\r\n"
		"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
		"First line=20\r\nSecond =C3=A4 line\r\n\r\n"
		"--pgp-boundary\r\nContent-Type: application/pgp-signature\r\n\r\n"
		"-----BEGIN PGP SIGNATURE-----\r\n\r\nopaque-signature\r\n-----END PGP SIGNATURE-----\r\n"
		"--pgp-boundary--\r\n",
	}};
	auto ret = openpgp_roundtrip2(info[0]);
	return ret == EXIT_SUCCESS ? openpgp_roundtrip2(info[1]) : ret;
}

static int openpgp_legacy_layout()
{
	/*
	 * Older converters stored OpenPGP parts as body and attachments. GpgOL
	 * still reclasses such messages, which must then export as regular
	 * mail instead of the OXOSMIME placeholder.
	 */
	static constexpr struct {
		const char *mclass, *data, *marker;
		unsigned int attachments;
	} cases[] = {
		{"IPM.Note.GpgOL.MultipartSigned",
		 "From: sender@example.org\r\nTo: recipient@example.org\r\n"
		 "Subject: legacy signed\r\nMIME-Version: 1.0\r\n"
		 "Content-Type: multipart/mixed; boundary=\"legacy\"\r\n\r\n"
		 "--legacy\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
		 "Signed body text\r\n"
		 "--legacy\r\nContent-Type: application/pgp-signature; name=\"signature.asc\"\r\n"
		 "Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n"
		 "-----BEGIN PGP SIGNATURE-----\r\n\r\nopaque-signature\r\n-----END PGP SIGNATURE-----\r\n"
		 "--legacy--\r\n", "Signed body text", 1},
		{"IPM.Note.GpgOL.MultipartEncrypted",
		 "From: sender@example.org\r\nTo: recipient@example.org\r\n"
		 "Subject: legacy encrypted\r\nMIME-Version: 1.0\r\n"
		 "Content-Type: multipart/mixed; boundary=\"legacy\"\r\n\r\n"
		 "--legacy\r\nContent-Type: application/pgp-encrypted; name=\"version.asc\"\r\n"
		 "Content-Disposition: attachment; filename=\"version.asc\"\r\n\r\nVersion: 1\r\n"
		 "--legacy\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n"
		 "Content-Disposition: attachment; filename=\"encrypted.asc\"\r\n\r\n"
		 "-----BEGIN PGP MESSAGE-----\r\n\r\nopaque-ciphertext\r\n-----END PGP MESSAGE-----\r\n"
		 "--legacy--\r\n", "encrypted.asc", 2},
	};
	for (const auto &c : cases) {
		MAIL source;
		assert(source.refonly_parse(c.data, strlen(c.data)));
		oxcmail_converter cvt;
		cvt.alloc = g_alloc;
		cvt.get_propids = ee_get_propids;
		auto mc = cvt.inet_to_mapi(source);
		assert(mc != nullptr);
		auto atl = mc->children.pattachments;
		assert(atl != nullptr && atl->count == c.attachments);
		assert(mc->proplist.set(PR_MESSAGE_CLASS, c.mclass) == ecSuccess);
		auto output = vmime::make_shared<vmime::message>();
		assert(cvt.mapi_to_inet(*mc, output) == ecSuccess);
		auto head = output->getHeader();
		assert(head != nullptr);
		vmime::mediaType mt_mixed(vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_MIXED);
		assert(output->getBody()->getContentType() == mt_mixed);
		auto text = vmail_to_string(*output);
		assert(text.find("[Message is not a valid OXOSMIME message") == std::string::npos);
		assert(text.find(c.marker) != std::string::npos);
	}
	return EXIT_SUCCESS;
}

int main()
{
	mlog_init(nullptr, nullptr, LV_DEBUG, nullptr);
	textmaps_init(getenv("GROMOX_TEST_DATA"));
	auto ee_get_user_ids = [](const char *, unsigned int *, unsigned int *, enum display_type *) STATIC_IN_CXX23 -> bool { return false; };
	auto ee_get_domain_ids = [](const char *, unsigned int *, unsigned int *) STATIC_IN_CXX23 -> bool { return false; };
	auto ee_userid_to_name = [](unsigned int, std::string &) STATIC_IN_CXX23 -> ec_error_t { return ecNotFound; };
	g_show_tree = g_show_props = true;
	if (!oxcmail_init_library("x500", ee_get_user_ids, ee_get_domain_ids, ee_userid_to_name)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}
	int ret = EXIT_SUCCESS;
#define E(f) {#f, f}
	static constexpr struct {
		const char *name;
		int (*fct)();
	} tests[] = {
		E(excess_attachment), E(nested_boundary_prefix),
		E(select_parts_1), E(select_parts_1a),
		E(ical_meeting_attendees),
		E(select_parts_2), E(select_parts_3), E(select_parts_4),
		E(select_parts_5), E(select_parts_6), E(select_parts_7),
		E(ical_export_1), E(ical_export_2), E(ical_reply_identity),
		E(ical_export_exception), E(ical_export_allday_exception),
		E(ical_allday_hint),
		E(hdrparse_1),
		E(vcard_tel_types), E(vcard_escaped_values), E(vcard_photo), E(vcard_dates),
		E(vcard_fileas_categories),
		E(vexport_head), E(vexport_simple_body), E(vexport_image),
		E(vexport_inline_image), E(vexport_recipients),
		E(vexport_headers), E(vexport_internet_headers),
		E(vexport_dsn), E(vexport_mdn), E(vexport_smime),
		E(vexport_embedded), E(vexport_depth_cap), E(vexport_tnef),
		E(vexport_dataless_attachment),
		E(vexport_filename_utf8), E(vexport_body_fallback),
		E(vexport_calendar), E(openpgp_roundtrip),
		E(openpgp_legacy_layout),
		E(ical_exception_roundtrip),
	};
#undef E
	for (const auto &t : tests)
		if (t.fct() != EXIT_SUCCESS) {
			printf("FAIL: %s\n", t.name);
			ret = EXIT_FAILURE;
		}
	return ret;
}
