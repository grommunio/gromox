// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <deque>
#include <libHX/string.h>
#include <gromox/element_data.hpp>
#include <gromox/ical.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/util.hpp>
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
		           [&](const auto &r) -> bool { return r.pn == (*pna)[i]; });
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
	BINARY conv_index = {uint32_t(strlen(XFE4)), {strdup(XFE4)}};
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
	const BINARY bin_html = {strlen(HSTR2), {deconst(HSTR2)}};
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
	if (mct->children.pattachments == nullptr)
		mct->children.pattachments = attachment_list_init();
	auto atx = attachment_content_init();
	if (atx != nullptr)
		mct->children.pattachments->append_internal(atx);
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
	const BINARY almost_empty = {1, deconst(" ")};
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
		"Content-Type: text/plain\r\n"
		"\r\n"
		"signed text\r\n"
		"--sig\r\n"
		"Content-Type: application/pkcs7-signature\r\n"
		"\r\n"
		"SIGSIG\r\n"
		"--sig--\r\n";
	const BINARY sbin = {strlen(signed_blob), {deconst(signed_blob)}};
	atx->proplist.set(PR_ATTACH_DATA_BIN, &sbin);
	props.set(PR_MESSAGE_CLASS, "IPM.Note.SMIME.MultipartSigned");
	err = cvt.mapi_to_inet(*mct, vmsg);
	assert(err == ecSuccess);
	ostr = vmsg->generate();
	assert(strstr(ostr.c_str(), "Content-Type: multipart/signed") != nullptr);
	assert(strstr(ostr.c_str(), "signed text") != nullptr);
	assert(strstr(ostr.c_str(), "SIGSIG") != nullptr);

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

int main()
{
	mlog_init(nullptr, nullptr, LV_DEBUG, nullptr);
	auto ee_get_user_ids = [](const char *, unsigned int *, unsigned int *, enum display_type *) -> bool { return false; };
	auto ee_get_domain_ids = [](const char *, unsigned int *, unsigned int *) -> bool { return false; };
	auto ee_userid_to_name = [](unsigned int, std::string &) -> ec_error_t { return ecNotFound; };
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
		E(excess_attachment), E(select_parts_1), E(select_parts_1a),
		E(select_parts_2), E(select_parts_3), E(select_parts_4),
		E(select_parts_5), E(select_parts_6), E(select_parts_7),
		E(ical_export_1), E(ical_export_2), E(hdrparse_1),
		E(vexport_head), E(vexport_simple_body), E(vexport_image),
		E(vexport_inline_image), E(vexport_recipients),
		E(vexport_headers), E(vexport_internet_headers),
		E(vexport_dsn), E(vexport_mdn), E(vexport_smime),
		E(vexport_embedded), E(vexport_depth_cap), E(vexport_tnef),
		E(vexport_dataless_attachment),
		E(vexport_filename_utf8), E(vexport_body_fallback),
		E(vexport_calendar),
	};
#undef E
	for (const auto &t : tests)
		if (t.fct() != EXIT_SUCCESS) {
			printf("FAIL: %s\n", t.name);
			ret = EXIT_FAILURE;
		}
	return ret;
}
