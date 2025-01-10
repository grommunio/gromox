// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cstdlib>
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

static BOOL ie_get_propids(const ie_name_entry *map, size_t mapsize,
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
	assert(m.load_from_str(data, strlen(data)));
	mptr mc(oxcmail_import(nullptr, "UTC", &m, g_alloc, ee_get_propids));
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
	assert(m.load_from_str(data.data(), data.size()));
	mptr mc(oxcmail_import(nullptr, "UTC", &m, g_alloc, ee_get_propids));
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

static int select_parts_2()
{
	fprintf(stderr, "== T2\n");
	auto data = std::string(appl_header) + appl_plain + appl_mixed +
	            appl_html1 + appl_zip + appl_mixed_footer + appl_alt_footer;
	MAIL m;
	assert(m.load_from_str(data.data(), data.size()));
	mptr mc(oxcmail_import(nullptr, "UTC", &m, g_alloc, ee_get_propids));
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
	assert(m.load_from_str(data, std::size(data)));
	mptr mc(oxcmail_import(nullptr, "UTC", &m, g_alloc, ee_get_propids));
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
	assert(m.load_from_str(data_4, std::size(data_4)));
	mptr mc(oxcmail_import("us-ascii", "UTC", &m, g_alloc, ee_get_propids));
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
	assert(HX_memmem(bin->pv, bin->cb, "cid:", 4) != nullptr);
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
	assert(m.load_from_str(data_5, std::size(data_5)));
	mptr mc(oxcmail_import(nullptr, "UTC", &m, g_alloc, ee_get_propids));
	assert(mc != nullptr);
	auto atl = mc->children.pattachments;
	assert(atl != nullptr);
	if (atl->count != 2)
		gi_print(0, *mc);
	assert(atl->count == 2);
	auto bin = mc->proplist.get<const BINARY>(PR_HTML);
	assert(bin != nullptr);
	assert(HX_memmem(bin->pv, bin->cb, "ZhtmlZ", 6) != nullptr);
	assert(HX_memmem(bin->pv, bin->cb, "cid:image001", 12) != nullptr);
	return 0;
}

static void ical_export_1()
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
	const BINARY bin_48{48, {reinterpret_cast<uint8_t *>(deconst("\304\377\377\377\0\0\0\0\304\377\377\377\0\0\0\0\n\0\0\0\5\0\3\0\0\0\0\0\0\0\0\0\0\0\3\0\0\0\5\0\2\0\0\0\0\0\0\0"))}};
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
	if (!oxcical_export(&msgctnt, "-", icalout, "x500org", malloc, get_propids, nullptr)) {
		fprintf(stderr, "oxcical_export failed\n");
		return;
	}
	std::string icstr;
	if (icalout.serialize(icstr) != ecSuccess) {
		fprintf(stderr, "ical_serialize failed\n");
		return;
	}
	constexpr char needle[] = "DTSTART;TZID=Europe/Vienna:20240612T215900";
	auto ptr = strstr(icstr.c_str(), needle);
	if (ptr == nullptr) {
		printf("%s\n", icstr.c_str());
		fprintf(stderr, "FAILED. Substrings Europe/215900 not found.\n");
	}
}

static void ical_export_2()
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
	static constexpr bool v_true = 1;
	static const BINARY v_122 = {122, {reinterpret_cast<uint8_t *>(deconst("\x02\x01\x34\x00\x02\x00\x17\x00\x57\x00\x2e\x00\x20\x00\x45\x00\x75\x00\x72\x00\x6f\x00\x70\x00\x65\x00\x20\x00\x53\x00\x74\x00\x61\x00\x6e\x00\x64\x00\x61\x00\x72\x00\x64\x00\x20\x00\x54\x00\x69\x00\x6d\x00\x65\x00\x01\x00\x02\x01\x3e\x00\x02\x00\x41\x06\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc4\xff\xff\xff\x00\x00\x00\x00\xc4\xff\xff\xff\x00\x00\x0a\x00\x00\x00\x05\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00\x00\x00"))}};
	const TAGGED_PROPVAL props[] = {
		{PR_MESSAGE_CLASS, deconst("IPM.Appointment")},
		{0x809d0040, deconst(&v_start)},
		{0x809e0040, deconst(&v_end)},
		{0x80a5000b, deconst(&v_true)},
		{0x80d20102, deconst(&v_122)},
		{0x80d30102, deconst(&v_122)},
	};
	fprintf(stderr, "=== ical_export_2\n");
	const MESSAGE_CONTENT msgctnt = {{std::size(props), deconst(props)}};
	ical icalout;
	if (!oxcical_export(&msgctnt, "-", icalout, "x500org", malloc, get_propids, nullptr)) {
		fprintf(stderr, "oxcical_export failed\n");
		return;
	}
	std::string icstr;
	if (icalout.serialize(icstr) != ecSuccess) {
		fprintf(stderr, "ical_serialize failed\n");
		return;
	}
	if (strstr(icstr.c_str(), "DTSTART;VALUE=DATE;TZID=W. Europe Standard Time:20240926") == nullptr ||
	    strstr(icstr.c_str(), "DTEND;VALUE=DATE;TZID=W. Europe Standard Time:20240927") == nullptr) {
		printf("%s\n", icstr.c_str());
		fprintf(stderr, "FAILED. Substrings DTSTART/20240926 and DTEND/20240927 not found.\n");
	}
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
	excess_attachment();
	select_parts_1();
	select_parts_2();
	select_parts_3();
	select_parts_4();
	select_parts_5();
	ical_export_1();
	ical_export_2();
	return EXIT_SUCCESS;
}
