// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sqlite3.h>
#include <sstream>
#include <string>
#include <utility>
#include <libHX/option.h>
#include <libHX/string.h>
#include <vmime/contentTypeField.hpp>
#include <vmime/dateTime.hpp>
#include <vmime/message.hpp>
#include <vmime/stringContentHandler.hpp>
#include <vmime/text.hpp>
#include <vmime/utility/outputStreamAdapter.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/database.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"

using namespace std::string_literals;
using namespace gromox;

static std::string exmdb_bouncer_attachs(sqlite3 *psqlite, uint64_t message_id)
{
	std::string r;
	void *pvalue;
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "SELECT attachment_id FROM "
	        "attachments WHERE message_id=%llu", static_cast<unsigned long long>(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	while (pstmt.step() == SQLITE_ROW) {
		auto attachment_id = pstmt.col_uint64(0);
		if (!cu_get_property(MAPI_ATTACH, attachment_id, CP_ACP,
		    psqlite, PR_ATTACH_LONG_FILENAME, &pvalue))
			return 0;
		if (pvalue == nullptr)
			continue;
		if (!r.empty())
			r += ", ";
		r += static_cast<const char *>(pvalue);
	}
	return r;
}

BOOL exmdb_bouncer_make_content(const char *from, const char *rcpt,
    sqlite3 *psqlite, uint64_t message_id, const char *bounce_type,
    std::string &subject, std::string &content) try
{
	void *pvalue;
	char charset[32], date_buff[128], lang[32];

	charset[0] = '\0';
	if (common_util_get_user_lang(from, lang, std::size(lang)))
		gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
	rfc1123_dstring(date_buff, std::size(date_buff), 0);
	if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP,
	    psqlite, PR_MESSAGE_SIZE, &pvalue))
		return FALSE;
	auto message_size = pvalue != nullptr ? *static_cast<uint32_t *>(pvalue) : 0;
	if ('\0' == charset[0]) {
		if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP, psqlite,
		    PR_INTERNET_CPID, &pvalue))
			return FALSE;
		if (NULL == pvalue) {
			strcpy(charset, "ascii");
		} else {
			auto pcharset = cpid_to_cset(static_cast<cpid_t>(*static_cast<uint32_t *>(pvalue)));
			gx_strlcpy(charset, pcharset != nullptr ? pcharset : "ascii", std::size(charset));
		}
	}

	auto tpptr = bounce_gen_lookup(charset, bounce_type);
	if (tpptr == nullptr)
		return false;
	auto &tp = *tpptr;
	auto fa = HXformat_init();
	if (fa == nullptr)
		return false;
	auto cl_0 = make_scope_exit([&]() { HXformat_free(fa); });
	unsigned int immed = HXFORMAT_IMMED;
	if (HXformat_add(fa, "time", date_buff,
	    HXTYPE_STRING | immed) < 0 ||
	    HXformat_add(fa, "from", from, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpt", rcpt, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "postmaster", bounce_gen_postmaster(), HXTYPE_STRING) < 0)
		return false;
	if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP, psqlite,
	    PR_SUBJECT, &pvalue))
		return FALSE;
	if (HXformat_add(fa, "subject", znul(static_cast<const char *>(pvalue)), HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "parts",
	    exmdb_bouncer_attachs(psqlite, message_id).c_str(),
	    HXTYPE_STRING | immed) < 0)
		return false;
	HX_unit_size(date_buff, std::size(date_buff), message_size, 1000, 0);
	if (HXformat_add(fa, "length", date_buff, HXTYPE_STRING) < 0)
		return false;

	hxmc_t *replaced = nullptr;
	if (HXformat_aprintf(fa, &replaced, &tp.content[tp.body_start]) < 0)
		return false;
	auto cl_1 = make_scope_exit([&]() { HXmc_free(replaced); });
	content = replaced;
	subject = tp.subject;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1219: ENOMEM");
	return false;
}

BOOL exmdb_bouncer_make(const char *from, const char *rcpt, sqlite3 *psqlite,
    uint64_t message_id, const char *bounce_type,
    vmime::shared_ptr<vmime::message> &pmail) try
{
	std::string subject, content_buff;
	
	if (!exmdb_bouncer_make_content(from, rcpt,
	    psqlite, message_id, bounce_type,
	    subject, content_buff))
		return FALSE;

	auto mta    = "dns;"s + get_host_ID();
	auto t_addr = "rfc822;"s + rcpt;
	auto now    = vmime::datetime::now();

	pmail = vmime::make_shared<vmime::message>();
	auto hdr = pmail->getHeader();
	hdr->getField("MIME-Version")->setValue("1.0");
	hdr->ContentType()->setValue(vmime::mediaType(vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_REPORT));
	vmime::dynamicCast<vmime::contentTypeField>(hdr->ContentType())->setReportType("delivery-status");

	hdr->From()->setValue(rcpt);
	hdr->To()->setValue(from);
	hdr->getField("X-Auto-Response-Suppress")->setValue("All");
	hdr->Date()->setValue(now);
	hdr->Subject()->setValue(vmime::text(std::move(subject), vmime::charsets::UTF_8));

	vmime::encoding enc;
	enc.setUsage(vmime::encoding::EncodingUsage::USAGE_TEXT);
	auto part1 = vmime::make_shared<vmime::bodyPart>();
	part1->getBody()->setContents(vmime::make_shared<vmime::stringContentHandler>(std::move(content_buff), std::move(enc)),
		vmime::mediaType(vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_REPORT),
		vmime::charsets::UTF_8);
	pmail->getBody()->appendPart(std::move(part1));

	std::ostringstream oss;
	vmime::utility::outputStreamAdapter vos(oss);
	vmime::header hdr2;
	hdr2.getField("Reporting-MTA")->setValue(mta);
	hdr2.getField("Arrival-Date")->setValue(now);
	hdr2.generate(vos);
	oss << "\r\n";

	vmime::header hdr3;
	hdr3.getField("Final-Recipient")->setValue(t_addr);
	hdr3.getField("Action")->setValue("failed");
	hdr3.getField("Status")->setValue("5.0.0");
	hdr3.getField("Remote-MTA")->setValue(mta);
	hdr3.generate(vos);

	auto dsn = vmime::make_shared<vmime::bodyPart>();
	dsn->getBody()->setContents(vmime::make_shared<vmime::stringContentHandler>(std::move(oss).str()),
		vmime::mediaType(vmime::mediaTypes::MESSAGE, vmime::mediaTypes::MESSAGE_DISPOSITION_NOTIFICATION));
	pmail->getBody()->appendPart(std::move(dsn));
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}
