// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vmime/addressList.hpp>
#include <vmime/contentTypeField.hpp>
#include <vmime/dateTime.hpp>
#include <vmime/mailbox.hpp>
#include <vmime/stringContentHandler.hpp>
#include <vmime/utility/outputStreamStringAdapter.hpp>
#include <gromox/authmgr.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

using namespace std::string_literals;
using namespace gromox;
DECLARE_HOOK_API(exmdb_local, extern);
using namespace exmdb_local;

/*
 *	make a bounce mail
 *	@param
 *		bounce_type			type of bounce mail
 *		pmail [out]			bounce mail object
 */
bool exml_bouncer_make(const char *from, const char *rcpt_to,
    MAIL *pmail_original, time_t original_time, const char *bounce_type,
    MAIL *qmail) try
{
	char date_buff[128];
	sql_meta_result mres;
	const char *charset = nullptr;

	auto pdomain = strchr(from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (mysql_adaptor_domain_list_query(pdomain) >= 1 &&
		    mysql_adaptor_meta(from, WANTPRIV_METAONLY, mres) == 0)
			charset = lang_to_charset(mres.lang.c_str());
	}
	rfc1123_dstring(date_buff, std::size(date_buff), original_time);
	auto mcharset = bounce_gen_charset(*pmail_original);
	if (charset == nullptr)
		charset = mcharset.c_str();
	charset = znul(charset);
	auto tpptr = bounce_gen_lookup(charset, bounce_type);
	if (tpptr == nullptr)
		return false;
	auto &tp = *tpptr;
	auto fa = HXformat_init();
	if (fa == nullptr)
		return false;
	auto cl_0 = HX::make_scope_exit([&]() { HXformat_free(fa); });
	unsigned int immed = HXFORMAT_IMMED;
	if (HXformat_add(fa, "time", date_buff, HXTYPE_STRING | immed) < 0 ||
	    HXformat_add(fa, "from", from, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpt", rcpt_to, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpts", rcpt_to, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "postmaster", bounce_gen_postmaster(), HXTYPE_STRING) < 0)
		return false;
	auto str = bounce_gen_subject(*pmail_original, mcharset.c_str());
	if (HXformat_add(fa, "subject", str.c_str(), HXTYPE_STRING | immed) < 0)
		return false;
	auto mail_len = pmail_original->get_length();
	if (mail_len < 0) {
		mlog(LV_ERR, "exmdb_local: failed to get mail length");
		mail_len = 0;
	}
	HX_unit_size(date_buff, std::size(date_buff), mail_len, 1000, 0);
	if (HXformat_add(fa, "length", date_buff, HXTYPE_STRING) < 0)
		return false;

	hxmc_t *replaced = nullptr;
	auto aprint_len = HXformat_aprintf(fa, &replaced, &tp.content[tp.body_start]);
	if (aprint_len < 0)
		return false;
	auto cl_1 = HX::make_scope_exit([&]() { HXmc_free(replaced); });
	std::string content_buff = replaced, subject = tp.subject;

	vmime::message pmail;
	auto hdr = pmail.getHeader();
	hdr->getField("MIME-Version")->setValue("1.0");
	hdr->ContentType()->setValue(vmime::mediaType(vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_REPORT));
	vmime::dynamicCast<vmime::contentTypeField>(hdr->ContentType())->setReportType("delivery-status");

	str = bounce_gen_thrindex(*pmail_original);
	if (!str.empty())
		hdr->getField("Thread-Index")->setValue(std::move(str));
	vmime::mailbox expeditor, target;
	expeditor.setEmail(tp.from.size() > 0 ? tp.from.c_str() : bounce_gen_postmaster());
	hdr->From()->setValue(expeditor);
	vmime::addressList target_list;
	target.setEmail(from /*orig_from*/);
	target_list.appendAddress(vmime::make_shared<vmime::mailbox>(target));
	hdr->To()->setValue(target_list);
	hdr->getField("X-Auto-Response-Suppress")->setValue("All");
	hdr->Date()->setValue(vmime::datetime::now());
	hdr->Subject()->setValue(vmime::text(std::move(subject), vmime::charsets::UTF_8));
	
	vmime::encoding enc;
	enc.setUsage(vmime::encoding::EncodingUsage::USAGE_TEXT);
	auto part1 = vmime::make_shared<vmime::bodyPart>();
	part1->getBody()->setContents(vmime::make_shared<vmime::stringContentHandler>(std::move(content_buff), std::move(enc)),
		vmime::mediaType(vmime::mediaTypes::TEXT, vmime::mediaTypes::TEXT_PLAIN),
		vmime::charsets::UTF_8);
	pmail.getBody()->appendPart(std::move(part1));

	auto part2 = vmime::make_shared<vmime::bodyPart>();
	std::string vstr;
	vmime::utility::outputStreamStringAdapter vadap(vstr);

	vmime::header dsn;
	auto mta = "dns;"s + get_host_ID();
	dsn.getField("Reporting-MTA")->setValue(mta);
	dsn.getField("Arrival-Date")->setValue(date_buff);
	dsn.generate(vadap);
	vstr += "\r\n";

	dsn = vmime::header();
	dsn.getField("Final-Recipient")->setValue("rfc822;"s + rcpt_to);
	if (strcmp(bounce_type, "BOUNCE_MAIL_DELIVERED") != 0) {
		dsn.getField("Action")->setValue("failed");
		dsn.getField("Status")->setValue("5.0.0");
	} else {
		dsn.getField("Action")->setValue("delivered");
		dsn.getField("Status")->setValue("2.0.0");
	}
	dsn.getField("Remote-MTA")->setValue(mta);
	dsn.generate(vadap);

	part2->getBody()->setContents(vmime::make_shared<vmime::stringContentHandler>(std::move(vstr)));
	part2->getBody()->setContentType(vmime::mediaType(vmime::mediaTypes::MESSAGE, vmime::mediaTypes::MESSAGE_DELIVERY_STATUS));
	pmail.getBody()->appendPart(std::move(part2));
	return vmail_to_mail(pmail, *qmail);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1216: ENOMEM");
	return false;
}
