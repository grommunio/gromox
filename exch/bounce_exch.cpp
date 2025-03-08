// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
// This file is part of Gromox.
#include <ctime>
#include <string>
#include <utility>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <vmime/addressList.hpp>
#include <vmime/contentTypeField.hpp>
#include <vmime/dateTime.hpp>
#include <vmime/mailbox.hpp>
#include <vmime/stringContentHandler.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/element_data.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>

namespace {

using namespace std::string_literals;
using namespace gromox;
using buff_t = bool (*)(const char *, char *, size_t);
using meta_t = errno_t (*)(const char *, unsigned int, sql_meta_result &);

static bool bounce_producer_make_content(meta_t meta,
    const char *username, MESSAGE_CONTENT *pbrief, const char *bounce_type,
    std::string &subject, std::string &content)
{
	char date_buff[128];

	auto tsptr = pbrief->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	auto ts = tsptr == nullptr ? time(nullptr) : rop_util_nttime_to_unix(*tsptr);
	auto from = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (from == nullptr)
		from = "";
	sql_meta_result mres;
	auto charset = meta(from, WANTPRIV_METAONLY, mres) == 0 ?
	               lang_to_charset(mres.lang.c_str()) : nullptr;
	rfc1123_dstring(date_buff, std::size(date_buff), ts);
	auto message_size = pbrief->proplist.get<const uint32_t>(PR_MESSAGE_SIZE);
	if (message_size == nullptr)
		return false;
	if (*znul(charset) == '\0') {
		auto cpid = pbrief->proplist.get<const uint32_t>(PR_INTERNET_CPID);
		if (cpid != nullptr)
			charset = cpid_to_cset(static_cast<cpid_t>(*cpid));
		if (charset == nullptr)
			charset = "ascii";
	}

	auto tpptr = bounce_gen_lookup(charset, bounce_type);
	if (tpptr == nullptr)
		return false;
	auto &tp = *tpptr;
	auto fa = HXformat_init();
	if (fa == nullptr)
		return false;
	auto cl_0 = HX::make_scope_exit([&]() { HXformat_free(fa); });
	unsigned int immed = HXFORMAT_IMMED;
	if (HXformat_add(fa, "time", date_buff,
	    HXTYPE_STRING | immed) < 0 ||
	    HXformat_add(fa, "from", from, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "user", username, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpts",
	    bounce_gen_rcpts(*pbrief->children.prcpts).c_str(),
	    HXTYPE_STRING | immed) < 0 ||
	    HXformat_add(fa, "postmaster", bounce_gen_postmaster(), HXTYPE_STRING) < 0)
		return false;
	auto subj = pbrief->proplist.get<const char>(PR_SUBJECT);
	if (HXformat_add(fa, "subject", znul(subj), HXTYPE_STRING) < 0)
		return false;
	HX_unit_size(date_buff, std::size(date_buff), *message_size, 1000, 0);
	if (HXformat_add(fa, "length", date_buff, HXTYPE_STRING) < 0)
		return false;

	hxmc_t *replaced = nullptr;
	if (HXformat_aprintf(fa, &replaced, &tp.content[tp.body_start]) < 0)
		return false;
	auto cl_1 = HX::make_scope_exit([&]() { HXmc_free(replaced); });
	content = replaced;
	subject = tp.subject;
	return true;
}

bool exch_bouncer_make(buff_t gudn, meta_t meta,
    const char *username, MESSAGE_CONTENT *pbrief,
    const char *bounce_type, vmime::shared_ptr<vmime::message> &pmail) try
{
	char tmp_buff[1024];
	vmime::mailbox expeditor, target;

	if (gudn(username, tmp_buff, std::size(tmp_buff)) && *tmp_buff != '\0')
		expeditor.setName(vmime::text(tmp_buff, vmime::charsets::UTF_8));
	expeditor.setEmail(username);

	std::string subject, content_buff;
	if (!bounce_producer_make_content(meta, username, pbrief,
	    bounce_type, subject, content_buff))
		return false;

	pmail = vmime::make_shared<vmime::message>();
	auto hdr = pmail->getHeader();
	hdr->getField("MIME-Version")->setValue("1.0");
	hdr->ContentType()->setValue(vmime::mediaType(vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_REPORT));
	vmime::dynamicCast<vmime::contentTypeField>(hdr->ContentType())->setReportType("disposition-notification");

	auto bv = pbrief->proplist.get<const BINARY>(PR_CONVERSATION_INDEX);
	if (bv != nullptr)
		hdr->getField("Thread-Index")->setValue(base64_encode({bv->pc, bv->cb}));
	hdr->From()->setValue(expeditor);
	auto str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_NAME);
	if (str != nullptr && *str != '\0')
		target.setName(vmime::text(str, vmime::charsets::UTF_8));
	str = pbrief->proplist.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr) {
		vmime::addressList target_list;
		target.setEmail(str);
		target_list.appendAddress(vmime::make_shared<vmime::mailbox>(target));
		hdr->To()->setValue(target_list);
	}
	hdr->getField("X-Auto-Response-Suppress")->setValue("All");
	hdr->Date()->setValue(vmime::datetime::now());
	hdr->Subject()->setValue(vmime::text(std::move(subject), vmime::charsets::UTF_8));

	vmime::encoding enc;
	enc.setUsage(vmime::encoding::EncodingUsage::USAGE_TEXT);
	auto part1 = vmime::make_shared<vmime::bodyPart>();
	part1->getBody()->setContents(vmime::make_shared<vmime::stringContentHandler>(std::move(content_buff), std::move(enc)),
		vmime::mediaType(vmime::mediaTypes::TEXT, vmime::mediaTypes::TEXT_PLAIN),
		vmime::charsets::UTF_8);
	pmail->getBody()->appendPart(std::move(part1));

	auto part2 = vmime::make_shared<vmime::bodyPart>();
	auto dsn = part2->getHeader();
	dsn->getField("Final-Recipient")->setValue("rfc822;"s + username);
	if (strcmp(bounce_type, "BOUNCE_NOTIFY_READ") == 0)
		dsn->getField("Disposition")->setValue("automatic-action/MDN-sent-automatically; displayed");
	else if (strcmp(bounce_type, "BOUNCE_NOTIFY_NON_READ") == 0)
		dsn->getField("Disposition")->setValue("manual-action/MDN-sent-automatically; deleted");
	str = pbrief->proplist.get<char>(PR_INTERNET_MESSAGE_ID);
	if (str != nullptr)
		dsn->getField("Original-Message-ID")->setValue(str);
	bv = pbrief->proplist.get<BINARY>(PR_PARENT_KEY);
	if (bv != nullptr)
		dsn->getField("X-MSExch-Correlation-Key")->setValue(base64_encode({bv->pc, bv->cb}));
	dsn->getField("X-Display-Name")->setValue(expeditor);
	part2->getBody()->setContentType(vmime::mediaType(vmime::mediaTypes::MESSAGE, vmime::mediaTypes::MESSAGE_DISPOSITION_NOTIFICATION));
	pmail->getBody()->appendPart(std::move(part2));
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1482: ENOMEM");
	return false;
}

}
