// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
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
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/bounce_gen.hpp>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mime.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"
#include "common_util.h"
#include "system_services.hpp"

using namespace std::string_literals;
using namespace gromox;

static BOOL bounce_producer_make_content(const char *username,
    MESSAGE_CONTENT *pbrief, const char *bounce_type, char *subject,
    char *content_type, char *pcontent, size_t content_size) try
{
	char charset[32];
	char date_buff[128];
	struct tm time_buff;
	int len;
	char lang[32], time_zone[64];

	charset[0] = '\0';
	time_zone[0] = '\0';
	auto ts = pbrief->proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	time_t tmp_time = ts == nullptr ? time(nullptr) : rop_util_nttime_to_unix(*ts);
	auto from = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (NULL == from) {
		from = "none@none";
	}
	if (system_services_get_user_lang(from, lang, arsizeof(lang))) {
		gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
		system_services_get_timezone(from, time_zone, arsizeof(time_zone));
	}
	if('\0' != time_zone[0]) {
		auto sp = tz::tzalloc(time_zone);
		if (NULL == sp) {
			return FALSE;
		}
		tz::localtime_rz(sp, &tmp_time, &time_buff);
		tz::tzfree(sp);
	} else {
		localtime_r(&tmp_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	auto num = pbrief->proplist.get<const uint32_t>(PR_MESSAGE_SIZE);
	if (num == nullptr)
		return FALSE;
	auto message_size = *num;
	if ('\0' == charset[0]) {
		num = pbrief->proplist.get<uint32_t>(PR_INTERNET_CPID);
		if (num == nullptr) {
			strcpy(charset, "ascii");
		} else {
			auto pcharset = cpid_to_cset(static_cast<cpid_t>(*num));
			gx_strlcpy(charset, pcharset != nullptr ? pcharset : "ascii", arsizeof(charset));
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
	    HXformat_add(fa, "user", username, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpts",
	    bounce_gen_rcpts(*pbrief->children.prcpts).c_str(),
	    HXTYPE_STRING | immed) < 0)
		return false;
	auto subj = pbrief->proplist.get<const char>(PR_SUBJECT);
	if (HXformat_add(fa, "subject", subj != nullptr ? subj : "",
	    HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "parts",
	    bounce_gen_attachs(*pbrief->children.pattachments).c_str(),
	    HXTYPE_STRING | immed) < 0)
		return false;
	HX_unit_size(date_buff, std::size(date_buff), message_size, 1000, 0);
	if (HXformat_add(fa, "length", date_buff, HXTYPE_STRING) < 0)
		return false;

	hxmc_t *replaced = nullptr;
	if (HXformat_aprintf(fa, &replaced, &tp.content[tp.body_start]) < 0)
		return false;
	gx_strlcpy(pcontent, replaced, content_size);
	HXmc_free(replaced);
	if (NULL != subject) {
		strcpy(subject, tp.subject.c_str());
	}
	if (NULL != content_type) {
		strcpy(content_type, tp.content_type.c_str());
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1217: ENOMEM");
	return false;
}

BOOL zcore_bouncer_make(const char *username, MESSAGE_CONTENT *pbrief,
    const char *bounce_type, MAIL *pmail)
{
	MIME *pmime;
	size_t out_len;
	time_t cur_time;
	char mime_to[1024];
	char subject[1024];
	char tmp_buff[1024];
	char date_buff[128];
	struct tm time_buff;
	char mime_from[1024];
	char content_type[128];
	char content_buff[256*1024];
	
	if (system_services_get_user_displayname(username, tmp_buff,
	    arsizeof(tmp_buff)) && '\0' != tmp_buff[0]) {
		strcpy(mime_from, "=?utf-8?b?");
		encode64(tmp_buff, strlen(tmp_buff), mime_from + 10,
			sizeof(mime_from) - 13, &out_len);
		strcpy(mime_from + 10 + out_len, "?=");
	} else {
		mime_from[0] = '\0';
	}
	if (!bounce_producer_make_content(username, pbrief,
	    bounce_type, subject, content_type, content_buff,
	    std::size(content_buff)))
		return FALSE;
	auto phead = pmail->add_head();
	if (NULL == phead) {
		return FALSE;
	}
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "disposition-notification");
	auto bv = pbrief->proplist.get<const BINARY>(PR_CONVERSATION_INDEX);
	if (bv != nullptr && encode64(bv->pb, bv->cb, tmp_buff,
	    sizeof(tmp_buff), &out_len) == 0)
		pmime->set_field("Thread-Index", tmp_buff);
	std::string t_addr;
	try {
		t_addr = "\""s + mime_from + "\" <" + username + ">";
		pmime->set_field("From", t_addr.c_str());
		t_addr = "<"s + username + ">";
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1479: ENOMEM");
		return false;
	}
	auto str = pbrief->proplist.get<const char>(PR_SENT_REPRESENTING_NAME);
	if (str != nullptr && *str != '\0') {
		strcpy(mime_to, "\"=?utf-8?b?");
		encode64(str, strlen(str), mime_to + 11,
			sizeof(mime_to) - 15, &out_len);
		strcpy(mime_to + 11 + out_len, "?=\"");
	} else {
		mime_to[0] = '\0';
	}
	str = pbrief->proplist.get<char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr) {
		out_len = strlen(mime_to);
		if (0 != out_len) {
			mime_to[out_len++] = ' ';
		}
		snprintf(mime_to + out_len, sizeof(mime_to) - out_len, "<%s>", str);
	}
	if ('\0' != mime_to[0]) {
		pmime->set_field("To", mime_to);
	}
	pmime->set_field("MIME-Version", "1.0");
	pmime->set_field("X-Auto-Response-Suppress", "All");
	time(&cur_time);
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", subject);
	pmime = pmail->add_child(phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		return FALSE;
	}
	pmime->set_content_type(content_type);
	pmime->set_content_param("charset", "\"utf-8\"");
	if (!pmime->write_content(content_buff,
	    strlen(content_buff), mime_encoding::automatic))
		return FALSE;

	DSN dsn;
	auto pdsn_fields = dsn.get_message_fields();
	try {
		t_addr = "rfc822;"s + username;
		dsn.append_field(pdsn_fields, "Final-Recipient", t_addr.c_str());
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1480: ENOMEM");
		return false;
	}
	if (strcmp(bounce_type, "BOUNCE_NOTIFY_READ") == 0)
		dsn.append_field(pdsn_fields, "Disposition",
			"automatic-action/MDN-sent-automatically; displayed");
	else if (strcmp(bounce_type, "BOUNCE_NOTIFY_NON_READ") == 0)
		dsn.append_field(pdsn_fields, "Disposition",
			"manual-action/MDN-sent-automatically; deleted");
	str = pbrief->proplist.get<char>(PR_INTERNET_MESSAGE_ID);
	if (str != nullptr)
		dsn.append_field(pdsn_fields, "Original-Message-ID", str);
	bv = pbrief->proplist.get<BINARY>(PR_PARENT_KEY);
	if (bv != nullptr) {
		encode64(bv->pb, bv->cb, tmp_buff, arsizeof(tmp_buff), &out_len);
		dsn.append_field(pdsn_fields,
			"X-MSExch-Correlation-Key", tmp_buff);
	}
	if ('\0' != mime_from[0]) {
		dsn.append_field(pdsn_fields, "X-Display-Name", mime_from);
	}
	if (dsn.serialize(content_buff, GX_ARRAY_SIZE(content_buff))) {
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/disposition-notification");
			pmime->write_content(content_buff,
				strlen(content_buff), mime_encoding::none);
		}
	}
	return TRUE;
}
