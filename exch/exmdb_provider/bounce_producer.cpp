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
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"

using namespace gromox;

static std::string exmdb_bouncer_attachs(sqlite3 *psqlite, uint64_t message_id)
{
	std::string r;
	void *pvalue;
	char sql_string[256];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT attachment_id FROM "
	        "attachments WHERE message_id=%llu", static_cast<unsigned long long>(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return 0;
	while (pstmt.step() == SQLITE_ROW) {
		auto attachment_id = pstmt.col_uint64(0);
		if (!cu_get_property(MAPI_ATTACH, attachment_id, CP_ACP,
		    psqlite, PR_ATTACH_LONG_FILENAME, &pvalue))
			return 0;
		if (NULL == pvalue) {
			continue;
		}
		if (!r.empty())
			r += bounce_gen_sep();
		r += static_cast<const char *>(pvalue);
	}
	return r;
}

BOOL exmdb_bouncer_make_content(const char *from, const char *rcpt,
    sqlite3 *psqlite, uint64_t message_id, const char *bounce_type,
    char *mime_from, char *subject, char *content_type, char *pcontent,
    size_t content_size) try
{
	void *pvalue;
	time_t cur_time;
	char charset[32];
	char date_buff[128];
	struct tm time_buff;
	int len;
	char lang[32], time_zone[64];

	time(&cur_time);
	charset[0] = '\0';
	time_zone[0] = '\0';
	if (common_util_get_user_lang(from, lang, arsizeof(lang))) {
		gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
		common_util_get_timezone(from, time_zone, arsizeof(time_zone));
	}
	if('\0' != time_zone[0]) {
		auto sp = tz::tzalloc(time_zone);
		if (NULL == sp) {
			return FALSE;
		}
		tz::localtime_rz(sp, &cur_time, &time_buff);
		tz::tzfree(sp);
	} else {
		localtime_r(&cur_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP,
	    psqlite, PR_MESSAGE_SIZE, &pvalue) || pvalue == nullptr)
		return FALSE;
	auto message_size = *static_cast<uint32_t *>(pvalue);
	if ('\0' == charset[0]) {
		if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP, psqlite,
		    PR_INTERNET_CPID, &pvalue))
			return FALSE;
		if (NULL == pvalue) {
			strcpy(charset, "ascii");
		} else {
			auto pcharset = cpid_to_cset(static_cast<cpid_t>(*static_cast<uint32_t *>(pvalue)));
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
	    HXformat_add(fa, "rcpt", rcpt, HXTYPE_STRING) < 0)
		return false;
	if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP, psqlite,
	    PR_SUBJECT, &pvalue))
		return FALSE;
	if (HXformat_add(fa, "subject", pvalue != nullptr ?
	    static_cast<const char *>(pvalue) : "", HXTYPE_STRING) < 0 ||
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
	gx_strlcpy(pcontent, replaced, content_size);
	HXmc_free(replaced);
	if (NULL != mime_from) {
		strcpy(mime_from, tp.from.c_str());
	}
	if (NULL != subject) {
		strcpy(subject, tp.subject.c_str());
	}
	if (NULL != content_type) {
		strcpy(content_type, tp.content_type.c_str());
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1219: ENOMEM");
	return false;
}

BOOL exmdb_bouncer_make(const char *from, const char *rcpt, sqlite3 *psqlite,
    uint64_t message_id, const char *bounce_type, MAIL *pmail)
{
	MIME *pmime;
	time_t cur_time;
	char subject[1024];
	struct tm time_buff;
	char mime_from[UADDR_SIZE];
	char tmp_buff[1024];
	char date_buff[128];
	char content_type[128];
	char content_buff[256*1024];
	
	if (!exmdb_bouncer_make_content(from, rcpt,
	    psqlite, message_id, bounce_type, mime_from,
	    subject, content_type, content_buff, std::size(content_buff)))
		return FALSE;
	auto phead = pmail->add_head();
	if (NULL == phead) {
		return FALSE;
	}
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "delivery-status");
	pmime->set_field("Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	pmime->set_field("From", mime_from);
	snprintf(tmp_buff, UADDR_SIZE + 2, "<%s>", from);
	pmime->set_field("To", tmp_buff);
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
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn.append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	dsn.append_field(pdsn_fields, "Arrival-Date", date_buff);
	pdsn_fields = dsn.new_rcpt_fields();
	if (NULL == pdsn_fields) {
		return FALSE;
	}
	snprintf(tmp_buff, 1024, "rfc822;%s", rcpt);
	dsn.append_field(pdsn_fields, "Final-Recipient", tmp_buff);
	dsn.append_field(pdsn_fields, "Action", "failed");
	dsn.append_field(pdsn_fields, "Status", "5.0.0");
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn.append_field(pdsn_fields, "Remote-MTA", tmp_buff);
	
	if (dsn.serialize(content_buff, GX_ARRAY_SIZE(content_buff))) {
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/delivery-status");
			pmime->write_content(content_buff,
				strlen(content_buff), mime_encoding::none);
		}
	}
	return TRUE;
}
