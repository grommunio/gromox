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
    char *mime_from, std::string &subject, std::string &content) try
{
	void *pvalue;
	char charset[32], date_buff[128], lang[32];

	charset[0] = '\0';
	if (common_util_get_user_lang(from, lang, std::size(lang)))
		gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
	rfc1123_dstring(date_buff, std::size(date_buff), 0);
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
	auto cl_1 = make_scope_exit([&]() { HXmc_free(replaced); });
	content = replaced;
	subject = tp.subject;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1219: ENOMEM");
	return false;
}

BOOL exmdb_bouncer_make(const char *from, const char *rcpt, sqlite3 *psqlite,
    uint64_t message_id, const char *bounce_type, MAIL *pmail) try
{
	MIME *pmime;
	char mime_from[UADDR_SIZE], date_buff[128];
	std::string subject, content_buff;
	
	if (!exmdb_bouncer_make_content(from, rcpt,
	    psqlite, message_id, bounce_type, mime_from,
	    subject, content_buff))
		return FALSE;
	auto phead = pmail->add_head();
	if (phead == nullptr)
		return FALSE;
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "delivery-status");
	pmime->set_field("From", mime_from);
	pmime->set_field("To", ("<"s + from + ">").c_str());
	pmime->set_field("MIME-Version", "1.0");
	pmime->set_field("X-Auto-Response-Suppress", "All");
	rfc1123_dstring(date_buff, std::size(date_buff), 0);
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", subject.c_str());
	pmime = pmail->add_child(phead, MIME_ADD_FIRST);
	if (pmime == nullptr)
		return FALSE;
	pmime->set_content_type("text/plain");
	pmime->set_content_param("charset", "utf-8");
	if (!pmime->write_content(content_buff.c_str(),
	    content_buff.size(), mime_encoding::automatic))
		return FALSE;

	DSN dsn;
	auto pdsn_fields = dsn.get_message_fields();
	auto mta = "dns;"s + get_host_ID();
	auto t_addr = "rfc822;"s + rcpt;
	dsn.append_field(pdsn_fields, "Reporting-MTA", mta.c_str());
	rfc1123_dstring(date_buff, std::size(date_buff), 0);
	dsn.append_field(pdsn_fields, "Arrival-Date", date_buff);
	pdsn_fields = dsn.new_rcpt_fields();
	if (pdsn_fields == nullptr)
		return FALSE;
	dsn.append_field(pdsn_fields, "Final-Recipient", t_addr.c_str());
	dsn.append_field(pdsn_fields, "Action", "failed");
	dsn.append_field(pdsn_fields, "Status", "5.0.0");
	dsn.append_field(pdsn_fields, "Remote-MTA", mta.c_str());
	
	content_buff.clear();
	content_buff.resize(256 * 1024);
	if (dsn.serialize(content_buff.data(), content_buff.size())) {
		content_buff.resize(strnlen(content_buff.c_str(), content_buff.size()));
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/delivery-status");
			pmime->write_content(content_buff.c_str(),
				content_buff.size(), mime_encoding::none);
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}
