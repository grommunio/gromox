// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include "bounce_producer.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <gromox/bounce_gen.hpp>
#include <gromox/defs.h>
#include <gromox/dsn.hpp>
#include <gromox/fileio.h>
#include <gromox/hook_common.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mime.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include <libHX/option.h>
#include <libHX/string.h>
#include <map>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <typeinfo>
#include <unistd.h>
#include <utility>

using namespace gromox;

int (*bounce_producer_check_domain)(const char *domainname);
bool (*bounce_producer_get_lang)(const char *username, char *lang, size_t);
bool (*bounce_producer_get_timezone)(const char *username, char *timezone, size_t);

int bounce_producer_run(const char *separator, const char *data_path,
    const char *bounce_grp)
{
#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "mlist_expand: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(bounce_producer_check_domain, "domain_list_query");
	E(bounce_producer_get_lang, "get_user_lang");
	E(bounce_producer_get_timezone, "get_timezone");
#undef E
	return bounce_gen_init(separator, data_path, bounce_grp) == 0 ? 0 : -1;
}

/*
 *	make a bounce mail
 *	@param
 *		bounce_type			type of bounce mail
 *		pmail [out]			bounce mail object
 */
bool mlex_bouncer_make(const char *from, const char *rcpt_to,
    MAIL *pmail_original, const char *bounce_type, MAIL *pmail) try
{
	MIME *pmime;
	time_t cur_time;
	char charset[32];
	char tmp_buff[1024];
	char date_buff[128];
	struct tm time_buff;
	int len;
	char lang[32], time_zone[64];
	
	
	time(&cur_time);
	charset[0] = '\0';
	time_zone[0] = '\0';
	auto pdomain = strchr(from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (bounce_producer_check_domain == nullptr) {
			mlog(LV_ERR, "bounce_producer: wtf, check_domain is null");
			return false;
		}
		auto lcldom = bounce_producer_check_domain(pdomain);
		if (lcldom < 0) {
			mlog(LV_ERR, "bounce_producer: check_domain: %s",
			        strerror(-lcldom));
			return false;
		}
		if (lcldom > 0) {
			if (bounce_producer_get_lang(from, lang, arsizeof(lang)))
				gx_strlcpy(charset, znul(lang_to_charset(lang)), std::size(charset));
			bounce_producer_get_timezone(from, time_zone, arsizeof(time_zone));
		}
	}
	
	if('\0' != time_zone[0]) {
		auto sp = tz::tzalloc(time_zone);
		if (sp == nullptr)
			return false;
		tz::localtime_rz(sp, &cur_time, &time_buff);
		tz::tzfree(sp);
	} else {
		localtime_r(&cur_time, &time_buff);
	}
	len = strftime(date_buff, 128, "%x %X", &time_buff);
	if ('\0' != time_zone[0]) {
		snprintf(date_buff + len, 128 - len, " %s", time_zone);
	}
	
	auto mcharset = bounce_gen_charset(*pmail_original);
	if ('\0' == charset[0]) {
		gx_strlcpy(charset, mcharset.c_str(), std::size(charset));
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
	if (HXformat_add(fa, "time", date_buff, HXTYPE_STRING | immed) < 0 ||
	    HXformat_add(fa, "from", from, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpt", rcpt_to, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpts", rcpt_to, HXTYPE_STRING) < 0)
		return false;
	auto str = bounce_gen_subject(*pmail_original, mcharset.c_str());
	if (HXformat_add(fa, "subject", str.c_str(), HXTYPE_STRING | immed) < 0)
		return false;
	str = bounce_gen_attachs(*pmail_original, mcharset.c_str());
	if (HXformat_add(fa, "parts", str.c_str(), HXTYPE_STRING | immed) < 0)
		return false;
	auto mail_len = pmail_original->get_length();
	if (mail_len < 0) {
		mlog(LV_ERR, "mlist_expand: failed to get mail length");
		mail_len = 0;
	}
	HX_unit_size(date_buff, std::size(date_buff), mail_len, 1000, 0);
	if (HXformat_add(fa, "length", date_buff, HXTYPE_STRING) < 0)
		return false;

	hxmc_t *replaced = nullptr;
	auto aprint_len = HXformat_aprintf(fa, &replaced, &tp.content[tp.body_start]);
	if (aprint_len < 0)
		return false;
	auto cl_1 = make_scope_exit([&]() { HXmc_free(replaced); });

	auto phead = pmail->add_head();
	if (NULL == phead) {
		mlog(LV_ERR, "mlist_expand: MIME pool exhausted");
		return false;
	}
	pmime = phead;
	pmime->set_content_type("multipart/report");
	pmime->set_content_param("report-type", "delivery-status");
	pmime->set_field("Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	str = bounce_gen_thrindex(*pmail_original);
	if (!str.empty())
		pmime->set_field("Thread-Index", str.c_str());
	pmime->set_field("From", tp.from.c_str());
	snprintf(tmp_buff, 256, "<%s>", from);
	pmime->set_field("To", tmp_buff);
	pmime->set_field("MIME-Version", "1.0");
	localtime_r(&cur_time, &time_buff);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z", &time_buff);
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", tp.subject.c_str());
	
	pmime = pmail->add_child(phead, MIME_ADD_FIRST);
	if (NULL == pmime) {
		mlog(LV_ERR, "mlist_expand: MIME pool exhausted");
		return false;
	}
	parse_field_value(tp.content_type.c_str(), tp.content_type.size(),
		tmp_buff, 256, &pmime->f_type_params);
	pmime->set_content_type(tmp_buff);
	pmime->set_content_param("charset", "\"utf-8\"");
	if (!pmime->write_content(replaced, aprint_len,
	    mime_encoding::automatic)) {
        mlog(LV_ERR, "mlist_expand: failed to write content");
		return false;
	}
	
	DSN dsn;
	auto pdsn_fields = dsn.get_message_fields();
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn.append_field(pdsn_fields, "Reporting-MTA", tmp_buff);
	dsn.append_field(pdsn_fields, "Arrival-Date", date_buff);
	pdsn_fields = dsn.new_rcpt_fields();
	if (NULL == pdsn_fields) {
		return false;
	}
	snprintf(tmp_buff, 1024, "rfc822;%s", rcpt_to);
	dsn.append_field(pdsn_fields, "Final-Recipient", tmp_buff);
	dsn.append_field(pdsn_fields, "Action", "failed");
	dsn.append_field(pdsn_fields, "Status", "5.0.0");
	snprintf(tmp_buff, 128, "dns;%s", get_host_ID());
	dsn.append_field(pdsn_fields, "Remote-MTA", tmp_buff);
	char original_ptr[256*1024];
	if (dsn.serialize(original_ptr, std::size(original_ptr))) {
		pmime = pmail->add_child(phead, MIME_ADD_LAST);
		if (NULL != pmime) {
			pmime->set_content_type("message/delivery-status");
			pmime->write_content(original_ptr,
				strlen(original_ptr), mime_encoding::none);
		}
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1215: ENOMEM");
	return false;
}
