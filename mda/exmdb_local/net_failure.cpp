// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <cstring>
#include <ctime>
#include <gromox/defs.h>
#include <gromox/hook_common.h>
#include <gromox/util.hpp>
#include <libHX/string.h>
#include <mutex>
#include "exmdb_local.hpp"
#define HTML_01 \
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\r\n\
<HTML><HEAD>\
<STYLE TYPE=\"text/css\"><!--\r\n\
BODY {FONT-SIZE: 10pt;FONT-WEIGHT: bold;COLOR: #ff0000;\r\n\
FONT-FAMILY: sans-serif, Verdana, Arial, Helvetica}\r\n\
TD {FONT-SIZE: 8pt; FONT-FAMILY: sans-serif, Verdana, Arial, Helvetica}\r\n\
A:active {COLOR: #3b53b1; TEXT-DECORATION: none}\r\n\
A:link {COLOR: #3b53b1; TEXT-DECORATION: none}\r\n\
A:visited {COLOR: #0000ff; TEXT-DECORATION: none}\r\n\
A:hover {COLOR: #0000ff; TEXT-DECORATION: underline}\r\n\
.AlarmTitle {FONT-WEIGHT: bold; FONT-SIZE: 13pt; COLOR: #ffffff}\r\n\
--></STYLE>\r\n\
<TITLE>Local Delivery Alarm</TITLE>\
<META http-equiv=Content-Type content=\"text/html; charset=us-ascii\">\r\n\
<META content=\"MSHTML 6.00.2900.2912\" name=GENERATOR></HEAD>\r\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\r\n\
marginheight=\"0\" marginwidth=\"0\">\r\n<CENTER><BR>\r\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0> <TBODY><TR>\r\n\
<TD><P></P><BR><P></P><BR><P></P><BR><BR>\r\n"

#define HTML_02     \
"</TD></TR></TBODY></TABLE><P></P><BR>\
<P></P><BR></CENTER></BODY></HTML>"

#define BOUND_ALARM				6

using namespace gromox;

static int g_times;
static int g_interval;
static time_t g_last_check_point;
static time_t g_last_alarm_time;
static int g_alarm_interval;
static int g_fail_accumulating;
static int g_total_fail;
static int g_OK_num;
static int g_temp_fail_num;
static int g_permanent_fail_num;
static int g_nouser_num;
static BOOL g_turnoff_alarm;
static std::mutex g_lock;

void net_failure_init(int times, int interval, int alarm_interval)
{
	g_times = times;
	g_interval = interval;
	g_fail_accumulating = 0;
	g_total_fail = 0;
	g_OK_num = 0;
	g_temp_fail_num = 0;
	g_permanent_fail_num = 0;
	g_nouser_num = 0;
	g_turnoff_alarm = FALSE;
	g_last_alarm_time = 0;
	g_alarm_interval = alarm_interval;
}

int net_failure_run()
{
	time(&g_last_check_point);
	return 0;
}

void net_failure_free()
{
	g_times = 0;
    g_interval = 0;
    g_fail_accumulating = 0;
	g_total_fail = 0;
    g_OK_num = 0;
    g_temp_fail_num = 0;
    g_permanent_fail_num = 0;
    g_nouser_num = 0;
	g_last_alarm_time = 0;
	g_alarm_interval = 0;
}

void net_failure_statistic(int OK_num, int temp_fail, int permanent_fail,
    int nouser_num) try
{
	BOOL need_alarm_one, need_alarm_two;
	MESSAGE_CONTEXT *pcontext;
	struct tm *datetime;
	struct tm time_buff;
	char tmp_buff[4096];
	time_t current_time;
	int offset;

	need_alarm_one = FALSE;
	need_alarm_two = FALSE;
    time(&current_time);
	std::unique_lock hold(g_lock);
	g_OK_num += OK_num;
	g_temp_fail_num += temp_fail;
	g_permanent_fail_num += permanent_fail;
	g_nouser_num += nouser_num;
	if (0 != OK_num) {
		g_total_fail = 0;
	} else {
		g_total_fail += temp_fail;
	}
	if (g_total_fail >= g_times && !g_turnoff_alarm)
		need_alarm_one = TRUE;
	g_fail_accumulating += temp_fail;
	if (current_time - g_last_check_point > g_interval) {
		g_fail_accumulating = 0;
	        g_last_check_point = current_time;
	} else if (g_fail_accumulating > g_times) {
		if (!g_turnoff_alarm)
			need_alarm_two = TRUE;
		g_fail_accumulating = 0;
		g_last_check_point = current_time;
	}
	hold.unlock();
	
	if (!need_alarm_one && !need_alarm_two)
		return;
	if (current_time - g_last_alarm_time < g_alarm_interval) {
		return;
	} else {
		g_last_alarm_time = current_time;
	}
	pcontext = get_context();
	if (NULL == pcontext) {
		return;
	}
	pcontext->ctrl.bound_type = BOUND_ALARM;
	pcontext->ctrl.need_bounce = FALSE;
	auto pdomain = strchr(get_admin_mailbox(), '@');
	if (NULL == pdomain) {
		put_context(pcontext);
		return;
	}
	if (0 == strcasecmp(pdomain, get_default_domain())) {
		gx_strlcpy(pcontext->ctrl.from, "local-alarm@system.mail", std::size(pcontext->ctrl.from));
	} else {
		sprintf(pcontext->ctrl.from, "local-alarm@%s",
		        get_default_domain());
	}
	pcontext->ctrl.rcpt.emplace_back(get_admin_mailbox());
	auto pmime = pcontext->mail.add_head();
	if (NULL == pmime) {
		put_context(pcontext);
		return;
	}
	pmime->set_content_type("multipart/related");
	auto pmime_child = pcontext->mail.add_child(pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}

	pmime_child->set_content_type("text/html");
	pmime_child->set_content_param("charset", "\"us-ascii\"");
	memcpy(tmp_buff, HTML_01, sizeof(HTML_01) - 1);
	offset = sizeof(HTML_01) - 1;

	if (need_alarm_one) {
		offset += sprintf(tmp_buff + offset, "  The local delivery of %s "
		          "failed %d times in a row.\r\n"
		          "<P></P><BR><P></P><BR><P></P><BR>Alarm time: ",
		          get_host_ID(), g_times);
	} else {
		offset += sprintf(tmp_buff + offset, "  The local delivery of %s "
		          "failed %d times within ", get_host_ID(),
		          g_times);
		HX_unit_seconds(&tmp_buff[offset], std::size(tmp_buff) - offset, g_interval, 0);
		offset += strlen(tmp_buff + offset);
		strcpy(tmp_buff + offset, "\r\n<P></P><BR><P></P><BR><P></P><BR>Alarm time: ");
		offset += strlen(tmp_buff + offset);
	}
	datetime = localtime_r(&current_time, &time_buff);
	offset += strftime(tmp_buff + offset, 255, "%x %X", datetime);
	tmp_buff[offset++] = '\r';
	tmp_buff[offset++] = '\n';
	memcpy(tmp_buff + offset, HTML_02, sizeof(HTML_02) - 1);
	offset += sizeof(HTML_02) - 1;
	pmime_child->write_content(tmp_buff, offset, mime_encoding::none);
	pmime->set_field("From", pcontext->ctrl.from);
	pmime->set_field("To", get_admin_mailbox());
	strftime(tmp_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
	         localtime_r(&current_time, &time_buff));
	pmime->set_field("Date", tmp_buff);
	snprintf(tmp_buff, std::size(tmp_buff), "Local Delivery Alarm from %s", get_host_ID());
	pmime->set_field("Subject", tmp_buff);
	enqueue_context(pcontext);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1083: ENOMEM");
}
