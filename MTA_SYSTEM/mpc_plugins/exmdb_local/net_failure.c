#include "net_failure.h"
#include "hook_common.h"
#include <stdio.h>
#include <time.h>
#include <time.h>
#include <pthread.h>


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
static pthread_mutex_t g_lock;

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
	pthread_mutex_init(&g_lock, NULL);
	return 0;
}

int net_failure_stop()
{
	pthread_mutex_destroy(&g_lock);
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
    int nouser_num)
{
	BOOL need_alarm_one, need_alarm_two;
	MESSAGE_CONTEXT *pcontext;
	MIME *pmime, *pmime_child;
	struct tm *datetime;
	struct tm time_buff;
	char *pdomain;
	char tmp_buff[4096];
	time_t current_time;
	int offset;

	need_alarm_one = FALSE;
	need_alarm_two = FALSE;
    time(&current_time);
	pthread_mutex_lock(&g_lock);
	g_OK_num += OK_num;
	g_temp_fail_num += temp_fail;
	g_permanent_fail_num += permanent_fail;
	g_nouser_num += nouser_num;
	if (0 != OK_num) {
		g_total_fail = 0;
	} else {
		g_total_fail += temp_fail;
	}
	if (g_total_fail >= g_times && FALSE == g_turnoff_alarm) {
		need_alarm_one = TRUE;
	}
	g_fail_accumulating += temp_fail;
	if (current_time - g_last_check_point <= g_interval) {
		if (g_fail_accumulating > g_times) {
			if (FALSE == g_turnoff_alarm) {
				need_alarm_two = TRUE;
			}
			g_fail_accumulating = 0;
			g_last_check_point = current_time;
		}
	} else {
		g_fail_accumulating = 0;
        g_last_check_point = current_time;
	}
	pthread_mutex_unlock(&g_lock);
	
	if (TRUE == need_alarm_one || TRUE == need_alarm_two) {
		if (current_time - g_last_alarm_time < g_alarm_interval) {
			return;
		} else {
			g_last_alarm_time = current_time;
		}
		pcontext = get_context();
		if (NULL == pcontext) {
			return;
		}
		pcontext->pcontrol->bound_type = BOUND_ALARM;
		pcontext->pcontrol->need_bounce = FALSE;
		pdomain = strchr(get_admin_mailbox(), '@');
		if (NULL == pdomain) {
			put_context(pcontext);
			return;
		}
		if (0 == strcasecmp(pdomain, get_default_domain())) {
			strcpy(pcontext->pcontrol->from, "local-alarm@system.mail");
		} else {
			sprintf(pcontext->pcontrol->from, "local-alarm@%s",
				get_default_domain());
		}
		mem_file_writeline(&pcontext->pcontrol->f_rcpt_to,
			(char*)get_admin_mailbox());
		pmime = mail_add_head(pcontext->pmail);
		if (NULL == pmime) {
			put_context(pcontext);
			return;
		}
		mime_set_content_type(pmime, "multipart/related");
		pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
		if (NULL == pmime_child) {
			put_context(pcontext);
			return;
		}
		
		mime_set_content_type(pmime_child, "text/html");
		mime_set_content_param(pmime_child, "charset", "\"us-ascii\"");
		
		memcpy(tmp_buff, HTML_01, sizeof(HTML_01) - 1);
		offset = sizeof(HTML_01) - 1;
		
		if (TRUE == need_alarm_one) {
			offset += sprintf(tmp_buff + offset, "  The local delivery of %s "
						"has found %d times of failure and zero time of "
						"success, please check it as soon as possible!!!\r\n"
						"<P></P><BR><P></P><BR><P></P><BR>Alarm time: ",
						get_host_ID(), g_times);
		} else {
			offset += sprintf(tmp_buff + offset, "  The local delivery of %s "
						"has found %d times of failure within ", get_host_ID(),
						g_times);
			itvltoa(g_interval, tmp_buff + offset);
			offset += strlen(tmp_buff + offset);
			strcpy(tmp_buff + offset, ", please check it as soon as "
				"possible!!!\r\n<P></P><BR><P></P><BR><P></P><BR>Alarm time: ");
			offset += strlen(tmp_buff + offset);
		}
		datetime = localtime_r(&current_time, &time_buff);
        offset += strftime(tmp_buff + offset, 255, "%x %X", datetime);
		tmp_buff[offset] = '\r';
		offset ++;
		tmp_buff[offset] = '\n';
		offset ++;
		memcpy(tmp_buff + offset, HTML_02, sizeof(HTML_02) - 1);
		offset += sizeof(HTML_02) - 1;
		mime_write_content(pmime_child, tmp_buff, offset, MIME_ENCODING_NONE);
		mime_set_field(pmime, "Received", "from unknown (helo localhost) "
				"(unkown@127.0.0.1)\r\n\tby herculiz with SMTP");
		mime_set_field(pmime, "From", pcontext->pcontrol->from);
		mime_set_field(pmime, "To", get_admin_mailbox());
		strftime(tmp_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
				localtime_r(&current_time, &time_buff));
		mime_set_field(pmime, "Date", tmp_buff);
		sprintf(tmp_buff,"Local Delivery Alarm form %s!!!", get_host_ID());
		mime_set_field(pmime, "Subject", tmp_buff);
		enqueue_context(pcontext);
	}
}

int net_failure_get_param(int param)
{
	int ret_val;

	switch(param) {
	case NET_FAILURE_OK:
		pthread_mutex_lock(&g_lock);
		ret_val = g_OK_num;
		g_OK_num = 0;		
		pthread_mutex_unlock(&g_lock);
		return ret_val;
    case NET_FAILURE_TEMP:
		pthread_mutex_lock(&g_lock);
		ret_val = g_temp_fail_num;
		g_temp_fail_num = 0;
		pthread_mutex_unlock(&g_lock);
		return ret_val;
    case NET_FAILURE_PERMANENT:
		pthread_mutex_lock(&g_lock);
		ret_val = g_permanent_fail_num;
		g_permanent_fail_num = 0;
		pthread_mutex_unlock(&g_lock);
		return ret_val;
    case NET_FAILURE_NOUSER:
		pthread_mutex_lock(&g_lock);
		ret_val = g_nouser_num;
		g_nouser_num = 0;
		pthread_mutex_unlock(&g_lock);
		return ret_val;
	case NET_FAILURE_TURN_ALARM:
		return g_turnoff_alarm;
	case NET_FAILURE_STATISTIC_TIMES:
		return g_times;
	case NET_FAILURE_STATISTIC_INTERVAL:
		return g_interval;
	case NET_FAILURE_ALARM_INTERVAL:
		return g_alarm_interval;
	}
}

void net_failure_set_param(int param, int val)
{
	switch (param) {
	case NET_FAILURE_TURN_ALARM:
		g_turnoff_alarm = (BOOL)val;
		break;
	case NET_FAILURE_STATISTIC_TIMES:
		g_times = val;
		break;
	case NET_FAILURE_STATISTIC_INTERVAL:
		g_interval = val;
		break;
	case NET_FAILURE_ALARM_INTERVAL:
		g_alarm_interval = val;
		break;
	}
}
