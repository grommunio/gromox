#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/hook_common.h>
#include "util.h"
#include <stdio.h>
#include <pthread.h>


#define HTML_01	\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\r\n\
<HTML><HEAD><STYLE TYPE=\"text/css\">\r\n\
<!--\r\n\
BODY {FONT-SIZE: 8pt; FONT-FAMILY: sans-serif, Verdana, Arial, Helvetica}\r\n\
TD {FONT-SIZE: 8pt; FONT-FAMILY: sans-serif, Verdana, Arial, Helvetica}\r\n\
A:active {COLOR: #3b53b1; TEXT-DECORATION: none}\r\n\
A:link {COLOR: #3b53b1; TEXT-DECORATION: none}\r\n\
A:visited {COLOR: #0000ff; TEXT-DECORATION: none}\r\n\
A:hover {COLOR: #0000ff; TEXT-DECORATION: underline}\r\n\
.TableTitle {FONT-WEIGHT: bold; FONT-SIZE: 10pt; FILTER:\r\n\
dropshadow(color=#000000,offx=2,offy=2); COLOR: #0b77d3; TEXT-ALIGN: center}\r\n\
.OddRow {MARGIN-LEFT: 5px; MARGIN-RIGHT: 5px; BACKGROUND-COLOR: #ffffff}\r\n\
.EvenRow {MARGIN-LEFT: 5px; MARGIN-RIGHT: 5px; BACKGROUND-COLOR: #f3f6f8}\r\n\
.SolidRow {FONT-WEIGHT: bold; MARGIN-LEFT: 5px; MARGIN-RIGHT:\r\n\
5px; BACKGROUND-COLOR: #d9d9d9}\r\n\
.ReportTitle {FONT-WEIGHT: bold; FONT-SIZE: 13pt; COLOR: #ffffff}\r\n\
-->\r\n\
</STYLE><TITLE>spam statistic</TITLE>\r\n\
<META http-equiv=Content-Type content=\"text/html; charset=us-ascii\"></HEAD>\r\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\r\n\
marginheight=\"0\" marginwidth=\"0\">\r\n\
<CENTER><TABLE cellSpacing=0 cellPadding=0 width=\"90%\" border=0>\r\n\
<TBODY><TR><TD cellPadding=3 class=TableTitle noWrap align=middle>Spam Statistics</TD>\r\n\
</TR><TR bgColor=#bfbfbf><TD colSpan=2><TABLE cellSpacing=1\r\n\
cellPadding=2 width=\"100%\" border=0><TBODY>"

#define HTML_02		\
"</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR>\r\n\
<TABLE width=\"90%\" border=0 cellpadding=1 cellspacing=1><TR>\r\n\
<TD height=\"23\" align=\"left\" nowrap>\r\n"

#define HTML_03		"</TD></TR></TABLE><P></P><BR></CENTER></BODY></HTML>"

#define HTML_TB_SMTP		"<TR class=SolidRow><TD colSpan=2>&nbsp; smtp forms (time range: "
#define HTML_TB_DELIVERY	"<TR class=SolidRow><TD colSpan=2>&nbsp; delivery forms (time range: "
#define HTML_TB_END			")</TD></TR>\r\n"
#define HTML_TBITEM_ODD_1	"<TR class=OddRow><TD width=\"25%\">&nbsp; "
#define HTML_TBITEM_EVEN_1	"<TR class=EvenRow><TD width=\"100%\">&nbsp; "
#define HTML_TBITEM_2		"&nbsp;</TD><TD noWrap width=\"0%\">&nbsp; "
#define HTML_TBITEM_3		"</TD></TR>\r\n"
#define HTML_CHART_32	"<IMG src=\"cid:000001c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_16	"<IMG src=\"cid:000901c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_8	"<IMG src=\"cid:000801c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_4	"<IMG src=\"cid:000701c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_2	"<IMG src=\"cid:000601c695cb$9bc53450$6601a8c0@herculiz\">"
#define HTML_CHART_1	"<IMG src=\"cid:000501c695cb$9bc53450$6601a8c0@herculiz\">"

#define SPAM_TAG_LEN        40
#define SPAM_TABLE_SIZE     4096

typedef BOOL (*CONSOLE_CONTROL)(const char *, char *, int);

typedef struct _STATISTIC_ITEM {
	char	tag[SPAM_TAG_LEN];
	int		number;
} STATISTIC_ITEM;

DECLARE_API;

static CONSOLE_CONTROL smtp_console_control;
static CONSOLE_CONTROL delivery_console_control;
static void* thread_work_func(void *arg);

static BOOL g_notify_stop;
static pthread_t g_thread_id;


BOOL HOOK_LibMain(int reason, void **ppdata)
{
	pthread_attr_t attr;
	
	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		g_notify_stop = TRUE;
		smtp_console_control = query_service("smtp_console_control");
		if (NULL == smtp_console_control) {
			printf("[report_forms]: failed to get service \"smtp_console_control\"\n");
			return FALSE;
		}
		delivery_console_control = query_service("delivery_console_control");
		if (NULL == delivery_console_control) {
			printf("[report_forms]: failed to get service \"delivery_console_control\"\n");
			return FALSE;
		}
		
		g_notify_stop = FALSE;
		pthread_attr_init(&attr);
		int ret = pthread_create(&g_thread_id, &attr, thread_work_func, nullptr);
		if (ret != 0) {
			pthread_attr_destroy(&attr);
			g_notify_stop = TRUE;
			printf("[report_forms]: failed to create thread: %s\n", strerror(ret));
			return FALSE;
		}
		pthread_setname_np(g_thread_id, "report_forms");
		pthread_attr_destroy(&attr);
        return TRUE;
    case PLUGIN_FREE:
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_cancel(g_thread_id);
		}
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}

static void* thread_work_func(void *arg)
{
	time_t cur_time;
	struct tm *ptime;
	struct tm time_buff;
	
	time(&cur_time);
	ptime = localtime_r(&cur_time, &time_buff);
	sleep(24*60*60 - ptime->tm_sec - 60*ptime->tm_min - 60*60*ptime->tm_hour);
	while (FALSE == g_notify_stop) {
		sleep(600);
		time(&cur_time);
		ptime = localtime_r(&cur_time, &time_buff);
		sleep(24*60*60 - ptime->tm_sec - 60*ptime->tm_min - 
			60*60*ptime->tm_hour);
	}
	return NULL;
}
