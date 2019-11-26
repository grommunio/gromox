#include "hook_common.h"
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

typedef BOOL (*CONSOLE_CONTROL)(char*, char*, int);

typedef struct _STATISTIC_ITEM {
	char	tag[SPAM_TAG_LEN];
	int		number;
} STATISTIC_ITEM;

DECLARE_API;

static CONSOLE_CONTROL smtp_console_control;
static CONSOLE_CONTROL delivery_console_control;
static void do_statistic();
static void* thread_work_func(void *arg);
static int buffer_extractor(char *buff_in, STATISTIC_ITEM *pitem);
static int time_extractor(char *buff_in, char *buff_out);
static char* html_reactor(STATISTIC_ITEM *pitem, int num, int max_val, char *buff_out);

static BOOL g_notify_stop;
static pthread_t g_thread_id;


BOOL HOOK_LibMain(int reason, void **ppdata)
{
	pthread_attr_t attr;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		g_notify_stop = TRUE;
		smtp_console_control = query_service("smtp_console_control");
		if (NULL == smtp_console_control) {
			printf("[report_forms]: fail to get service "
				"\"smtp_console_control\"\n");
			return FALSE;
		}
		delivery_console_control = query_service("delivery_console_control");
		if (NULL == delivery_console_control) {
			printf("[report_forms]: fail to get service "
				"\"delivery_console_control\"\n");
			return FALSE;
		}
		
		g_notify_stop = FALSE;
		pthread_attr_init(&attr);
		if (0 != pthread_create(&g_thread_id, &attr, thread_work_func, NULL)) {
			pthread_attr_destroy(&attr);
			g_notify_stop = TRUE;
			printf("[report_forms]: fail to create thread\n");
			return FALSE;
		}
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
		do_statistic();
		sleep(600);
		time(&cur_time);
		ptime = localtime_r(&cur_time, &time_buff);
		sleep(24*60*60 - ptime->tm_sec - 60*ptime->tm_min - 
			60*60*ptime->tm_hour);
	}

}

static int time_extractor(char *buff_in, char *buff_out)
{
	int i, j, buff_len;

	buff_len = strlen(buff_in);
	for (i=buff_len-1,j=0; i>=0; i--) {
		if (':' == buff_in[i]) {
			j++;
			if (3 == j) {
				break;
			}
		}
	}
	if (i < 0) {
		return 0;
	}
	memcpy(buff_out, buff_in + i + 2, buff_len - i - 4);
	return buff_len - i - 4;

}
	
static void do_statistic()
{
	time_t cur_time;
	struct tm time_buff;
	int i, max_num;
	int smtp_num, delivery_num;
	int total_num, normal_num, spam_num;
	char html_buff[128*1024];
	char *pdomain, *ptr;
	char temp_buff[16*1024];
	char temp_response[16*1024];
	MESSAGE_CONTEXT *pcontext;
	MIME *pmime, *pmime_child;
	STATISTIC_ITEM items[SPAM_TABLE_SIZE];
	
	ptr = html_buff;
	memcpy(ptr, HTML_01, sizeof(HTML_01) - 1);
	ptr += sizeof(HTML_01) - 1;
	if (FALSE == smtp_console_control("spam_statistic.svc report", temp_buff,
		16*1024) || 0 != strncmp(temp_buff, "250 ", 4)) {
		return;	
	}
	smtp_console_control("spam_statistic.svc clear", temp_response, 16*1024);
	memcpy(ptr, HTML_TB_SMTP, sizeof(HTML_TB_SMTP) - 1);
	ptr += sizeof(HTML_TB_SMTP) - 1;
	ptr += time_extractor(temp_buff, ptr);
	*ptr = '-';
	ptr ++;
	time(&cur_time);
	ptr += strftime(ptr, 128, "%Y/%m/%d %H:%M:%S",
			localtime_r(&cur_time, &time_buff));
	memcpy(ptr, HTML_TB_END, sizeof(HTML_TB_END) - 1);
	ptr += sizeof(HTML_TB_END) - 1;
	
	smtp_num = buffer_extractor(temp_buff, items);
	if (0 == smtp_num) {
		return;
	}
	
	if (FALSE == delivery_console_control("spam_statistic.svc report",
		temp_buff, 16*1024) || 0 != strncmp(temp_buff, "250 ", 4)) {
		return;
	}
	delivery_console_control("spam_statistic.svc clear", temp_response, 16*1024);
	delivery_num = buffer_extractor(temp_buff, items + smtp_num);
	if (0 == delivery_num) {
		return;
	}
	max_num = items[0].number;
	for (i=1; i<smtp_num+delivery_num; i++) {
		if (items[i].number > max_num) {
			max_num = items[i].number;
		}
	}
	ptr = html_reactor(items, smtp_num, max_num, ptr);
	if (NULL == ptr) {
		return;
	}
	
	memcpy(ptr, HTML_TB_DELIVERY, sizeof(HTML_TB_DELIVERY) - 1);
	ptr += sizeof(HTML_TB_DELIVERY) - 1;
	ptr += time_extractor(temp_buff, ptr);
	*ptr = '-';
	ptr ++;
	time(&cur_time);
	ptr += strftime(ptr, 128, "%Y/%m/%d %H:%M:%S",
			localtime_r(&cur_time, &time_buff));
	memcpy(ptr, HTML_TB_END, sizeof(HTML_TB_END) - 1);
	ptr += sizeof(HTML_TB_END) - 1;
	
	ptr = html_reactor(items + smtp_num, delivery_num, max_num, ptr);
	if (NULL == ptr) {
		return;
	}
	memcpy(ptr, HTML_02, sizeof(HTML_02) - 1);
	ptr += sizeof(HTML_02) - 1;

	for (i=1, total_num=0; i<smtp_num+delivery_num; i++) {
		total_num += items[i].number;
	}
	if (0 != total_num) {
		normal_num = items[smtp_num].number;
		spam_num = total_num - normal_num;
		ptr += sprintf(ptr, "total session: %d, normal session: %d, "
					"spam session: %d, spam percentage: %5.2f%%",
					total_num, normal_num, spam_num,
					(float)spam_num/total_num*100);
	}
	
	memcpy(ptr, HTML_03, sizeof(HTML_03) - 1);
	ptr += sizeof(HTML_03) - 1;
	
	pcontext =  get_context();
	if (NULL == pcontext) {
		return;
	}
	pdomain = strchr(get_admin_mailbox(), '@');
	if (NULL == pdomain) {
		put_context(pcontext);
		return;
	}
	pdomain ++;
	if (0 == strcasecmp(pdomain, get_default_domain())) {
		strcpy(pcontext->pcontrol->from, "report-forms@system.mail");
	} else {
		sprintf(pcontext->pcontrol->from, "report-forms@%s",
			get_default_domain());
	}
	mem_file_writeline(&pcontext->pcontrol->f_rcpt_to,(void*)get_admin_mailbox());
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
	mime_set_content_param(pmime_child, "charset", "us-ascii");
	mime_write_content(pmime_child, html_buff, ptr - html_buff, 
		MIME_ENCODING_NONE);
	
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
			                "(unkown@127.0.0.1)\r\n\tby herculiz with SMTP");
	mime_set_field(pmime, "From", pcontext->pcontrol->from);
	mime_set_field(pmime, "To", get_admin_mailbox());
	sprintf(temp_buff, "Anti-spam gateway report forms from %s", get_host_ID());
	mime_set_field(pmime, "Subject", temp_buff);
	time(&cur_time);
	strftime(temp_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
		localtime_r(&cur_time, &time_buff));
	mime_set_field(pmime, "Date", temp_buff);
	enqueue_context(pcontext);
}
		
static int buffer_extractor(char *buff_in, STATISTIC_ITEM *pitem)
{
	char temp_buff[64];
	int buff_len, last_crlf;
	int  start_pos, end_pos;
	int i, j, item_num, temp_len; 
	
	buff_len = strlen(buff_in);
	for (i=0; i<buff_len; i++) {
		if ('\n' == buff_in[i]) {
			break;
		}
	}
	if (i == buff_len) {
		return 0;
	}
	start_pos = i + 1;
	for (i=buff_len-3; i>start_pos; i--) {
		if ('\n' == buff_in[i]) {
			break;
		}
	}
	if (i <= start_pos) {
		return 0;
	}
	end_pos = i;
	
	for (i=start_pos,last_crlf=start_pos-1,item_num=0; i<end_pos; i++) {
		if ('\r' == buff_in[i]) {
			for (j=i; j>last_crlf; j--) {
				if (' ' == buff_in[j]) {
					break;
				}
			}
			if (j > last_crlf) {
				memcpy(pitem->tag, buff_in + last_crlf + 1, j - last_crlf);
				pitem->tag[j - last_crlf - 1] = '\0';
				rtrim_string(pitem->tag);
				if (i - j - 1 >= 64) {
					return 0;
				}
				memcpy(temp_buff, buff_in + j + 1, i - j - 1);
				temp_buff[i - j - 1] = '\0';
				pitem->number = atoi(temp_buff);
				item_num ++;
				pitem ++;
			}
			last_crlf = i + 1;
		}
	}
	return item_num;
}

static char* html_reactor(STATISTIC_ITEM *pitem, int num, int max_val, char *buff_out)
{ 
	int i, temp_len;
	int base_val, temp_num;
	char *ptr, temp_buff[1024];
	
	ptr = buff_out;
	base_val = max_val / 64;

	for (i=0; i<num; i++,pitem++) {
		if (i % 2 != 0) {
			memcpy(ptr, HTML_TBITEM_ODD_1, sizeof(HTML_TBITEM_ODD_1) - 1);
			ptr += sizeof(HTML_TBITEM_ODD_1) - 1;
		} else {
			memcpy(ptr, HTML_TBITEM_EVEN_1, sizeof(HTML_TBITEM_EVEN_1) - 1);
			ptr += sizeof(HTML_TBITEM_EVEN_1) - 1;
		} 
		temp_len = strlen(pitem->tag);
		memcpy(ptr, pitem->tag, temp_len);
		ptr += temp_len;
		
		memcpy(ptr, HTML_TBITEM_2, sizeof(HTML_TBITEM_2) - 1);
		ptr += sizeof(HTML_TBITEM_2) - 1;
		
		ptr += sprintf(ptr, "%d", pitem->number);
				
		memcpy(ptr, HTML_TBITEM_3, sizeof(HTML_TBITEM_3) - 1);
		ptr += sizeof(HTML_TBITEM_3) - 1;
	}
	return ptr;
}

