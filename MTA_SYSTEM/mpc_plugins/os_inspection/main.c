#include "hook_common.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/vfs.h>

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
<TITLE>Gateway Dispatch Alarm</TITLE>\
<META http-equiv=Content-Type content=\"text/html; charset=us-ascii\">\r\n\
<META content=\"MSHTML 6.00.2900.2912\" name=GENERATOR></HEAD>\r\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\r\n\
marginheight=\"0\" marginwidth=\"0\">\r\n<CENTER><BR>\r\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0> <TBODY><TR>\r\n\
<TD><P></P><BR><P></P><BR><P></P><BR><BR>\r\n"

#define HTML_02     \
"</TD></TR></TBODY></TABLE><P></P><BR>\
<P></P><BR></CENTER></BODY></HTML>"

DECLARE_API;

static void* thread_work_func(void *arg);

static void alarm_message(const char *content);

static BOOL g_notify_stop = TRUE;
static pthread_t g_thread_id;
static time_t g_fs_alarm_time = 0;
static int g_fs_alarm_percentage;
static time_t g_mem_alarm_time = 0;
static int g_mem_alarm_percentage;
static int g_alarm_interval;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char temp_buff[32];
	char file_name[256], tmp_path[256];
	char *psearch, *str_val;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(tmp_path);
		if (NULL == pfile) {
			printf("[os_inspection]: error to open config file!!!\n");
			return FALSE;
		}
		str_val = config_file_get_value(pfile, "ALARM_INTERVAL");
		if (NULL == str_val) {
			g_alarm_interval = 1800;
			config_file_set_value(pfile, "ALARM_INTERVAL", "30minutes");
		} else {
			g_alarm_interval = atoitvl(str_val);
			if (g_alarm_interval <= 0) {
				g_alarm_interval = 1800;
				config_file_set_value(pfile, "ALARM_INTERVAL", "30minutes");
			}
		}
		itvltoa(g_alarm_interval, temp_buff);
		printf("[os_inspection]: alarm interval is %s\n", temp_buff);
		
		str_val = config_file_get_value(pfile, "PARTITION_QUOTA_PERCENTAGE");
		if (NULL == str_val) {
			g_fs_alarm_percentage = 85;
			config_file_set_value(pfile, "PARTITION_QUOTA_PERCENTAGE", "85");
		} else {
			g_fs_alarm_percentage = atoi(str_val);
			if (g_fs_alarm_percentage > 100 ||
				g_fs_alarm_percentage <= 0) {
				g_fs_alarm_percentage = 85;
				config_file_set_value(pfile, "PARTITION_QUOTA_PERCENTAGE", "85");
			}
		}
		printf("[os_inspection]: partition quota alarm percentage is %d%%\n",
			g_fs_alarm_percentage);

		
		str_val = config_file_get_value(pfile, "SWAP_QUOTA_PERCENTAGE");
		if (NULL == str_val) {
			g_mem_alarm_percentage = 50;
			config_file_set_value(pfile, "SWAP_QUOTA_PERCENTAGE", "50");
		} else {
			g_mem_alarm_percentage = atoi(str_val);
			if (g_mem_alarm_percentage > 100 ||
				g_mem_alarm_percentage <= 0) {
				g_mem_alarm_percentage = 50;
				config_file_set_value(pfile, "SWAP_QUOTA_PERCENTAGE", "50");
			}
		}
		printf("[os_inspection]: swap quota alarm percentage is %d%%\n",
			g_mem_alarm_percentage);
		
		config_file_save(pfile);
		config_file_free(pfile);
		
		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_thread_id, NULL, thread_work_func, NULL)) {
			g_notify_stop = TRUE;
			printf("[os_inspection]: fail to create thread\n");
			return FALSE;
		}
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
	FILE *fp;
	int percentage;
	char *ptr1, *ptr2;
	char temp_line[1024];
	char tmp_buff[512];
	time_t current_time;
	struct statfs fs_stat;
	double total, used, unused;
	
	while (FALSE == g_notify_stop) {
		sleep(180);
		
		time(&current_time);
		fp = fopen("/etc/mtab", "r");
		if (NULL == fp) {
			continue;
		}
		while (NULL != fgets(temp_line, 1024, fp)) {
			temp_line[1023] = '\0';
			ptr1 = strchr(temp_line, ' ');
			if (NULL == ptr1) {
				continue;
			}
			ptr1 ++;
			ptr2 = strchr(ptr1, ' ');
			if (NULL == ptr2) {
				continue;
			}
			*ptr2 = '\0';
			if (0 != statfs(ptr1, &fs_stat)) {
				continue;
			}
			unused = ((double)fs_stat.f_bsize)*fs_stat.f_bfree;
			total = ((double)fs_stat.f_bsize)*fs_stat.f_blocks;
			if (0 == total) {
				continue;
			}
			percentage = 100 - 100*unused/total;
			if (percentage >= g_fs_alarm_percentage &&
				current_time - g_fs_alarm_time > g_alarm_interval) {
				g_fs_alarm_time = current_time;
				sprintf(tmp_buff, "%d%% disk space has been used"
					" up in mount point %s on host %s, please check it ASAP!!!",
					percentage, ptr1, get_host_ID());
				alarm_message(tmp_buff);
			}
		}
		fclose(fp);
		
		fp = fopen("/proc/swaps", "r");
		if (NULL == fp) {
			continue;
		}
		/* ignore first line */
		fgets(temp_line, 1024, fp);
		while (NULL != fgets(temp_line, 1024, fp)) {
			temp_line[1023] = '\0';
			ptr1 = temp_line;
			while (*ptr1 != ' ' && *ptr1 != '\t') {
				ptr1 ++;
			}
			while (*ptr1 == ' ' || *ptr1 == '\t') {
				ptr1 ++;
			}
			while (*ptr1 != ' ' && *ptr1 != '\t') {
				ptr1 ++;
			}
			while (*ptr1 == ' ' || *ptr1 == '\t') {
				ptr1 ++;
			}
			ptr2 = ptr1;
			while (*ptr2 != ' ' && *ptr2 != '\t') {
				ptr2 ++;
			}
			*ptr2 = '\0';
			total = atof(ptr1);
			if (0 == total) {
				continue;
			}
			ptr1 = ptr2 + 1;
			while (*ptr1 == ' ' || *ptr1 == '\t') {
				ptr1 ++;
			}
			ptr2 = ptr1;
			while (*ptr2 != ' ' && *ptr2 != '\t') {
				ptr2 ++;
			}
			*ptr2 = '\0';
			used = atof(ptr1);
			percentage = 100*used/total;
			if (percentage >= g_mem_alarm_percentage &&
				current_time - g_mem_alarm_time > g_alarm_interval) {
				g_mem_alarm_time = current_time;
				sprintf(tmp_buff, "Swap partition on host %s is over "
					"loaded, %d%% has been used up, if it continues, "
					"system will be shut down!!!", get_host_ID(), percentage);
				alarm_message(tmp_buff);
			}
		}
		fclose(fp);
		
	}
	return NULL;
}

/*
	
 */

static void alarm_message(const char *content)
{
	int offset, len;
	char *pdomain;
	char tmp_buff[4096];
	time_t current_time;
	struct tm time_buff;
	MESSAGE_CONTEXT *pcontext;
	MIME *pmime, *pmime_child;
	
	time(&current_time);
	pcontext = get_context();
	if (NULL == pcontext) {
		return;
	}
	pcontext->pcontrol->need_bounce = FALSE;
	pdomain = strchr(get_admin_mailbox(), '@');
	if (NULL == pdomain) {
		put_context(pcontext);
		return;
	}
	if (0 == strcasecmp(pdomain, get_default_domain())) {
		strcpy(pcontext->pcontrol->from, "inspection-alarm@system.mail");
	} else {
		sprintf(pcontext->pcontrol->from, "inspection-alarm@%s",
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
		
	len = strlen(content);
	memcpy(tmp_buff + offset, content, len);
	offset += len;
	
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
	sprintf(tmp_buff,"Operation System Inspection Alarm form %s!!!",
		get_host_ID());
	mime_set_field(pmime, "Subject", tmp_buff);
	enqueue_context(pcontext);
}

