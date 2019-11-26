#include "hook_common.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>


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
.ReportTitle {FONT-WEIGHT: bold; FONT-SIZE: 13pt; COLOR: #ffffff}\r\n\
.ChartTable {BORDER-TOP-WIDTH: 1px; BORDER-LEFT-WIDTH: 0px; \r\n\
BORDER-BOTTOM-WIDTH: 0px; BACKGROUND-COLOR: #ffffff; BORDER-RIGHT-WIDTH: 0px}\
-->\r\n\
</STYLE><TITLE>spam statistic</TITLE>\r\n\
<META http-equiv=Content-Type content=\"text/html; charset=us-ascii\"></HEAD>\r\n\
<BODY bottomMargin=0 leftMargin=0 topMargin=0 rightMargin=0\r\n\
marginheight=\"0\" marginwidth=\"0\"><CENTER>\r\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0> <TBODY><TR>\r\n\
<TD noWrap align=left height=23></TD></TR></TBODY></TABLE><BR>\r\n\
<A name=General_Statistics></A>\r\n\
<TABLE cellSpacing=1 cellPadding=2 width=\"100%\" border=0><TBODY>\r\n\
<TABLE class=ChartTable cellSpacing=0 cellPadding=2 width=\"100%\" border=0>\r\n\
<TBODY><TR><TD align=middle><CENTER>\r\n"

#define HTML_02		\
"<TABLE><TBODY><TR><TD width=80 bgColor=#ececec>hour</TD>\r\n\
<TD width=160 bgColor=#ffb055> CPU usage</TD>\r\n\
<TD width=160 bgColor=#4477dd> network transmit</TD>\r\n\
<TD width=160 bgColor=#66f0ff> connection concurrence</TD></TR>\r\n"

#define HTML_03		\
"</TBODY></TABLE><BR></CENTER></TD></TR></TBODY></TABLE></TD></TR> \
</TBODY></TABLE></TD></TR><BR></CENTER></BODY></HTML>"

#define HTML_TBCELL_BEGIN	"<TD>"
#define HTML_TBCELL_END		"</TD>\r\n"
#define HTML_TBLINE_BEGIN	"<TR>"
#define HTML_TBLINE_END		"</TR>\r\n"


#define MAX_UNIT_NUM		32

typedef struct _CPU_INFO {
	double user;
	double nice;
	double system;
	double idle;
} CPU_INFO;

typedef struct _NETWORK_INFO {
	double in;
	double out;
} NETWORK_INFO;

typedef BOOL (*CONSOLE_CONTROL)(char*, char*, int);

DECLARE_API;

static CONSOLE_CONTROL smtp_console_control;

static void do_statistic();

static void* thread_work_func(void *arg);

static void collect_service_information(int second_index, int hour_index);

static void collect_cpu_information(int time_index);

static int collect_cpu_information_ex();

static void collect_network_information(int time_index);

static int collect_network_information_ex();

static void extract_cpu(char *buff, CPU_INFO *pinfo);

static void extract_network(char *buff, NETWORK_INFO *pinfo);

static void console_talk(int argc, char **argv, char *result, int length);
	
static void *g_shm_begin = NULL;
static double *g_cpu_status;
static double *g_network_status;
static int *g_connection_status;
static CPU_INFO *g_last_cpu;
static NETWORK_INFO *g_last_network;
static int *g_connection_data;
static BOOL *g_cpu_clear;
static BOOL *g_network_clear;
static int *g_last_hour;
static int *g_thread_day;
static int *g_thread_hour;
static BOOL g_notify_stop;
static pthread_t g_thread_id;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	int shm_id;
	key_t k_shm;
	char *psearch;
	char file_name[256];
	char temp_path[256];
	BOOL new_created;
	pthread_attr_t attr;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		g_notify_stop = TRUE;
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		k_shm = ftok(temp_path, 1);
		if (-1 == k_shm) {
			printf("[status_forms]: cannot open key for share memory\n");
			return FALSE;
		}
		shm_id = shmget(k_shm, 2*sizeof(double)*24 + sizeof(int)*24 +
					sizeof(CPU_INFO)*MAX_UNIT_NUM + 
					sizeof(NETWORK_INFO)*MAX_UNIT_NUM + sizeof(int)*1200 +
					2*sizeof(BOOL) + 3*sizeof(int), 0666);
		if (-1 == shm_id) {
			shm_id = shmget(k_shm, 2*sizeof(double)*24 + sizeof(int)*24 +
						sizeof(CPU_INFO)*MAX_UNIT_NUM +
						sizeof(NETWORK_INFO)*MAX_UNIT_NUM + sizeof(int)*1200 +
						2*sizeof(BOOL) + 3*sizeof(int), 0666|IPC_CREAT);
			new_created = TRUE;
		} else {
			new_created = FALSE;
		}
		if (-1 == shm_id) {
			printf("[status_forms]: fail to get or create share memory\n");
			return FALSE;
		}
		g_shm_begin = shmat(shm_id, NULL, 0);
		if ((void*)-1 == g_shm_begin) {
			printf("[status_forms]: fail to attach share memory\n");
			g_shm_begin = NULL;
			return FALSE;
		}
		g_cpu_status = (double*)g_shm_begin;
		g_network_status = g_cpu_status + 24;
		g_connection_status = (int*)(g_network_status + 24);
		g_last_cpu = (CPU_INFO*)(g_connection_status + 24);
		g_last_network = (NETWORK_INFO*)(g_last_cpu + MAX_UNIT_NUM);
		g_connection_data = (int*)(g_last_network + MAX_UNIT_NUM);
		g_cpu_clear = (BOOL*)(g_connection_data + 1200);
		g_network_clear = g_cpu_clear + 1;
		g_last_hour = (int*)(g_network_clear + 1);
		g_thread_day = g_last_hour + 1;
		g_thread_hour = g_thread_day + 1;
		
		if (TRUE == new_created) {
			*g_cpu_clear = TRUE;
			*g_network_clear = TRUE;
			*g_last_hour = -1;
			*g_thread_day = -1;
			*g_thread_hour = -1;
		}
		
		smtp_console_control = query_service("smtp_console_control");
		if (NULL == smtp_console_control) {
			printf("[status_forms]: fail to get service "
				"\"smtp_console_control\"\n");
			return FALSE;
		}
		
		g_notify_stop = FALSE;
		pthread_attr_init(&attr);
		if (0 != pthread_create(&g_thread_id, &attr, thread_work_func, NULL)) {
			pthread_attr_destroy(&attr);
			g_notify_stop = TRUE;
			printf("[status_forms]: fail to create thread\n");
			return FALSE;
		}
		pthread_attr_destroy(&attr);
		register_talk(console_talk);
        return TRUE;
    case PLUGIN_FREE:
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_cancel(g_thread_id);
		}
		if (NULL != g_shm_begin) {
			shmdt(g_shm_begin);
			g_shm_begin = NULL;
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
	
	while (FALSE == g_notify_stop) {
		time(&cur_time);
		ptime = localtime_r(&cur_time, &time_buff);
		if (0 == ptime->tm_hour && ptime->tm_mday != *g_thread_day) {
			do_statistic();
			*g_thread_day = ptime->tm_mday;
		}
		if (ptime->tm_sec % 3 == 0) {
			collect_service_information(ptime->tm_min*20 + ptime->tm_sec/3,
				ptime->tm_hour);
		}
		if (0 == ptime->tm_min && ptime->tm_hour != *g_thread_hour) {
			collect_cpu_information(ptime->tm_hour);
			collect_network_information(ptime->tm_hour);
			*g_thread_hour = ptime->tm_hour;
		}
		sleep(1);
	}

}

static void do_statistic()
{
	int i, len;
	int max_connection;
	double max_network;
	time_t cur_time;
	struct tm time_buff;
	char html_buff[128*1024];
	char *pdomain, *ptr;
	char temp_buff[4096];
	MESSAGE_CONTEXT *pcontext;
	MIME *pmime, *pmime_child;

	ptr = html_buff;
	memcpy(ptr, HTML_01, sizeof(HTML_01) - 1);
	ptr += sizeof(HTML_01) - 1;

	max_network = 0;
	max_connection = 0;
	for (i=0; i<24; i++) {
		if (g_network_status[i] > max_network) {
			max_network = g_network_status[i];
		}
		if (g_connection_status[i] > max_connection) {
			max_connection = g_connection_status[i];
		}
	}
	
	memcpy(ptr, HTML_02, sizeof(HTML_02) - 1);
	ptr += sizeof(HTML_02) - 1;

	for (i=0 ; i<24; i++) {
		memcpy(ptr, HTML_TBLINE_BEGIN, sizeof(HTML_TBLINE_BEGIN) - 1);
		ptr += sizeof(HTML_TBLINE_BEGIN) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		if (i < 9) {
			ptr += sprintf(ptr, "0%d:00", i + 1);
		} else {
			ptr += sprintf(ptr, "%d:00", i + 1);
		}
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d%%", (int)(100*g_cpu_status[i]));
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		if (g_network_status[i] > 0xFFFFFFFF) {
			ptr += sprintf(ptr, "%dG", (int)(g_network_status[i]/0x3FFFFFFF));
		} else {
			bytetoa((size_t)g_network_status[i], ptr);
			ptr += strlen(ptr);
		}
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBCELL_BEGIN, sizeof(HTML_TBCELL_BEGIN) - 1);
		ptr += sizeof(HTML_TBCELL_BEGIN) - 1;
		ptr += sprintf(ptr, "%d", g_connection_status[i]);
		memcpy(ptr, HTML_TBCELL_END, sizeof(HTML_TBCELL_END) - 1);
		ptr += sizeof(HTML_TBCELL_END) - 1;
		memcpy(ptr, HTML_TBLINE_END, sizeof(HTML_TBLINE_END) - 1);
		ptr += sizeof(HTML_TBLINE_END) - 1;
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
		strcpy(pcontext->pcontrol->from, "status-forms@system.mail");
	} else {
		sprintf(pcontext->pcontrol->from, "status-forms@%s",
			get_default_domain());
	}
	mem_file_writeline(&pcontext->pcontrol->f_rcpt_to,
		(void*)get_admin_mailbox());
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
	mime_write_content(pmime_child, html_buff,
		ptr - html_buff, MIME_ENCODING_NONE);

	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
							"(unkown@127.0.0.1)\r\n\tby herculiz with SMTP");
	mime_set_field(pmime, "From", pcontext->pcontrol->from);
	mime_set_field(pmime, "To", get_admin_mailbox());
	len = sprintf(temp_buff, "Anti-spam gateway status forms from %s of ",
		get_host_ID());
	time(&cur_time);
	cur_time -= 3600;
	strftime(temp_buff + len, 128, "%F", localtime_r(&cur_time, &time_buff));
	mime_set_field(pmime, "Subject", temp_buff);
	time(&cur_time);
	strftime(temp_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
		localtime_r(&cur_time, &time_buff));
	mime_set_field(pmime, "Date", temp_buff);
	enqueue_context(pcontext);
}


static void collect_service_information(int second_index, int hour_index)
{
	char temp_buff[4096];
	char *ptr, *ptr1;
	int i, total_num;
	int parsing_num, flushing_num;
	
	if (FALSE == smtp_console_control("system status", temp_buff, 4095)) {
		return;
	}
	ptr = strstr(temp_buff, "current parsing contexts     ");
	if (NULL == ptr) {
		return;
	}
	ptr += 29;
	ptr1 = strchr(ptr, '\n');
	if (NULL == ptr1) {
		return;
	}
	*ptr1 = '\0';
	parsing_num = atoi(ptr);
	ptr = ptr1 + 1;
	ptr = strstr(ptr, "current flushing contexts    ");
	if (NULL == ptr) {
		return;
	}
	ptr += 29;
	ptr1 = strchr(ptr, '\n');
	if (NULL == ptr1) {
		return;
	}
	*ptr1 = '\0';
	flushing_num = atoi(ptr);
	g_connection_data[second_index] = parsing_num + flushing_num;
	if (*g_last_hour == hour_index) {
		return;
	}
	for (i=0,total_num=0; i<1200; i++) {
		total_num += g_connection_data[i];
		g_connection_data[i] = 0;
	}
	g_connection_status[hour_index] = total_num/1200;
	*g_last_hour = hour_index;
}

static void collect_cpu_information(int time_index)
{
	FILE *fp;
	int i, cpu_num;	
	CPU_INFO cpu_status;
	CPU_INFO cpu_info[MAX_UNIT_NUM];
	CPU_INFO temp_cpu[MAX_UNIT_NUM];
	char *ptr, temp_buff[4096];
	double total_cpu, total_used;

	fp = fopen("/proc/stat", "r");
	if (NULL == fp) {
		return;
	}
	cpu_num = 0;
	while (TRUE) {
		if (NULL == fgets(temp_buff, 4096, fp)) {
			break;
		}
		if (0 == strncmp(temp_buff, "cpu ", 4)) {
			continue;
		}
		if (0 == strncmp(temp_buff, "cpu", 3)) {
			ptr = strchr(temp_buff + 3, ' ');
			if (TRUE == *g_cpu_clear) {
				extract_cpu(ptr, g_last_cpu + cpu_num);
			} else {
				extract_cpu(ptr, &cpu_info[cpu_num]);
			}
			cpu_num ++;
			if (cpu_num >= MAX_UNIT_NUM) {
				break;
			}
		} else {
			break;
		}
	}
	fclose(fp);
	
	if (TRUE == *g_cpu_clear) {
		*g_cpu_clear = FALSE;
		return;
	}
	memcpy(temp_cpu, g_last_cpu, MAX_UNIT_NUM*sizeof(CPU_INFO));
	memcpy(g_last_cpu, cpu_info, MAX_UNIT_NUM*sizeof(CPU_INFO));
	for (i=0; i<cpu_num; i++) {
		cpu_info[i].user -= temp_cpu[i].user;
		if (cpu_info[i].user < 0) {
			cpu_info[i].user += 0x7FFFFFFF;
		}
		cpu_info[i].nice -= temp_cpu[i].nice;
		if (cpu_info[i].nice < 0) {
			cpu_info[i].nice += 0x7FFFFFFF;
		}
		cpu_info[i].system -= temp_cpu[i].system;
		if (cpu_info[i].system < 0) {
			cpu_info[i].system += 0x7FFFFFFF;
		}
		cpu_info[i].idle -= temp_cpu[i].idle;
		if (cpu_info[i].idle < 0) {
			cpu_info[i].system += 0x7FFFFFFF;
		}
	}
	memset(&cpu_status, 0, sizeof(CPU_INFO));
	for (i=0; i<cpu_num; i++) {
		cpu_status.user += cpu_info[i].user;
		cpu_status.nice += cpu_info[i].nice;
		cpu_status.system += cpu_info[i].system;
		cpu_status.idle += cpu_info[i].idle;
	}
	
	total_used = cpu_status.user + cpu_status.nice + cpu_status.system;
	total_cpu = total_used + cpu_status.idle;
	g_cpu_status[time_index] = total_used/total_cpu;
}

static void collect_network_information(int time_index)
{
	FILE *fp;
	int i, network_num;	
	NETWORK_INFO network_status;
	NETWORK_INFO network_info[MAX_UNIT_NUM];
	NETWORK_INFO temp_network[MAX_UNIT_NUM];
	char *ptr, *ptr1, temp_buff[4096];
	
	fp = fopen("/proc/net/dev", "r");
	if (NULL == fp) {
		return;
	}
	network_num = 0;
	memset(temp_buff, 0, 4096);
	ptr = temp_buff;
	fread(temp_buff, 4095, 1, fp);
	fclose(fp);
	while (NULL != (ptr1 = strstr(ptr, "eth")) ||
		NULL != (ptr1 = strstr(ptr, "em"))) {
		ptr = strchr(ptr1, ':') + 1;
		while (' ' == *ptr) {
			ptr ++;
		}
		ptr1 = strchr(ptr, '\n');
		if (NULL == ptr1) {
			return;
		}
		*ptr1 = '\0';
		if (TRUE == *g_network_clear) {
			extract_network(ptr, g_last_network + network_num);
		} else {
			extract_network(ptr, &network_info[network_num]);
		}
		network_num ++;
		ptr = ptr1 + 1;
		if (network_num >= MAX_UNIT_NUM) {
			break;
		}
	}
	
	if (TRUE == *g_network_clear) {
		*g_network_clear = FALSE;
		return;
	}
	memcpy(temp_network, g_last_network, MAX_UNIT_NUM*sizeof(NETWORK_INFO));
	memcpy(g_last_network, network_info, MAX_UNIT_NUM*sizeof(NETWORK_INFO));
	for (i=0; i<network_num; i++) {
		network_info[i].in -= temp_network[i].in;
		if (network_info[i].in < 0) {
			network_info[i].in += 0xFFFFFFFF;
		}
		network_info[i].out -= temp_network[i].out;
		if (network_info[i].out < 0) {
			network_info[i].out += 0xFFFFFFFF;
		}
	}
	memset(&network_status, 0, sizeof(NETWORK_INFO));
	for (i=0; i<network_num; i++) {
		network_status.in += network_info[i].in;
		network_status.out += network_info[i].out;
	}	
	g_network_status[time_index] = network_status.in + network_status.out;
}

static int collect_cpu_information_ex()
{
	FILE *fp;
	int i, cpu_num;	
	static time_t last_time = 0;
	time_t current_time;
	CPU_INFO cpu_status;
	CPU_INFO cpu_info[MAX_UNIT_NUM];
	CPU_INFO temp_cpu[MAX_UNIT_NUM];
	static CPU_INFO last_cpu[MAX_UNIT_NUM];
	char *ptr, temp_buff[4096];
	double total_cpu, total_used;

	fp = fopen("/proc/stat", "r");
	if (NULL == fp) {
		return 0;
	}
	cpu_num = 0;
	time(&current_time);
	while (TRUE) {
		if (NULL == fgets(temp_buff, 4096, fp)) {
			break;
		}
		if (0 == strncmp(temp_buff, "cpu ", 4)) {
			continue;
		}
		if (0 == strncmp(temp_buff, "cpu", 3)) {
			ptr = strchr(temp_buff + 3, ' ');
			if (current_time - last_time > 60) {
				extract_cpu(ptr, last_cpu + cpu_num);
			} else {
				extract_cpu(ptr, &cpu_info[cpu_num]);
			}
			cpu_num ++;
			if (cpu_num >= MAX_UNIT_NUM) {
				break;
			}
		} else {
			break;
		}
	}
	fclose(fp);
	
	if (current_time - last_time > 60) {
		last_time = current_time;
		return 0;
	}
	memcpy(temp_cpu, last_cpu, MAX_UNIT_NUM*sizeof(CPU_INFO));
	memcpy(last_cpu, cpu_info, MAX_UNIT_NUM*sizeof(CPU_INFO));
	for (i=0; i<cpu_num; i++) {
		cpu_info[i].user -= temp_cpu[i].user;
		if (cpu_info[i].user < 0) {
			cpu_info[i].user += 0x7FFFFFFF;
		}
		cpu_info[i].nice -= temp_cpu[i].nice;
		if (cpu_info[i].nice < 0) {
			cpu_info[i].nice += 0x7FFFFFFF;
		}
		cpu_info[i].system -= temp_cpu[i].system;
		if (cpu_info[i].system < 0) {
			cpu_info[i].system += 0x7FFFFFFF;
		}
		cpu_info[i].idle -= temp_cpu[i].idle;
		if (cpu_info[i].idle < 0) {
			cpu_info[i].system += 0x7FFFFFFF;
		}
	}
	memset(&cpu_status, 0, sizeof(CPU_INFO));
	for (i=0; i<cpu_num; i++) {
		cpu_status.user += cpu_info[i].user;
		cpu_status.nice += cpu_info[i].nice;
		cpu_status.system += cpu_info[i].system;
		cpu_status.idle += cpu_info[i].idle;
	}
	
	total_used = cpu_status.user + cpu_status.nice + cpu_status.system;
	total_cpu = total_used + cpu_status.idle;
	return (int)((total_used/total_cpu)*100);
}

static int collect_network_information_ex()
{
	FILE *fp;
	int i, network_num;	
	static time_t last_time = 0;
	time_t current_time;
	NETWORK_INFO network_status;
	NETWORK_INFO network_info[MAX_UNIT_NUM];
	NETWORK_INFO temp_network[MAX_UNIT_NUM];
	static NETWORK_INFO  last_network[MAX_UNIT_NUM];
	char *ptr, *ptr1, temp_buff[4096];
	
	fp = fopen("/proc/net/dev", "r");
	if (NULL == fp) {
		return 0;
	}
	network_num = 0;
	time(&current_time);
	memset(temp_buff, 0, 4096);
	ptr = temp_buff;
	fread(temp_buff, 4095, 1, fp);
	fclose(fp);
	while (NULL != (ptr1 = strstr(ptr, "eth")) ||
		NULL != (ptr1 = strstr(ptr, "em"))) {
		ptr = strchr(ptr1, ':') + 1;
		while (' ' == *ptr) {
			ptr ++;
		}
		ptr1 = strchr(ptr, '\n');
		if (NULL == ptr1) {
			return 0;
		}
		*ptr1 = '\0';
		if (current_time - last_time > 60) {
			extract_network(ptr, last_network + network_num);
		} else {
			extract_network(ptr, &network_info[network_num]);
		}
		network_num ++;
		ptr = ptr1 + 1;
		if (network_num >= MAX_UNIT_NUM) {
			break;
		}
	}
	
	if (current_time - last_time > 60) {
		last_time = current_time;
		return 0;
	}
	memcpy(temp_network, last_network, MAX_UNIT_NUM*sizeof(NETWORK_INFO));
	memcpy(last_network, network_info, MAX_UNIT_NUM*sizeof(NETWORK_INFO));
	for (i=0; i<network_num; i++) {
		network_info[i].in -= temp_network[i].in;
		if (network_info[i].in < 0) {
			network_info[i].in += 0xFFFFFFFF;
		}
		network_info[i].out -= temp_network[i].out;
		if (network_info[i].out < 0) {
			network_info[i].out += 0xFFFFFFFF;
		}
	}
	memset(&network_status, 0, sizeof(NETWORK_INFO));
	for (i=0; i<network_num; i++) {
		network_status.in += network_info[i].in;
		network_status.out += network_info[i].out;
	}	
	return (int)(network_status.in + network_status.out);
}

static void extract_cpu(char *buff, CPU_INFO *pinfo)
{
	int i, len, prev_pos;

	len = strlen(buff);
	
	for (i=0; i<len; i++) {
		if (' ' != buff[i]) {
			break;
		}
	}
	if (i == len) {
		return;
	}
	prev_pos = i;
	for (; i<len; i++) {
		if (' ' == buff[i]) {
			break;
		}
	}
	if (i == len) {
		return;
	}
	buff[i] = '\0';
	pinfo->user = atof(buff + prev_pos);
	i ++;
	for (; i<len; i++) {
		if (' ' != buff[i]) {
			break;
		}
	}
	if (i == len) {
		return;
	}
	prev_pos = i;
	for (; i<len; i++) {
		if (' ' == buff[i]) {
			break;
		}
	}
	if (i == len) {
		return;
	}
	buff[i] = '\0';
	pinfo->nice = atof(buff + prev_pos);
	i ++;
	for (; i<len; i++) {
		if (' ' != buff[i]) {
			break;
		}
	}
	if (i == len) {
		return;
	}
	prev_pos = i;
	for (; i<len; i++) {
		if (' ' == buff[i]) {
			break;
		}
	}
	if (i == len) {
		return;
	}
	buff[i] = '\0';
	pinfo->system = atof(buff + prev_pos);
	i ++;
	for (; i<len; i++) {
		if (' ' != buff[i]) {
			break;
		}
	}
	if (i == len) {
		return;
	}
	prev_pos = i;
	buff[len - 1] = '\0';
	pinfo->idle = atof(buff + prev_pos);
}

static void extract_network(char *buff, NETWORK_INFO *pinfo)
{
	int i, j, len, prev_pos;
	BOOL b_space, b_in, b_out;

	len = strlen(buff);
	b_space = FALSE;
	b_in = FALSE;
	b_out = FALSE;
	
	for (i=0,j=0; i<len; i++) {
		if (FALSE == b_space) {
			if (' ' == buff[i]) {
				j ++;
				b_space = TRUE;
			}
		} else {
			if (' ' != buff[i]) {
				j ++;
				b_space = FALSE;
			}
		}
		if (1 == j && FALSE == b_in) {
			buff[i] = '\0';
			pinfo->in = atof(buff);
			b_in = TRUE;
		}
		if (16 == j && FALSE == b_out) {
			prev_pos = i;
			b_out = TRUE;
		}
		if (17 == j) {
			buff[i] = '\0';
			pinfo->out = atof(buff + prev_pos);
			break;
		}
	}
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	char *ptr;
	int i, len;
	time_t cur_time;
	struct tm temp_tm;
	char help_string[] = "250 status forms help information:\r\n"
						 "\t%s status\r\n"
						 "\t    --print real-time cpu and network information\r\n"
		                 "\t%s report\r\n"
						 "\t    --print the current day status information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("status", argv[1])) {
		snprintf(result, length, "250 status information:\r\n"
								 "%d%%                %d",
								 collect_cpu_information_ex(),
								 collect_network_information_ex());
		return;
	}
	if (2 == argc && 0 == strcmp("report", argv[1])) {
		len = snprintf(result, length, "250 status information:\r\n");
		ptr = result + len;
		time(&cur_time);
		localtime_r(&cur_time, &temp_tm);
		for (i=0; i<=temp_tm.tm_hour; i++) {
			if (i < 10) {
				ptr += sprintf(ptr,
					"0%d:00            %d%%%12.0lf            %d\r\n",
					i,	(int)(g_cpu_status[i]*100), g_network_status[i],
					g_connection_status[i]);
			} else {
				ptr += sprintf(ptr,
					"%d:00            %d%%%12.0lf            %d\r\n",
					i,	(int)(g_cpu_status[i]*100), g_network_status[i],
					g_connection_status[i]);
			}
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

