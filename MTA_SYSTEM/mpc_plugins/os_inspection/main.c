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
marginheight=\"0\" marginwidth=\"0\">\r\n\
<CENTER><TABLE cellSpacing=0 cellPadding=0 width=\"100%\" border=0><TBODY>\r\n\
<TR><TD noWrap align=middle background=\r\n\
\"cid:001501c695cb$9bc2ea60$6601a8c0@herculiz\" height=55>\r\n\
<SPAN class=AlarmTitle>Green Messenger Dispatch Alarm</SPAN>\r\n\
<TD vAlign=bottom noWrap width=\"22%\"\r\n\
background=\"cid:001501c695cb$9bc2ea60$6601a8c0@herculiz\"><A\r\n\
href=\"http://www.gridware.com.cn\" target=_blank><IMG height=48\r\n\
src=\"cid:001901c695cb$9bc53450$6601a8c0@herculiz\" width=195 align=right\r\n\
border=0></A></TD></TR></TBODY></TABLE><BR>\r\n\
<TABLE cellSpacing=1 cellPadding=1 width=\"90%\" border=0> <TBODY><TR>\r\n\
<P></P><BR><P></P><BR><P></P><BR><BR>\r\n"


#define HTML_02     \
"</TBODY></TABLE></TD></TR></TBODY></TABLE><P></P><BR>\
<P></P><BR></CENTER></BODY></HTML>"


#define PIC01_FILE	\
"R0lGODlhAwA3ANUAAHWQwX2XxV5+tGCAtnCMvmyJvE5xrFByrYKayICZx3+Yxlp6slFzrmaEuXqU\r\n\
xMjIyHOPwFV2sGSCuGmGunmUw3eSwld4sWuIu3uVxFt7s2KBt1N1r1h5slh5sVx8s26LvXmTxAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAAAAAAALAAAAAADADcAAAZSQINw\r\n\
eCgaGchkcsNsRp5Qi7RD5VgX2IzWwxV4v9+BeKwpS87ohno9aV/e8IL8Q68T7niIfr8H+CuAgSCD\r\n\
FIUOhxiJAYuMjAqPCZGSCJSVlQ+YQQA7\r\n"

#define PIC05_FILE	\
"R0lGODlhwwAwAPcAAP5VKvyLb/xtThik/2yJvGWDuP/9mMrU6HWQwf75tKuUnvPMBPv8/XCMvl5+\r\n\
tOixBWGAttzj8Jer0Z6Obi+t/f780FCv9fL1+eeqBLTD3rrI4YyjzGmGu9Lb7ICZx6u72lp6svPY\r\n\
h+Xq9P+0plV2sJGnzn+Yxn2Wxf+kkoWdyXOOwDFPrpC3+P6DXOjt9e/ITfDNdqGz1v/sasSudEyR\r\n\
0e3w98iSjzOWx/6YgHqUxGyJv8WaKP/948+lJvN+E/zIwsLO5GR9q2S3+tWrIP/7kP/gA//DuZ63\r\n\
5qbD/5TJ/0Niuum4NXeSwruOKuDm8Zyv09GvkoWFi1+JwZt2WHmUw01su/fmlCx30c22zPb4+9q+\r\n\
brmtysenWnN+kOCMemCSzMOVRqS12PexAF96rPKrAKi52UFaseiwFa+/24ifymB+u3iSxVd4sVh5\r\n\
sVh5slx7s6a32Kut0XuVxHCBn2qk11x7r5OYuVme3YCLsMjIyFN1r1R1r4KayIKbyIGax////wAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAAwwAwAAAI/wD1CBxI\r\n\
sKDBgwgTKlzIsKHDhxAjSpxYcI/FixgzatzIsaPHjyBDihxJsqTJkxlJqFxJYkyXCTO0vJgxh6XN\r\n\
mzhz6tzJs6fPn0CDCh1KVOVLLSGIEDFghWbRp1CjSp1KdSibq1e7cAlhIIGBr0xpYh1LtqzZs2jT\r\n\
ql3Ltq3bt3Djpm1Dt00ULVa8ggVrRcucOnUDCx5MuLDhw4gTK17MuLHjx4XduGnTRUsCvUv3GiCi\r\n\
JUodyaBDix5NurTp06hTq17NurXr16JB1JnD5XJmzWA5R3kDorfv38CDCx9OvLjx48iTK1/OvLnv\r\n\
N2MmhKhwG/fezkHeaN/Ovbv37+DDi/8fT768+fPo06vfHqV2gurWv+rOvr6+/fv48+tXDwZGhfjx\r\n\
cTZBEA4UaOCBCCao4IIMNujggxBGKOGEFFboQA8w8ACgZkp9BYMCFoYo4ogklmhihUPIwMN7ASq1\r\n\
VAIV8FCBFjTU+MUXUkBw4o489uhjiRAM8UIFLO7l4lcwyphACC9wccMAA1BAwR1U5gjBlVhmqeWW\r\n\
XHbp5ZdghinmmGSWaaaXQyxAxB+bbdYhjDFWYAUML5xxhhg7PAnlnhRYcIeVZwYq6KCEFmpomGkW\r\n\
IeObcS4JwxJnYCApBnjquSefFnxx6KacduqpoQUkqmKMMloRwhJLTCrpA6xWeumrfX7/UcCstM6K\r\n\
Za245qrrrrz26uuvwAYr7LDEFtDDAkUUYQAPTEKqKqvQtprnq7BmquutxWar7bbcduttokXIEEKk\r\n\
q0Zr7gOuUntprL7+4e67wL77x67yemuvrvUKK++8987KwbHJygBDueeam666e1pgAQcMN0zrvvn2\r\n\
GjGuE/drb8US79tvwwCHGwLBBUN7MMJRZtowww/DqzG3GFvMMrzBtswtx8h6jEHI54rRhKUkD2CB\r\n\
ECc3HDHMs0I878RGHw1zvkNDnPLKBTjNa9NGFy111FALyzABHYsLMs4680wyBUJ8QcDZBDAsb9BB\r\n\
Q6z2u0In/ba7HKy99txu171v3Hmz/6033Xi7bXTgcPttOAdod/0xzgbv3DOfQtyBdtp//0EAxGjL\r\n\
O7nml7/bueefW64556SDzvnZpbs7+eagh4666a0nrfrqtNeu+Nchh/34nkJYQPvo+2beuuvEpy66\r\n\
56cLbzzrSddOfPGwzw699M7X3sAONXvNeLRkgEHH7iVL3sD4r0t/evLLPy/78LKXb7nyRjt/fvTv\r\n\
zz978tWjPX4Dt9+8/QPdg4MQdiclGuyvAe6DnwIXmL7QNc99x7sf+4aXP/vVj34MpGD+CLA/7AVs\r\n\
cf9jFRhYgAQWUKBnFrhBFVRwwPEBL3YTlKDqggfBGiZweu+rIf4WiMMbOpCGG9RfA/9U4EGb+W97\r\n\
3TtCEkp4QnVJSQlqUIEUWehC2e1PXgfEYhWNlsV3bfEPXUzaF1soxhZe0YtjbIAWtfhFNprxjUOU\r\n\
YhG1tz0M+AAAABAAC5ZoQmpJ6QpmiKMUybgvQrorjGA8I8TCyEhEFlKNaHRkIuHIxjWi0Y2QxCQc\r\n\
WyhFBMzxY0c0lx3viEc8CkCJJbTAuihwhRWYQQUIiCUCpkjLWtrylrjMpS53ycte+vKXwPylLD/5\r\n\
tVGW8pimjMESkaDKKLFyBStQAixlGcxqWvOa2MymNnEZSyZ8MlrGRKY48xiHZQ7wmdCUJhPWyQRq\r\n\
bvOd8IynPH3Jzm+Gc5ylFEAe8dj/gnIiAQlCaCU0o6kCdjJBDgZNqEIXytCGOvShEI2oRCdK0Yqu\r\n\
EwFNeEDAYEBKfArgoyANqQBasIUlHsEMA40mAqjA0pZSwaIwjalMZ0rTmbY0ClPAQLhQkM88ivSn\r\n\
LQhqAIRaUhagdKBKWKlLWVrTpjr1qVCdKEvXgAA8TKEJS2iBT4E60qC2IABgDWsAcDBWLLBACQM1\r\n\
QxWYkIO2ujUHcoirXOdK17ra9a54zate98rXvvr1r3hta1xfilOQtqCrQv2qWHHAWMai4LGPHcEW\r\n\
0ArNKiAAsJjNrGY3y9nO+vUEoD2BHPBgA68qdqxjbSwKcADZyI5gBEaILRYou9bQ/9oWtJ7NrW53\r\n\
y9vP3ha0dvCCaVML2dcaF7ax/YFyjTCCH5zVDGpYw29t29vqWve6nQWtCba73RNQwQ6lHe5YXZtc\r\n\
5f6AuasNgBfiUAUdcPe98MWufOdLX7vCF752UIBwTSvU1LJ2tWTlLxRU4IH73re+CE6wdbfrgQY7\r\n\
uMDbza8X9svfCntVvTawAx8ezOEHK/jDIOZshztsAj/YIb82mDBY+QvWCdtAAXYowYZHTGID2/jG\r\n\
OM6xjnfM4x77+Mc6brAfhkzkIhv5yEhOspKJ3IcmO/nJUI6ylKdM5Spb+cpYzrKWt0zlIfPhy2AO\r\n\
s5jHTOYymxnMXE6zmtfM5ja7GTvKX37zm1NA5zrb+c54zrOe98znPvv5z4AOtKD33OQ8GPrQiE60\r\n\
ohfN6EY7+tGQjrSkJ03pSlv60okOCAA7\r\n"

#define PIC01_CID	"<001501c695cb$9bc2ea60$6601a8c0@herculiz>"
#define PIC05_CID	"<001901c695cb$9bc53450$6601a8c0@herculiz>"


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
	pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime_child, "image/gif");
	mime_write_content(pmime_child, PIC01_FILE, sizeof(PIC01_FILE) - 1,
		MIME_ENCODING_NONE);
	mime_set_field(pmime_child, "Content-ID", PIC01_CID);
	mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	pmime_child = mail_add_child(pcontext->pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime_child) {
		put_context(pcontext);
		return;
	}
	mime_set_content_type(pmime_child, "image/gif");
	mime_write_content(pmime_child, PIC05_FILE, sizeof(PIC05_FILE) - 1,
		MIME_ENCODING_NONE);
	mime_set_field(pmime_child, "Content-ID", PIC05_CID);
	mime_set_field(pmime_child, "Content-Transfer-Encoding", "base64");
	
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

