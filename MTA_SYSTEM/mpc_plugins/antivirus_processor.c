#include <stdbool.h>
#include <unistd.h>
#include <gromox/hook_common.h>
#include "mail_func.h"
#include "util.h"
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>

#define MAX_CIRCLE_NUMBER		0x7FFFFFFF
#define DEF_MODE				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
#define SPAM_STATISTIC_SPAM_INSULATION  1

typedef void (*SPAM_STATISTIC)(int);

typedef struct _ANTIVIRUS_RESULT {
	BOOL is_found;
	char virusname[1024];
	MIME *pmime;
} ANTIVIRUS_RESULT;

static int g_insulation_id;
static char g_insulation_path[256];
static pthread_mutex_t g_id_lock;

static SPAM_STATISTIC spam_statistic;

static void enum_attachment(MIME *pmime, ANTIVIRUS_RESULT *presult);
static void antivirus_log(MESSAGE_CONTEXT *pcontext, int level, const char *format, ...);
static BOOL message_insulate(MESSAGE_CONTEXT *pcontext,
	ANTIVIRUS_RESULT *presult, int id);
static int increase_id(void);
static BOOL antivirus_hook(MESSAGE_CONTEXT *pcontext);

static BOOL (*check_virus)(int buflen, void *pbuff, char *virusname);

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	char *psearch;
	char file_name[128];

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		check_virus = query_service("check_virus");
		if (NULL == check_virus) {
			printf("[antivirus_processor]: fail to get \"check_virus\" service\n");
			return FALSE;

		}
		

		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(g_insulation_path, "%s/insulation", get_queue_path());
		g_insulation_id = 0;
		pthread_mutex_init(&g_id_lock, NULL);

        if (FALSE == register_hook(antivirus_hook)) {
			printf("[antivirus_processor]: failed to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		pthread_mutex_destroy(&g_id_lock);
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}


static BOOL antivirus_hook(MESSAGE_CONTEXT *pcontext)
{
	MAIL *pmail;
	MIME *pmime;
	char temp_buff[1024];
	ANTIVIRUS_RESULT result;

	if (pcontext->pcontrol->bound_type != BOUND_IN &&
		pcontext->pcontrol->bound_type != BOUND_RELAY &&
		pcontext->pcontrol->bound_type != BOUND_OUT) {
		return FALSE;
	}
	pmail = pcontext->pmail;
	pmime = mail_get_head(pcontext->pmail);
	if (NULL == pmime || TRUE == mime_get_field(pmime, "X-Insulation-Reason",
		temp_buff, 1024)) {
		return FALSE;
	}
	result.is_found = FALSE;
	mail_enum_mime(pmail, (MAIL_MIME_ENUM)enum_attachment, &result);
	if (TRUE == result.is_found && TRUE == message_insulate(pcontext,
		&result, increase_id())) {	
		mime_set_content_param(result.pmime, "name", "\"virus.txt\"");
		mime_set_field(result.pmime, "Content-Disposition",
			"attachment; filename=\"virus.txt\"");
		mime_write_content(result.pmime, "virus found in the content", 26,
			MIME_ENCODING_NONE);
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_SPAM_INSULATION);
		}
		return FALSE;
	}
	return FALSE;
}

/*
 *	enum the mail attachement
 */
static void enum_attachment(MIME *pmime, ANTIVIRUS_RESULT *presult)
{
	size_t len;
	char temp_buff[256*1024];

	if (TRUE == presult->is_found) {
		return;
	}
	if (SINGLE_MIME != pmime->mime_type) {
		return;
	}
	len = sizeof(temp_buff);
	if (FALSE == mime_read_content(pmime, temp_buff, &len) || 0 == len) {
		return;
	}

	if (FALSE == check_virus(len, temp_buff, presult->virusname)) {
		presult->is_found = TRUE;
		presult->pmime = pmime;
	}
	
}

static BOOL message_insulate(MESSAGE_CONTEXT *pcontext,
	ANTIVIRUS_RESULT *presult, int id)
{
	int	fd, len;
	char msgid[256];
	char temp_rcpt[256];
	char temp_path[256];
	char temp_buff[512];
	time_t current_time;

	time(&current_time);
	snprintf(msgid, 256, "av.%d.%ld.%s", id, current_time, get_host_ID());
	snprintf(temp_path, 256, "%s/%s", g_insulation_path, msgid);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Queue-Id: %d\r\n",
			pcontext->pcontrol->queue_ID);
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Bound-Type: %d\r\n",
			pcontext->pcontrol->bound_type);
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Insulation-Reason: %s\r\n", presult->virusname);
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Envelop-From: %s\r\n",
			pcontext->pcontrol->from);
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		temp_rcpt, 256)) {
		len = sprintf(temp_buff, "X-Envelop-Rcpt: %s\r\n", temp_rcpt);
		if (len != write(fd, temp_buff, len)) {
			close(fd);
			remove(temp_path);
			return FALSE;
		}
	}
	if (FALSE == mail_to_file(pcontext->pmail, fd)) {
        close(fd);
        remove(temp_path);
        return FALSE;
    }
	close(fd);
	antivirus_log(pcontext, 8, "message has been put into insulated with ID %s "
		"because virus [%s] found in mail", msgid, presult->virusname);
	return TRUE;
}


/*
 *  increase the message ID with 1
 *  @return
 *     message ID before increasement
 */
static int increase_id()
{
	int current_id;
	pthread_mutex_lock(&g_id_lock);
	if (MAX_CIRCLE_NUMBER == g_insulation_id) {
		g_insulation_id = 1;
	} else {
		g_insulation_id ++;
	}
	current_id  = g_insulation_id;
	pthread_mutex_unlock(&g_id_lock);
	return current_id;
}


static void antivirus_log(MESSAGE_CONTEXT *pcontext, int level,
    const char *format, ...)
{
	char log_buf[2048], rcpt_buff[2048];
	size_t size_read = 0, rcpt_len = 0, i;
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	log_buf[sizeof(log_buf) - 1] = '\0';

	/* maximum record 8 rcpt to address */
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
			MEM_FILE_SEEK_BEGIN);
	for (i=0; i<8; i++) {
		size_read = mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
						rcpt_buff + rcpt_len, 256);
		if (size_read == MEM_END_OF_FILE) {
			break;
		}
		rcpt_len += size_read;
		rcpt_buff[rcpt_len] = ' ';
		rcpt_len ++;
	}
	rcpt_buff[rcpt_len] = '\0';
	
	log_info(level, "SMTP message queue-ID: %d, FROM: %s, TO: %s %s",
			pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
			rcpt_buff, log_buf);

}

