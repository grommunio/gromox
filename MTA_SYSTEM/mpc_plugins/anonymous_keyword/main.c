#include <stdbool.h>
#include <unistd.h>
#include "hook_common.h"
#include "anonymous_keyword.h"
#include "mail_func.h"
#include "util.h"
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>

#define TAG_LEN					40
#define MAX_CIRCLE_NUMBER		0x7FFFFFFF
#define DEF_MODE				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
#define SPAM_STATISTIC_SPAM_INSULATION  1

typedef void (*SPAM_STATISTIC)(int);

typedef struct _KEYWORD_RESULT {
	BOOL is_found;
	char keyword[1024];
	char group[256];
} KEYWORD_RESULT;

static int g_insulation_id;
static int g_statistic_offset;
static time_t g_statistic_time;
static char g_insulation_path[256];
static char g_statistic_buff[4096];
static pthread_mutex_t g_id_lock;

static SPAM_STATISTIC spam_statistic;

static void enum_text(MIME *pmime, KEYWORD_RESULT *presult);

static void enum_attachment(MIME *pmime, KEYWORD_RESULT *presult);

static void enum_group(const char *name, int times);

static void keyword_log(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...);

static BOOL message_insulate(MESSAGE_CONTEXT *pcontext,
	KEYWORD_RESULT *presult, int id);

static int increase_id();

static void console_talk(int argc, char **argv, char *result, int length);

static BOOL keyword_hook(MESSAGE_CONTEXT *pcontext);

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	char *psearch;
	char file_name[256];
	char charset_path[256];
	char keyword_path[256];
	char queue_path[256];

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(charset_path, "%s/%s/charset.txt", get_data_path(), file_name);
		sprintf(keyword_path, "%s/%s/keyword.txt", get_data_path(), file_name);
		sprintf(g_insulation_path, "%s/insulation", get_queue_path());
		g_insulation_id = 0;
		time(&g_statistic_time);
		pthread_mutex_init(&g_id_lock, NULL);
		anonymous_keyword_init(charset_path, keyword_path);
		if (0 != anonymous_keyword_run()) {
			printf("[anonymous_keyword]: fail to run keyword engine\n");
			return FALSE;
		}
        if (FALSE == register_hook(keyword_hook)) {
			printf("[anonymous_keyword]: fail to register the hook function\n");
            return FALSE;
        }
		register_talk(console_talk);
        return TRUE;
    case PLUGIN_FREE:
		anonymous_keyword_stop();
		anonymous_keyword_free();
		pthread_mutex_destroy(&g_id_lock);
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}


static BOOL keyword_hook(MESSAGE_CONTEXT *pcontext)
{
	MIME *pmime;
	MAIL *pmail;
	char decode_buff[1024];
	KEYWORD_RESULT result;
	char temp_buff[1024];
	int buff_len, decode_len;
	ENCODE_STRING encode_string;

	if (pcontext->pcontrol->bound_type != BOUND_IN &&
		pcontext->pcontrol->bound_type != BOUND_RELAY &&
		pcontext->pcontrol->bound_type != BOUND_OUT) {
		return FALSE;
	}
	pmail = pcontext->pmail;
	pmime = mail_get_head(pmail);
	if (NULL == pmime || TRUE == mime_get_field(pmime, "X-Insulation-Reason",
		temp_buff, 1024)) {
		return FALSE;
	}
	if (TRUE == mime_get_field(pmime, "Subject", temp_buff, 1024)) {
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		decode_len = decode_mime_string(temp_buff, buff_len, decode_buff, 1024);
		if (TRUE == anonymous_keyword_match(encode_string.charset, decode_buff,
			decode_len, result.keyword, result.group) &&
			TRUE == message_insulate(pcontext, &result, increase_id())) {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_SPAM_INSULATION);
			}
			return TRUE;
		}
	}
	if (TRUE == mime_get_field(pmime, "From", temp_buff, 1024)) {
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		decode_len = decode_mime_string(temp_buff, buff_len, decode_buff, 1024);
		if (TRUE == anonymous_keyword_match(encode_string.charset, decode_buff,
			decode_len, result.keyword, result.group) &&
			TRUE == message_insulate(pcontext, &result, increase_id())) {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_SPAM_INSULATION);
			}
			return TRUE;
		}
	}
	if (TRUE == mime_get_field(pmime, "To", temp_buff, 1024)) {
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		decode_len = decode_mime_string(temp_buff, buff_len, decode_buff, 1024);
		if (TRUE == anonymous_keyword_match(encode_string.charset, decode_buff,
			decode_len, result.keyword, result.group) &&
			TRUE == message_insulate(pcontext, &result, increase_id())) {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_SPAM_INSULATION);
			}
			return TRUE;
		}
	}
	if (TRUE == mime_get_field(pmime, "Cc", temp_buff, 1024)) {
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		decode_len = decode_mime_string(temp_buff, buff_len, decode_buff, 1024);
		if (TRUE == anonymous_keyword_match(encode_string.charset, decode_buff,
			decode_len, result.keyword, result.group) &&
			TRUE == message_insulate(pcontext, &result, increase_id())) {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_SPAM_INSULATION);
			}
			return TRUE;
		}
	}
	result.is_found = FALSE;
	mail_enum_mime(pmail, (MAIL_MIME_ENUM)enum_text, &result);
	if (TRUE == result.is_found && TRUE == message_insulate(pcontext,
		&result, increase_id())) {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_SPAM_INSULATION);
		}
		return TRUE;
	}
	mail_enum_mime(pmail, (MAIL_MIME_ENUM)enum_attachment, &result);
	if (TRUE == result.is_found && TRUE == message_insulate(pcontext,
		&result, increase_id())) {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_SPAM_INSULATION);
		}
		return TRUE;
	}
	return FALSE;
}

static void enum_text(MIME *pmime, KEYWORD_RESULT *presult)
{
	size_t len;
	char charset[32];
	char *begin, *end;
	char temp_buff[128*1024];
	const char *ptype;
	
	if (TRUE == presult->is_found) {
		return;
	}
	ptype = mime_get_content_type(pmime);
	if (0 != strncasecmp("text/", ptype, 5)) {
		return;
	}
	if (mime_get_length(pmime) > sizeof(temp_buff)) {
		return;
	}
	memset(charset, 0, 32);
	if (TRUE == mime_get_content_param(pmime, "charset", charset, 32)) {
		len = strlen(charset);
		if (len <= 2) {
			return;
		}
		begin = strchr(charset, '"');
		if (NULL != begin) {
			end = strchr(begin + 1, '"');
			if (NULL == end) {
				return;
			}
			len = end - begin - 1;
			memmove(charset, begin + 1, len);
			charset[len] = '\0';
		}
	}
	len = sizeof(temp_buff) - 1;
	if (FALSE == mime_read_content(pmime, temp_buff, &len)) {
		return;
	}
	temp_buff[len] = '\0';
	presult->is_found = anonymous_keyword_match(charset, temp_buff, len,
						presult->keyword, presult->group);
}

/*
 *	enum the mail attachement
 */
static void enum_attachment(MIME *pmime, KEYWORD_RESULT *presult)
{
	int name_len;
	int attach_len;
	char name[256];
	char attach[512];
	ENCODE_STRING encode_string;

	if (TRUE == presult->is_found) {
		return;
	}
	if (FALSE == mime_get_filename(pmime, name)) {
		return;
	}
	name_len = strlen(name);
	parse_mime_encode_string(name, name_len, &encode_string);
	attach_len = decode_mime_string(name, name_len, attach, 512);
	presult->is_found = anonymous_keyword_match(encode_string.charset,
				attach, attach_len, presult->keyword, presult->group);
}

static BOOL message_insulate(MESSAGE_CONTEXT *pcontext,
	KEYWORD_RESULT *presult, int id)
{
	int	fd, len;
	char msgid[256];
	char temp_rcpt[256];
	char temp_path[256];
	char temp_buff[512];
	time_t current_time;

	time(&current_time);
	snprintf(msgid, 256, "anon.%d.%ld.%s", id, current_time, get_host_ID());
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
	len = sprintf(temp_buff, "X-Insulation-Reason: %s\r\n", presult->group);
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
	keyword_log(pcontext, 8, "message has been insulated with ID %s because "
		"anonymous keyword [%s] found in mail", msgid, presult->keyword);
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


static void keyword_log(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...)
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

static void enum_group(const char *name, int times)
{
	int len;
	
	if (g_statistic_offset > 4000) {
		return;
	}
	len = strlen(name);
	strcpy(g_statistic_buff + g_statistic_offset, name);
	memset(g_statistic_buff + g_statistic_offset + len, ' ', TAG_LEN - len);
	g_statistic_offset += TAG_LEN;
	g_statistic_offset += sprintf(g_statistic_buff + g_statistic_offset,
							"%d\r\n", times);

}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int len;
	struct tm time_buff;
	char help_string[] = "250 anonymous keyword help information:\r\n"
					     "\t%s reload\r\n"
						 "\t    --refresh the charset and ketword list\r\n"
						 "\t%s status\r\n"
						 "\t    --print keyword group statistics information\r\n"
						 "\t%s clear\r\n"
						 "\t    --clear keyword group statistics information";
	
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		if (TRUE == anonymous_keyword_refresh()) {
			strncpy(result, "250 anonymous keyword reload OK", length);
		} else {
			strncpy(result, "550 fail to reload anonymous keyword", length);
		}
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "status")) {
		g_statistic_offset = 0;
		anonymous_keyword_enum_group(enum_group);
		g_statistic_buff[g_statistic_offset] = '\0';
		len = snprintf(result, length, "250 group statistics infomation:\r\n%s",
				g_statistic_buff);
		len += sprintf(result + len, "\r\n* last statistic time: ");
		strftime(result + len, 128, "%Y/%m/%d %H:%M:%S",
			localtime_r(&g_statistic_time, &time_buff));
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "clear")) {
		anonymous_keyword_clear_statistic();
		time(&g_statistic_time);
		strncpy(result, "250 group statistics information cleared", length);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
}

		
