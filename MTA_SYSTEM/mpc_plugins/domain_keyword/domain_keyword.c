#include <errno.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include "domain_keyword.h"
#include "bounce_producer.h"
#include "keyword_engine.h"
#include "mail_func.h"
#include "list_file.h"
#include "str_hash.h"
#include "double_list.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <iconv.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <stdarg.h>


enum {
	DOMAIN_KEYWORD_ADD_OK = 0,
	DOMAIN_KEYWORD_FILE_FAIL,
	DOMAIN_KEYWORD_HASH_FAIL
};

typedef struct _KEYWORD_RESULT {
	MESSAGE_CONTEXT *pcontext;
	BOOL is_found;
	char domain[256];
	char keyword[256];
} KEYWORD_RESULT;


static char				g_root_path[256];
static int				g_growing_num;
static char             g_dm_host[256];
static int				g_hash_cap;
static STR_HASH_TABLE	*g_hash_table;
static pthread_mutex_t  g_sequence_lock;
static pthread_rwlock_t g_hash_lock;

static BOOL (*domain_keyword_get_homedir)(const char*, char*);

static int domain_keyword_add(const char *domain);

static void domain_keyword_remove(const char *domain);
static int domain_keyword_sequence_ID(void);
static BOOL domain_keyword_insulate(MESSAGE_CONTEXT *pcontext, char *msgid);

static BOOL domain_keyword_match(MESSAGE_CONTEXT *pcontext,
	const char *charset, const char *buff, int length,
	char *domain, char *keyword);

static void domain_keyword_convert_to_utf8(const char *charset,
	const char *string, char *buff_out);

static void domain_keyword_enum_text(MIME *pmime, KEYWORD_RESULT *presult);

static void domain_keyword_enum_attachment(MIME *pmime,
	KEYWORD_RESULT *presult);

static BOOL domain_keyword_get_fwdinfo(const char *domain,
	char *forward_to, char *lang);
static void domain_keyword_log_info(MESSAGE_CONTEXT *pcontext, int level, const char *format, ...);

void domain_keyword_init(const char *root_path, int growing_num,
	const char *dm_host)
{
	strcpy(g_root_path, root_path);
	g_growing_num = growing_num;
	strcpy(g_dm_host, dm_host);
	g_hash_cap = 0;
	pthread_rwlock_init(&g_hash_lock, NULL);
	pthread_mutex_init(&g_sequence_lock, NULL);
	g_hash_table = NULL;
}


int domain_keyword_run()
{
	DIR *dirp;
	int domain_num;
	int i, temp_len;
	char charset_path[256];
	char keyword_path[256];
	char temp_domain[256];
	struct dirent *direntp;
	KEYWORD_ENGINE *pengine;


	domain_keyword_get_homedir = query_service("get_domain_homedir");
	if (NULL == domain_keyword_get_homedir) {
		printf("[domain_keyword]: failed to get service \"get_domain_homedir\"\n");
		return -1;
	}

	dirp = opendir(g_root_path);
	if (NULL == dirp) {
		printf("[domain_keyword]: failed to open directory %s: %s\n",
			g_root_path, strerror(errno));
		return -2;
	}
	domain_num = 0;
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..") ||
			0 == strcmp(direntp->d_name, "charset.txt")) {
			continue;
		}
		domain_num ++;
	}
	g_hash_cap = domain_num + g_growing_num;
	g_hash_table = str_hash_init(g_hash_cap, sizeof(void*), NULL);
	if (NULL == g_hash_table) {
		closedir(dirp);
		printf("[domain_keyword]: fail to init hash table\n");
		return -3;
	}
	seekdir(dirp, 0);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..") ||
			0 == strcmp(direntp->d_name, "charset.txt")) {
			continue;
		}
		strcpy(temp_domain, direntp->d_name);
		temp_len = strlen(temp_domain);
		if (temp_len <= 4 && 0 != strcasecmp(temp_domain +
			temp_len - 4, ".txt")) {
			continue;
		}
		temp_domain[temp_len - 4] = '\0';
		for (i=0; i<temp_len-4; i++) {
			if (HX_isupper(temp_domain[i]))
				break;
		}
		if (i < temp_len - 4) {
			continue;
		}
		
		sprintf(charset_path, "%s/charset.txt", g_root_path);
		sprintf(keyword_path, "%s/%s", g_root_path, direntp->d_name);
		pengine = keyword_engine_init(charset_path, keyword_path);
		if (NULL != pengine) {
			str_hash_add(g_hash_table, temp_domain, &pengine);
		}
	}
	closedir(dirp);
	return 0;	
}


BOOL domain_keyword_process(MESSAGE_CONTEXT *pcontext)
{
	MIME *pmime;
	MAIL *pmail;
	char lang[32];
	char key[256];
	char msgid[128];
	char domain[256];
	char keyword[256];
	char forward_to[256];
	char temp_buff[1024];
	KEYWORD_RESULT result;
	char decode_buff[1024];
	int buff_len, decode_len;
	ENCODE_STRING encode_string;
	MESSAGE_CONTEXT *pforward_context;


	if (pcontext->pcontrol->bound_type != BOUND_IN &&
		pcontext->pcontrol->bound_type != BOUND_OUT &&
		pcontext->pcontrol->bound_type != BOUND_RELAY) {
		return FALSE;
	}


	pmail = pcontext->pmail;
	pmime = mail_get_head(pmail);
	if (NULL == pmime || TRUE == mime_get_field(pmime,
		"X-Domain-Keyword", key, 256)) {
		return FALSE;
	}


	if (TRUE == mime_get_field(pmime, "Subject", temp_buff, 1024)) {
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		decode_len = decode_mime_string(temp_buff, buff_len, decode_buff, 1024);
		if (TRUE == domain_keyword_match(pcontext, encode_string.charset,
			decode_buff, decode_len, domain, keyword)) {
			goto INSULATE_MESSAGE;
		}
	}
		
	if (TRUE == mime_get_field(pmime, "From", temp_buff, 1024)) {
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		decode_len = decode_mime_string(temp_buff, buff_len, decode_buff, 1024);
		if (TRUE == domain_keyword_match(pcontext, encode_string.charset,
			decode_buff, decode_len, domain, keyword)) {
			goto INSULATE_MESSAGE;
		}
	}
		
	if (TRUE == mime_get_field(pmime, "To", temp_buff, 1024)) {
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		decode_len = decode_mime_string(temp_buff, buff_len, decode_buff, 1024);
		if (TRUE == domain_keyword_match(pcontext, encode_string.charset,
			decode_buff, decode_len, domain, keyword)) {
			goto INSULATE_MESSAGE;
		}
	}
		

	if (TRUE == mime_get_field(pmime, "Cc", temp_buff, 1024)) {
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		decode_len = decode_mime_string(temp_buff, buff_len, decode_buff, 1024);
		if (TRUE == domain_keyword_match(pcontext, encode_string.charset,
			decode_buff, decode_len, domain, keyword)) {
			goto INSULATE_MESSAGE;
		}
	}
		


	result.is_found = FALSE;
	result.pcontext = pcontext;
	mail_enum_mime(pmail, (MAIL_MIME_ENUM)domain_keyword_enum_text, &result);
	if (TRUE == result.is_found) {
		strncpy(keyword, result.keyword, 256);
		strncpy(domain, result.domain, 256);
		goto INSULATE_MESSAGE;
	}

	mail_enum_mime(pmail, (MAIL_MIME_ENUM)domain_keyword_enum_attachment,
		&result);
	if (TRUE == result.is_found) {
		strncpy(keyword, result.keyword, 256);
		strncpy(domain, result.domain, 256);
		goto INSULATE_MESSAGE;
	}
	return FALSE;

INSULATE_MESSAGE:
	pforward_context = get_context();
	if (NULL == pforward_context) {
		return FALSE;
	} 
	if (FALSE == domain_keyword_get_fwdinfo(domain, forward_to, lang) ||
		FALSE == domain_keyword_insulate(pcontext, msgid)) {
		put_context(pforward_context);
		return FALSE;
	}
	snprintf(key, 256, "http://%s/cgi/domain_keyword?domain=%s&session=%s",
		g_dm_host, domain, msgid);

	bounce_producer_make(pcontext, forward_to, lang,
		keyword, key, pforward_context->pmail);
	pforward_context->pcontrol->need_bounce = FALSE;
	sprintf(pforward_context->pcontrol->from, "sys-trap@%s",
		get_default_domain());
	mem_file_writeline(&pforward_context->pcontrol->f_rcpt_to, forward_to);
	throw_context(pforward_context);
	domain_keyword_log_info(pcontext, 8, "message has been insulated "
		"with ID %s because keyword [%s] of domain %s found in mail",
		msgid, keyword, domain);
	return TRUE;
}

int domain_keyword_stop()
{
	STR_HASH_ITER *iter;
	KEYWORD_ENGINE **ppengine;
	
	if (NULL != g_hash_table) {
		iter = str_hash_iter_init(g_hash_table);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppengine = (KEYWORD_ENGINE**)str_hash_iter_get_value(iter, NULL);
			keyword_engine_free(*ppengine);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
	}
	return 0;
}


void domain_keyword_free()
{
	g_root_path[0] = '\0';
	g_dm_host[0] = '\0';
	pthread_rwlock_destroy(&g_hash_lock);
	pthread_mutex_destroy(&g_sequence_lock);
}



static BOOL domain_keyword_match(MESSAGE_CONTEXT *pcontext,
	const char *charset, const char *buff, int length,
	char *domain, char *keyword)
{
	char *pdomain;
	char temp_rcpt[256];
	char from_domain[256];
	const char *pkeyword;
	KEYWORD_ENGINE **ppengine;

	pdomain = strchr(pcontext->pcontrol->from, '@');
	if (NULL != pdomain) {
		strcpy(from_domain, pdomain + 1);
		HX_strlower(from_domain);
		pthread_rwlock_rdlock(&g_hash_lock);
		/* query the hash table */
		ppengine = (KEYWORD_ENGINE**)str_hash_query(g_hash_table, from_domain);
		if (NULL != ppengine) {
			pkeyword = keyword_engine_match(*ppengine, charset, buff, length);
			if (NULL != pkeyword) {
				domain_keyword_convert_to_utf8(charset, pkeyword, keyword);
				pthread_rwlock_unlock(&g_hash_lock);
				strcpy(domain, from_domain);
				return TRUE;
			}
		}
	}

	mem_file_seek(&pcontext->pcontrol->f_rcpt_to,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, temp_rcpt, 256)) {
		HX_strlower(temp_rcpt);
		pdomain = strchr(temp_rcpt, '@');
		if (NULL == pdomain) {
			continue;
		}
		pdomain ++;
		ppengine = (KEYWORD_ENGINE**)str_hash_query(g_hash_table, pdomain);
		if (NULL != ppengine) {
			pkeyword = keyword_engine_match(*ppengine, charset, buff, length);
			if (NULL != pkeyword) {
				domain_keyword_convert_to_utf8(charset, pkeyword, keyword);
				pthread_rwlock_unlock(&g_hash_lock);
				strcpy(domain, pdomain);
				return TRUE;
			}	
		}
	}
	pthread_rwlock_unlock(&g_hash_lock);
	return FALSE;
}


void domain_keyword_console_talk(int argc, char **argv, char *result,
	int length)
{
	char help_string[] = "250 mail approving help information:\r\n"
						 "\t%s bounce reload\r\n"
						 "\t    --reload the bounce resource list\r\n"
						 "\t%s add <domain>\r\n"
						 "\t    --add domain keyword table into system\r\n"
						 "\t%s remove <domain>\r\n"
						 "\t    --remove domain keyword table from system";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}

	if (3 == argc && 0 == strcmp("bounce", argv[1]) &&
		0 == strcmp("reload", argv[2])) {
		if (TRUE == bounce_producer_refresh()) {
			snprintf(result, length, "250 bounce resource list reload OK");	
		} else {
			snprintf(result, length, "550 bounce resource list reload error");
		}
		return;
	}

	if (3 == argc && 0 == strcmp("add", argv[1])) {
		switch (domain_keyword_add(argv[2])) {
		case DOMAIN_KEYWORD_ADD_OK:
			snprintf(result, length, "250 domain %s's keyword list added OK",
				argv[2]);
			break;
		case DOMAIN_KEYWORD_FILE_FAIL:
			snprintf(result, length, "550 fail to open domain %s's keyword "
				"list file", argv[2]);
			break;
		case DOMAIN_KEYWORD_HASH_FAIL:
			snprintf(result, length, "550 fail to add domain %s's keyword "
				"list into hash table", argv[2]);
			break;
		}
		return;
	}
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		domain_keyword_remove(argv[2]);
		snprintf(result, length, "250 domain %s's keyword list removed OK",
			argv[2]);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}



static int domain_keyword_sequence_ID()
{
	int temp_ID;
	static int sequence_ID = 1;

	pthread_mutex_lock(&g_sequence_lock);
	if (sequence_ID >= 0X7FFFFFFF) {
		sequence_ID = 1;
	} else {
		sequence_ID ++;
	}
	temp_ID = sequence_ID;
	pthread_mutex_unlock(&g_sequence_lock);
	return temp_ID;
}


static void domain_keyword_log_info(MESSAGE_CONTEXT *pcontext, int level,
    const char *format, ...)
{
    char log_buf[2048], rcpt_buff[256];
    va_list ap;

    va_start(ap, format);
    vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
    log_buf[sizeof(log_buf) - 1] = '\0';

    mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
    while (MEM_END_OF_FILE != mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, rcpt_buff, 256)) {
		log_info(level, "SMTP message queue-ID: %d, FROM: %s, "
			"TO: %s  %s", pcontext->pcontrol->queue_ID,
			pcontext->pcontrol->from, rcpt_buff, log_buf);

    }
}



static void domain_keyword_enum_text(MIME *pmime, KEYWORD_RESULT *presult)
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
	presult->is_found = domain_keyword_match(presult->pcontext, charset,
						temp_buff, len, presult->domain, presult->keyword);
}

/*
 *	enum the mail attachement
 */
static void domain_keyword_enum_attachment(MIME *pmime, KEYWORD_RESULT *presult)
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
	presult->is_found = domain_keyword_match(presult->pcontext,
						encode_string.charset, attach, attach_len,
						presult->domain, presult->keyword);
}

static BOOL domain_keyword_insulate(MESSAGE_CONTEXT *pcontext, char *msgid)
{
	int	fd, len;
	char *pdomain;
	time_t current_time;
	char temp_rcpt[256];
	char temp_path[256];
	char temp_buff[512];
	char temp_domain[256];

	
	pdomain = strchr(pcontext->pcontrol->from, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	pdomain ++;
	strcpy(temp_domain, pdomain);
	HX_strlower(temp_domain);
	time(&current_time);
	snprintf(msgid, 128, "on.%d.%ld.%s", domain_keyword_sequence_ID(),
		current_time, get_host_ID());
	snprintf(temp_path, 256, "%s/insulation/%s", get_queue_path(), msgid);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, 0666);
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
	len = sprintf(temp_buff, "X-Domain-Keyword: 1\r\n");
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Insulation-Reason: %s\r\n", temp_domain);
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
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
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
	return TRUE;
}

static void domain_keyword_remove(const char *domain)
{
	char temp_domain[256];
	char temp_path[256];
	KEYWORD_ENGINE **ppengine;

	strcpy(temp_domain, domain);
	HX_strlower(temp_domain);
	pthread_rwlock_wrlock(&g_hash_lock);
	ppengine= (KEYWORD_ENGINE**)str_hash_query(g_hash_table, temp_domain);
	if (NULL != ppengine) {
		keyword_engine_free(*ppengine);
		str_hash_remove(g_hash_table, temp_domain);
	}
	pthread_rwlock_unlock(&g_hash_lock);
	sprintf(temp_path, "%s/%s.txt", g_root_path, domain);
	remove(temp_path);
}

static int domain_keyword_add(const char *domain)
{
	STR_HASH_TABLE *phash;
	STR_HASH_ITER *iter;
	char temp_buff[256];
	char temp_domain[256];
	char charset_path[256];
	char keyword_path[256];
	KEYWORD_ENGINE *pengine;
	KEYWORD_ENGINE **ppengine;

	strcpy(temp_domain, domain);
	HX_strlower(temp_domain);
	sprintf(charset_path, "%s/charset.txt", g_root_path);
	sprintf(keyword_path, "%s/%s.txt", g_root_path, temp_domain);
	pengine = keyword_engine_init(charset_path, keyword_path);
	if (NULL == pengine) {
		printf("[domain_keyword]: fail to init keyword engine from file %s\n",
			keyword_path);
		return DOMAIN_KEYWORD_FILE_FAIL;
	}
	pthread_rwlock_wrlock(&g_hash_lock);
	ppengine = (KEYWORD_ENGINE**)str_hash_query(g_hash_table, temp_domain);
	if (NULL != ppengine) {
		keyword_engine_free(*ppengine);
		str_hash_remove(g_hash_table, temp_domain);
	}
	if (str_hash_add(g_hash_table, temp_domain, &pengine) > 0) {
		pthread_rwlock_unlock(&g_hash_lock);
		return DOMAIN_KEYWORD_ADD_OK;
	}
	phash = str_hash_init(g_hash_cap + g_growing_num, sizeof(SINGLE_LIST), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_hash_lock);
		keyword_engine_free(pengine);
		return DOMAIN_KEYWORD_HASH_FAIL;
	}
	iter = str_hash_iter_init(g_hash_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		ppengine = (KEYWORD_ENGINE**)str_hash_iter_get_value(iter, temp_buff);
		str_hash_add(phash, temp_buff, ppengine);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_hash_table);
	g_hash_table = phash;
	str_hash_add(g_hash_table, temp_domain, &pengine);
	g_hash_cap += g_growing_num;
	pthread_rwlock_unlock(&g_hash_lock);
	return DOMAIN_KEYWORD_ADD_OK;
}

static BOOL domain_keyword_get_fwdinfo(const char *domain,
	char *forward_to, char *lang)
{
	char *str_value;
	char homedir[256];
	char tmp_path[256];
	CONFIG_FILE *pconfig;

	if (FALSE == domain_keyword_get_homedir(domain, homedir)) {
		return FALSE;
	}

	snprintf(tmp_path, 256, "%s/domain.cfg", homedir);
	pconfig = config_file_init2(NULL, tmp_path);
	if (NULL == pconfig) {
		return FALSE;
	}

	str_value = config_file_get_value(pconfig, "KBOUNCE_LANGUAGE");
	if (NULL != str_value) {
		strncpy(lang, str_value, 32);
	} else {
		strcpy(lang, "en");
	}

	str_value = config_file_get_value(pconfig, "KBOUNCE_MAILBOX");
	if (NULL == str_value) {
		config_file_free(pconfig);
		return FALSE;
	}

	strncpy(forward_to, str_value, 256);
	config_file_free(pconfig);
	return TRUE;
}

static void domain_keyword_convert_to_utf8(const char *charset,
	const char *string, char *buff_out)
{
    int length;
    iconv_t conv_id;
    char *pin, *pout;
    size_t in_len, out_len;


    if (0 == strcasecmp(charset, "UTF-8") ||
        0 == strcasecmp(charset, "ASCII") ||
        0 == strcasecmp(charset, "US-ASCII")) {
        strncpy(buff_out, string, 256);
		return;
    }

    length = strlen(string) + 1;
    conv_id = iconv_open("UTF-8", charset);
    if ((iconv_t)-1 == conv_id) {
		buff_out[0] = '\0';
        return;
    }
    pin = (char*)string;
    pout = buff_out;
    in_len = length;
    out_len = 256;
    if (-1 == iconv(conv_id, &pin, &in_len, &pout, &out_len)) {
        iconv_close(conv_id);
		buff_out[0] = '\0';
        return;
    }
    iconv_close(conv_id);
}

