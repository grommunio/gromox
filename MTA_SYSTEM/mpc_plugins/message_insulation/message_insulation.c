#include "message_insulation.h"
#include "bounce_producer.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

static char g_config_path[256];
static char g_queue_path[256];
static int g_scan_interval;
static int g_on_valid_interval;
static int g_anon_valid_interval;
static BOOL g_notify_stop = TRUE;
static pthread_t g_thread_id;

static void* thread_work_func(void* arg);
static void message_insulation_log_info(MESSAGE_CONTEXT *pcontext, int level, const char *format, ...);

void message_insulation_init(const char* config_path, const char *queue_path,
	int scan_interval, int on_valid_interval, int anon_valid_interval)
{
	strcpy(g_config_path, config_path);
	strcpy(g_queue_path, queue_path);
	g_scan_interval = scan_interval;
	g_on_valid_interval = on_valid_interval;
	g_anon_valid_interval = anon_valid_interval;
}

int message_insulation_run()
{
	struct stat node_stat;
	pthread_attr_t attr;
	
	if (0 != stat(g_queue_path, &node_stat) ||
		0 == S_ISDIR(node_stat.st_mode)) {
		printf("[message_insulation]: %s is not a directory\n", g_queue_path);
		return -1;
	}
	g_notify_stop = FALSE;
	pthread_attr_init(&attr);
	if(0 != pthread_create(&g_thread_id, &attr, thread_work_func, NULL)) {
		pthread_attr_destroy(&attr);
		g_notify_stop = TRUE;
		return -2;
	}
	pthread_attr_destroy(&attr);
	return 0;
}

int message_insulation_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	return 0;
}

void message_insulation_free()
{
	g_config_path[0] = '\0';
	g_queue_path[0] = '\0';
}


static void* thread_work_func(void* arg)
{
	int i, fd;
	DIR *dirp;
	MIME *pmime;
	char *pbuff;
	int interval;
	int rcpt_num;
	BOOL b_onymous;
	time_t tmp_time;
	char *ptr1, *ptr2;
	char time_str[32];
	char temp_path[256];
	char temp_rcpt[256];
	time_t current_time;
	struct stat node_stat;
	struct dirent *direntp;
	MESSAGE_CONTEXT *pcontext;
	MESSAGE_CONTEXT *pbounce_context;


	interval = 0;
	dirp = opendir(g_queue_path);
	while (FALSE == g_notify_stop) {
		sleep(1);
		interval ++;
		if (interval < g_scan_interval) {
			continue;
		}
		
		time(&current_time);
		seekdir(dirp, 0);
		while ((direntp = readdir(dirp)) != NULL) {
			if (0 == strcmp(".", direntp->d_name) ||
				0 == strcmp("..", direntp->d_name)) {
				continue;
			}
			sprintf(temp_path, "%s/%s", g_queue_path, direntp->d_name);
			ptr1 = strchr(direntp->d_name, '.');
			if (NULL == ptr1) {
				remove(temp_path);
				continue;
			}
			if (0 == strncmp(direntp->d_name, "on.", 3)) {
				b_onymous = TRUE;
			} else {
				b_onymous = FALSE;
			}
			ptr1 ++;
			ptr1 = strchr(ptr1, '.');
			if (NULL == ptr1) {
				remove(temp_path);
				continue;
			}
			ptr1 ++;
			ptr2 = strchr(ptr1, '.');
			if (NULL == ptr2) {
				remove(temp_path);
				continue;
			}
			if (ptr2 - ptr1 > 16) {
				remove(temp_path);
				continue;
			}
			memcpy(time_str, ptr1, ptr2 - ptr1);
			time_str[ptr2 - ptr1] = '\0';
			tmp_time = atoi(time_str);
			
			if (FALSE == b_onymous) {
				if (current_time - tmp_time >= g_anon_valid_interval) {
					remove(temp_path);
				}
				continue;
			} else {
				if (current_time - tmp_time < g_on_valid_interval) {
					continue;
				}
				if (0 != stat(temp_path, &node_stat)) {
					remove(temp_path);
					continue;
				}
				fd = open(temp_path, O_RDONLY);
				if (-1 == fd) {
					remove(temp_path);
					continue;
				}
				pbuff = malloc(((node_stat.st_size - 1)/
						(64 * 1024) + 1) * 64 * 1024);
				if (NULL == pbuff) {
					close(fd);
					remove(temp_path);
					continue;
				}
				if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
					free(pbuff);
					close(fd);
					remove(temp_path);
					continue;
				}
				close(fd);
				pcontext = get_context();
				if (NULL == pcontext) {
					free(pbuff);
					remove(temp_path);
					continue;
				}
				if (FALSE == mail_retrieve_ex(pcontext->pmail,
					pbuff, node_stat.st_size)) {
					free(pbuff);
					put_context(pcontext);
					remove(temp_path);
					continue;
				}
				free(pbuff);
				pmime = mail_get_head(pcontext->pmail);
				
				mime_get_field(pmime, "X-Envelop-From",
					pcontext->pcontrol->from, 256);
				rcpt_num = mime_get_field_num(pmime, "X-Envelop-Rcpt");
				for (i=0; i<rcpt_num; i++) {
					if (TRUE == mime_search_field(pmime, "X-Envelop-Rcpt", i,
						temp_rcpt, 256)) {
						mem_file_writeline(&pcontext->pcontrol->f_rcpt_to,
							temp_rcpt);
					}
				}
				pbounce_context = get_context();
				if (NULL == pbounce_context) {
					put_context(pcontext);
					remove(temp_path);
					continue;
				}
				bounce_producer_make(pcontext, tmp_time,
					pbounce_context->pmail); 
				snprintf(pbounce_context->pcontrol->from, 256, "postmaster@%s",
					get_default_domain());
				mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
					pcontext->pcontrol->from);
				put_context(pcontext);
				remove(temp_path);
				enqueue_context(pbounce_context);
			}
		}
		interval = 0;
	}
	closedir(dirp);
	return NULL;
}

BOOL message_insulation_activate(const char *file_name)
{
	int i, fd;
	int rcpt_num;
	MIME *pmime;
	char *pbuff;
	char temp_rcpt[256];
	char queue_buff[32];
	char bound_buff[32];
	struct stat node_stat;
	MESSAGE_CONTEXT *pcontext;
	
	if (0 != stat(file_name, &node_stat)) {
		return FALSE;
	}
	fd = open(file_name, O_RDONLY);
	if (-1 == fd) {
		return FALSE;
	}
	pbuff = malloc(((node_stat.st_size - 1)/(64 * 1024) + 1) * 64 * 1024);
	if (NULL == pbuff) {
		return FALSE;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		return FALSE;
	}
	close(fd);
	pcontext = get_context();
	if (NULL == pcontext) {
		free(pbuff);
		return FALSE;
	}
	if (FALSE == mail_retrieve_ex(pcontext->pmail, pbuff, node_stat.st_size)) {
		free(pbuff);
		put_context(pcontext);
		return FALSE;
	}
	free(pbuff);
	pmime = mail_get_head(pcontext->pmail);
	if (FALSE == mime_get_field(pmime, "X-Queue-Id", queue_buff, 32)) {
		put_context(pcontext);
		return FALSE;
	}
	pcontext->pcontrol->queue_ID = atoi(queue_buff);
	if (FALSE == mime_get_field(pmime, "X-Bound-Type", bound_buff, 32)) {
		put_context(pcontext);
		return FALSE;
	}
	pcontext->pcontrol->bound_type = atoi(bound_buff);
	if (FALSE == mime_get_field(pmime, "X-Envelop-From",
		pcontext->pcontrol->from, 256)) {
		put_context(pcontext);
		return FALSE;
	}
	rcpt_num = mime_get_field_num(pmime, "X-Envelop-Rcpt");
	for (i=0; i<rcpt_num; i++) {
		if (FALSE == mime_search_field(pmime, "X-Envelop-Rcpt", i,
			temp_rcpt, 256)) {
			put_context(pcontext);
			return FALSE;
		}
		mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, temp_rcpt);
	}
	pcontext->pcontrol->need_bounce = TRUE;
	message_insulation_log_info(pcontext, 8, "message is activated "
		"from insulation queue");
	enqueue_context(pcontext);
	remove(file_name);
	return TRUE;
}

void message_insulation_console_talk(int argc, char **argv, char *result,
	int length)
{
    int interval, len;
    CONFIG_FILE *pfile;
	char temp_path[256];
    char help_string[] = "250 message insulation help information:\r\n"
                         "\t%s info\r\n"
                         "\t    --printf spam insulation's information\r\n"
                         "\t%s set scan-interval <interval>\r\n"
                         "\t    --set scan interval of insulation queue\r\n"
                         "\t%s set onymous-valid-interval <interval>\r\n"
                         "\t    --set onymous valid interval of insulated messages\r\n"
                         "\t%s set anonymous-valid-interval <interval>\r\n"
                         "\t    --set anonymous valid interval of insulated messages\r\n"
						 "\t%s bounce reload\r\n"
						 "\t    --reload the bounce resource list\r\n"
						 "\t%s activate <filename>\r\n"
						 "\t    --activate the message from insulation queue";

    if (1 == argc) {
        strncpy(result, "550 too few arguments", length);
        return;
    }
    if (2 == argc && 0 == strcmp("--help", argv[1])) {
        snprintf(result, length, help_string, argv[0], argv[0],
			argv[0], argv[0], argv[0], argv[0]);
        result[length - 1] ='\0';
        return;
    }

    if (2 == argc && 0 == strcmp(argv[1], "info")) {
        len = snprintf(result, length, "250 %s information:\r\n"
                                        "\tscan interval                   ",
                                        argv[0]);
        itvltoa(g_scan_interval, result + len);
		len += strlen(result + len);
		len += sprintf(result + len, "\r\n\tonymous valid interval          ");
        itvltoa(g_on_valid_interval, result + len);
		len += strlen(result + len);
		len += sprintf(result + len, "\r\n\tanonymous valid interval        ");
        itvltoa(g_anon_valid_interval, result + len);
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


	if (3 == argc && 0 == strcmp("activate", argv[1])) {
		sprintf(temp_path, "%s/%s", g_queue_path, argv[2]);
		if (TRUE == message_insulation_activate(temp_path)) {
			strncpy(result, "250 message is activated", length);
		} else {
			strncpy(result, "550 fail to activate message", length);
		}
		return;
	}
    if (4 == argc && 0 == strcmp("set", argv[1]) &&
        0 == strcmp("scan-interval", argv[2])) {
        interval = atoitvl(argv[3]);
        if (interval <= 0) {
            snprintf(result, length, "550 illegal interval %s", argv[3]);
        } else {
            pfile = config_file_init(g_config_path);
            if (NULL == pfile) {
                strncpy(result, "550 fail to open config file", length);
                return;
            }
            config_file_set_value(pfile, "SCAN_INTERVAL", argv[3]);
            if (FALSE == config_file_save(pfile)) {
                strncpy(result, "550 fail to save config file", length);
                config_file_free(pfile);
                return;
            }
            g_scan_interval = interval;
            strncpy(result, "250 scan-interval set OK", length);
        }
        return;
    }
    if (4 == argc && 0 == strcmp("set", argv[1]) &&
        0 == strcmp("onymous-valid-interval", argv[2])) {
        interval = atoitvl(argv[3]);
        if (interval <= 0) {
            snprintf(result, length, "550 illegal interval %s", argv[3]);
        } else {
            pfile = config_file_init(g_config_path);
            if (NULL == pfile) {
                strncpy(result, "550 fail to open config file", length);
                return;
            }
            config_file_set_value(pfile, "ONYMOUS_VALID_INTERVAL", argv[3]);
            if (FALSE == config_file_save(pfile)) {
                strncpy(result, "550 fail to save config file", length);
                config_file_free(pfile);
                return;
            }
			g_on_valid_interval = interval;
            strncpy(result, "250 onymous-valid-interval set OK", length);
        }
        return;
    }
    if (4 == argc && 0 == strcmp("set", argv[1]) &&
        0 == strcmp("anonymous-valid-interval", argv[2])) {
        interval = atoitvl(argv[3]);
        if (interval <= 0) {
            snprintf(result, length, "550 illegal interval %s", argv[3]);
        } else {
            pfile = config_file_init(g_config_path);
            if (NULL == pfile) {
                strncpy(result, "550 fail to open config file", length);
                return;
            }
            config_file_set_value(pfile, "ANONYMOUS_VALID_INTERVAL", argv[3]);
            if (FALSE == config_file_save(pfile)) {
                strncpy(result, "550 fail to save config file", length);
                config_file_free(pfile);
                return;
            }
			g_anon_valid_interval = interval;
            strncpy(result, "250 anonymous-valid-interval set OK", length);
        }
        return;
    }
    snprintf(result, length, "550 invalid argument %s", argv[1]);
    return;
}

static void message_insulation_log_info(MESSAGE_CONTEXT *pcontext, int level,
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

