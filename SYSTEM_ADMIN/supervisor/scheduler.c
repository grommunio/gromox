#include <unistd.h>
#include "common_types.h"
#include "scheduler.h"
#include "list_file.h"
#include "double_list.h"
#include "message.h"
#include "smtp.h"
#include "pop3.h"
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>


typedef struct _SMTP_UNIT {
	DOUBLE_LIST_NODE node;
	pthread_t tid;
	BOOL need_auth;
	char supervise_mailbox[256];
	char username[256];
	char password[256];
	int check_id;
	char dest_ip[16];
	int dest_port;
	time_t last_time;
} SMTP_UNIT;

typedef struct _POP3_UNIT {
	DOUBLE_LIST_NODE node;
	pthread_t tid;
	char supervise_mailbox[256];
	char username[256];
	char password[256];
	int check_id;
	char dest_ip[16];
	int dest_port;
	time_t last_time;
} POP3_UNIT;

static char g_list_path[256];
static char g_failure_path[256];
static char g_admin_mailbox[256];
static char g_default_domain[256];
static int g_max_interval;
static DOUBLE_LIST g_smtp_list;
static DOUBLE_LIST g_pop3_list;
static pthread_mutex_t g_smtp_lock;
static pthread_mutex_t g_pop3_lock;

static void* smtp_work_func(void *param);

static void* pop3_work_func(void *param);

void scheduler_init(const char *list_path, const char *failure_path,
	const char *default_domain, const char *admin_mailbox, int max_interval)
{
	g_max_interval = max_interval;
	strcpy(g_list_path, list_path);
	strcpy(g_failure_path, failure_path);
	strcpy(g_default_domain, default_domain);
	strcpy(g_admin_mailbox, admin_mailbox);
	double_list_init(&g_smtp_list);
	double_list_init(&g_pop3_list);
	pthread_mutex_init(&g_smtp_lock, NULL);
	pthread_mutex_init(&g_pop3_lock, NULL);
}

int scheduler_run()
{
	int i;
	int list_len;
	int smtp_num;
	int pop3_num;
	char *pitem;
	LIST_FILE *plist_file;
	SMTP_UNIT *psmtp_unit;
	POP3_UNIT *ppop3_unit;	
	DOUBLE_LIST_NODE *pnode;

	plist_file = list_file_init(g_list_path, "%s:16:%s:256%s:256%s:256%s:16%d");
	if (NULL == plist_file) {
		printf("[scheduler]: fail to init supervising list\n");
		return -1;
	}
	list_len = list_file_get_item_num(plist_file);
	pitem = (char*)list_file_get_list(plist_file);
	smtp_num = 0;
	pop3_num = 0;
	for (i=0; i<list_len; i++, pitem+=2*16+sizeof(int)+3*256) {
		if (0 == strcasecmp(pitem, "SMTP_IN")) {
			psmtp_unit = (SMTP_UNIT*)malloc(sizeof(SMTP_UNIT));
			if (NULL == psmtp_unit) {
				printf("[scheduler]: fail to allocate memory for smtp unit\n");
				continue;
			}
			psmtp_unit->node.pdata = psmtp_unit;
			psmtp_unit->tid = 0;
			psmtp_unit->need_auth = FALSE;
			strcpy(psmtp_unit->supervise_mailbox, pitem + 16);
			strcpy(psmtp_unit->username, pitem + 16 + 256);
			strcpy(psmtp_unit->password, pitem + 16 + 2*256);
			psmtp_unit->check_id = i;
			strcpy(psmtp_unit->dest_ip, pitem + 16 + 3*256);
			psmtp_unit->dest_port = *(int*)(pitem + 2*16 + 3*256);
			psmtp_unit->last_time = 0;
			double_list_append_as_tail(&g_smtp_list, &psmtp_unit->node);
			smtp_num ++;
		} else if (0 == strcasecmp(pitem, "SMTP_OUT")) {
			psmtp_unit = (SMTP_UNIT*)malloc(sizeof(SMTP_UNIT));
			if (NULL == psmtp_unit) {
				printf("[scheduler]: fail to allocate memory for smtp unit\n");
				continue;
			}
			psmtp_unit->node.pdata = psmtp_unit;
			psmtp_unit->tid = 0;
			psmtp_unit->need_auth = TRUE;
			psmtp_unit->check_id = i;
			strcpy(psmtp_unit->supervise_mailbox, pitem + 16);
			strcpy(psmtp_unit->username, pitem + 16 + 256);
			strcpy(psmtp_unit->password, pitem + 16 + 2*256);
			strcpy(psmtp_unit->dest_ip, pitem + 16 + 3*256);
			psmtp_unit->dest_port = *(int*)(pitem + 2*16 + 3*256);
			psmtp_unit->last_time = 0;
			double_list_append_as_tail(&g_smtp_list, &psmtp_unit->node);
			smtp_num ++;
		} else if (0 == strcasecmp(pitem, "POP3")) {
			ppop3_unit = (POP3_UNIT*)malloc(sizeof(POP3_UNIT));
			if (NULL == ppop3_unit) {
				printf("[scheduler]: fail to allocate memory for pop3 unit\n");
				continue;
			}
			ppop3_unit->node.pdata = ppop3_unit;
			ppop3_unit->tid = 0;
			ppop3_unit->check_id = i;
			ppop3_unit->last_time = 0;
			strcpy(ppop3_unit->supervise_mailbox, pitem + 16);
			strcpy(ppop3_unit->username, pitem + 16 + 256);
			strcpy(ppop3_unit->password, pitem + 16 + 2*256);
			strcpy(ppop3_unit->dest_ip, pitem + 16 + 3*256);
			ppop3_unit->dest_port = *(int*)(pitem + 2*16 + 3*256);
			double_list_append_as_tail(&g_pop3_list, &ppop3_unit->node);
			pop3_num ++;
		} else {
			printf("[scheduler]: %s is unrecognized, should be SMTP_IN, "
				"SMTP_OUT or POP3\n", pitem);
			continue;
		}
	}
	list_file_free(plist_file);

	if (0 == smtp_num) {
		printf("[scheduler]: cannot find SMTP service in supervising list!\n");
		return 0;
	}
	if (0 == pop3_num) {
		printf("[scheduler]: cannot find POP3 service in supervising list!\n");
		return 0;
	}

	for (pnode=double_list_get_head(&g_smtp_list); pnode!=NULL;
		pnode=double_list_get_after(&g_smtp_list, pnode)) {
		psmtp_unit = (SMTP_UNIT*)pnode->pdata;
		if (0 != pthread_create(&psmtp_unit->tid, NULL, smtp_work_func,
			psmtp_unit)) {
			printf("[scheduler]: fail to create monitor thread for SMTP "
				"service %s:%d\n", psmtp_unit->dest_ip, psmtp_unit->dest_port);
			continue;
		}
	}
	for (pnode=double_list_get_head(&g_pop3_list); pnode!=NULL;
		pnode=double_list_get_after(&g_pop3_list, pnode)) {
		ppop3_unit = (POP3_UNIT*)pnode->pdata;
		if (0 != pthread_create(&ppop3_unit->tid, NULL, pop3_work_func,
			ppop3_unit)) {
			printf("[scheduler]: fail to create monitor thread for POP3 "
				"service %s:%d\n", ppop3_unit->dest_ip, ppop3_unit->dest_port);
			continue;
		}
	}
	return 0;	
}

void scheduler_stop(void)
{
	SMTP_UNIT *psmtp_unit;
	POP3_UNIT *ppop3_unit;	
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_smtp_list); pnode!=NULL;
		pnode=double_list_get_after(&g_smtp_list, pnode)) {
		psmtp_unit = (SMTP_UNIT*)pnode->pdata;
		if (0 != psmtp_unit->tid) {
			pthread_cancel(psmtp_unit->tid);
		}
	}
	for (pnode=double_list_get_head(&g_pop3_list); pnode!=NULL;
		pnode=double_list_get_after(&g_pop3_list, pnode)) {
		ppop3_unit = (POP3_UNIT*)pnode->pdata;
		if (0 != ppop3_unit->tid) {
			pthread_cancel(ppop3_unit->tid);
		}
	}
	while (pnode=double_list_get_from_head(&g_smtp_list)) {
		free(pnode->pdata);
	}
	while (pnode=double_list_get_from_head(&g_pop3_list)) {
		free(pnode->pdata);
	}
}

void scheduler_free()
{
	double_list_free(&g_smtp_list);
	double_list_free(&g_pop3_list);
	pthread_mutex_destroy(&g_smtp_lock);
	pthread_mutex_destroy(&g_pop3_lock);
}

static void* smtp_work_func(void *param)
{
	int fd, len;
	int s_result;
	BOOL b_removed;
	time_t cur_time;
	struct tm temp_tm;
	char temp_buff[MESSAGE_BUFF_SIZE];
	char record_buff[1024];
	char last_command[1024];
	char last_response[1024];
	char *pdomain, sender_buff[256];
	SMTP_UNIT *psmtp_unit;
	POP3_UNIT *ppop3_unit;
	DOUBLE_LIST_NODE *pnode;

	b_removed = FALSE;
	psmtp_unit = (SMTP_UNIT*)param;
	time(&psmtp_unit->last_time);
	while (TRUE) {
		message_supervising(temp_buff, MESSAGE_SUPERVISING_SMTP,
			psmtp_unit->check_id);
		if (FALSE == psmtp_unit->need_auth) {
			s_result = smtp_send_inbound(psmtp_unit->dest_ip,
				psmtp_unit->dest_port, psmtp_unit->supervise_mailbox,
				temp_buff, last_command, last_response);
		} else {
			s_result = smtp_send_outbound(psmtp_unit->dest_ip,
				psmtp_unit->dest_port, psmtp_unit->username,
				psmtp_unit->password, psmtp_unit->supervise_mailbox,
				temp_buff, last_command, last_response);
		}
		if (SMTP_SEND_OK != s_result) {
			time(&cur_time);
			if (cur_time - psmtp_unit->last_time > g_max_interval) {
				if (FALSE == b_removed) {
					pthread_mutex_lock(&g_smtp_lock);
					if (double_list_get_nodes_num(&g_smtp_list) > 1) {
						double_list_remove(&g_smtp_list, &psmtp_unit->node);
					}
					pthread_mutex_unlock(&g_smtp_lock);
					b_removed = TRUE;
					len = strftime(record_buff, 1024, "%Y-%m-%d-%H-%M\t",
							localtime_r(&cur_time, &temp_tm));
					sprintf(record_buff + len, "%s:%d\t%d\n",
						psmtp_unit->dest_ip, psmtp_unit->dest_port,
						MESSAGE_SMTP_BASE + s_result);
					fd = open(g_failure_path, O_WRONLY|O_APPEND);
					if (-1 != fd) {
						write(fd, record_buff, strlen(record_buff));
						close(fd);
					}
					message_alarm_message(temp_buff, MESSAGE_SMTP_BASE +
						s_result, last_command, last_response,
						psmtp_unit->dest_ip, psmtp_unit->dest_port,
						g_admin_mailbox);
					pdomain = strchr(g_admin_mailbox, '@');
					if (NULL != pdomain) {
						pdomain ++;
						if (0 == strcasecmp(pdomain, g_default_domain)) {
							smtp_send_message("supervise-alarm@system.mail",
								g_admin_mailbox, temp_buff);
						} else {
							sprintf(sender_buff, "supervise-alarm@%s",
								g_default_domain);
						}
						smtp_send_message(sender_buff, g_admin_mailbox,
							temp_buff);
					}
				}
				sleep(g_max_interval*10);
				continue;
			} else {
				sleep(g_max_interval/10);
				continue;
			}
		}
		sleep(g_max_interval/10);
		time(&psmtp_unit->last_time);
SMTPTHR_RETRIEVE:
		pthread_mutex_lock(&g_pop3_lock);
		pnode = double_list_get_from_head(&g_pop3_list);
		if (NULL != pnode) {
			double_list_append_as_tail(&g_pop3_list, pnode);
		}
		pthread_mutex_unlock(&g_pop3_lock);
		if (NULL == pnode) {
			sleep(g_max_interval/10);
			goto SMTPTHR_RETRIEVE;
		}
		ppop3_unit = (POP3_UNIT*)pnode->pdata;
		if (POP3_RETRIEVE_OK != pop3_retrieve_message(ppop3_unit->dest_ip,
			ppop3_unit->dest_port, psmtp_unit->username, psmtp_unit->password,
			MESSAGE_SUPERVISING_SMTP, psmtp_unit->check_id,
			last_command, last_response)) {
			time(&cur_time);
			if (cur_time - psmtp_unit->last_time > g_max_interval) {
				if (FALSE == b_removed) {
					pthread_mutex_lock(&g_smtp_lock);
					if (double_list_get_nodes_num(&g_smtp_list) > 1) {
						double_list_remove(&g_smtp_list, &psmtp_unit->node);
					}
					pthread_mutex_unlock(&g_smtp_lock);
					b_removed = TRUE;
					len = strftime(record_buff, 1024, "%Y-%m-%d-%H-%M\t",
							localtime_r(&cur_time, &temp_tm));
					sprintf(record_buff + len, "%s:%d\t%d\n",
						psmtp_unit->dest_ip, psmtp_unit->dest_port,
						MESSAGE_ALARM_QUEUE);
					fd = open(g_failure_path, O_WRONLY|O_APPEND);
					if (-1 != fd) {
						write(fd, record_buff, strlen(record_buff));
						close(fd);
					}
					message_alarm_message(temp_buff, MESSAGE_ALARM_QUEUE,
						NULL, NULL, psmtp_unit->dest_ip, psmtp_unit->dest_port,
						g_admin_mailbox);
					pdomain = strchr(g_admin_mailbox, '@');
					if (NULL != pdomain) {
						pdomain ++;
						if (0 == strcasecmp(pdomain, g_default_domain)) {
							smtp_send_message("supervise-alarm@system.mail",
								g_admin_mailbox, temp_buff);
						} else {
							sprintf(sender_buff, "supervise-alarm@%s",
								g_default_domain);
						}
						smtp_send_message(sender_buff, g_admin_mailbox,
							temp_buff);
					}
				}
				sleep(g_max_interval*10);
				continue;
			} else {
				sleep(g_max_interval/10);
				goto SMTPTHR_RETRIEVE;
			}
		}
		if (TRUE == b_removed) {
			pthread_mutex_lock(&g_smtp_lock);
			double_list_append_as_tail(&g_smtp_list, &psmtp_unit->node);
			pthread_mutex_unlock(&g_smtp_lock);
			b_removed = FALSE;
		}
		sleep(g_max_interval);
		time(&psmtp_unit->last_time);
	}
	return NULL;
}
	
static void* pop3_work_func(void *param)
{
	int fd, len;
	int s_result;
	int r_result;
	BOOL b_removed;
	time_t cur_time;
	struct tm temp_tm;
	char temp_buff[MESSAGE_BUFF_SIZE];
	char record_buff[1024];
	char last_command[1024];
	char last_response[1024];
	char *pdomain, sender_buff[256];
	SMTP_UNIT *psmtp_unit;
	POP3_UNIT *ppop3_unit;
	DOUBLE_LIST_NODE *pnode;

	b_removed = FALSE;
	ppop3_unit = (POP3_UNIT*)param;
	time(&ppop3_unit->last_time);
	while (TRUE) {
		message_supervising(temp_buff, MESSAGE_SUPERVISING_POP3,
			ppop3_unit->check_id);
POP3THR_SEND:
		pthread_mutex_lock(&g_smtp_lock);
		pnode = double_list_get_from_head(&g_smtp_list);
		if (NULL != pnode) {
			double_list_append_as_tail(&g_smtp_list, pnode);
		}
		pthread_mutex_unlock(&g_smtp_lock);
		if (NULL == pnode) {
			sleep(g_max_interval/10);
			goto POP3THR_SEND;
		}
		psmtp_unit = (SMTP_UNIT*)pnode->pdata;
		if (FALSE == psmtp_unit->need_auth) {
			s_result = smtp_send_inbound(psmtp_unit->dest_ip,
				psmtp_unit->dest_port, ppop3_unit->supervise_mailbox,
				temp_buff, last_command, last_response);
		} else {
			s_result = smtp_send_outbound(psmtp_unit->dest_ip,
				psmtp_unit->dest_port, ppop3_unit->username,
				ppop3_unit->password, ppop3_unit->supervise_mailbox,
				temp_buff, last_command, last_response);
		}
		if (SMTP_SEND_OK != s_result) {
			sleep(g_max_interval/10);
			goto POP3THR_SEND;
		}
		sleep(g_max_interval/10);
		time(&ppop3_unit->last_time);
POP3THR_RETRIEVE:
		r_result = pop3_retrieve_message(ppop3_unit->dest_ip,
					ppop3_unit->dest_port, ppop3_unit->username,
					ppop3_unit->password, MESSAGE_SUPERVISING_POP3,
					ppop3_unit->check_id, last_command, last_response);
		time(&cur_time);
		if (POP3_RETRIEVE_OK != r_result) {
			if (cur_time - ppop3_unit->last_time > g_max_interval) {
				if (FALSE == b_removed) {
					pthread_mutex_lock(&g_pop3_lock);
					if (double_list_get_nodes_num(&g_pop3_list) > 1) {
						double_list_remove(&g_pop3_list, &ppop3_unit->node);
					}
					pthread_mutex_unlock(&g_pop3_lock);
					b_removed = TRUE;
					len = strftime(record_buff, 1024, "%Y-%m-%d-%H-%M\t",
							localtime_r(&cur_time, &temp_tm));
					sprintf(record_buff + len, "%s:%d\t%d\n",
						ppop3_unit->dest_ip, ppop3_unit->dest_port,
						MESSAGE_POP3_BASE + r_result);
					fd = open(g_failure_path, O_WRONLY|O_APPEND);
					if (-1 != fd) {
						write(fd, record_buff, strlen(record_buff));
						close(fd);
					}
					message_alarm_message(temp_buff, MESSAGE_POP3_BASE +
						r_result, last_command, last_response,
						ppop3_unit->dest_ip, ppop3_unit->dest_port,
						g_admin_mailbox);
					pdomain = strchr(g_admin_mailbox, '@');
					if (NULL != pdomain) {
						pdomain ++;
						if (0 == strcasecmp(pdomain, g_default_domain)) {
							smtp_send_message("supervise-alarm@system.mail",
								g_admin_mailbox, temp_buff);
						} else {
							sprintf(sender_buff, "supervise-alarm@%s",
								g_default_domain);
						}
						smtp_send_message(sender_buff, g_admin_mailbox,
							temp_buff);
					}
				}
				sleep(g_max_interval*10);
				continue;
			} else {
				sleep(g_max_interval/10);
				goto POP3THR_RETRIEVE;
			}
		}
		if (TRUE == b_removed) {
			pthread_mutex_lock(&g_pop3_lock);
			double_list_append_as_tail(&g_pop3_list, &ppop3_unit->node);
			pthread_mutex_unlock(&g_pop3_lock);
			b_removed = FALSE;
		}
		sleep(g_max_interval);
		time(&ppop3_unit->last_time);
	}
	return NULL;
}

