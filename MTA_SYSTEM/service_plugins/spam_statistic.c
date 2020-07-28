#include <errno.h>
#include <stdbool.h>
#include <libHX/defs.h>
#include <gromox/defs.h>
#include <gromox/svc_common.h>
#include "list_file.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

#define SPAM_TAG_LEN		40
#define SPAM_TABLE_SIZE		1024

static void console_talk(int argc, char **argv, char *result, int length);

static void spam_statistic(int ID);

DECLARE_API;

static void *g_shm_begin;
static time_t *g_status_time;
static time_t *g_report_time;
static LIST_FILE *g_list;
static char g_table_path[256];
static int *g_status_table;
static int *g_report_table;


BOOL SVC_LibMain(int reason, void **ppdata)
{
	int shm_id;
	key_t k_shm;
	BOOL new_created;
	char file_name[256];
	char temp_path[256];
	char *psearch;
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		k_shm = ftok(temp_path, 1);
		if (-1 == k_shm) {
			printf("[spam_statistic]: ftok %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		shm_id = shmget(k_shm, 2*sizeof(int)*SPAM_TABLE_SIZE + 
					2*sizeof(time_t), 0666);
		if (-1 == shm_id) {
			shm_id = shmget(k_shm, 2*sizeof(int)*SPAM_TABLE_SIZE + 
						2*sizeof(time_t), 0666|IPC_CREAT);
			new_created = TRUE;
		} else {
			new_created = FALSE;
		}
		if (-1 == shm_id) {
			printf("[spam_statistic]: shmget: %s\n", strerror(errno));
			return FALSE;
		}
		g_shm_begin = shmat(shm_id, NULL, 0);
		if ((void*)-1 == g_shm_begin) {
			printf("[spam_statistic]: shmat: %s\n", strerror(errno));
			g_shm_begin = NULL;
			return FALSE;
		}
		g_status_table = (int*)g_shm_begin;
		g_report_table = (int*)g_shm_begin + SPAM_TABLE_SIZE;
		g_status_time = (time_t*)(g_report_table + SPAM_TABLE_SIZE);
		g_report_time = g_status_time + 1;
		if (TRUE == new_created) {
			time(g_status_time);
			time(g_report_time);
		}
		sprintf(g_table_path, "%s/%s.txt", get_data_path(), file_name);
		g_list = list_file_init(g_table_path, "%s:256");
        if (FALSE == register_talk(console_talk)) {
			printf("[sample]: failed to register console talk\n");
			return FALSE;
		}
		if (FALSE == register_service("spam_statistic", spam_statistic)) {
			printf("[spam_statistic]: failed to register service function\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		if (NULL != g_shm_begin) {
			shmdt(g_shm_begin);
			g_shm_begin = NULL;
		}
		if (NULL != g_list) {
			list_file_free(g_list);
			g_list = NULL;
		}
		return TRUE;
	}
	return false;
}


static void console_talk(int argc, char **argv, char *result, int length)
{
	int i, j;
	char *ptr;
	int item_len, item_num;
	struct tm time_buff;
	char help_string[] = "250 spam statistic help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the spam description table\r\n"
						 "\t%s status\r\n"
						 "\t    --print spam statistic infomation\r\n"
						 "\t%s report\r\n"
						 "\t    --only for spam report forms\r\n"
						 "\t%s clear\r\n"
						 "\t    --clear spam report information";
	struct srcitem { char thing[256]; };						 

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0],
			argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		if (NULL != g_list) {
			list_file_free(g_list);
		}
		g_list = list_file_init(g_table_path, "%s:256");
		if (NULL == g_list) {
			strncpy(result, "550 fail to reload string table", length);
		} else {
			strncpy(result, "250 reload string table OK", length);
		}
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "status")) {
		if (NULL == g_list) {
			strncpy(result, "550 spam information table error", length);
			return;
		}
		const struct srcitem *pitem = reinterpret_cast(struct srcitem *, list_file_get_list(g_list));
		item_len = sprintf(result, "250 spam statistics infomation:\r\n");
		ptr = result + item_len;
		item_len = 0;
		item_num = list_file_get_item_num(g_list);
		for (i=0; i<item_num && i<SPAM_TABLE_SIZE; i++) {
			item_len = strlen(pitem[i].thing);
			memcpy(ptr, pitem[i].thing, item_len);
			ptr += item_len;
			for (j=0; j<SPAM_TAG_LEN-item_len; j++, ptr++) {
				*ptr = ' ';
			}
			item_len = sprintf(ptr, "%d\r\n", g_status_table[i]);
			ptr += item_len;
		}
		item_len = sprintf(ptr, "\r\n* last statistic time: ");
		ptr += item_len;
		strftime(ptr, 128, "%Y/%m/%d %H:%M:%S",
			localtime_r(g_status_time, &time_buff));
		time(g_status_time);
		memset(g_status_table, 0, sizeof(int)*SPAM_TABLE_SIZE);
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "report")) {
		if (NULL == g_list) {
			strncpy(result, "550 spam information table error", length);
			return;
		}
		const struct srcitem *pitem = reinterpret_cast(struct srcitem *, list_file_get_list(g_list));
		item_len = sprintf(result, "250 spam statistics infomation:\r\n");
		ptr = result + item_len;
		item_len = 0;
		item_num = list_file_get_item_num(g_list);
		for (i=0; i<item_num && i<SPAM_TABLE_SIZE; i++) {
			item_len = strlen(pitem[i].thing);
			memcpy(ptr, pitem[i].thing, item_len);
			ptr += item_len;
			for (j=0; j<SPAM_TAG_LEN-item_len; j++, ptr++) {
				*ptr = ' ';
			}
			item_len = sprintf(ptr, "%d\r\n", g_report_table[i]);
			ptr += item_len;
		}
		item_len = sprintf(ptr, "\r\n* last statistic time: ");
		ptr += item_len;
		strftime(ptr, 128, "%Y/%m/%d %H:%M:%S",
			localtime_r(g_report_time, &time_buff));
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "clear")) {
		time(g_report_time);
		memset(g_report_table, 0, sizeof(int)*SPAM_TABLE_SIZE);
		strncpy(result, "250 clear report information OK!", length);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

static void spam_statistic(int ID)
{
	if (ID > SPAM_TABLE_SIZE - 1 || ID < 0) {
		return;
	}
	g_status_table[ID] ++;
	g_report_table[ID] ++;
}

