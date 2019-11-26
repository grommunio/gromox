#include <unistd.h>
#include "exec_sched.h"
#include "str_hash.h"
#include "util.h"
#include "vuser.h"
#include "list_file.h"
#include <pthread.h>
#include <stdio.h>
#include <fcntl.h>


#define HASH_GROWING_NUM		100

#define SCAN_INTERVAL			60

typedef struct _USER_INFO {
	time_t last_time;
	BOOL b_working;
} USER_INFO;

static STR_HASH_TABLE *g_hash_table = NULL;
static pthread_rwlock_t g_table_lock;
static DOUBLE_LIST g_execute_list;
static pthread_t g_scan_tid;
static char g_list_path[256];
static int g_hash_cap = 0;
static int g_pop_interval;
static int g_threads_num;
static pthread_t *g_thread_tids;

static void* scan_work_func(void *param);

static void* thread_work_func(void *param);

void exec_sched_init(const char *list_path, int pop_interval, int threads_num)
{
	strcpy(g_list_path, list_path);
	g_pop_interval = pop_interval;
	g_threads_num = threads_num;
    pthread_rwlock_init(&g_table_lock, NULL);
	double_list_init(&g_execute_list);
}

void exec_sched_free()
{
    pthread_rwlock_destroy(&g_table_lock);
	double_list_free(&g_execute_list);
	g_list_path[0] = '\0';
	g_hash_cap = 0;
}

int exec_sched_run()
{
	char *pitem;
    STR_HASH_TABLE *phash = NULL;
    int i, list_len, hash_cap;
	LIST_FILE *plist_file;
	USER_INFO temp_info;
	
    /* initialize the list filter */
	plist_file = list_file_init(g_list_path, "%s:128");
	if (NULL == plist_file) {
		printf("[exec_sched]: fail to open list file %s\n", g_list_path);
		return -1;
	}
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	hash_cap = list_len + HASH_GROWING_NUM;
	
    g_hash_table = str_hash_init(hash_cap, sizeof(USER_INFO), NULL);
	if (NULL == g_hash_table) {
		printf("[exec_sched]: fail to allocate hash map");
		list_file_free(plist_file);
		return -2;
	}

	temp_info.last_time = 0;
	temp_info.b_working = FALSE;

    for (i=0; i<list_len; i++) {
		lower_string(pitem + 128*i);
        str_hash_add(g_hash_table, pitem + 128*i, &temp_info);   
    }
    list_file_free(plist_file);	
	g_hash_cap = hash_cap;

	if (0 != pthread_create(&g_scan_tid, NULL, scan_work_func, NULL)) {
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
		g_hash_cap = 0;
		return -3;
	}

	g_thread_tids = malloc(g_threads_num*sizeof(pthread_t));
	if (NULL == g_thread_tids) {
		pthread_cancel(g_scan_tid);
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
		g_hash_cap = 0;
		return -4;
	}

	for (i=0; i<g_threads_num; i ++) {
		pthread_create(&g_thread_tids[i], NULL, thread_work_func, NULL);
	}

    return 0;
}

int exec_sched_stop()
{
	int i;
	DOUBLE_LIST_NODE *pnode;
    

	pthread_cancel(g_scan_tid);
	for (i=0; i<g_threads_num; i++) {
		pthread_cancel(g_thread_tids[i]);
	}
	free(g_thread_tids);
	g_thread_tids = NULL;

	while (pnode=double_list_get_from_head(&g_execute_list)) {
		free(pnode->pdata);
		free(pnode);
	}
    str_hash_free(g_hash_table);
    g_hash_table = NULL;
	g_hash_cap = 0;

    return 0;
}


BOOL exec_sched_add(const char* username)
{
	char temp_string[128];
	char file_item[256];
	int i, j, hash_cap;
	int fd, string_len;
	STR_HASH_ITER *iter;
	STR_HASH_TABLE *phash;
	USER_INFO temp_info;
	USER_INFO *pinfo;


	strncpy(temp_string, username, 128);
	temp_string[127] = '\0';
	lower_string(temp_string);
	string_len = strlen(temp_string);
	for (i=0, j=0; i<string_len; i++, j++) {
		if (' ' == temp_string[i] || '\\' == temp_string[i] ||
			'\t' == temp_string[i] || '#' == temp_string[i]) {
			file_item[j] = '\\';
			j ++;
		}
		file_item[j] = temp_string[i];
	}
	string_len = j;
	file_item[string_len] = '\n';
	string_len ++;
	pthread_rwlock_wrlock(&g_table_lock);
	/* check first if the string is already in the table */
	if (NULL != str_hash_query(g_hash_table, temp_string)) {
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	}
	fd = open(g_list_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
	if (string_len != write(fd, file_item, string_len)) {
		close(fd);
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
	close(fd);
	temp_info.last_time = 0;
	temp_info.b_working = FALSE;
	if (str_hash_add(g_hash_table, temp_string, &temp_info) > 0) {
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	}
	hash_cap = g_hash_cap + HASH_GROWING_NUM;
	phash = str_hash_init(hash_cap, sizeof(USER_INFO), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
	iter = str_hash_iter_init(g_hash_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pinfo = (USER_INFO*)str_hash_iter_get_value(iter, file_item);
		str_hash_add(phash, file_item, pinfo);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_hash_table);
	g_hash_table = phash;
	g_hash_cap = hash_cap;
	if (str_hash_add(g_hash_table, temp_string, &temp_info) > 0) {
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	}
	pthread_rwlock_unlock(&g_table_lock);
	return FALSE;
}

BOOL exec_sched_remove(const char* username)
{
	int i, j;
	int fd, string_len;
	char temp_string[128];
	char file_item[256];
	STR_HASH_ITER *iter;
	
	strncpy(temp_string, username, 127);
	temp_string[127] = '\0';
	lower_string(temp_string);
	pthread_rwlock_wrlock(&g_table_lock);
	/* check first if the string is in hash table */
	if (NULL == str_hash_query(g_hash_table, temp_string)) {
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	}
	if (1 != str_hash_remove(g_hash_table, temp_string)) {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
	fd = open(g_list_path, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
	iter = str_hash_iter_init(g_hash_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		str_hash_iter_get_value(iter, temp_string);
		string_len = strlen(temp_string);
		for (i=0, j=0; i<string_len; i++, j++) {
			if (' ' == temp_string[i] || '\\' == temp_string[i] ||
				'\t' == temp_string[i] || '#' == temp_string[i]) {
				file_item[j] = '\\';
				j ++;
			}
			file_item[j] = temp_string[i];
		}
		string_len = j;
		file_item[string_len] = '\n';
		string_len ++;
		write(fd, file_item, string_len);
	}
	str_hash_iter_free(iter);
	close(fd);
	pthread_rwlock_unlock(&g_table_lock);
	return TRUE;
}

static void* scan_work_func(void *param)
{
	STR_HASH_ITER *iter;
	USER_INFO *pinfo;
	char temp_string[128];
	DOUBLE_LIST_NODE *pnode;
	time_t last_time;

	while (TRUE) {
		sleep(SCAN_INTERVAL);

		pthread_rwlock_wrlock(&g_table_lock);
		time(&last_time);
		iter = str_hash_iter_init(g_hash_table);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pinfo = (USER_INFO*)str_hash_iter_get_value(iter, temp_string);
			if (FALSE == pinfo->b_working &&
				last_time - pinfo->last_time >= g_pop_interval) {
				pnode = malloc(sizeof(DOUBLE_LIST_NODE));
				if (NULL == pnode) {
					continue;
				}
				pnode->pdata = strdup(temp_string);
				if (NULL == pnode->pdata) {
					free(pnode);
					continue;
				}
				double_list_append_as_tail(&g_execute_list, pnode);
				pinfo->b_working = TRUE;
			}
		}
		pthread_rwlock_unlock(&g_table_lock);
	}
	return NULL;
}

static void* thread_work_func(void *param)
{
	DOUBLE_LIST_NODE *pnode;
	VUSER iuser;
	USER_INFO *pinfo;

	while (TRUE) {
		pthread_rwlock_wrlock(&g_table_lock);
		pnode = double_list_get_from_head(&g_execute_list);
		pthread_rwlock_unlock(&g_table_lock);

		if (NULL == pnode) {
			sleep(1);
			continue;
		}

		vuser_init(&iuser, pnode->pdata);

		if (VUSER_NONE == vuser_work(&iuser)) {
			exec_sched_remove(pnode->pdata);
		} else {
			pthread_rwlock_wrlock(&g_table_lock);
			pinfo = str_hash_query(g_hash_table, pnode->pdata);
			if (NULL != pinfo) {
				pinfo->b_working = FALSE;
				time(&pinfo->last_time);
			}
			pthread_rwlock_unlock(&g_table_lock);
		}
		vuser_free(&iuser);
		free(pnode->pdata);
		free(pnode);
	}
	return NULL;
}

