#include "uri_cache.h"
#include "str_hash.h"
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>


#define DEF_MODE    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct _BLCAK_ITEM {
	time_t time_stamp;
	char string[128];
} BLCAK_ITEM;

static int g_black_size;
static int g_black_interval;
static STR_HASH_TABLE *g_black_hash;
static pthread_mutex_t g_black_lock;

static void uri_cache_collect_black(time_t cur_time);

void uri_cache_init(int black_size, int black_interval)
{
	g_black_hash = NULL;
	g_black_size = black_size;
	g_black_interval = black_interval;
	pthread_mutex_init(&g_black_lock, NULL);
}

int uri_cache_run()
{
	g_black_hash = str_hash_init(g_black_size, sizeof(BLCAK_ITEM), NULL);
	if (NULL == g_black_hash) {
		printf("[uri_rbl]: fail to init black list cache\n");
		return -1;
	}
	return 0;
}

int uri_cache_stop()
{
	if (NULL != g_black_hash) {
		str_hash_free(g_black_hash);
		g_black_hash = NULL;
	}
	return 0;
}

void uri_cache_free()
{
	g_black_size = 0;
	g_black_interval = 0;
	pthread_mutex_destroy(&g_black_lock);
}

BOOL uri_cache_query(const char *uri, char *reason, int length)
{
	time_t cur_time;
	BLCAK_ITEM *pitem;
	
	pthread_mutex_lock(&g_black_lock);
	pitem = (BLCAK_ITEM*)str_hash_query(g_black_hash, (char*)uri);
	if (NULL != pitem) {
		time(&cur_time);
		if (cur_time - pitem->time_stamp < g_black_interval) {
			if (NULL != reason) {
				strncpy(reason, pitem->string, length);
				reason[length - 1] = '\0';
			}
			pthread_mutex_unlock(&g_black_lock);
			return TRUE;
		} else {
			str_hash_remove(g_black_hash, (char*)uri);
		}
	}
	pthread_mutex_unlock(&g_black_lock);
	return FALSE;
}

void uri_cache_add(const char *uri, char *reason)
{
	int add_result;
	time_t cur_time;
	BLCAK_ITEM temp_item;
	
	time(&cur_time);
	memset(&temp_item, 0, sizeof(temp_item));
	temp_item.time_stamp = cur_time;
	if (NULL != reason) {
		strncpy(temp_item.string, reason, 127);
	}
	pthread_mutex_lock(&g_black_lock);
	if (1 != str_hash_add(g_black_hash, (char*)uri, &temp_item)) {
		uri_cache_collect_black(cur_time);
		str_hash_add(g_black_hash, (char*)uri, &temp_item);
	}
	pthread_mutex_unlock(&g_black_lock);
}

static void uri_cache_collect_black(time_t cur_time)
{
	BLCAK_ITEM *pitem;
	STR_HASH_ITER *iter;
	
	iter = str_hash_iter_init(g_black_hash);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pitem = (BLCAK_ITEM*)str_hash_iter_get_value(iter, NULL);
		if (cur_time - pitem->time_stamp >= g_black_interval) {
			str_hash_iter_remove(iter);
		}
	}
	str_hash_iter_free(iter);
}

BOOL uri_cache_dump_black(const char *path)
{
	int fd, len;
	char temp_string[256];
	STR_HASH_ITER *iter;
	BLCAK_ITEM *pitem;
	time_t current_time;
	struct tm time_buff;

	if (NULL == path) {
		return FALSE;
	}
	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	time(&current_time);
	pthread_mutex_lock(&g_black_lock);
	iter = str_hash_iter_init(g_black_hash);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pitem = (BLCAK_ITEM*)str_hash_iter_get_value(iter, temp_string);
		if (current_time - pitem->time_stamp > g_black_interval) {
			str_hash_iter_remove(iter);
		} else {
			len = strlen(temp_string);
			temp_string[len] = '\t';
			len ++;
			len += strftime(temp_string + len, 256 - len, "%Y/%m/%d %H:%M:%S",
				localtime_r(&pitem->time_stamp, &time_buff));
			temp_string[len] = '\t';
			len ++;
			strcpy(temp_string + len, pitem->string);
			len += strlen(pitem->string);
			temp_string[len] = '\n';
			len ++;
			write(fd, temp_string, len);
		}
	}
	str_hash_iter_free(iter);
	pthread_mutex_unlock(&g_black_lock);
	close(fd);
	return TRUE;
}

void uri_cache_set_param(int type, int value)
{
	switch (type) {
	case URI_CACHE_BLACK_INTERVAL:
		g_black_interval = value;
		break;
	}
}

int uri_cache_get_param(int type)
{
	switch (type) {
	case URI_CACHE_BLACK_SIZE:
		return g_black_size;
	case URI_CACHE_BLACK_INTERVAL:
		return g_black_interval;
	}
	return 0;
}

