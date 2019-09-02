#include "rbl_cache.h"
#include "ip4_hash.h"
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#define DEF_MODE    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct _BLCAK_ITEM {
	time_t time_stamp;
	char string[128];
} BLCAK_ITEM;

static int g_black_size;
static int g_normal_size;
static int g_black_interval;
static int g_normal_interval;
static IP4_HASH_TABLE *g_black_hash;
static IP4_HASH_TABLE *g_normal_hash;
static pthread_mutex_t g_black_lock;
static pthread_mutex_t g_normal_lock;

static void rbl_cache_collect_normal(time_t cur_time);

static void rbl_cache_collect_black(time_t cur_time);

void rbl_cache_init(int normal_size, int normal_interval,
	int black_size, int black_interval)
{
	g_normal_hash = NULL;
	g_black_hash = NULL;
	g_normal_size = normal_size;
	g_normal_interval = normal_interval;
	g_black_size = black_size;
	g_black_interval = black_interval;
	pthread_mutex_init(&g_black_lock, NULL);
	pthread_mutex_init(&g_normal_lock, NULL);
}

int rbl_cache_run()
{
	g_black_hash = ip4_hash_init(g_black_size, sizeof(BLCAK_ITEM), NULL);
	if (NULL == g_black_hash) {
		printf("[dns_rbl]: fail to init black list cache\n");
		return -1;
	}
	g_normal_hash = ip4_hash_init(g_normal_size, sizeof(time_t), NULL);
	if (NULL == g_normal_hash) {
		printf("[dns_rbl]: fail to init normal list cache\n");
		ip4_hash_free(g_black_hash);
		g_black_hash = NULL;
		return -2;
	}
	return 0;
}

int rbl_cache_stop()
{
	if (NULL != g_black_hash) {
		ip4_hash_free(g_black_hash);
		g_black_hash = NULL;
	}
	if (NULL != g_normal_hash) {
		ip4_hash_free(g_normal_hash);
		g_normal_hash = NULL;
	}
	return 0;
}

void rbl_cache_free()
{
	g_normal_size = 0;
	g_normal_interval = 0;
	g_black_size = 0;
	g_black_interval = 0;
	pthread_mutex_destroy(&g_black_lock);
	pthread_mutex_destroy(&g_normal_lock);
}

int rbl_cache_query(char *ip, char *reason, int length)
{
	BLCAK_ITEM *pitem;
	time_t *ptime, cur_time;
	
	pthread_mutex_lock(&g_normal_lock);
	ptime = (time_t*)ip4_hash_query(g_normal_hash, ip);
	if (NULL != ptime) {
		time(ptime);
		pthread_mutex_unlock(&g_normal_lock);
		return RBL_CACHE_NORMAL;
	}
	pthread_mutex_unlock(&g_normal_lock);
	
	pthread_mutex_lock(&g_black_lock);
	pitem = (BLCAK_ITEM*)ip4_hash_query(g_black_hash, ip);
	if (NULL != pitem) {
		time(&cur_time);
		if (cur_time - pitem->time_stamp < g_black_interval) {
			if (NULL != reason) {
				strncpy(reason, pitem->string, length);
				reason[length - 1] = '\0';
			}
			pthread_mutex_unlock(&g_black_lock);
			return RBL_CACHE_BLACK;
		} else {
			ip4_hash_remove(g_black_hash, ip);
		}
	}
	pthread_mutex_unlock(&g_black_lock);
	return RBL_CACHE_NONE;
}

void rbl_cache_add(char *ip, int type, char *reason)
{
	int add_result;
	time_t cur_time;
	BLCAK_ITEM temp_item;
	
	time(&cur_time);
	if (RBL_CACHE_NORMAL == type) {
		pthread_mutex_lock(&g_normal_lock);
		if (1 != ip4_hash_add(g_normal_hash, ip, &cur_time)) {
			rbl_cache_collect_normal(cur_time);
			ip4_hash_add(g_normal_hash, ip, &cur_time);
		}
		pthread_mutex_unlock(&g_normal_lock);
	} else if (RBL_CACHE_BLACK == type) {
		memset(&temp_item, 0, sizeof(temp_item));
		temp_item.time_stamp = cur_time;
		if (NULL != reason) {
			strncpy(temp_item.string, reason, 127);
		}
		pthread_mutex_lock(&g_black_lock);
		if (1 != ip4_hash_add(g_black_hash, ip, &temp_item)) {
			rbl_cache_collect_black(cur_time);
			ip4_hash_add(g_black_hash, ip, &temp_item);
		}
		pthread_mutex_unlock(&g_black_lock);
	}
}

static void rbl_cache_collect_normal(time_t cur_time)
{
	time_t *ptime;
	IP4_HASH_ITER *iter;
	
	iter = ip4_hash_iter_init(g_normal_hash);
	for (ip4_hash_iter_begin(iter); !ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		ptime = (time_t*)ip4_hash_iter_get_value(iter, NULL);
		if (cur_time - *ptime >= g_normal_interval) {
			ip4_hash_iter_remove(iter);
		}
	}
	ip4_hash_iter_free(iter);
}

static void rbl_cache_collect_black(time_t cur_time)
{
	BLCAK_ITEM *pitem;
	IP4_HASH_ITER *iter;
	
	iter = ip4_hash_iter_init(g_black_hash);
	for (ip4_hash_iter_begin(iter); !ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		pitem = (BLCAK_ITEM*)ip4_hash_iter_get_value(iter, NULL);
		if (cur_time - pitem->time_stamp >= g_black_interval) {
			ip4_hash_iter_remove(iter);
		}
	}
	ip4_hash_iter_free(iter);
}

BOOL rbl_cache_dump_normal(const char *path)
{
	int fd, len;
	char temp_string[128];
	IP4_HASH_ITER *iter;
	time_t *ptime;
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
	pthread_mutex_lock(&g_normal_lock);
	iter = ip4_hash_iter_init(g_normal_hash);
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		ptime = (time_t*)ip4_hash_iter_get_value(iter, temp_string);
		if (current_time - *ptime > g_normal_interval) {
			ip4_hash_iter_remove(iter);
		} else {
			len = strlen(temp_string);
			temp_string[len] = '\t';
			len ++;
			len += strftime(temp_string + len, 128 - len, "%Y/%m/%d %H:%M:%S",
				localtime_r(ptime, &time_buff));
			temp_string[len] = '\n';
			len ++;
			write(fd, temp_string, len);
		}
	}
	ip4_hash_iter_free(iter);
	pthread_mutex_unlock(&g_normal_lock);
	close(fd);
	return TRUE;
}

BOOL rbl_cache_dump_black(const char *path)
{
	int fd, len;
	char temp_string[256];
	IP4_HASH_ITER *iter;
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
	iter = ip4_hash_iter_init(g_black_hash);
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		pitem = (BLCAK_ITEM*)ip4_hash_iter_get_value(iter, temp_string);
		if (current_time - pitem->time_stamp > g_black_interval) {
			ip4_hash_iter_remove(iter);
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
	ip4_hash_iter_free(iter);
	pthread_mutex_unlock(&g_black_lock);
	close(fd);
	return TRUE;
}

void rbl_cache_set_param(int type, int value)
{
	switch (type) {
	case RBL_CACHE_NORMAL_INTERVAL:
		g_normal_interval = value;
		break;
	case RBL_CACHE_BLACK_INTERVAL:
		g_black_interval = value;
		break;
	}
}

int rbl_cache_get_param(int type)
{
	switch (type) {
	case RBL_CACHE_NORMAL_SIZE:
		return g_normal_size;
	case RBL_CACHE_NORMAL_INTERVAL:
		return g_normal_interval;
	case RBL_CACHE_BLACK_SIZE:
		return g_black_size;
	case RBL_CACHE_BLACK_INTERVAL:
		return g_black_interval;
	}
	return 0;
}
