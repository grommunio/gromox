// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "ip_filter.h"
#include "grey_list.h"
#include "list_file.h"
#include "ip4_hash.h"
#include "util.h"
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>

typedef struct _GREY_LIST_ENTRY {
	int				current_times;
	int				allowed_times;
	int				interval;
	struct timeval  last_access;
} GREY_LIST_ENTRY;

static IP4_HASH_TABLE *g_grey_table;
static pthread_rwlock_t  g_refresh_lock;
static char g_list_path[256]; 
static int g_growing_num;
static int g_hash_cap;

static void grey_list_flush(void);
	
/*
 *	grey list's construct function
 */
void grey_list_init(const char *path, int growing_num)
{
    strcpy(g_list_path, path);
	g_growing_num = growing_num;
	g_hash_cap = 0;
    pthread_rwlock_init(&g_refresh_lock, NULL);
}

/*
 *	grey list's destruct function
 */
void grey_list_free()
{
    pthread_rwlock_destroy(&g_refresh_lock);
    g_list_path[0] ='\0';
	g_growing_num = 0;
	g_hash_cap = 0;
}

/*
 *	run grey list module
 *	@return
 *		 0		sucess
 *		<>0		fail
 */
int grey_list_run()
{
    if (0 != grey_list_refresh()) {
        return -1;
	}
    return 0;

}

/*
 *	stop grey list module
 *	@return
 *		 0		sucess
 *		<>0		fail
 */
int grey_list_stop()
{
    if (NULL != g_grey_table) {
        ip4_hash_free(g_grey_table);
        g_grey_table = NULL;
    }
    return 0;

}


/*  query the grey list for the specified ipaddr.
 *  @param  
 *		ip [in]					ip address
 *		b_count					whether to count the access times
 *  @return
 *      GREY_LIST_ALLOW			allow connection
 *      GREY_LIST_NOT_FOUND     allow connection not in grey list
 *      GREY_LIST_DENY		    deny it
 */
int grey_list_query(const char *ip, BOOL b_count)
{
    struct timeval current_time;

	if (NULL == ip) {
		return GREY_LIST_NOT_FOUND;
	}
	if (0 == g_growing_num) {
		return GREY_LIST_NOT_FOUND;
	}
    pthread_rwlock_rdlock(&g_refresh_lock);
	auto pentry = static_cast<GREY_LIST_ENTRY *>(ip4_hash_query(g_grey_table, deconst(ip)));
    if (NULL == pentry) {
		pthread_rwlock_unlock(&g_refresh_lock);
        return GREY_LIST_NOT_FOUND; /* not in grey list */
    }

    if (0 == pentry->allowed_times) {
		pthread_rwlock_unlock(&g_refresh_lock);
        return GREY_LIST_DENY; /* deny it */
    }
    if (0 == pentry->interval) {
		pthread_rwlock_unlock(&g_refresh_lock);
        return GREY_LIST_ALLOW; 
    }
    gettimeofday(&current_time, NULL);
    if (CALCULATE_INTERVAL(current_time, pentry->last_access) >
        pentry->interval) {
		if (TRUE == b_count) {
			pentry->last_access = current_time;
			pentry->current_times = 0;
		} else {
			pthread_rwlock_unlock(&g_refresh_lock);
			return GREY_LIST_ALLOW; 
		}
    }
	if (TRUE == b_count) {
		pentry->current_times++;
	}
    if (pentry->current_times <= pentry->allowed_times) {
		pthread_rwlock_unlock(&g_refresh_lock);
        return GREY_LIST_ALLOW;
	} else {
        pthread_rwlock_unlock(&g_refresh_lock);
        return GREY_LIST_DENY;
	}
}

/*  search the grey list for the specified string.
 *  @param
 *      ip [in]             ip address
 *      ptimes [out]		for retrieving times for special
 *      pinterval [out]     for retrieving interval for special
 *  @return
 *      TRUE                find
 *      FALSE               not find
 *
 */
BOOL grey_list_echo(const char *ip, int *ptimes, int *pinterval)
{
	struct timeval current_time;

	if (NULL == ip || NULL == ptimes || NULL == pinterval) {
		return FALSE;
	}
	if (0 == g_growing_num) {
		return FALSE;
	}
	pthread_rwlock_rdlock(&g_refresh_lock);
	gettimeofday(&current_time, NULL);
	auto pentry = static_cast<GREY_LIST_ENTRY *>(ip4_hash_query(g_grey_table, deconst(ip)));
	if (NULL == pentry) {
		*ptimes = 0;
		*pinterval = 0;
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE; /* not in grey list */
	}
	if (0 == pentry->allowed_times) {
		*ptimes = 0;
		*pinterval = 0;
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	if (0 == pentry->interval) {
		*ptimes = 1;
		*pinterval = 0;
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	*ptimes = pentry->allowed_times;
	*pinterval = pentry->interval;
	if (CALCULATE_INTERVAL(current_time, pentry->last_access) >
		pentry->interval) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	} else {
	    if (pentry->current_times <= pentry->allowed_times) {
		    pthread_rwlock_unlock(&g_refresh_lock);
		    return FALSE;
		} else {
			pthread_rwlock_unlock(&g_refresh_lock);
			return TRUE;
		}
	}
}

/*
 *	reload the grey list
 *	@return
 *		GREY_REFRESH_OK				OK
 *		GREY_REFRESH_HASH_FAIL		hash fail
 *		GREY_REFRESH_FILE_ERROR		fail to open list file
 */
int grey_list_refresh()
{
    IP4_HASH_TABLE *phash;
    GREY_LIST_ENTRY entry;
    struct timeval current_time;
    int list_len, i, hash_cap;

	if (0 == g_growing_num) {
		return GREY_REFRESH_OK;
	}
	LIST_FILE *plist_file = list_file_init3(g_list_path, /* LIST_ITEM */ "%s:32%d%s:32", false);
	if (NULL == plist_file) {
		ip_filter_echo("Failed to read graylist from %s: %s",
			g_list_path, strerror(errno));
        return GREY_REFRESH_FILE_ERROR;
	}

	typedef struct _LIST_ITEM {
		char ip[32];
		int allow_times;
		char interval[32];
	} LIST_ITEM;
	auto pitem = reinterpret_cast<LIST_ITEM *>(list_file_get_list(plist_file));
    list_len = list_file_get_item_num(plist_file);
	hash_cap = list_len + g_growing_num;
	
    phash = ip4_hash_init(hash_cap, sizeof(GREY_LIST_ENTRY), NULL);
    if (NULL == phash) {
		ip_filter_echo("Failed to allocate hash map for grey list");
		list_file_free(plist_file);	
        return GREY_REFRESH_HASH_FAIL;
    }
    memset(&entry, 0, sizeof(GREY_LIST_ENTRY));
    gettimeofday(&current_time, NULL);
    entry.last_access   = current_time;
    entry.current_times = 0;
    for (i = 0; i < list_len; i++, pitem++) {
        entry.allowed_times = pitem->allow_times;
        entry.interval      = atoitvl(pitem->interval);
        ip4_hash_add(phash, pitem->ip, &entry);
    }
    list_file_free(plist_file);

    pthread_rwlock_wrlock(&g_refresh_lock);
    if (NULL != g_grey_table) {
        ip4_hash_free(g_grey_table);
    }
    g_grey_table = phash;
	g_hash_cap = hash_cap;
    pthread_rwlock_unlock(&g_refresh_lock);
    return GREY_REFRESH_OK;
}

/*
 *  add item into ipaddr file and hash table
 *  @param
 *      ip [in]        ip address
 *      times          times
 *      interval       interval
 *  @return
 *      TRUE            OK
 *      FALSE           fail
 */
BOOL grey_list_add_ip(const char *ip, int times, int interval)
{
	struct timeval current_time;
	char file_item[576];
	int hash_cap;
	int fd, string_len;
	IP4_HASH_ITER *iter;
	IP4_HASH_TABLE *phash;
	GREY_LIST_ENTRY entry;

	if (NULL == ip) {
		return FALSE;
	}
	if (0 == g_growing_num) {
		return FALSE;
	}
	strcpy(file_item, ip);
	string_len = strlen(file_item);
	string_len += sprintf(file_item + string_len, "\t%d\t", times);
	itvltoa(interval, file_item + string_len);
	string_len += strlen(file_item + string_len);
	file_item[string_len] = '\n';
	string_len ++;
	/* check first if the string is already in the table */
	pthread_rwlock_wrlock(&g_refresh_lock);
	auto pentry = static_cast<GREY_LIST_ENTRY *>(ip4_hash_query(g_grey_table, deconst(ip)));
	if (NULL != pentry) {
		pentry->allowed_times = times;
		pentry->interval = interval;
		grey_list_flush();
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	fd = open(g_list_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	if (string_len != write(fd, file_item, string_len)) {
		close(fd);
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	close(fd);
	memset(&entry, 0, sizeof(GREY_LIST_ENTRY));
	gettimeofday(&current_time, NULL);
	entry.last_access = current_time;
	entry.current_times = 0;
	entry.allowed_times = times;
	entry.interval = interval;
	if (ip4_hash_add(g_grey_table, (char*)ip, &entry) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	hash_cap = g_hash_cap + g_growing_num;
	phash = ip4_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	iter = ip4_hash_iter_init(g_grey_table);
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		pentry = static_cast<GREY_LIST_ENTRY *>(ip4_hash_iter_get_value(iter, file_item));
		ip4_hash_add(phash, file_item, pentry);
	}
	ip4_hash_iter_free(iter);
	ip4_hash_free(g_grey_table);
	g_grey_table = phash;
	g_hash_cap = hash_cap;
	if (ip4_hash_add(g_grey_table, (char*)ip, &entry) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	pthread_rwlock_unlock(&g_refresh_lock);
	return FALSE;
}

/*
 *  remove item from ipaddr file and hash table
 *  @param
 *      ip [in]        ip address
 *  @return
 *      TRUE            OK
 *      FALSE           fail
 */
BOOL grey_list_remove_ip(const char* ip)
{
	if (NULL == ip) {
		return TRUE;
	}
	if (0 == g_growing_num) {
		return TRUE;
	}
	/* check first if the string is in hash table */
	pthread_rwlock_wrlock(&g_refresh_lock);
	auto pentry = static_cast<GREY_LIST_ENTRY *>(ip4_hash_query(g_grey_table, deconst(ip)));
	if (NULL == pentry) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	if (1 != ip4_hash_remove(g_grey_table, (char*)ip)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	grey_list_flush();
	pthread_rwlock_unlock(&g_refresh_lock);
	return TRUE;
}

static void grey_list_flush()
{
	int fd;
	int string_len;
	char file_item[576];
	IP4_HASH_ITER *iter;

	if (0 == g_growing_num) {
		return;
	}
	fd = open(g_list_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	iter = ip4_hash_iter_init(g_grey_table);
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		auto pentry = static_cast<GREY_LIST_ENTRY *>(ip4_hash_iter_get_value(iter, file_item));
		string_len = strlen(file_item);
		string_len += sprintf(file_item + string_len, "\t%d\t", 
						pentry->allowed_times);
		itvltoa(pentry->interval, file_item + string_len);
		string_len += strlen(file_item + string_len);
		file_item[string_len] = '\n';
		string_len ++;
		write(fd, file_item, string_len);
	}
	ip4_hash_iter_free(iter);
	close(fd);
}

BOOL grey_list_dump(const char *path)
{
	int fd, len;
	char temp_string[512];
	IP4_HASH_ITER *iter;
	struct tm time_buff;
	struct timeval current_times;

	if (NULL == path) {
		return FALSE;
	}
	if (0 == g_growing_num) {
		return FALSE;
	}
	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	pthread_rwlock_rdlock(&g_refresh_lock);
	gettimeofday(&current_times, NULL);
	iter = ip4_hash_iter_init(g_grey_table);
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		auto pentry = static_cast<GREY_LIST_ENTRY *>(ip4_hash_iter_get_value(iter, temp_string));
		if (0 == pentry->allowed_times || 0 == pentry->interval) {
			continue;
		}
		if (CALCULATE_INTERVAL(current_times, pentry->last_access) <=
			pentry->interval && pentry->current_times > pentry->allowed_times) {
			len = strlen(temp_string);
			temp_string[len] = '\t';
			len ++;
			len += strftime(temp_string + len, 512 - len, "%Y/%m/%d %H:%M:%S",
					localtime_r(&pentry->last_access.tv_sec, &time_buff));
			temp_string[len] = '\t';
			len ++;
			itoa(pentry->current_times, temp_string + len, 10);
			len += strlen(temp_string + len);
			temp_string[len] = '\n';
			len ++;
			write(fd, temp_string, len);
		}
	}
	ip4_hash_iter_free(iter);
	pthread_rwlock_unlock(&g_refresh_lock);
	close(fd);
	return TRUE;
}


