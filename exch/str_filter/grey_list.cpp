// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "str_filter.h"
#include "grey_list.h"
#include <gromox/list_file.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include <sys/time.h>
#include <fcntl.h>
#include <cstdio>
#include <pthread.h>

DECLARE_API(extern);

struct GREY_LIST_ENTRY {
	int				current_times;
	int				allowed_times;
	int				interval;
	struct timeval	last_access;
};

struct LIST_ITEM {
	char    string[256];
	int     allow_times;
	char    interval[32];
};

static void grey_list_flush();

static STR_HASH_TABLE *g_grey_table;
static pthread_rwlock_t  g_refresh_lock;
static char g_list_path[256]; 
static BOOL g_case_sensitive;
static int g_growing_num;
static int g_hash_cap;

/*
 *	grey list's construct function
 */
void grey_list_init(BOOL case_sensitive, const char *path, int growing_num)
{
	g_case_sensitive = case_sensitive;
	HX_strlcpy(g_list_path, path, GX_ARRAY_SIZE(g_list_path));
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
        str_hash_free(g_grey_table);
        g_grey_table = NULL;
    }
    return 0;

}


/*  query the grey list for the specified string. 
 *  @param  
 *		str [in]				string
 *		b_count					whether to count the access times
 *  @return
 *      GREY_LIST_ALLOW			allow connection
 *      GREY_LIST_NOT_FOUND		allow connection not in grey list
 *      GREY_LIST_DENY		    deny it
 */
int grey_list_query(const char *str, BOOL b_count)
{
	char temp_string [256];
    struct timeval current_time;

    if (NULL == str) {
        return GREY_LIST_NOT_FOUND;
    }
    if (0 == g_growing_num) { /* no grey list */
        return GREY_LIST_NOT_FOUND;
    }
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
    pthread_rwlock_rdlock(&g_refresh_lock);
	auto pentry = static_cast<GREY_LIST_ENTRY *>(str_hash_query(g_grey_table, temp_string));
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
		pentry->current_times ++;
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
 *		str [in]			string
 *		ptimes [out]		for retrieving times for special
 *		pinterval [out]		for retrieving interval for special
 *  @return
 *		TRUE				find
 *		FALSE				not find
 * 
 */
BOOL grey_list_echo(const char *str, int *ptimes, int *pinterval)
{
    struct timeval current_time;
	char temp_string[256];

    if (NULL == str || NULL == ptimes || NULL == pinterval) {
        return FALSE;
    }
	if (0 == g_growing_num) {
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
    pthread_rwlock_rdlock(&g_refresh_lock);
	gettimeofday(&current_time, NULL);
	auto pentry = static_cast<GREY_LIST_ENTRY *>(str_hash_query(g_grey_table, temp_string));
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
    STR_HASH_TABLE *phash;
    GREY_LIST_ENTRY entry;
    struct timeval current_time;

	if (0 == g_growing_num) {
		return GREY_REFRESH_OK;
	}
	auto plist_file = list_file_initd(g_list_path, get_state_path(), "%s:256%d%s:32");
	if (NULL == plist_file) {
		str_filter_echo("Failed to read graylist from %s: %s",
			g_list_path, strerror(errno));
        return GREY_REFRESH_FILE_ERROR;
	}
	auto pitem = static_cast<LIST_ITEM *>(plist_file->get_list());
	auto list_len = plist_file->get_size();
	auto hash_cap = list_len + g_growing_num;
    phash = str_hash_init(hash_cap, sizeof(GREY_LIST_ENTRY), NULL);
    if (NULL == phash) {
		str_filter_echo("Failed to allocate hash map for grey list");
        return GREY_REFRESH_HASH_FAIL;
    }
    memset(&entry, 0, sizeof(GREY_LIST_ENTRY));
    gettimeofday(&current_time, NULL);
    entry.last_access   = current_time;
    entry.current_times = 0;
	for (decltype(list_len) i = 0; i < list_len; ++i, ++pitem) {
        entry.allowed_times = pitem->allow_times;
        entry.interval = atoitvl(pitem->interval);
		if (FALSE == g_case_sensitive) {
			HX_strlower(pitem->string);
		}
        str_hash_add(phash, pitem->string, &entry);
    }
    pthread_rwlock_wrlock(&g_refresh_lock);
    if (NULL != g_grey_table) {
        str_hash_free(g_grey_table);
    }
    g_grey_table = phash;
	g_hash_cap = hash_cap;
    pthread_rwlock_unlock(&g_refresh_lock);
    return GREY_REFRESH_OK;
}

/*
 *	add item into string file and hash table
 *	@param
 *		str [in]		string to be added
 *		times			times
 *		interval		interval
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
BOOL grey_list_add_string(const char* str, int times, int interval)
{
	struct timeval current_time;
	char temp_string[256];
	char file_item[576];
	int i, j, hash_cap;
	int fd, string_len;
	STR_HASH_ITER *iter;
	STR_HASH_TABLE *phash;
	GREY_LIST_ENTRY entry;

	if (NULL == str) {
		return FALSE;
	}
	if (0 == g_growing_num) {
		return FALSE;
	}
	strncpy(temp_string, str, 255);
	temp_string[255] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
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
	string_len += sprintf(file_item + string_len, "\t%d\t", times);
	itvltoa(interval, file_item + string_len);
	string_len += strlen(file_item + string_len);
	file_item[string_len] = '\n';
	string_len ++;
	/* check first if the string is already in the table */
	pthread_rwlock_wrlock(&g_refresh_lock);
	auto pentry = static_cast<GREY_LIST_ENTRY *>(str_hash_query(g_grey_table, temp_string));
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
	if (str_hash_add(g_grey_table, temp_string, &entry) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	hash_cap = g_hash_cap + g_growing_num;
	phash = str_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	iter = str_hash_iter_init(g_grey_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pentry = static_cast<GREY_LIST_ENTRY *>(str_hash_iter_get_value(iter, file_item));
		str_hash_add(phash, file_item, pentry);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_grey_table);
	g_grey_table = phash;
	g_hash_cap = hash_cap;
	if (str_hash_add(g_grey_table, temp_string, &entry) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	pthread_rwlock_unlock(&g_refresh_lock);
	return FALSE;
}

/*
 *	remove item from string file and hash table
 *	@param
 *		str [in]		string to be removed
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
BOOL grey_list_remove_string(const char* str)
{
	char temp_string[256];
	
	if (NULL == str) {
		return TRUE;
	}
	if (0 == g_growing_num) {
		return TRUE;
	}
	strncpy(temp_string, str, 255);
	temp_string[255] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	/* check first if the string is in hash table */
	pthread_rwlock_wrlock(&g_refresh_lock);
	auto pentry = static_cast<GREY_LIST_ENTRY *>(str_hash_query(g_grey_table, temp_string));
	if (NULL == pentry) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	if (1 != str_hash_remove(g_grey_table, temp_string)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	grey_list_flush();
	pthread_rwlock_unlock(&g_refresh_lock);
	return TRUE;
}

static void grey_list_flush()
{
	int i, j, fd;
	int string_len;
	char temp_string[256];
	char file_item[576];
	STR_HASH_ITER *iter;
	
	if (0 == g_growing_num) {
		return;
	}
	fd = open(g_list_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	iter = str_hash_iter_init(g_grey_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		auto pentry = static_cast<GREY_LIST_ENTRY *>(str_hash_iter_get_value(iter, temp_string));
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
		string_len += sprintf(file_item + string_len, "\t%d\t",
						pentry->allowed_times);
		itvltoa(pentry->interval, file_item + string_len);
		string_len += strlen(file_item + string_len);
		file_item[string_len] = '\n';
		string_len ++;
		write(fd, file_item, string_len);
	}
	str_hash_iter_free(iter);
	close(fd);

}

BOOL grey_list_dump(const char *path)
{
	int fd, len;
	char temp_string[512];
	STR_HASH_ITER *iter;
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
	iter = str_hash_iter_init(g_grey_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		auto pentry = static_cast<GREY_LIST_ENTRY *>(str_hash_iter_get_value(iter, temp_string));
		if (0 == pentry->allowed_times || 0 == pentry->interval) {
			continue;
		}
		if (CALCULATE_INTERVAL(current_times, pentry->last_access) <=
			pentry->interval && pentry->current_times > pentry->allowed_times) {
			len = strlen(temp_string);
			temp_string[len] = '\t';
			len ++;
			len += strftime(temp_string + len, 512 - len,
					"%Y/%m/%d %H:%M:%S",
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
	str_hash_iter_free(iter);
	pthread_rwlock_unlock(&g_refresh_lock);
	close(fd);
	return TRUE;
}

