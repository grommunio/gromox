// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/str_hash.hpp>
#include <gromox/util.hpp>
#include "grey_list.h"
#include "str_filter.h"
#include "temp_list.h"

static size_t temp_list_collect_string_entry();

/* private global variable */
static std::unique_ptr<STR_HASH_TABLE> g_string_hash;
static std::mutex g_string_mutex_lock;
static size_t g_size;
static BOOL				g_case_sensitive;

void temp_list_init(BOOL case_sensitive, size_t size)
{
	g_size = size;
	g_case_sensitive = case_sensitive;
}

int temp_list_run()
{
	if (g_size <= 0) {
		g_string_hash = NULL;
		return 0;
	}
	g_string_hash = STR_HASH_TABLE::create(g_size, sizeof(time_t), nullptr);
	if (NULL == g_string_hash) {
		return -1;
	}
	return 0;
}

void temp_list_free() 
{
	g_size = 0;
}

/*
 *	add the specified string into the temp list
 *
 *	@param	
 *		str				string
 *		interval		interval in temp list
 *	@return	 
 *		TRUE
 *		FALSE
 */
BOOL temp_list_add_string(const char *str, int interval)
{
	time_t current_time;
	time_t when;
	char temp_string[256];

	if (NULL == g_string_hash || NULL == str) {
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (!g_case_sensitive)
		HX_strlower(temp_string);
	if (grey_list_query(temp_string, false) != GREY_LIST_NOT_FOUND)
		return FALSE;

	std::lock_guard sm_hold(g_string_mutex_lock);
	time(&current_time);
	when = current_time + interval;
	if (g_string_hash->add(temp_string, &when) > 0)
		return TRUE;
	if (0 == temp_list_collect_string_entry()) {
		return FALSE;
	}
	return g_string_hash->add(temp_string, &when) > 0 ? TRUE : false;
}

/*
 *	remove the specified string from the temp list
 *	@param	
 *		str		string
 *	@return	 
 *		TRUE	success
 *		FALSE	fail
 */
BOOL temp_list_remove_string(const char *str)
{
	char temp_string[256];
	
	if (NULL == g_string_hash || NULL == str) {
		return TRUE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (!g_case_sensitive)
		HX_strlower(temp_string);
	std::lock_guard sm_hold(g_string_mutex_lock);
	if (g_string_hash->query1(temp_string) == nullptr)
		return TRUE;
	return g_string_hash->remove(temp_string) == 1 ? TRUE : false;
}

/*
 *	query if the specified string is in the 
 *	temp list
 *	@param	
 *		str		string
 *	@return	 
 *		TRUE	found in list
 *		FALSE	not found in list
 */
BOOL temp_list_query(const char *str) 
{
	time_t current_time;
	char temp_string[256];
	
	if (NULL == g_string_hash || NULL == str)	{
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (!g_case_sensitive)
		HX_strlower(temp_string);
	std::lock_guard sm_hold(g_string_mutex_lock);
	auto pwhen = g_string_hash->query<time_t>(temp_string);
	if (NULL == pwhen) {
		return FALSE; /* not found */
	}
	
	time(&current_time);
	if (current_time <= *pwhen) {
		return TRUE; /* found, in temp list */
	}
	g_string_hash->remove(temp_string);
	return FALSE; /* is overdue */
}

/*
 *  collect the timeout entry in the string hash table 
 *
 *  @return
 *      the number of entries collected
 */
static size_t temp_list_collect_string_entry()
{
	time_t *pwhen;
	time_t current_time;

	time(&current_time);
	size_t collected_num = 0;
	auto iter = g_string_hash->make_iter();
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pwhen = (time_t*)str_hash_iter_get_value(iter, NULL);
		if (current_time > *pwhen) {
			str_hash_iter_remove(iter);
			collected_num++;
		}
	}
	str_hash_iter_free(iter);
	return collected_num;
}

/*
 *  enumerate each item in temp list hash table
 *	@param
 *		str [in]		string
 *		puntil [out]	buffer for saving until time
 *	@return
 *		TRUE			found
 *		FALSE			found nothing
 */
BOOL temp_list_echo(const char *str, time_t *puntil)
{
	char temp_string[256];

	if (NULL == g_string_hash || NULL == str || NULL == puntil) {
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (!g_case_sensitive)
		HX_strlower(temp_string);
	std::lock_guard sm_hold(g_string_mutex_lock);
	/* first remove the overdue items */
	temp_list_collect_string_entry();
	auto pwhen = g_string_hash->query<time_t>(temp_string);
	if (NULL == pwhen) {
		return FALSE;
	}
	*puntil = *pwhen;
	return TRUE;
}

BOOL temp_list_dump(const char *path)
{
	int fd, len;
	char temp_string[512];
	struct tm time_buff;
	time_t current_time;

	if (NULL == g_string_hash || NULL == path) {
		return FALSE;
	}
	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}

	std::unique_lock sm_hold(g_string_mutex_lock);
	time(&current_time);
	auto iter = g_string_hash->make_iter();
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		auto pwhen = static_cast<time_t *>(str_hash_iter_get_value(iter, temp_string));
		if (current_time >= *pwhen) {
			str_hash_iter_remove(iter);
		} else {
			len = strlen(temp_string);
			temp_string[len] = '\t';
			len ++;
			len += strftime(temp_string + len, 512 - len, "%Y/%m/%d %H:%M:%S",
					localtime_r(pwhen, &time_buff));
			temp_string[len] = '\n';
			len ++;
			write(fd, temp_string, len);
		}
	}
	str_hash_iter_free(iter);
	sm_hold.unlock();
	close(fd);
	return TRUE;
}

