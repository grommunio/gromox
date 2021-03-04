// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <unistd.h>
#include <libHX/string.h>
#include "temp_list.h"
#include "str_filter.h"
#include <gromox/str_hash.hpp>
#include "grey_list.h"
#include <gromox/util.hpp>
#include <fcntl.h>
#include <ctime>
#include <cstring>
#include <pthread.h>

static int temp_list_collect_string_entry();

/* private global variable */
static STR_HASH_TABLE *g_string_hash;
static pthread_mutex_t	g_string_mutex_lock;
static int				g_size;
static BOOL				g_case_sensitive;

void temp_list_init(BOOL case_sensitive, int size)
{
	g_size = size;
	g_case_sensitive = case_sensitive;
	pthread_mutex_init(&g_string_mutex_lock, NULL);
}

/*
 * temp	list's construction	function
 *
 *	@param
 *		size	the size of the list
 *	@return		
 *		0		success
 *		<>0		fail
 */
int temp_list_run()
{
	if (g_size <= 0) {
		g_string_hash = NULL;
		return 0;
	}
	g_string_hash = str_hash_init(g_size, sizeof(time_t), NULL);
	if (NULL == g_string_hash) {
		return -1;
	}
	return 0;
}



/*
 *	temp list's	destruction	function
 *
 *	@return		
 *		0		success
 *		<>0		fail
 */

int temp_list_stop() 
{
	if (NULL != g_string_hash) {
		str_hash_free(g_string_hash);
		g_string_hash = NULL;
	}
	return 0;
}

void temp_list_free() 
{
	g_size = 0;
	pthread_mutex_destroy(&g_string_mutex_lock);
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
	if (GREY_LIST_NOT_FOUND != grey_list_query(temp_string, FALSE)) {
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	pthread_mutex_lock(&g_string_mutex_lock);
	
	time(&current_time);
	when = current_time + interval;
	if (str_hash_add(g_string_hash, temp_string, &when) > 0) {
		pthread_mutex_unlock(&g_string_mutex_lock);
		return TRUE;
	}
	if (0 == temp_list_collect_string_entry()) {
		pthread_mutex_unlock(&g_string_mutex_lock);
		return FALSE;
	}

	if (str_hash_add(g_string_hash, temp_string, &when) > 0) {
		pthread_mutex_unlock(&g_string_mutex_lock);
		return TRUE;
	}
	pthread_mutex_unlock(&g_string_mutex_lock);
	return FALSE;
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
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	pthread_mutex_lock(&g_string_mutex_lock);
	if (NULL == str_hash_query(g_string_hash, temp_string)) {
		pthread_mutex_unlock(&g_string_mutex_lock);
		return TRUE;
	}
	if (str_hash_remove(g_string_hash, temp_string) != 1) {
		pthread_mutex_unlock(&g_string_mutex_lock);
		return FALSE;
	}
	pthread_mutex_unlock(&g_string_mutex_lock);
	return TRUE;
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
	time_t *pwhen;
	char temp_string[256];
	
	if (NULL == g_string_hash || NULL == str)	{
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	pthread_mutex_lock(&g_string_mutex_lock);
	pwhen = (time_t*)str_hash_query(g_string_hash, temp_string);
	if (NULL == pwhen) {
		pthread_mutex_unlock(&g_string_mutex_lock);
		return FALSE; /* not found */
	}
	
	time(&current_time);
	if (current_time <= *pwhen) {
		pthread_mutex_unlock(&g_string_mutex_lock);
		return TRUE; /* found, in temp list */
	}
	str_hash_remove(g_string_hash, temp_string);
	pthread_mutex_unlock(&g_string_mutex_lock);
	return FALSE; /* is overdue */
}

/*
 *  collect the timeout entry in the string hash table 
 *
 *  @return
 *      the number of entries collected
 */
static int temp_list_collect_string_entry()
{
	STR_HASH_ITER *iter;
	time_t *pwhen;
	int	collected_num;
	time_t current_time;

	time(&current_time);
	collected_num = 0;
	iter = str_hash_iter_init(g_string_hash); 
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
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
	time_t *pwhen;  
	char temp_string[256];

	if (NULL == g_string_hash || NULL == str || NULL == puntil) {
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	pthread_mutex_lock(&g_string_mutex_lock);
	/* first remove the overdue items */
	temp_list_collect_string_entry();
    pwhen = (time_t*)str_hash_query(g_string_hash, temp_string);
	if (NULL == pwhen) {
		pthread_mutex_unlock(&g_string_mutex_lock);
		return FALSE;
	}
	*puntil = *pwhen;
	pthread_mutex_unlock(&g_string_mutex_lock);
	return TRUE;
}

BOOL temp_list_dump(const char *path)
{
	int fd, len;
	char temp_string[512];
	STR_HASH_ITER *iter;
	struct tm time_buff;
	time_t current_time;

	if (NULL == g_string_hash || NULL == path) {
		return FALSE;
	}
	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	pthread_mutex_lock(&g_string_mutex_lock);
	time(&current_time);
	iter = str_hash_iter_init(g_string_hash); 
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
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
	pthread_mutex_unlock(&g_string_mutex_lock);
	close(fd);
	return TRUE;
}

