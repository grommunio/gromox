#include <unistd.h>
#include "temp_list.h"
#include "ip_filter.h"
#include "grey_list.h"
#include "ip4_hash.h"
#include "util.h"
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

/* private global variable */
static IP4_HASH_TABLE *g_ip4_hash;
static pthread_mutex_t	g_ip_mutex_lock;
static int				g_size;

static int temp_list_collect_ip_entry();

void temp_list_init(int size)
{
	g_size = size;
	pthread_mutex_init(&g_ip_mutex_lock, NULL);
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
		g_ip4_hash = NULL;
		return 0;
	}
	g_ip4_hash	= ip4_hash_init(g_size, sizeof(time_t), NULL);
	if (NULL == g_ip4_hash) {
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
	if (NULL != g_ip4_hash) {
		ip4_hash_free(g_ip4_hash);
		g_ip4_hash = NULL;
	}
	return 0;
}

void temp_list_free() 
{
	g_size = 0;
	pthread_mutex_destroy(&g_ip_mutex_lock);
}

/*
 *	add the specified ip into the temp list
 *
 *	@param	
 *		ip				ip address
 *		interval		interval in temp list
 *	@return	 
 *		TRUE
 *		FALSE
 */
BOOL temp_list_add_ip(const char *ip, int interval)
{
	time_t current_time;
	time_t when;

	if (NULL == g_ip4_hash || NULL == ip) {
		return FALSE;
	}
	if (GREY_LIST_NOT_FOUND != grey_list_query(ip, FALSE)) {
		return FALSE;
	}
	pthread_mutex_lock(&g_ip_mutex_lock);
	
	time(&current_time);
	when = current_time + interval;
	if (ip4_hash_add(g_ip4_hash, (char*)ip, &when) > 0) {
		pthread_mutex_unlock(&g_ip_mutex_lock);
		return TRUE;
	}
	if (0 == temp_list_collect_ip_entry()) {
		pthread_mutex_unlock(&g_ip_mutex_lock);
		return FALSE;
	}

	if (ip4_hash_add(g_ip4_hash, (char*)ip, &when) > 0) {
		pthread_mutex_unlock(&g_ip_mutex_lock);
		return TRUE;
	}
	pthread_mutex_unlock(&g_ip_mutex_lock);
	return FALSE;
}

/*
 *	remove the specified ip from the temp list
 *
 *	@param	
 *		ip		ip address to remove
 *
 *	@return	 
 *		TRUE	success
 *		FALSE	fail
 */
BOOL temp_list_remove_ip(const char *ip)
{
	if (NULL == g_ip4_hash || NULL == ip) {
		return FALSE;
	}
	pthread_mutex_lock(&g_ip_mutex_lock);
	if (NULL == ip4_hash_query(g_ip4_hash, (char*)ip)) {
		pthread_mutex_unlock(&g_ip_mutex_lock);
		return TRUE;
	}
	if (ip4_hash_remove(g_ip4_hash, (char*)ip) != 1) {
		pthread_mutex_unlock(&g_ip_mutex_lock);
		return FALSE;
	}
	pthread_mutex_unlock(&g_ip_mutex_lock);
	return TRUE;
}

/*
 *	query if the specified ip is in the temp list
 *	@param	
 *		ip		ip address to query
 *	@return	 
 *		TRUE	found in list
 *		FALSE	not found in list
 */
BOOL temp_list_query(const char *ip) 
{
	time_t current_time;
	time_t *pwhen;
	
	if (NULL == g_ip4_hash || NULL == ip)	{
		return FALSE;
	}
	pthread_mutex_lock(&g_ip_mutex_lock);
	pwhen = (time_t*)ip4_hash_query(g_ip4_hash, (char*)ip);
	if (NULL == pwhen) {
		pthread_mutex_unlock(&g_ip_mutex_lock);
		return FALSE; /* not found */
	}
	
	time(&current_time);
	if (current_time <= *pwhen) {
		pthread_mutex_unlock(&g_ip_mutex_lock);
		return TRUE; /* found, in temp list */
	}
	ip4_hash_remove(g_ip4_hash, (char*)ip);
	pthread_mutex_unlock(&g_ip_mutex_lock);
	return FALSE; /* is overdue */
}

/*
 *  collect the timeout entry in the ip hash table 
 *
 *  @return
 *      the number of entries collected
 */
static int temp_list_collect_ip_entry()
{
	IP4_HASH_ITER *iter;
	time_t *pwhen;
	int	collected_num;
	time_t current_time;

	time(&current_time);
	collected_num = 0;
	iter = ip4_hash_iter_init(g_ip4_hash); 
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		pwhen = (time_t*)ip4_hash_iter_get_value(iter, NULL);
		if (current_time > *pwhen) {
			ip4_hash_iter_remove(iter);
			collected_num++;
		}
	}
	ip4_hash_iter_free(iter);
	return collected_num;
}

/*
 *  enumerate each item in temp list hash table
 *  @param
 *      ip [in]        ip address
 *      puntil [out]    buffer for saving until time
 *  @return
 *      TRUE            found
 *      FALSE           found nothing
 */
BOOL temp_list_echo(const char *ip, time_t *puntil)
{
	time_t *pwhen;

	if (NULL == g_ip4_hash || NULL == ip || NULL == puntil) {
		return FALSE;
	}
	pthread_mutex_lock(&g_ip_mutex_lock);
	/* first remove the overdue items */
	temp_list_collect_ip_entry();
	pwhen = (time_t*)ip4_hash_query(g_ip4_hash, (char*)ip);
	if (NULL == pwhen) {
		pthread_mutex_unlock(&g_ip_mutex_lock);
		return FALSE;
	}
	*puntil = *pwhen;
	pthread_mutex_unlock(&g_ip_mutex_lock);
	return TRUE;
}

BOOL temp_list_dump(const char *path)
{
	int fd, len;
	char temp_string[512];
	IP4_HASH_ITER *iter;
	time_t *pwhen;
	time_t current_time;
	struct tm time_buff;

	if (NULL == g_ip4_hash || NULL == path) {
		return FALSE;
	}
	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	pthread_mutex_lock(&g_ip_mutex_lock);
	time(&current_time);
	iter = ip4_hash_iter_init(g_ip4_hash);
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		pwhen = ip4_hash_iter_get_value(iter, temp_string);
		if (current_time >= *pwhen) {
			ip4_hash_iter_remove(iter);
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
	ip4_hash_iter_free(iter);
	pthread_mutex_unlock(&g_ip_mutex_lock);
	close(fd);
	return TRUE;
}

