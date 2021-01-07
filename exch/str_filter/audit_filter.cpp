// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  Audit filter module which is a sub module of the string filter.
 *  We check if in the specified interval a client comes from the same
 *  string appears too much and we will reject it as long as the specified
 *  period after its last connection. If the client try to connect again
 *  and again, it will be reject forever. If the string is in the white list,
 *  it will never pass through this module.
 *
 */
#include <unistd.h>
#include <libHX/string.h>
#include "str_filter.h"
#include "audit_filter.h"
#include "str_hash.h"
#include "util.h"
#include <cstdio>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>

struct STR_AUDIT {
    struct timeval  first_time_stamp;/* time stamp of first time of visit */
    struct timeval  last_time_stamp; /* time stamp of last time of visit  */
    int             times;
};

/* private global variable */
static STR_HASH_TABLE *g_audit_hash;

static int g_audit_num;
static int g_audit_interval;         /*  connecting times  per interval */ 
static int g_max_within_interval;    /*  max times within the interval  */  
static pthread_mutex_t g_audit_mutex_lock;
static BOOL g_case_sensitive;


static int audit_filter_collect_entry(struct timeval *current_time);

/*
 *  initialize the audit filter
 *
 *  @param 
 *      audit_num   number of string to audit
 */

void audit_filter_init(BOOL case_sensitive, int audit_num, int audit_interval,
    int audit_times) 
{
	g_case_sensitive        = case_sensitive;
    g_audit_num             = audit_num;
    g_audit_interval        = audit_interval;
    g_max_within_interval   = audit_times;
	pthread_mutex_init(&g_audit_mutex_lock, NULL);
}

int audit_filter_run()
{
	/* invalidate the audit hash table if audit number is less than 0 */
	if (g_audit_num <= 0) {
		g_audit_hash = NULL;
		return 0;
	}
    g_audit_hash = str_hash_init(g_audit_num, sizeof(STR_AUDIT), NULL);
    if (NULL == g_audit_hash) {
		str_filter_echo("Failed to allocate audit hash table");
        return -1;
	}
	return 0;
}

int audit_filter_set_param(int type, int value)
{
    switch (type) {
    case AUDIT_INTERVAL:
        g_audit_interval = value;
        break;
    case AUDIT_TIMES:
        g_max_within_interval = value;
        break;
    default:
        return -1;
    }
    return 0;
}

int audit_filter_get_param(int type)
{
    switch (type) {
	case AUDIT_CAPABILITY:
		return g_audit_num;
    case AUDIT_INTERVAL:
        return g_audit_interval;
    case AUDIT_TIMES:
        return g_max_within_interval;
    }
    return -1;
}

/*
 *  audit filter's destruction function
 *
 */

int audit_filter_stop() 
{
    if (NULL != g_audit_hash) {
        str_hash_free(g_audit_hash);
        g_audit_hash = NULL;
    }
    return 0;
}

void audit_filter_free()
{
	pthread_mutex_destroy(&g_audit_mutex_lock);
}

/*
 *  query and audit string in audit hash map
 *  @param  
 *      str     string
 *  @return  
 *      TRUE	legal connection 
 *      FALSE   illegal connection
 */
BOOL audit_filter_judge(const char *str) 
{
    struct timeval current_time;
    STR_AUDIT *paudit, new_audit;
	char temp_string[256];

    if (NULL == g_audit_hash || NULL == str) {
        return TRUE;
    }
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);	
	}
	pthread_mutex_lock(&g_audit_mutex_lock); 
    paudit = (STR_AUDIT*)str_hash_query(g_audit_hash, temp_string);
    gettimeofday(&current_time, NULL);                  
    if (NULL != paudit) {
        if (paudit->times < g_max_within_interval) {
            if (CALCULATE_INTERVAL(current_time, paudit->first_time_stamp) >
				g_audit_interval) {
                paudit->times = 0;
                paudit->first_time_stamp = current_time;
            }
            paudit->times ++;
            paudit->last_time_stamp = current_time;
        } else {
            if (CALCULATE_INTERVAL(current_time, paudit->last_time_stamp) >
				g_audit_interval) {
                paudit->times = 1;
                paudit->first_time_stamp = current_time;
                paudit->last_time_stamp = current_time;
            } else {
				paudit->times ++;
                paudit->last_time_stamp = current_time;
				pthread_mutex_unlock(&g_audit_mutex_lock);
                return FALSE;  
            }
        }
		pthread_mutex_unlock(&g_audit_mutex_lock);
        return TRUE;
    }
    /* paduit == NULL, not found in the str_hash_table */
    new_audit.first_time_stamp  = current_time;
    new_audit.last_time_stamp   = current_time;
    new_audit.times = 1;
    if (str_hash_add(g_audit_hash, temp_string, &new_audit) != 1) {
        if (0 == audit_filter_collect_entry(&current_time)) {
            /* still cannot find one unit for auditing, give up */
            debug_info("[str_filter]: still cannot find one unit "
                        "for auditing, give up");
			pthread_mutex_unlock(&g_audit_mutex_lock);
            return TRUE;
        }
        str_hash_add(g_audit_hash, temp_string, &new_audit);
    }
	pthread_mutex_unlock(&g_audit_mutex_lock);
    return TRUE;
}

/*
 *  query string in hash map
 *  @param  
 *      str     string
 *  @return  
 *      TRUE    in hash map
 *      FALSE   not in hash map
 */
BOOL audit_filter_query(const char *str) 
{
	struct timeval current_time;
    STR_AUDIT *paudit;
	char temp_string[256];

    if (NULL == g_audit_hash || NULL == str) {
        return FALSE;
    }
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);	
	}
	pthread_mutex_lock(&g_audit_mutex_lock); 
	gettimeofday(&current_time, NULL);
    paudit = (STR_AUDIT*)str_hash_query(g_audit_hash, temp_string);
	if (NULL == paudit) {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return FALSE;
	}
    if (paudit->times < g_max_within_interval) {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return FALSE;
	} else {
        if (CALCULATE_INTERVAL(current_time, 
            paudit->last_time_stamp) > g_audit_interval) {
			pthread_mutex_unlock(&g_audit_mutex_lock);
			return FALSE;
		} else {
			pthread_mutex_unlock(&g_audit_mutex_lock);
			return TRUE;
		}
	}
}

/*
 *  collect the timeout entry in the hash table 
 *
 *  @param
 *      current_time [in]       the current time
 *
 *  @return
 *      the number of entries collected
 */
static int audit_filter_collect_entry(struct timeval *current_time)
{
    STR_HASH_ITER    *iter = NULL;
    int num_of_collect  = 0;

    iter = str_hash_iter_init(g_audit_hash); 
    for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
        str_hash_iter_forward(iter)) {
		auto iter_audit = static_cast<STR_AUDIT *>(str_hash_iter_get_value(iter, nullptr));
        if (CALCULATE_INTERVAL(*current_time, 
            iter_audit->last_time_stamp) >= g_audit_interval) {
            str_hash_iter_remove(iter);
            num_of_collect++;
        }
    }
    str_hash_iter_free(iter);
    return num_of_collect;
}

/*
 *  echo string in audit hash map
 *  @param  
 *      str [in]			string
 *      pfirst_access [out]	for retrieving first access time
 *      plast_access [out]	for retrieving last access time
 *      ptimes [out]		for retrieving access times
 *  @return  
 *		TRUE				found
 *		FALSE				found nothing
 */
BOOL audit_filter_echo(const char *str, time_t *pfirst_access,
	time_t *plast_access, int *ptimes)
{
	STR_AUDIT *paudit;
	struct timeval current_time;
	char temp_string[256];
	
	if (NULL == g_audit_hash || NULL == str ||
		NULL == pfirst_access || NULL == ptimes) {
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	pthread_mutex_lock(&g_audit_mutex_lock);
    gettimeofday(&current_time, NULL);           
	/* first remove the overdue items */
	paudit = (STR_AUDIT*)str_hash_query(g_audit_hash, temp_string);
	if (NULL == paudit) {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return FALSE;
	}
    if (paudit->times > g_max_within_interval && CALCULATE_INTERVAL(
		current_time, paudit->last_time_stamp) <= g_audit_interval) {
		*pfirst_access = paudit->first_time_stamp.tv_sec;
		*plast_access = paudit->last_time_stamp.tv_sec;
		*ptimes = paudit->times;
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return TRUE;
	} else {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return FALSE;
	}
}

/*
 *  remove the specified string from the audit
 *  @param
 *		str      string
 *  @return
 *      TRUE    success
 *      FALSE   fail
 */
BOOL audit_filter_remove_string(const char *str)
{
	char temp_string[256];
	
	if (NULL == g_audit_hash || NULL == str) {
		return TRUE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	pthread_mutex_lock(&g_audit_mutex_lock);
	if (NULL == str_hash_query(g_audit_hash, temp_string)) {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return TRUE;
	}
	if (str_hash_remove(g_audit_hash, temp_string) != 1) {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return FALSE;
	}
	pthread_mutex_unlock(&g_audit_mutex_lock);
	return TRUE;
}

BOOL audit_filter_dump(const char *path)
{
	int fd, len;
	char temp_string[512];
    STR_HASH_ITER *iter;
	struct tm time_buff;
	struct timeval current_time;

	if (NULL == g_audit_hash || NULL == path) {
		return FALSE;
	}
	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	pthread_mutex_lock(&g_audit_mutex_lock);
	gettimeofday(&current_time, NULL);
    iter = str_hash_iter_init(g_audit_hash); 
    for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
        str_hash_iter_forward(iter)) {
		auto iter_audit = static_cast<STR_AUDIT *>(str_hash_iter_get_value(iter, temp_string));
        if (CALCULATE_INTERVAL(current_time, 
            iter_audit->last_time_stamp) > g_audit_interval) {
            str_hash_iter_remove(iter);
        } else {
			if (iter_audit->times > g_max_within_interval) {
				len = strlen(temp_string);
				temp_string[len] = '\t';
				len ++;
				len += strftime(temp_string + len, 512 - len,
					"%Y/%m/%d %H:%M:%S",
					localtime_r(&iter_audit->first_time_stamp.tv_sec,
					&time_buff));
				temp_string[len] = '\t';
				len ++;
				len += strftime(temp_string + len, 512 - len,
					"%Y/%m/%d %H:%M:%S",
					localtime_r(&iter_audit->last_time_stamp.tv_sec,
					&time_buff));
				temp_string[len] = '\t';
				len ++;
				itoa(iter_audit->times, temp_string + len, 10);
				len += strlen(temp_string + len);
				temp_string[len] = '\n';
				len ++;
				write(fd, temp_string, len);
			}
		}
    }
    str_hash_iter_free(iter);
	pthread_mutex_unlock(&g_audit_mutex_lock);
	close(fd);
	return TRUE;
}


