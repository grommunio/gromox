/*
 *  Audit filter module which is a sub module of the connection filter.
 *  We check if in the specified iterval a client comes from the same
 *  ip connects too much and we will reject it as long as the specified
 *  period after its last connection. If the client try to connect again
 *  and again, it will be reject forever. If the ip is in the white list,
 *  it will never pass through this module.
 *
 */
#include <unistd.h>
#include "ip_filter.h"
#include "audit_filter.h"
#include "ip4_hash.h"
#include "util.h"
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>

typedef struct _IP_AUDIT {
    struct timeval  first_time_stamp;/* time stamp of first time of visit */
    struct timeval  last_time_stamp; /* time stamp of last time of visit  */
    int				times;
} IP_AUDIT;

/* private global variable */
static IP4_HASH_TABLE *g_audit_hash;

static long g_audit_num;
static long g_audit_interval;           /*  connecting times  per interval */ 
static int  g_max_within_interval;       /*  max times within the interval  */  
static pthread_mutex_t g_audit_mutex_lock;


static int audit_filter_collect_entry(struct timeval *current_time);

/*
 *  initialize the audit filter
 *
 *  @param 
 *      audit_num   number of ip addresses to audit
 */

void audit_filter_init(int audit_num, long audit_interval, int audit_times) 
{
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
    g_audit_hash = ip4_hash_init(g_audit_num, sizeof(IP_AUDIT), NULL);
    if (NULL == g_audit_hash) {
        ip_filter_echo("fail to allocate audit hash table");
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
        ip4_hash_free(g_audit_hash);
        g_audit_hash = NULL;
    }
    return 0;
}

void audit_filter_free()
{
	pthread_mutex_destroy(&g_audit_mutex_lock);
}


/*
 *  query and audit IP in audit hash map
 *  @param  
 *      ip      ip address to query
 *  @return  
 *      TRUE    legal connection 
 *      FALSE   illegal connection
 */
BOOL audit_filter_judge(const char *ip) 
{
    struct timeval current_time;
    IP_AUDIT *paudit, new_audit;
    
    if (NULL == g_audit_hash || NULL == ip) {
        return TRUE;
    }
	pthread_mutex_lock(&g_audit_mutex_lock); 
    paudit = (IP_AUDIT*)ip4_hash_query(g_audit_hash, (char*)ip);
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
    /* paduit == NULL, not found in the ip4_hash_table */
    new_audit.first_time_stamp  = current_time;
    new_audit.last_time_stamp   = current_time;
    new_audit.times = 1;
    if (ip4_hash_add(g_audit_hash, (char*)ip, &new_audit) != 1) {
        if (0 == audit_filter_collect_entry(&current_time)) {
            /* still cannot find one unit for auditing, give up */
            debug_info("[ip_filter]: still cannot find one unit "
                        "for auditing, give up");
			pthread_mutex_unlock(&g_audit_mutex_lock);
            return TRUE;
        }
        ip4_hash_add(g_audit_hash, (char*)ip, &new_audit);
    }
	pthread_mutex_unlock(&g_audit_mutex_lock);
    return TRUE;
}

/*
 *  query IP in hash map
 *  @param  
 *      ip      ip address to query
 *  @return  
 *      TRUE    in hash map 
 *      FALSE   not in hash map
 */
BOOL audit_filter_query(const char *ip) 
{
    struct timeval current_time;
    IP_AUDIT *paudit;
    
    if (NULL == g_audit_hash || NULL == ip) {
        return FALSE;
    }

	pthread_mutex_lock(&g_audit_mutex_lock); 
    gettimeofday(&current_time, NULL);                  
    paudit = (IP_AUDIT*)ip4_hash_query(g_audit_hash, (char*)ip);
	if (NULL == paudit) {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return FALSE;
	}
    if (paudit->times < g_max_within_interval) {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return FALSE;
	} else { 
		if (CALCULATE_INTERVAL(current_time,
			paudit->first_time_stamp) > g_audit_interval) {
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
    IP4_HASH_ITER    *iter = NULL;
    IP_AUDIT *iter_audit  = NULL;
    int num_of_collect  = 0;

    iter = ip4_hash_iter_init(g_audit_hash); 
    for (ip4_hash_iter_begin(iter); !ip4_hash_iter_done(iter);
        ip4_hash_iter_forward(iter)) {
        iter_audit = ip4_hash_iter_get_value(iter, NULL);
        if (CALCULATE_INTERVAL(*current_time, 
            iter_audit->last_time_stamp) >= g_audit_interval) {
            ip4_hash_iter_remove(iter);
            num_of_collect++;
        }
    }
    ip4_hash_iter_free(iter);
    return num_of_collect;
}

/*
 *  echo ip in audit hash map
 *  @param
 *      ip [in]            ip address
 *      pfirst_access [out] for retrieving first access time
 *      plast_access [out]  for retrieving last access time
 *      ptimes [out]        for retrieving access times
 *  @return
 *      TRUE                found
 *      FALSE               found nothing
 */
BOOL audit_filter_echo(const char *ip, time_t *pfirst_access,
		    time_t *plast_access, int *ptimes)
{
	IP_AUDIT *paudit;
	struct timeval current_time;

	if (NULL == g_audit_hash || NULL == ip ||
		NULL == pfirst_access || NULL == ptimes) {
		return FALSE;
	}
	pthread_mutex_lock(&g_audit_mutex_lock);
	gettimeofday(&current_time, NULL);
	/* first remove the overdue items */
	paudit = (IP_AUDIT*)ip4_hash_query(g_audit_hash, (char*)ip);
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
 *  remove the specified ip from the audit
 *  @param
 *		ip      ip address to remove
 *  @return
 *      TRUE    success
 *      FALSE   fail
 */
BOOL audit_filter_remove_ip(const char *ip)
{
	if (NULL == g_audit_hash || NULL == ip) {
		return FALSE;
	}
	pthread_mutex_lock(&g_audit_mutex_lock);
	if (NULL == ip4_hash_query(g_audit_hash, (char*)ip)) {
		pthread_mutex_unlock(&g_audit_mutex_lock);
		return TRUE;
	}
	if (ip4_hash_remove(g_audit_hash, (char*)ip) != 1) {
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
	IP4_HASH_ITER *iter;
	IP_AUDIT *iter_audit;
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
	iter = ip4_hash_iter_init(g_audit_hash);
	for (ip4_hash_iter_begin(iter); !ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		iter_audit = ip4_hash_iter_get_value(iter, temp_string);
		if (CALCULATE_INTERVAL(current_time,
			iter_audit->last_time_stamp) > g_audit_interval) {
			ip4_hash_iter_remove(iter);
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
	ip4_hash_iter_free(iter);
	pthread_mutex_unlock(&g_audit_mutex_lock);
	close(fd);
	return TRUE;
}
