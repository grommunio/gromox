#include <libHX/string.h>
#include "bounce_audit.h"
#include <gromox/hook_common.h>
#include "mail_func.h"
#include "str_hash.h"
#include "util.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>


/* private global variable */
static int g_audit_num;
static int g_audit_interval;
static pthread_mutex_t g_audit_mutex_lock;
static STR_HASH_TABLE *g_audit_hash;

static int bounce_audit_collect_entry(time_t current_time);

void bounce_audit_init(int audit_num, int audit_interval) 
{
    g_audit_num             = audit_num;
    g_audit_interval        = audit_interval;
	pthread_mutex_init(&g_audit_mutex_lock, NULL);
}

int bounce_audit_run()
{
	/* invalidate the audit hash table if audit number is less than 0 */
	if (g_audit_num <= 0) {
		g_audit_hash = NULL;
		return 0;
	}
    g_audit_hash = str_hash_init(g_audit_num, sizeof(time_t), NULL);
    if (NULL == g_audit_hash) {
        printf("[exmdb_local]: fail to create audit hash map\n");
        return -1;
	}
	return 0;
}

int bounce_audit_set_param(int type, int value)
{
    switch (type) {
    case BOUNCE_AUDIT_INTERVAL:
        g_audit_interval = value;
        break;
    default:
        return -1;
    }
    return 0;
}

int bounce_audit_get_param(int type)
{
    switch (type) {
	case BOUNCE_AUDIT_CAPABILITY:
		return g_audit_num;
    case BOUNCE_AUDIT_INTERVAL:
        return g_audit_interval;
    }
    return -1;
}

int bounce_audit_stop() 
{
    if (NULL != g_audit_hash) {
        str_hash_free(g_audit_hash);
        g_audit_hash = NULL;
    }
    return 0;
}

void bounce_audit_free()
{
	pthread_mutex_destroy(&g_audit_mutex_lock);
}

BOOL bounce_audit_check(const char *audit_string) 
{
    time_t *ptime;
    time_t current_time;
	char temp_string[512];

    if (NULL == g_audit_hash) {
        return TRUE;
    }
	strncpy(temp_string, audit_string, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	HX_strlower(temp_string);
	pthread_mutex_lock(&g_audit_mutex_lock); 
    ptime = (time_t*)str_hash_query(g_audit_hash, temp_string);
    time(&current_time);    
    if (NULL != ptime) {
		if (current_time - *ptime > g_audit_interval) {
			*ptime = current_time;
			pthread_mutex_unlock(&g_audit_mutex_lock);
            return TRUE;  	
		} else {
			*ptime = current_time;
			pthread_mutex_unlock(&g_audit_mutex_lock);
            return FALSE;  	
		}
    }
    if (str_hash_add(g_audit_hash, temp_string, &current_time) != 1) {
        if (0 == bounce_audit_collect_entry(current_time)) {
			pthread_mutex_unlock(&g_audit_mutex_lock);
            return TRUE;
        }
        str_hash_add(g_audit_hash, temp_string, &current_time);
    }
	pthread_mutex_unlock(&g_audit_mutex_lock);
    return TRUE;
}

static int bounce_audit_collect_entry(time_t current_time)
{
    STR_HASH_ITER    *iter = NULL;
	time_t           *ptime;
    int num_of_collect  = 0;

    iter = str_hash_iter_init(g_audit_hash); 
    for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
        str_hash_iter_forward(iter)) {
        ptime = str_hash_iter_get_value(iter, NULL);
        if (current_time - *ptime >= g_audit_interval) {
            str_hash_iter_remove(iter);
            num_of_collect++;
        }
    }
    str_hash_iter_free(iter);
    return num_of_collect;
}
