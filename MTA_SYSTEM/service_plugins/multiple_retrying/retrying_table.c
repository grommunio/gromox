#include "retrying_table.h"
#include "config_file.h"
#include "str_hash.h"
#include "util.h"
#include <stdio.h>
#include <pthread.h>
#include <time.h>

/* private global variable */
static STR_HASH_TABLE  *g_hash_table;

static int g_table_size;
static int g_minimum_interval;  /*  connecting times  per interval */ 
static int g_valid_interval;    /*  max times within the interval  */  
static pthread_mutex_t g_table_lock;

static int retrying_table_collect_entry(time_t current_time, int *pvalid_num);

/*
 *  initialize the retrying table
 *
 *  @param 
 *      size			table size
 *      min_intvl		minimum interval of item
 *      valid_intvl		valid interval of item
 */
void retrying_table_init(int size, int min_intvl, int valid_intvl) 
{
	g_table_size = size;
	g_minimum_interval = min_intvl;
	g_valid_interval =  valid_intvl;
	pthread_mutex_init(&g_table_lock, NULL);
}

int retrying_table_run()
{
	/* invalidate the audit hash table if audit number is less than 0 */
	if (g_table_size <= 0) {
		g_hash_table = NULL;
		return 0;
	}
    g_hash_table = str_hash_init(g_table_size, sizeof(time_t), NULL);
    if (NULL == g_hash_table) {
        printf("[retrying_table]: fail to allocate hash table\n");
        return -1;
	}
	return 0;
}


/*
 *  retrying table's destruction function
 */
int retrying_table_stop() 
{
    if (NULL != g_hash_table) {
        str_hash_free(g_hash_table);
        g_hash_table = NULL;
    }
    return 0;
}

void retrying_table_free()
{
	pthread_mutex_destroy(&g_table_lock);
}

/*
 *  query or record strings in hash table
 *  @param
 *		ip [in]		  ip address
 *      from [in]     from address
 *      pfile [in]	  rcpt addresses
 *  @return  
 *      TRUE	legal connection 
 *      FALSE   illegal connection
 */
BOOL retrying_table_check(char *temp_string) 
{
	int interval;
	time_t *ptime, current_time;

    if (NULL == g_hash_table) {
        return TRUE;
    }
	lower_string(temp_string);
	
	pthread_mutex_lock(&g_table_lock); 
    ptime = (time_t*)str_hash_query(g_hash_table, temp_string);
    time(&current_time);                  
    if (NULL != ptime) {
		interval = current_time - *ptime;
		if (interval >= g_minimum_interval && interval <= g_valid_interval) {
			pthread_mutex_unlock(&g_table_lock);
            return TRUE;  
        } else {
			if (interval > g_valid_interval) {
				str_hash_remove(g_hash_table, temp_string);
			}
			pthread_mutex_unlock(&g_table_lock);
			return FALSE;
		}
    }
    if (str_hash_add(g_hash_table, temp_string, &current_time) != 1) {
        if (0 == retrying_table_collect_entry(current_time, NULL)) {
			pthread_mutex_unlock(&g_table_lock);
            return FALSE;
        }
        str_hash_add(g_hash_table, temp_string, &current_time);
    }
	pthread_mutex_unlock(&g_table_lock);
    return FALSE;
}


/*
 *  collect the timeout entry in the hash table 
 *
 *  @param
 *      current_time        the current time
 *      pvalid_num [out]	valid number
 *
 *  @return
 *      the number of entries collected
 */
static int retrying_table_collect_entry(time_t current_time, int *pvalid_num)
{
    time_t *ptime;
    STR_HASH_ITER *iter;
    int collect_num, valid_num;

	valid_num = 0;
	collect_num = 0;
    iter = str_hash_iter_init(g_hash_table); 
    for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
        str_hash_iter_forward(iter)) {
        ptime = (time_t*)str_hash_iter_get_value(iter, NULL);
        if (current_time - *ptime >= g_valid_interval) {
            str_hash_iter_remove(iter);
            collect_num++;
        } else {
			valid_num ++;
		}
    }
    str_hash_iter_free(iter);
	if (NULL != pvalid_num) {
		*pvalid_num = valid_num;
	}
    return collect_num;
}

int retrying_table_get_valid()
{
	int valid_num;
	time_t current_time;
	
	pthread_mutex_lock(&g_table_lock);
	time(&current_time);
	retrying_table_collect_entry(current_time, &valid_num);
	pthread_mutex_unlock(&g_table_lock);
	return valid_num;
}

void retrying_table_set_param(int param, int value)
{
	switch (param) {
	case RETRYING_TABLE_MIN_INTERVAL:
		g_minimum_interval = value;
		break;
	case RETRYING_TABLE_MAX_INTERVAL:
		g_valid_interval = value;
		break;
	}
}

int retrying_table_get_param(int param)
{
	switch (param) {
	case RETRYING_TABLE_MIN_INTERVAL:
		return g_minimum_interval;
	case RETRYING_TABLE_MAX_INTERVAL:
		return g_valid_interval;
	case RETRYING_TABLE_TABLE_SIZE:
		return g_table_size;
	}
	return 0;
}

