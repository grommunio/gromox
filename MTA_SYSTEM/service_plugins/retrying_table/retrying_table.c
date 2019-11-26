#include <libHX/string.h>
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
static char g_config_path[256];

static int retrying_table_collect_entry(time_t current_time, int *pvalid_num);

/*
 *  initialize the retrying table
 *
 *  @param 
 *      size			table size
 *      min_intvl		minimum interval of item
 *      valid_intvl		valid interval of item
 */
void retrying_table_init(const char *config_path, int size, int min_intvl,
	int valid_intvl) 
{
	strcpy(g_config_path, config_path);
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
	g_config_path[0] = '\0';
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
BOOL retrying_table_check(const char *ip, const char *from, MEM_FILE *pfile) 
{
	int interval;
	int i, rcpt_num;
	const char *pdot;
	char temp_ip[16];
	char temp_rcpt[256];
	char temp_string[256];
	time_t *ptime, current_time;

    if (NULL == g_hash_table) {
        return TRUE;
    }
	rcpt_num = 0;
	mem_file_seek(pfile, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(pfile, temp_rcpt, 256)) {
		rcpt_num ++;
	}
	pdot = ip - 1;
	for (i=0; i<2; i++) {
		pdot = strchr(pdot + 1, '.');
	}
	memcpy(temp_ip, ip, pdot - ip);
	temp_ip[pdot - ip] = '\0';
	snprintf(temp_string, 255, "%s:%s:%s:%d", temp_ip, from, temp_rcpt,
		rcpt_num);
	temp_string[255] = '\0';
	HX_strlower(temp_string);
	
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

/*
 *  retrying table's console talk
 *  @param
 *      argc            arguments number
 *      argv [in]       arguments value
 *      result [out]    buffer for retrieving result
 *      length          result buffer length
 */
void retrying_table_console_talk(int argc, char **argv,
	char *result, int length)
{
	CONFIG_FILE *pfile;
	time_t current_time;
	int len, interval, valid_num;
	char help_string[] = "250 retrying table help information:\r\n"
			             "\t%s info\r\n"
						 "\t    --print the retrying table information\r\n"
						 "\t%s set min-interval <interval>\r\n"
						 "\t    --set minimum interval of retying table\r\n"
						 "\t%s set valid-interval <interval>\r\n"
						 "\t    --set valid interval of retrying table";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		pthread_mutex_lock(&g_table_lock);
		time(&current_time);
		retrying_table_collect_entry(current_time, &valid_num);
		pthread_mutex_unlock(&g_table_lock);
		len = snprintf(result, length,
			"250 retrying table information:\r\n"
			"\ttable capacity      %d\r\n"
			"\tcurrent used        %d\r\n"
			"\tminimum interval    ", g_table_size, valid_num);
		itvltoa(g_minimum_interval, result + len);
		len += strlen(result + len);
		memcpy(result + len, "\r\n\tvalid interval      ", 23);
		len += 23;
		itvltoa(g_valid_interval, result + len);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("min-interval", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0) {
			snprintf(result, length, "550 %s is illegal", argv[3]);
			return;
		}
		if (interval > g_valid_interval) {
			snprintf(result, length, "550 %s is larger than valid "
				"interval", argv[3]);
			return;
		}
		pfile = config_file_init(g_config_path);
		if (NULL == pfile) {
			strncpy(result, "550 fail to open config file", length);
			return;
		}
		config_file_set_value(pfile, "MINIMUM_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			strncpy(result, "550 fail to save config file", length);
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		g_minimum_interval = interval;
		strncpy(result, "250 minimum interval set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("valid-interval", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0) {
			snprintf(result, length, "550 %s is illegal", argv[3]);
			return;
		}
		if (interval < g_minimum_interval) {
			snprintf(result, length, "550 %s is less than valid "
				"interval", argv[3]);
			return;
		}
		pfile = config_file_init(g_config_path);
		if (NULL == pfile) {
			strncpy(result, "550 fail to open config file", length);
			return;
		}
		config_file_set_value(pfile, "VALID_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			strncpy(result, "550 fail to save config file", length);
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		g_valid_interval = interval;
		strncpy(result, "250 valid interval set OK", length);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

