#include <unistd.h>
#include "invalid_user.h"
#include "config_file.h"
#include "mail_func.h"
#include "str_hash.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

/* private global variable */
static STR_HASH_TABLE  *g_hash_table;

static int g_table_size;
static int g_valid_interval;    /*  max times within the interval  */  
static pthread_mutex_t g_table_lock;
static char g_config_path[256];

static int invalid_user_collect_entry(time_t current_time, int *pvalid_num);

static BOOL invalid_user_add(const char *rcpt_address);

static void invalid_user_remove(const char *rcpt_address);

static void invalid_user_clear();

static BOOL invalid_user_dump(const char *path);

/*
 *  initialize the invalid user
 *
 *  @param 
 *      size			table size
 *      valid_intvl		valid interval of item
 */
void invalid_user_init(const char *config_path, int size, int valid_intvl) 
{
	strcpy(g_config_path, config_path);
	g_table_size = size;
	g_valid_interval =  valid_intvl;
	pthread_mutex_init(&g_table_lock, NULL);
}

int invalid_user_run()
{
    g_hash_table = str_hash_init(g_table_size, sizeof(time_t), NULL);
    if (NULL == g_hash_table) {
        printf("[invalid_user]: fail to allocate hash table\n");
        return -1;
	}
	return 0;
}


/*
 *  invalid user's destruction function
 */
int invalid_user_stop() 
{
    if (NULL != g_hash_table) {
        str_hash_free(g_hash_table);
        g_hash_table = NULL;
    }
    return 0;
}

void invalid_user_free()
{
	g_config_path[0] = '\0';
	pthread_mutex_destroy(&g_table_lock);
}

/*
 *  query rcpt address in hash table
 *  @param
 *      rcpt_address [in]	  rcpt address
 *  @return  
 *      TRUE	valid address
 *      FALSE   invalid address
 */
BOOL invalid_user_check(const char *rcpt_address) 
{
	char temp_string[256];
	time_t *ptime, current_time;

	strncpy(temp_string, rcpt_address, 255);
	temp_string[255] = '\0';
	lower_string(temp_string);
	
	pthread_mutex_lock(&g_table_lock); 
    ptime = (time_t*)str_hash_query(g_hash_table, temp_string);
    time(&current_time);                  
    if (NULL != ptime) {
		if (current_time - *ptime <= g_valid_interval) {
			pthread_mutex_unlock(&g_table_lock);
            return FALSE;  
        } else {
			str_hash_remove(g_hash_table, temp_string);
		}
    }
	pthread_mutex_unlock(&g_table_lock);
    return TRUE;
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
static int invalid_user_collect_entry(time_t current_time, int *pvalid_num)
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

static void invalid_user_clear()
{
    STR_HASH_ITER *iter;

	pthread_mutex_lock(&g_table_lock);
    iter = str_hash_iter_init(g_hash_table); 
    for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
        str_hash_iter_forward(iter)) {
		str_hash_iter_remove(iter);
    }
    str_hash_iter_free(iter);
	pthread_mutex_unlock(&g_table_lock);
}

static BOOL invalid_user_add(const char *rcpt_address)
{
	char temp_string[256];
	time_t current_time, *ptime;

	strncpy(temp_string, rcpt_address, 256);
	temp_string[255] = '\0';
	lower_string(temp_string);
	pthread_mutex_lock(&g_table_lock);
	time(&current_time);
    ptime = (time_t*)str_hash_query(g_hash_table, temp_string);
	if (NULL != ptime) {
		*ptime = current_time;
		pthread_mutex_unlock(&g_table_lock);
		return TRUE;
	}
	if (1 != str_hash_add(g_hash_table, temp_string, &current_time)) {
		if (0 == invalid_user_collect_entry(current_time, NULL)) {
			pthread_mutex_unlock(&g_table_lock);
			return FALSE;
		}
		str_hash_add(g_hash_table, temp_string, &current_time);
	}
	pthread_mutex_unlock(&g_table_lock);
	return TRUE;
}


static void invalid_user_remove(const char *rcpt_address)
{
	char temp_string[256];

	strncpy(temp_string, rcpt_address, 256);
	temp_string[255] = '\0';
	lower_string(temp_string);
	pthread_mutex_lock(&g_table_lock);
    str_hash_remove(g_hash_table, temp_string);
	pthread_mutex_unlock(&g_table_lock);
}

static BOOL invalid_user_dump(const char *path)
{
	int fd, len;
	STR_HASH_ITER *iter;
	char temp_string[257];
	time_t *ptime, current_time;
	
	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	pthread_mutex_lock(&g_table_lock);
	time(&current_time);
    iter = str_hash_iter_init(g_hash_table); 
    for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
        str_hash_iter_forward(iter)) {
        ptime = (time_t*)str_hash_iter_get_value(iter, temp_string);
        if (current_time - *ptime >= g_valid_interval) {
            str_hash_iter_remove(iter);
        } else {
			len = strlen(temp_string);
			temp_string[len] = '\n';
			write(fd, temp_string, len + 1);
		}
    }
    str_hash_iter_free(iter);
	pthread_mutex_unlock(&g_table_lock);
	close(fd);
	return TRUE;
}

/*
 *  invalid user's console talk
 *  @param
 *      argc            arguments number
 *      argv [in]       arguments value
 *      result [out]    buffer for retrieving result
 *      length          result buffer length
 */
void invalid_user_console_talk(int argc, char **argv, char *result, int length)
{
	CONFIG_FILE *pfile;
	EMAIL_ADDR email_addr;
	time_t current_time;
	int len, interval, valid_num;
	char temp_string[256];
	char help_string[] = "250 invalid user help information:\r\n"
			             "\t%s info\r\n"
						 "\t    --print the invalid user information\r\n"
						 "\t%s set valid-interval <interval>\r\n"
						 "\t    --set valid interval of invalid user\r\n"
						 "\t%s add <rcpt-address>\r\n"
						 "\t    --add an invalid user into table\r\n"
						 "\t%s remove <rcpt-address>\r\n"
						 "\t    --remove invalid user from table\r\n"
						 "\t%s clear\r\n"
						 "\t    --clear all items in table\r\n"
						 "\t%s dump <path>\r\n"
						 "\t    --dump invalid users to file";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0],
				argv[0], argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		pthread_mutex_lock(&g_table_lock);
		time(&current_time);
		invalid_user_collect_entry(current_time, &valid_num);
		pthread_mutex_unlock(&g_table_lock);
		len = snprintf(result, length,
			"250 invalid user information:\r\n"
			"\ttable capacity      %d\r\n"
			"\tcurrent used        %d\r\n"
			"\tvalid interval      ", g_table_size, valid_num);
		itvltoa(g_valid_interval, result + len);
		return;
	}
	if (2 == argc && 0 == strcmp("clear", argv[1])) {
		invalid_user_clear();
		strncpy(result, "250 all items cleaned up", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("valid-interval", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0) {
			snprintf(result, length, "550 %s is illegal", argv[3]);
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
	if (3 == argc && 0 == strcmp("add", argv[1])) {
		parse_email_addr(&email_addr, argv[2]);
		if (0 == strlen(email_addr.local_part) ||
			0 == strlen(email_addr.domain)) {
			snprintf(result, length, "550 %s is not email address", argv[2]);
			return;
		}
		snprintf(temp_string, 256, "%s@%s", email_addr.local_part,
				email_addr.domain);
		temp_string[255] = '\0';
		if (TRUE == invalid_user_add(temp_string)) {
			snprintf(result, length, "250 %s is added", argv[2]);
		} else {
			snprintf(result, length, "550 fail to add %s", argv[2]);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		parse_email_addr(&email_addr, argv[2]);
		if (0 == strlen(email_addr.local_part) ||
			0 == strlen(email_addr.domain)) {
			snprintf(result, length, "550 %s is not email address", argv[2]);
			return;
		}
		snprintf(temp_string, 256, "%s@%s", email_addr.local_part,
				email_addr.domain);
		temp_string[255] = '\0';
		invalid_user_remove(temp_string);
		snprintf(result, length, "250 %s is removed", argv[2]);
		return;
	}
	if (3 == argc && 0 == strcmp("dump", argv[1])) {
		if (TRUE == invalid_user_dump(argv[2])) {
			strncpy(result, "250 dump table OK", length);
		} else {
			strncpy(result, "550 fail to dump table", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

