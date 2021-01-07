// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include "str_table.h"
#include "str_hash.h"
#include "util.h"
#include "list_file.h"
#include <pthread.h>
#include <stdarg.h>

enum{
	STR_TABLE_REFRESH_OK,
	STR_TABLE_REFRESH_FILE_ERROR,
	STR_TABLE_REFRESH_HASH_FAIL
};

static int str_table_refresh(void);

static STR_HASH_TABLE *g_string_list_table;
static pthread_rwlock_t g_refresh_lock;
static char g_list_path[256];
static BOOL g_case_sensitive;
static char g_module_name[256];
static int g_growing_num;
static int g_hash_cap;
/*
 *	string table's construct function
 */
void str_table_init(const char *module_name, BOOL case_sensitive,
	const char *path, int growing_num)
{
	strcpy(g_module_name, module_name);
	g_case_sensitive = case_sensitive;
	strcpy(g_list_path, path);
	g_growing_num = growing_num;
	g_hash_cap = 0;
}

/*
 *	string table's destruct function
 */
void str_table_free()
{
	g_list_path[0] = '\0';
	g_growing_num = 0;
	g_hash_cap = 0;
}

/*
 *	run string table
 *	@return
 *		 0		success
 *		<>0		fail
 */
int str_table_run()
{
    pthread_rwlock_init(&g_refresh_lock, NULL);
    if (STR_TABLE_REFRESH_OK != str_table_refresh()) {
        return -1;
    }
    return 0;
}

/*
 *	stop string table
 *	@return
 *		 0		success
 *		<>0		fail
 */
int str_table_stop()
{
    if (NULL != g_string_list_table) {
        str_hash_free(g_string_list_table);
        g_string_list_table = NULL;
    }
    pthread_rwlock_destroy(&g_refresh_lock);
    return 0;
}

/*
 *  check if the specified string is in the table
 *
 *  @param
 *      str [in]     string 
 *
 *  @return
 *      TRUE        allow
 *      FALSE       disallow
 */
BOOL str_table_query(const char* str)
{
	char temp_string[256];
	
	if (NULL == str) {
		return FALSE;
	}
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	pthread_rwlock_rdlock(&g_refresh_lock);
    if (NULL != str_hash_query(g_string_list_table, temp_string)) {
		pthread_rwlock_unlock(&g_refresh_lock);
        return TRUE;
    }
	pthread_rwlock_unlock(&g_refresh_lock);
    return FALSE;
}

/*
 *  refresh the string list, the list is from the
 *  file which is specified in configuration file.
 *
 *  @return
 *		STR_TABLE_REFRESH_OK			OK
 *		STR_TABLE_REFRESH_FILE_ERROR	fail to open list file
 *		STR_TABLE_REFRESH_HASH_FAIL		fail to open hash map
 */
static int str_table_refresh()
{
    STR_HASH_TABLE *phash = NULL;
    int i, list_len, hash_cap;
	LIST_FILE *plist_file;
	
    /* initialize the list filter */
	struct srcitem { char s[256]; };
	plist_file = list_file_init3(g_list_path, "%s:256", false);
	if (NULL == plist_file) {
		str_table_echo("list_file_init %s: %s", g_list_path, strerror(errno));
		return STR_TABLE_REFRESH_FILE_ERROR;
	}
	auto pitem = reinterpret_cast<srcitem *>(list_file_get_list(plist_file));
	list_len = list_file_get_item_num(plist_file);
	hash_cap = list_len + g_growing_num;
	
    phash = str_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		str_table_echo("Failed to allocate hash map");
		list_file_free(plist_file);
		return STR_TABLE_REFRESH_HASH_FAIL;
	}
    for (i=0; i<list_len; i++) {
		if (FALSE == g_case_sensitive) {
			HX_strlower(pitem[i].s);
		}
		str_hash_add(phash, pitem[i].s, &i);
    }
    list_file_free(plist_file);
	
	pthread_rwlock_wrlock(&g_refresh_lock);
	if (NULL != g_string_list_table) {
		str_hash_free(g_string_list_table);
	}
    g_string_list_table = phash;
	g_hash_cap = hash_cap;
    pthread_rwlock_unlock(&g_refresh_lock);

    return STR_TABLE_REFRESH_OK;
}

/*
 *	add item into string file and hash table
 *	@param
 *		str [in]		string to be added
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
BOOL str_table_add(const char* str)
{
	char temp_string[256];
	char file_item[512];
	int dummy_val = 0;
	int i, j, hash_cap;
	int fd, string_len;
	STR_HASH_ITER *iter;
	STR_HASH_TABLE *phash;

	if (NULL == str) {
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
	file_item[string_len] = '\n';
	string_len ++;
	pthread_rwlock_wrlock(&g_refresh_lock);
	/* check first if the string is already in the table */
	if (NULL != str_hash_query(g_string_list_table, temp_string)) {
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
	if (str_hash_add(g_string_list_table, temp_string, &dummy_val) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	hash_cap = g_hash_cap + g_growing_num;
	phash = str_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	iter = str_hash_iter_init(g_string_list_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		str_hash_iter_get_value(iter, file_item);
		str_hash_add(phash, file_item, &dummy_val);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_string_list_table);
	g_string_list_table = phash;
	g_hash_cap = hash_cap;
	if (str_hash_add(g_string_list_table, temp_string, &dummy_val) > 0) {
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
BOOL str_table_remove(const char* str)
{
	int i, j;
	int fd, string_len;
	char temp_string[256];
	char file_item[512];
	STR_HASH_ITER *iter;
	
	if (NULL == str) {
		return FALSE;
	}
	strncpy(temp_string, str, 255);
	temp_string[255] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}
	pthread_rwlock_wrlock(&g_refresh_lock);
	/* check first if the string is in hash table */
	if (NULL == str_hash_query(g_string_list_table, temp_string)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	if (1 != str_hash_remove(g_string_list_table, temp_string)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	fd = open(g_list_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	iter = str_hash_iter_init(g_string_list_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		str_hash_iter_get_value(iter, temp_string);
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
		file_item[string_len] = '\n';
		string_len ++;
		write(fd, file_item, string_len);
	}
	str_hash_iter_free(iter);
	close(fd);
	pthread_rwlock_unlock(&g_refresh_lock);
	return TRUE;
}

/*
 *	string table's console talk
 *	@param
 *		argc			arguments number
 *		argv [in]		arguments value
 *		result [out]	buffer for retrieving result
 *		length			result buffer length
 */
void str_table_console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 string table help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the string table from list file\r\n"
						 "\t%s add <string>\r\n"
						 "\t    --add string to the string table\r\n"
						 "\t%s remove <string>\r\n"
						 "\t    --remove string from the string table\r\n"
						 "\t%s search <string>\r\n"
						 "\t    --search string in the string table";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0],
				argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("reload", argv[1])) {
		switch(str_table_refresh()) {
		case STR_TABLE_REFRESH_OK:
			strncpy(result, "250 string table reload OK", length);
			return;
		case STR_TABLE_REFRESH_FILE_ERROR:
			strncpy(result, "550 string list file error", length);
			return;
		case STR_TABLE_REFRESH_HASH_FAIL:
			strncpy(result, "550 hash map error for string table", length);
			return;
		}
	}
	if (3 == argc && 0 == strcmp("add", argv[1])) {
		if (TRUE == str_table_add(argv[2])) {
			snprintf(result, length, "250 %s is added", argv[2]);
		} else {
			snprintf(result, length, "550 fail to add %s", argv[2]);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		if (TRUE == str_table_remove(argv[2])) {
			snprintf(result, length, "250 %s is removed", argv[2]);
		} else {
			snprintf(result, length, "550 fail to remove %s", argv[2]);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("search", argv[1])) {
		if (TRUE == str_table_query(argv[2])) {
			snprintf(result, length, "250 %s is found in the string table",
					argv[2]);
		} else {
			snprintf(result, length, "550 cannot find %s in the string table",
					argv[2]);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

void str_table_echo(const char *format, ...)
{
	char msg[256];
	va_list ap;

	memset(msg, 0, sizeof(msg));
	va_start(ap, format);
	vsprintf(msg, format, ap);
	va_end(ap);
	printf("[%s]: %s\n", g_module_name, msg);

}
