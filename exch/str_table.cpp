// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#define DECLARE_API_STATIC
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/str_hash.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include <gromox/list_file.hpp>
#include <pthread.h>
#include <cstdarg>
#include <unistd.h>
#define DEF_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

using namespace std::string_literals;

enum{
	STR_TABLE_REFRESH_OK,
	STR_TABLE_REFRESH_FILE_ERROR,
	STR_TABLE_REFRESH_HASH_FAIL
};

static void str_table_echo(const char *, ...);
static int str_table_refresh();

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
static void str_table_init(const char *module_name, BOOL case_sensitive,
	const char *path, int growing_num)
{
	HX_strlcpy(g_module_name, module_name, GX_ARRAY_SIZE(g_module_name));
	g_case_sensitive = case_sensitive;
	HX_strlcpy(g_list_path, path, GX_ARRAY_SIZE(g_list_path));
	g_growing_num = growing_num;
	g_hash_cap = 0;
}

/*
 *	string table's destruct function
 */
static void str_table_free()
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
static int str_table_run()
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
static int str_table_stop()
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
static BOOL str_table_query(const char* str)
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
	
    /* initialize the list filter */
	struct srcitem { char s[256]; };
	auto plist_file = list_file_initd(g_list_path, std::string(get_state_path() + ":"s + get_config_path()).c_str(), "%s:256");
	if (NULL == plist_file) {
		str_table_echo("list_file_init %s: %s", g_list_path, strerror(errno));
		return STR_TABLE_REFRESH_FILE_ERROR;
	}
	auto pitem = static_cast<srcitem *>(plist_file->get_list());
	auto list_len = plist_file->get_size();
	auto hash_cap = list_len + g_growing_num;
	
    phash = str_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		str_table_echo("Failed to allocate hash map");
		return STR_TABLE_REFRESH_HASH_FAIL;
	}
	for (decltype(list_len) i = 0 ; i < list_len; ++i) {
		if (FALSE == g_case_sensitive) {
			HX_strlower(pitem[i].s);
		}
		str_hash_add(phash, pitem[i].s, &i);
    }
	
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
static BOOL str_table_add(const char* str)
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
static BOOL str_table_remove(const char* str)
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
static void str_table_console_talk(int argc, char **argv, char *result, int length)
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

static void str_table_echo(const char *format, ...)
{
	char msg[256];
	va_list ap;

	memset(msg, 0, sizeof(msg));
	va_start(ap, format);
	vsprintf(msg, format, ap);
	va_end(ap);
	printf("[%s]: %s\n", g_module_name, msg);

}

static BOOL svc_str_table(int reason, void **ppdata)
{
	char file_name[256], tmp_path[256], *psearch;
	BOOL case_sensitive;
	int growing_num;

	switch (reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		HX_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (psearch != nullptr)
			*psearch = '\0';
		if (!register_talk(str_table_console_talk)) {
			printf("[%s]: failed to register console talk\n", file_name);
			return false;
		}
		snprintf(tmp_path, GX_ARRAY_SIZE(tmp_path), "%s.cfg", file_name);
		auto pfile = config_file_initd(tmp_path, get_config_path());
		if (pfile == nullptr) {
			printf("[%s]: config_file_initd %s: %s\n", file_name,
			       tmp_path, strerror(errno));
			return false;
		}
		auto str_value = config_file_get_value(pfile, "QUERY_SERVICE_NAME");
		std::string query_name = str_value != nullptr ? str_value : file_name + "_query"s;
		str_value = config_file_get_value(pfile, "ADD_SERVICE_NAME");
		std::string add_name = str_value != nullptr ? str_value : file_name + "_add"s;
		str_value = config_file_get_value(pfile, "REMOVE_SERVICE_NAME");
		std::string remove_name = str_value != nullptr ? str_value : file_name + "_remove"s;
		str_value = config_file_get_value(pfile, "GROWING_NUM");
		if (str_value == nullptr) {
			growing_num = 100;
			config_file_set_value(pfile, "GROWING_NUM", "100");
		} else {
			growing_num = atoi(str_value);
			if (growing_num <= 0) {
				growing_num = 100;
				config_file_set_value(pfile, "GROWING_NUM", "100");
			}
		}
		printf("[%s]: table growing number is %d\n", file_name, growing_num);
		str_value = config_file_get_value(pfile, "IS_CASE_SENSITIVE");
		if (str_value == nullptr) {
			case_sensitive = FALSE;
			config_file_set_value(pfile, "IS_CASE_SENSITIVE", "FALSE");
			printf("[%s]: case-insensitive\n", file_name);
		} else {
			if (strcasecmp(str_value, "FALSE") == 0) {
				case_sensitive = FALSE;
				printf("[%s]: case-insensitive\n", file_name);
			} else if (strcasecmp(str_value, "TRUE") == 0) {
				case_sensitive = TRUE;
				printf("[%s]: case-sensitive\n", file_name);
			} else {
				case_sensitive = FALSE;
				config_file_set_value(pfile, "IS_CASE_SENSITIVE", "FALSE");
				printf("[%s]: case-insensitive\n", file_name);
			}
		}
		snprintf(tmp_path, GX_ARRAY_SIZE(tmp_path), "%s.txt", file_name);
		str_table_init(file_name, case_sensitive, tmp_path, growing_num);
		if (str_table_run() != 0) {
			printf("[%s]: failed to run the module\n", file_name);
			return FALSE;
		}
		if (query_name.size() > 0 && !register_service(query_name.c_str(), str_table_query)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       file_name, query_name.c_str());
			return false;
		}
		if (add_name.size() > 0 && !register_service(add_name.c_str(), str_table_add)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       file_name, add_name.c_str());
			return false;
		}
		if (remove_name.size() > 0 && !register_service(remove_name.c_str(), str_table_remove)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       file_name, remove_name.c_str());
			return false;
		}
		return TRUE;
	}
	case PLUGIN_FREE:
		str_table_stop();
		str_table_free();
		return TRUE;
	}
	return false;
}
SVC_ENTRY(svc_str_table);
