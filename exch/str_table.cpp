// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#define DECLARE_SVC_API_STATIC
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <shared_mutex>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <utility>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/str_hash.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include <gromox/list_file.hpp>
#include <cstdarg>
#include <unistd.h>
#define DEF_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

using namespace std::string_literals;
using namespace gromox;

enum{
	STR_TABLE_REFRESH_OK,
	STR_TABLE_REFRESH_FILE_ERROR,
	STR_TABLE_REFRESH_HASH_FAIL
};

static void str_table_echo(const char *, ...);
static int str_table_refresh();

static std::unique_ptr<STR_HASH_TABLE> g_string_list_table;
static std::shared_mutex g_refresh_lock;
static char g_list_path[256];
static BOOL g_case_sensitive;
static char g_module_name[256];
static int g_growing_num;
static int g_hash_cap;

static void str_table_init(const char *module_name, BOOL case_sensitive,
	const char *path, int growing_num)
{
	gx_strlcpy(g_module_name, module_name, GX_ARRAY_SIZE(g_module_name));
	g_case_sensitive = case_sensitive;
	gx_strlcpy(g_list_path, path, GX_ARRAY_SIZE(g_list_path));
	g_growing_num = growing_num;
	g_hash_cap = 0;
}

static void str_table_free()
{
	g_list_path[0] = '\0';
	g_growing_num = 0;
	g_hash_cap = 0;
}

static int str_table_run()
{
    if (STR_TABLE_REFRESH_OK != str_table_refresh()) {
        return -1;
    }
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
	std::shared_lock rd_hold(g_refresh_lock);
	return g_string_list_table->query1(temp_string) != nullptr ? TRUE : false;
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
	auto phash = STR_HASH_TABLE::create(hash_cap, sizeof(int), nullptr);
	if (NULL == phash) {
		str_table_echo("Failed to allocate hash map");
		return STR_TABLE_REFRESH_HASH_FAIL;
	}
	for (decltype(list_len) i = 0 ; i < list_len; ++i) {
		if (FALSE == g_case_sensitive) {
			HX_strlower(pitem[i].s);
		}
		phash->add(pitem[i].s, &i);
    }
	
	std::lock_guard wr_hold(g_refresh_lock);
	g_string_list_table = std::move(phash);
	g_hash_cap = hash_cap;
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

	std::lock_guard wr_hold(g_refresh_lock);
	/* check first if the string is already in the table */
	if (g_string_list_table->query1(temp_string) != nullptr)
		return TRUE;
	fd = open(g_list_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		return FALSE;
	}
	if (string_len != write(fd, file_item, string_len)) {
		close(fd);
		return FALSE;
	}
	close(fd);
	if (g_string_list_table->add(temp_string, &dummy_val) > 0)
		return TRUE;
	hash_cap = g_hash_cap + g_growing_num;
	auto phash = STR_HASH_TABLE::create(hash_cap, sizeof(int), nullptr);
	if (NULL == phash) {
		return FALSE;
	}
	auto iter = g_string_list_table->make_iter();
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		str_hash_iter_get_value(iter, file_item);
		phash->add(file_item, &dummy_val);
	}
	str_hash_iter_free(iter);
	g_string_list_table = std::move(phash);
	g_hash_cap = hash_cap;
	return g_string_list_table->add(temp_string, &dummy_val) > 0 ? TRUE : false;
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
	
	if (NULL == str) {
		return FALSE;
	}
	strncpy(temp_string, str, 255);
	temp_string[255] = '\0';
	if (FALSE == g_case_sensitive) {
		HX_strlower(temp_string);
	}

	std::lock_guard wr_hold(g_refresh_lock);
	/* check first if the string is in hash table */
	if (g_string_list_table->query1(temp_string) == nullptr)
		return TRUE;
	if (g_string_list_table->remove(temp_string) != 1)
		return FALSE;
	fd = open(g_list_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	auto iter = g_string_list_table->make_iter();
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
	return TRUE;
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
	BOOL case_sensitive;
	int growing_num;

	switch (reason) {
	case PLUGIN_INIT: {
		LINK_SVC_API(ppdata);
		std::string plugname = get_plugin_name();
		auto pos = plugname.find('.');
		if (pos != plugname.npos)
			plugname.erase(pos);
		auto cfg_path = plugname + ".cfg"s;
		auto pfile = config_file_initd(cfg_path.c_str(), get_config_path());
		if (pfile == nullptr) {
			printf("[%s]: config_file_initd %s: %s\n", plugname.c_str(),
			       cfg_path.c_str(), strerror(errno));
			return false;
		}
		auto str_value = pfile->get_value("QUERY_SERVICE_NAME");
		std::string query_name = str_value != nullptr ? str_value : plugname + "_query"s;
		str_value = pfile->get_value("ADD_SERVICE_NAME");
		std::string add_name = str_value != nullptr ? str_value : plugname + "_add"s;
		str_value = pfile->get_value("REMOVE_SERVICE_NAME");
		std::string remove_name = str_value != nullptr ? str_value : plugname + "_remove"s;
		str_value = pfile->get_value("GROWING_NUM");
		growing_num = str_value != nullptr ? strtol(str_value, nullptr, 0) : 100;
		if (growing_num <= 0)
			growing_num = 100;
		printf("[%s]: table growing number is %d\n", plugname.c_str(), growing_num);
		str_value = pfile->get_value("IS_CASE_SENSITIVE");
		if (str_value == nullptr) {
			case_sensitive = FALSE;
			printf("[%s]: case-insensitive\n", plugname.c_str());
		} else {
			if (strcasecmp(str_value, "FALSE") == 0) {
				case_sensitive = FALSE;
				printf("[%s]: case-insensitive\n", plugname.c_str());
			} else if (strcasecmp(str_value, "TRUE") == 0) {
				case_sensitive = TRUE;
				printf("[%s]: case-sensitive\n", plugname.c_str());
			} else {
				case_sensitive = FALSE;
				printf("[%s]: case-insensitive\n", plugname.c_str());
			}
		}
		cfg_path = plugname + ".txt"s;
		str_table_init(plugname.c_str(), case_sensitive, cfg_path.c_str(), growing_num);
		if (str_table_run() != 0) {
			printf("[%s]: failed to run the module\n", plugname.c_str());
			return FALSE;
		}
		if (query_name.size() > 0 && !register_service(query_name.c_str(), str_table_query)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       plugname.c_str(), query_name.c_str());
			return false;
		}
		if (add_name.size() > 0 && !register_service(add_name.c_str(), str_table_add)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       plugname.c_str(), add_name.c_str());
			return false;
		}
		if (remove_name.size() > 0 && !register_service(remove_name.c_str(), str_table_remove)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       plugname.c_str(), remove_name.c_str());
			return false;
		}
		return TRUE;
	}
	case PLUGIN_FREE:
		str_table_free();
		return TRUE;
	case PLUGIN_RELOAD:
		printf("[%s]: reloading %s\n", g_module_name, g_list_path);
		str_table_refresh();
		return TRUE;
	}
	return TRUE;
}
SVC_ENTRY(svc_str_table);
