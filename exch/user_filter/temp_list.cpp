// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <libHX/io.h>
#include <libHX/string.h>
#include <gromox/util.hpp>
#include "user_filter.hpp"

static size_t temp_list_collect_string_entry();

/* private global variable */
static std::unordered_map<std::string, time_t> g_string_hash;
static std::mutex g_string_mutex_lock;
static size_t g_size;
static BOOL				g_case_sensitive;

void temp_list_init(BOOL case_sensitive, size_t size)
{
	g_size = size;
	g_case_sensitive = case_sensitive;
}

int temp_list_run()
{
	if (g_size <= 0)
		g_string_hash.clear();
	return 0;
}

void temp_list_free() 
{
	g_size = 0;
}

/*
 *	add the specified string into the temp list
 *
 *	@param	
 *		str				string
 *		interval		interval in temp list
 *	@return	 
 *		TRUE
 *		FALSE
 */
BOOL temp_list_add_string(const char *str, int interval)
{
	time_t current_time;
	time_t when;
	char temp_string[256];

	if (str == nullptr)
		return FALSE;
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (!g_case_sensitive)
		HX_strlower(temp_string);
	if (grey_list_query(temp_string, false) != GREY_LIST_NOT_FOUND)
		return FALSE;

	std::lock_guard sm_hold(g_string_mutex_lock);
	time(&current_time);
	when = current_time + interval;
	try {
		if (g_string_hash.size() >= g_size) {
			auto pair = g_string_hash.emplace(temp_string, when);
			if (pair.second)
				return TRUE;
		}
	} catch (const std::bad_alloc &) {
	}
	if (0 == temp_list_collect_string_entry()) {
		return FALSE;
	}
	if (g_string_hash.size() >= g_size) try {
		auto pair = g_string_hash.emplace(temp_string, when);
		if (pair.second)
			return TRUE;
	} catch (const std::bad_alloc &) {
	}
	return false;
}

/*
 *	query if the specified string is in the 
 *	temp list
 *	@param	
 *		str		string
 *	@return	 
 *		TRUE	found in list
 *		FALSE	not found in list
 */
BOOL temp_list_query(const char *str) 
{
	time_t current_time;
	char temp_string[256];
	
	if (str == nullptr)
		return FALSE;
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (!g_case_sensitive)
		HX_strlower(temp_string);
	std::lock_guard sm_hold(g_string_mutex_lock);
	auto iter = g_string_hash.find(temp_string);
	if (iter == g_string_hash.end())
		return FALSE; /* not found */
	time(&current_time);
	if (current_time <= iter->second)
		return TRUE; /* found, in temp list */
	g_string_hash.erase(temp_string);
	return FALSE; /* is overdue */
}

/*
 *  collect the timeout entry in the string hash table 
 *
 *  @return
 *      the number of entries collected
 */
static size_t temp_list_collect_string_entry()
{
	time_t current_time;

	time(&current_time);
#if __cplusplus >= 202000L
	return std::erase_if(g_string_hash, [&](auto &&e) { return current_time > e.second; });
#else
	size_t collected_num = 0;
	for (auto iter = g_string_hash.begin(); iter != g_string_hash.end(); ) {
		if (current_time > iter->second) {
			iter = g_string_hash.erase(iter);
			collected_num++;
		} else {
			++iter;
		}
	}
	return collected_num;
#endif
}
