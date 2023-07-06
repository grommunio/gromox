// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <libHX/string.h>
#include <gromox/clock.hpp>
#include <gromox/defs.h>
#include <gromox/list_file.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "user_filter.hpp"

using namespace gromox;

DECLARE_SVC_API(extern);

namespace {

struct GREY_LIST_ENTRY {
	int current_times = 0, allowed_times = 0;
	time_duration interval{};
	time_point last_access{};
};

struct LIST_ITEM {
	char    string[256];
	int     allow_times;
	char    interval[32];
};

}

static std::unordered_map<std::string, GREY_LIST_ENTRY> g_grey_table;
static std::shared_mutex g_refresh_lock;
static char g_list_path[256]; 
static BOOL g_case_sensitive;
static int g_growing_num;
static int g_hash_cap;

void grey_list_init(BOOL case_sensitive, const char *path, int growing_num)
{
	g_case_sensitive = case_sensitive;
	gx_strlcpy(g_list_path, path, std::size(g_list_path));
	g_growing_num = growing_num;
	g_hash_cap = 0;
}

void grey_list_free()
{
    g_list_path[0] ='\0';
	g_growing_num = 0;
	g_hash_cap = 0;
}

int grey_list_run()
{

    if (0 != grey_list_refresh()) {
        return -1;
	}
    return 0;

}

/*  query the grey list for the specified string. 
 *  @param  
 *		str [in]				string
 *		b_count					whether to count the access times
 *  @return
 *      GREY_LIST_ALLOW			allow connection
 *      GREY_LIST_NOT_FOUND		allow connection not in grey list
 *      GREY_LIST_DENY		    deny it
 */
int grey_list_query(const char *str, BOOL b_count)
{
	char temp_string [256];

    if (NULL == str) {
        return GREY_LIST_NOT_FOUND;
    }
    if (0 == g_growing_num) { /* no grey list */
        return GREY_LIST_NOT_FOUND;
    }
	strncpy(temp_string, str, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	if (!g_case_sensitive)
		HX_strlower(temp_string);

	std::shared_lock rd_hold(g_refresh_lock);
	auto iter = g_grey_table.find(temp_string);
	if (iter == g_grey_table.end())
		return GREY_LIST_NOT_FOUND; /* not in grey list */
	auto pentry = &iter->second;
    if (0 == pentry->allowed_times) {
        return GREY_LIST_DENY; /* deny it */
    }
	if (pentry->interval == time_duration{})
		return GREY_LIST_ALLOW;
	auto current_time = tp_now();
	if (current_time - pentry->last_access > pentry->interval) {
		if (!b_count)
			return GREY_LIST_ALLOW;
		pentry->last_access = current_time;
		pentry->current_times = 0;
	}
	if (b_count)
		pentry->current_times ++;
	return pentry->current_times <= pentry->allowed_times ?
	       GREY_LIST_ALLOW : GREY_LIST_DENY;
}

/*
 *	@return
 *		GREY_REFRESH_OK				OK
 *		GREY_REFRESH_HASH_FAIL		hash fail
 *		GREY_REFRESH_FILE_ERROR		fail to open list file
 */
int grey_list_refresh()
{
	if (0 == g_growing_num) {
		return GREY_REFRESH_OK;
	}
	auto plist_file = list_file_initd(g_list_path, get_state_path(), "%s:256%d%s:32");
	if (NULL == plist_file) {
		str_filter_echo("Failed to read graylist from %s: %s",
			g_list_path, strerror(errno));
        return GREY_REFRESH_FILE_ERROR;
	}
	auto pitem = static_cast<LIST_ITEM *>(plist_file->get_list());
	auto list_len = plist_file->get_size();
	decltype(g_grey_table) phash;

	auto current_time = tp_now();
	for (decltype(list_len) i = 0; i < list_len; ++i, ++pitem) try {
		if (!g_case_sensitive)
			HX_strlower(pitem->string);
		phash.emplace(pitem->string, GREY_LIST_ENTRY{0, pitem->allow_times,
			std::chrono::seconds(HX_strtoull_sec(pitem->interval, nullptr)), current_time});
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1564: ENOMEM");
		return false;
	}

	std::lock_guard wr_hold(g_refresh_lock);
	g_grey_table = std::move(phash);
    return GREY_REFRESH_OK;
}
