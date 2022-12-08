// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  Audit filter module which is a sub module of the string filter.
 *  We check if in the specified interval a client comes from the same
 *  string appears too much and we will reject it as long as the specified
 *  period after its last connection. If the client try to connect again
 *  and again, it will be reject forever. If the string is in the white list,
 *  it will never pass through this module.
 *
 */
#include <cstdio>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <libHX/string.h>
#include <sys/time.h>
#include <gromox/util.hpp>
#include "user_filter.hpp"

using namespace gromox;

namespace {
struct STR_AUDIT {
    struct timeval  first_time_stamp;/* time stamp of first time of visit */
    struct timeval  last_time_stamp; /* time stamp of last time of visit  */
    int             times;
};
}

static std::unordered_map<std::string, STR_AUDIT> g_audit_hash;

static int g_audit_num;
static int g_audit_interval;         /*  connecting times  per interval */ 
static int g_max_within_interval;    /*  max times within the interval  */  
static std::mutex g_audit_mutex_lock;
static BOOL g_case_sensitive;

static size_t audit_filter_collect_entry(const struct timeval *);

/*
 *  initialize the audit filter
 *
 *  @param 
 *      audit_num   number of string to audit
 */

void audit_filter_init(BOOL case_sensitive, int audit_num, int audit_interval,
    int audit_times) 
{
	g_case_sensitive        = case_sensitive;
    g_audit_num             = audit_num;
    g_audit_interval        = audit_interval;
    g_max_within_interval   = audit_times;
}

void audit_filter_stop()
{
	g_audit_hash.clear();
}

/*
 *  query and audit string in audit hash map
 *  @param  
 *      str     string
 *  @return  
 *      TRUE	legal connection 
 *      FALSE   illegal connection
 */
BOOL audit_filter_judge(const char *str) 
{
    struct timeval current_time;

	if (g_audit_num <= 0 || str == nullptr)
		return TRUE;
	std::string temp_string;
	try {
		temp_string = str;
	} catch (const std::bad_alloc &) {
		return false;
	}
	if (!g_case_sensitive)
		HX_strlower(temp_string.data());
	std::lock_guard am_hold(g_audit_mutex_lock); 
	auto iter = g_audit_hash.find(temp_string);
    gettimeofday(&current_time, NULL);                  
	if (iter != g_audit_hash.end()) {
		auto paudit = &iter->second;
        if (paudit->times < g_max_within_interval) {
            if (CALCULATE_INTERVAL(current_time, paudit->first_time_stamp) >
				g_audit_interval) {
                paudit->times = 0;
                paudit->first_time_stamp = current_time;
            }
            paudit->times ++;
            paudit->last_time_stamp = current_time;
		} else if (CALCULATE_INTERVAL(current_time, paudit->last_time_stamp) > g_audit_interval) {
			paudit->times = 1;
			paudit->first_time_stamp = current_time;
			paudit->last_time_stamp = current_time;
		} else {
			paudit->times++;
			paudit->last_time_stamp = current_time;
			return FALSE;
        }
        return TRUE;
    }
	STR_AUDIT new_audit;
    new_audit.first_time_stamp  = current_time;
    new_audit.last_time_stamp   = current_time;
    new_audit.times = 1;
	try {
		if (g_audit_hash.size() < static_cast<size_t>(g_audit_num) &&
		    g_audit_hash.try_emplace(temp_string, new_audit).second)
			return TRUE;
	} catch (const std::bad_alloc &) {
	}
	if (0 == audit_filter_collect_entry(&current_time)) {
		mlog(LV_DEBUG, "str_filter: still cannot find one unit for auditing, giving up");
		return TRUE;
	}
	try {
		g_audit_hash.try_emplace(temp_string, new_audit);
	} catch (const std::bad_alloc &) {
	}
    return TRUE;
}

/*
 *  query string in hash map
 *  @param  
 *      str     string
 *  @return  
 *      TRUE    in hash map
 *      FALSE   not in hash map
 */
BOOL audit_filter_query(const char *str) 
{
	struct timeval current_time;

	if (g_audit_num <= 0 || str == nullptr)
		return FALSE;
	std::string temp_string;
	try {
		temp_string = str;
	} catch (const std::bad_alloc &) {
		return false;
	}
	if (!g_case_sensitive)
		HX_strlower(temp_string.data());
	std::lock_guard am_hold(g_audit_mutex_lock);
	gettimeofday(&current_time, NULL);
	auto iter = g_audit_hash.find(temp_string);
	if (iter == g_audit_hash.end())
		return FALSE;
	auto paudit = &iter->second;
	if (paudit->times < g_max_within_interval)
		return FALSE;
	return g_audit_interval <= CALCULATE_INTERVAL(current_time,
	       paudit->last_time_stamp) ? TRUE : false;
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
static size_t audit_filter_collect_entry(const struct timeval *current_time)
{
#if __cplusplus >= 202000L
	return std::erase_if(g_audit_hash, [=](const auto &it) {
		auto &sa = it.second;
		return CALCULATE_INTERVAL(*current_time, sa.last_time_stamp) >= g_audit_interval;
	});
#else
	size_t num_of_collect = 0;

	for (auto iter = g_audit_hash.begin(); iter != g_audit_hash.end(); ) {
		auto iter_audit = &iter->second;
        if (CALCULATE_INTERVAL(*current_time, 
            iter_audit->last_time_stamp) >= g_audit_interval) {
			iter = g_audit_hash.erase(iter);
            num_of_collect++;
		} else {
			++iter;
		}
    }
    return num_of_collect;
#endif
}
