// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/hook_common.h>
#include <gromox/mail_func.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

/* private global variable */
static int g_audit_num;
static int g_audit_interval;
static std::mutex g_audit_mutex_lock;
static std::unordered_map<std::string, time_t> g_audit_hash;

void bounce_audit_init(int audit_num, int audit_interval) 
{
    g_audit_num             = audit_num;
    g_audit_interval        = audit_interval;
}

static size_t bounce_audit_collect_entry(time_t current_time)
{
#if __cplusplus >= 202001L
	return std::erase_if(g_audit_hash, [=](const auto &e) {
		return current_time - e.second >= g_audit_interval;
	});
#else
	size_t collected = 0;
	for (auto iter = g_audit_hash.begin(); iter != g_audit_hash.end(); ) {
		if (current_time - iter->second >= g_audit_interval) {
			iter = g_audit_hash.erase(iter);
			++collected;
		} else {
			++iter;
		}
	}
	return collected;
#endif
}

BOOL bounce_audit_check(const char *audit_string) try
{
	if (g_audit_num <= 0) /* counting deactivated */
		return TRUE;
	std::string temp_string = audit_string;
	HX_strlower(temp_string.data());
	std::unique_lock am_hold(g_audit_mutex_lock);
	auto current_time = time(nullptr);
	if (g_audit_hash.size() >= static_cast<size_t>(g_audit_num))
		bounce_audit_collect_entry(current_time);
	auto xp = g_audit_hash.emplace(temp_string, current_time);
	if (!xp.second) {
		auto result = current_time - xp.first->second > g_audit_interval;
		xp.first->second = current_time;
		return result ? TRUE : false;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1563: ENOMEM\n");
	return TRUE;
}
