// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/svc_common.h>
#include "str_filter.h"
#include <gromox/config_file.hpp>
#include <gromox/util.hpp>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <sys/types.h>

using namespace std::string_literals;

DECLARE_API();

static BOOL svc_str_filter(int reason, void **ppdata)
{
	char file_name[256], list_path[256];
	char config_path[256], temp_buff[128], *psearch;
	int audit_max, audit_interval, audit_times;
	int temp_list_size, growing_num;
	BOOL case_sensitive;
	
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		gx_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		if (FALSE == register_talk(str_filter_console_talk)) {
			printf("[%s]: failed to register console talk\n", file_name);
			return FALSE;
		}
		snprintf(config_path, GX_ARRAY_SIZE(config_path), "%s.cfg", file_name);
		auto pfile = config_file_initd(config_path, get_config_path());
		if (NULL == pfile) {
			printf("[%s]: config_file_initd %s: %s\n",
			       file_name, config_path, strerror(errno));
			return FALSE;
		}
		auto str_value = config_file_get_value(pfile, "IS_CASE_SENSITIVE");
		if (NULL == str_value) {
			case_sensitive = FALSE;
			config_file_set_value(pfile, "IS_CASE_SENSITIVE", "FALSE");
			printf("[%s]: case-insensitive\n", file_name);
		} else {
			if (0 == strcasecmp(str_value, "FALSE")) {
				case_sensitive=FALSE;
				printf("[%s]: case-insensitive\n", file_name);
			} else if (0 == strcasecmp(str_value, "TRUE")) {
				case_sensitive=TRUE;
				printf("[%s]: case-sensitive\n", file_name);
			} else {
				case_sensitive = FALSE;
				config_file_set_value(pfile, "IS_CASE_SENSITIVE", "FALSE");
				printf("[%s]: case-insensitive\n", file_name);
			}
		}				
		str_value = config_file_get_value(pfile, "AUDIT_MAX_NUM");
		if (NULL == str_value) {
			audit_max = 0;
			config_file_set_value(pfile, "AUDIT_MAX_NUM", "0");
		} else {
			audit_max = atoi(str_value);
			if (audit_max < 0) {
				audit_max = 0;
				config_file_set_value(pfile, "AUDIT_MAX_NUM", "0");
			}
		}
		printf("[%s]: audit capacity is %d\n", file_name, audit_max);	
		str_value = config_file_get_value(pfile, "AUDIT_INTERVAL");
		if (NULL == str_value) {
			audit_interval = 60;
			config_file_set_value(pfile, "AUDIT_INTERVAL", "1minute");
		} else {
			audit_interval = atoitvl(str_value);
			if (audit_interval <= 0) {
				audit_interval = 60;
				config_file_set_value(pfile, "AUDIT_INTERVAL", "1minute");
			}
		}
		itvltoa(audit_interval, temp_buff);
		printf("[%s]: audit interval is %s\n", file_name, temp_buff);
		str_value = config_file_get_value(pfile, "AUDIT_TIMES");
		if (NULL == str_value) {
			audit_times = 10;
			config_file_set_value(pfile, "AUDIT_TIMES", "10");
		} else {
			audit_times = atoi(str_value);
			if (audit_times <= 0) {
				audit_times = 10;
				config_file_set_value(pfile, "AUDIT_TIMES", "10");
			}
		}
		printf("[%s]: audit times is %d\n", file_name, audit_times);
		str_value = config_file_get_value(pfile, "TEMP_LIST_SIZE");
		if (NULL == str_value) {
			temp_list_size = 0;
			config_file_set_value(pfile, "TEMP_LIST_SIZE", "0");
		} else {
			temp_list_size = atoi(str_value);
			if (temp_list_size < 0) {
				temp_list_size = 0;
				config_file_set_value(pfile, "TEMP_LIST_SIZE", "0");
			}
		}
		printf("[%s]: temporary list capacity is %d\n", file_name,
			temp_list_size);
		str_value = config_file_get_value(pfile, "GREY_GROWING_NUM");
		if (NULL == str_value) {
			growing_num = 0;
			config_file_set_value(pfile, "GREY_GROWING_NUM", "0");
		} else {
			growing_num = atoi(str_value);
			if (growing_num < 0) {
				growing_num = 0;
				config_file_set_value(pfile, "GREY_GROWING_NUM", "0");
			}
		}
		printf("[%s]: grey list growing number is %d\n", file_name,
			growing_num);
		str_value = config_file_get_value(pfile, "JUDGE_SERVICE_NAME");
		std::string judge_name = str_value != nullptr ? str_value : file_name + "_judge"s;
		str_value = config_file_get_value(pfile, "ADD_SERVICE_NAME");
		std::string add_name = str_value != nullptr ? str_value : file_name + "_add"s;
		str_value = config_file_get_value(pfile, "QUERY_SERVICE_NAME");
		std::string query_name = str_value != nullptr ? str_value : file_name + "_query"s;
		snprintf(list_path, GX_ARRAY_SIZE(list_path), "%s.txt", file_name);
		str_filter_init(file_name, case_sensitive, audit_max,
		   audit_interval, audit_times, temp_list_size, list_path, growing_num);
		if (0 != str_filter_run()) {
			printf("[%s]: failed to run the module\n", file_name);
			return FALSE;
		}
		if (judge_name.size() > 0 && !register_service(judge_name.c_str(), str_filter_judge)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       file_name, judge_name.c_str());
			return FALSE;
		}
		if (query_name.size() > 0 && !register_service(query_name.c_str(), str_filter_query)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       file_name, query_name.c_str());
			return FALSE;
		}
		if (add_name.size() > 0 && !register_service(add_name.c_str(), str_filter_add_string_into_temp_list)) {
			printf("[%s]: failed to register \"%s\" service\n",
			       file_name, add_name.c_str());
			return FALSE;
		}
		return TRUE;
	}
	case PLUGIN_FREE:
		str_filter_stop();
		str_filter_free();
		return TRUE;
	}
	return TRUE;
}
SVC_ENTRY(svc_str_filter);
