// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <libHX/string.h>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/fileio.h>
#include <gromox/hook_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

using namespace gromox;

DECLARE_HOOK_API();

static BOOL hook_exmdb_local(int reason, void **ppdata)
{
	int conn_num;
	char charset[32], org_name[256], separator[16], temp_buff[45], cache_path[256];
	int cache_interval;
	int retrying_times;
	int alarm_interval;
	int times, interval;
	int response_capacity;
	int response_interval;
	 
	/* path contains the config files directory */
    switch (reason) {
	case PLUGIN_INIT: {
		LINK_HOOK_API(ppdata);
		textmaps_init();
		auto pfile = config_file_initd("exmdb_local.cfg",
		             get_config_path(), nullptr);
		if (NULL == pfile) {
			mlog(LV_ERR, "exmdb_local: config_file_initd exmdb_local.cfg: %s",
				strerror(errno));
			return FALSE;
		}

		auto str_value = pfile->get_value("SEPARATOR_FOR_BOUNCE");
		gx_strlcpy(separator, str_value == nullptr ? " " : str_value, GX_ARRAY_SIZE(separator));

		sprintf(cache_path, "%s/cache", get_queue_path());
		
		str_value = pfile->get_value("X500_ORG_NAME");
		gx_strlcpy(org_name, str_value != nullptr ? str_value : "Gromox default", arsizeof(org_name));
		mlog(LV_INFO, "exmdb_local: x500 org name is \"%s\"", org_name);
		
		str_value = pfile->get_value("DEFAULT_CHARSET");
		gx_strlcpy(charset, str_value != nullptr ? str_value : "windows-1252", arsizeof(charset));
		mlog(LV_INFO, "exmdb_local: default charset is \"%s\"", charset);
		
		str_value = pfile->get_value("EXMDB_CONNECTION_NUM");
		conn_num = str_value != nullptr ? strtol(str_value, nullptr, 0) : 5;
		if (conn_num < 2 || conn_num > 100)
			conn_num = 5;
		mlog(LV_INFO, "exmdb_local: exmdb connection number is %d", conn_num);
		
		str_value = pfile->get_value("CACHE_SCAN_INTERVAL");
		if (NULL == str_value) {
			cache_interval = 180;
		} else {
			cache_interval = HX_strtoull_sec(str_value, nullptr);
			if (cache_interval <= 0)
				cache_interval = 180;
		}
		HX_unit_seconds(temp_buff, arsizeof(temp_buff), cache_interval, 0);
		mlog(LV_INFO, "exmdb_local: cache scanning interval is %s", temp_buff);

		str_value = pfile->get_value("RETRYING_TIMES");
		retrying_times = str_value != nullptr ? strtol(str_value, nullptr, 0) : 30;
		if (retrying_times <= 0)
			retrying_times = 30;
		mlog(LV_INFO, "exmdb_local: retrying times on temporary failure is %d",
			retrying_times);
		
		str_value = pfile->get_value("FAILURE_TIMES_FOR_ALARM");
		times = str_value != nullptr ? strtol(str_value, nullptr, 0) : 10;
		if (times <= 0)
			times = 10;
		mlog(LV_INFO, "exmdb_local: failure count for alarm is %d", times);

		str_value = pfile->get_value("INTERVAL_FOR_FAILURE_STATISTIC");
		if (NULL == str_value) {
			interval = 3600;
		} else {
			interval = HX_strtoull_sec(str_value, nullptr);
			if (interval <= 0)
				interval = 3600;
		}
		HX_unit_seconds(temp_buff, arsizeof(temp_buff), interval, 0);
		mlog(LV_INFO, "exmdb_local: interval for failure alarm is %s", temp_buff);

		str_value = pfile->get_value("ALARM_INTERVAL");
		if (NULL == str_value) {
			alarm_interval = 1800;
		} else {
			alarm_interval = HX_strtoull_sec(str_value, nullptr);
			if (alarm_interval <= 0)
				alarm_interval = 1800;
		}
		HX_unit_seconds(temp_buff, arsizeof(temp_buff), alarm_interval, 0);
		mlog(LV_INFO, "exmdb_local: alarms interval is %s", temp_buff);

		str_value = pfile->get_value("RESPONSE_AUDIT_CAPACITY");
		response_capacity = str_value != nullptr ? strtol(str_value, nullptr, 0) : 1000;
		if (response_capacity < 0)
			response_capacity = 1000;
		mlog(LV_INFO, "exmdb_local: auto response audit capacity is %d",
			response_capacity);

		str_value = pfile->get_value("RESPONSE_INTERVAL");
		if (NULL == str_value) {
			response_interval = 180;
		} else {
			response_interval = HX_strtoull_sec(str_value, nullptr);
			if (response_interval <= 0)
				response_interval = 180;
		}
		HX_unit_seconds(temp_buff, arsizeof(temp_buff), response_interval, 0);
		mlog(LV_INFO, "exmdb_local: auto response interval is %s", temp_buff);

		net_failure_init(times, interval, alarm_interval);
		bounce_audit_init(response_capacity, response_interval);
		cache_queue_init(cache_path, cache_interval, retrying_times);
		exmdb_client_init(conn_num, 0);
		exmdb_local_init(org_name, charset);
		
		if (0 != net_failure_run()) {
			mlog(LV_ERR, "exmdb_local: failed to start net_failure component");
			return FALSE;
		}
		if (bounce_gen_init(";", get_data_path(), "local_bounce") != 0) {
			mlog(LV_ERR, "exmdb_local: failed to start bounce producer");
			return FALSE;
		}
		if (0 != cache_queue_run()) {
			mlog(LV_ERR, "exmdb_local: failed to start cache queue");
			return FALSE;
		}
		if (exmdb_client_run(get_config_path(), EXMDB_CLIENT_ASYNC_CONNECT) != 0) {
			mlog(LV_ERR, "exmdb_local: failed to start exmdb_client");
			return FALSE;
		}
		if (0 != exmdb_local_run()) {
			mlog(LV_ERR, "exmdb_local: failed to start exmdb_local");
			return FALSE;
		}
		if (!register_local(exmdb_local_hook)) {
			mlog(LV_ERR, "exmdb_local: failed to register the hook function");
            return FALSE;
        }
        return TRUE;
	}
    case PLUGIN_FREE:
		exmdb_client_stop();
		cache_queue_stop();
		cache_queue_free();
		net_failure_free();
        return TRUE;
    }
	return TRUE;
}
HOOK_ENTRY(hook_exmdb_local);
