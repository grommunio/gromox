// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cstdio>
#include <cstdlib>
#include <string>
#include <gromox/config_file.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>

using namespace gromox;
static std::string g_log_filename;

static BOOL svc_logger(int reason, void **data)
{
	if (reason != PLUGIN_INIT && reason != PLUGIN_RELOAD)
		return TRUE;
	if (reason == PLUGIN_INIT)
		LINK_SVC_API(data);

	auto cfg = config_file_initd("log_plugin.cfg", get_config_path(), nullptr);
	auto sv = cfg->get_value("log_level");
	auto level = sv != nullptr ? strtoul(sv, nullptr, 0) : 4;
	sv = cfg->get_value("log_file_name");
	if (reason == PLUGIN_RELOAD) {
		if (cfg == nullptr)
			return TRUE;
		if (sv != nullptr && *sv != '\0')
			mlog_init(sv, level);
		return TRUE;
	}
	if (sv != nullptr && *sv != '\0') {
		mlog_init(sv, level);
	}
	return register_service("log_info", mlog);
}
SVC_ENTRY(svc_logger);
