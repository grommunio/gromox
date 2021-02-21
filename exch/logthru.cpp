// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#define DECLARE_API_STATIC
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <gromox/config_file.hpp>
#include <gromox/svc_common.h>
static unsigned int g_max_loglevel = 4;
static void xlog_info(int level, const char *fmt, ...)
{
	if (level > g_max_loglevel)
		return;
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	putc('\n', stdout);
	va_end(args);
}

static BOOL svc_logger(int reason, void **data)
{
	if (reason == PLUGIN_FREE)
		return TRUE;
	else if (reason != PLUGIN_INIT)
		return false;
	LINK_API(data);
	auto cfg = config_file_initd("log_plugin.cfg", get_config_path());
	auto sv = config_file_get_value(cfg, "log_level");
	g_max_loglevel = sv != nullptr ? strtoul(sv, nullptr, 0) : 4;
	return register_service("log_info", xlog_info);
}
SVC_ENTRY(svc_logger);
