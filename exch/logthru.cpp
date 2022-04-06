// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <shared_mutex>
#include <string>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/svc_common.h>

using namespace gromox;

static unsigned int g_max_loglevel = LV_WARN;
static std::string g_log_filename;
static std::shared_mutex g_log_mutex;
static std::unique_ptr<FILE, file_deleter> g_logfp;

static void xlog_info(unsigned int level, const char *fmt, ...)
{
	if (level > g_max_loglevel)
		return;
	va_list args;
	va_start(args, fmt);
	if (g_log_filename.empty()) {
		vprintf(fmt, args);
		fputc('\n', stdout);
		va_end(args);
		return;
	}
	char buf[64];
	buf[0] = '<';
	buf[1] = '0' + level;
	buf[2] = '>';
	auto now = time(nullptr);
	struct tm tmbuf;
	strftime(buf + 3, GX_ARRAY_SIZE(buf) - 3, "%FT%T ", localtime_r(&now, &tmbuf));
	std::shared_lock hold(g_log_mutex);
	fputs(buf, g_logfp.get());
	vfprintf(g_logfp.get(), fmt, args);
	fputc('\n', g_logfp.get());
	va_end(args);
}

static void xlog_open()
{
	if (g_log_filename.empty()) {
		setvbuf(stdout, nullptr, _IOLBF, 0);
		return;
	}
	std::lock_guard hold(g_log_mutex);
	g_logfp.reset(fopen(g_log_filename.c_str(), "a"));
	if (g_logfp == nullptr)
		fprintf(stderr, "Could not open %s for writing: %s. Using stdout.\n",
		        g_log_filename.c_str(), strerror(errno));
	else
		setvbuf(g_logfp.get(), nullptr, _IOLBF, 0);
}

static BOOL svc_logger(int reason, void **data)
{
	if (reason == PLUGIN_RELOAD) {
		xlog_open();
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(data);
	auto cfg = config_file_initd("log_plugin.cfg", get_config_path(), nullptr);
	auto sv = cfg->get_value("log_level");
	g_max_loglevel = sv != nullptr ? strtoul(sv, nullptr, 0) : 4;
	sv = cfg->get_value("log_file_name");
	if (sv != nullptr && *sv != '\0') {
		g_log_filename = sv;
		xlog_open();
	}
	return register_service("log_info", xlog_info);
}
SVC_ENTRY(svc_logger);
