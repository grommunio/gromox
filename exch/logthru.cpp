// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#define DECLARE_API_STATIC
#include <cstdarg>
#include <cstdio>
#include <gromox/svc_common.h>
static void xlog_info(int level, const char *fmt, ...)
{
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
	return register_service("log_info", xlog_info);
}
SVC_ENTRY(svc_logger);
