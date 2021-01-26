// SPDX-License-Identifier: AGPL-3.0-or-later
// This file is part of Gromox.
#define DECLARE_API_STATIC
#include <cstdio>
#include <gromox/oxoabkt.hpp>
#include <gromox/svc_common.h>
BOOL SVC_LibMain(int reason, void **apidata)
{
	if (reason == PLUGIN_FREE)
		return TRUE;
	if (reason != PLUGIN_INIT)
		return false;
	LINK_API(apidata);
	if (!register_service("abkt_tobinary", reinterpret_cast<void *>(gromox::abkt_tobinary)) ||
	    !register_service("abkt_tojson", reinterpret_cast<void *>(gromox::abkt_tojson))) {
		fprintf(stderr, "[abktxfrm]: failed to register services\n");
		return false;
	}
	return TRUE;
}
