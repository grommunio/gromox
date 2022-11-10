// SPDX-License-Identifier: AGPL-3.0-or-later
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cstdio>
#include <gromox/oxoabkt.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
using namespace gromox;
static BOOL svc_abktplug(int reason, void **apidata)
{
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(apidata);
	if (!register_service("abkt_tobinary", gromox::abkt_tobinary) ||
	    !register_service("abkt_tojson", gromox::abkt_tojson)) {
		mlog(LV_ERR, "abktxfrm: failed to register services");
		return false;
	}
	return TRUE;
}
SVC_ENTRY(svc_abktplug);
