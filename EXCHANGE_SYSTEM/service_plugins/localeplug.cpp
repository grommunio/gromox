#include <cstdio>
#include <gromox/localemap.hpp>
#include <gromox/svc_common.h>
#include "common_types.h"

DECLARE_API;

BOOL SVC_LibMain(int reason, void **apidata)
{
	if (reason == PLUGIN_FREE)
		return TRUE;
	if (reason != PLUGIN_INIT)
		return false;
	LINK_API(apidata);
	using namespace gromox;
	localemap_init();
	if (!register_service("verify_cpid", reinterpret_cast<void *>(verify_cpid)) ||
	    !register_service("cpid_to_charset", reinterpret_cast<void *>(cpid_to_cset)) ||
	    !register_service("charset_to_cpid", reinterpret_cast<void *>(cset_to_cpid)) ||
	    !register_service("ltag_to_lcid", reinterpret_cast<void *>(ltag_to_lcid)) ||
	    !register_service("lcid_to_ltag", reinterpret_cast<void *>(lcid_to_ltag))) {
		fprintf(stderr, "[localemap]: failed to register services\n");
		return FALSE;
	}
	return TRUE;
}
