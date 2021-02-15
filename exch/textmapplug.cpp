// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#define DECLARE_API_STATIC
#include <cstdio>
#include <gromox/common_types.hpp>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>

static BOOL svc_textmaps(int reason, void **apidata)
{
#define E(s, f) register_service(s, reinterpret_cast<void *>(f))
	if (reason == PLUGIN_FREE)
		return TRUE;
	if (reason != PLUGIN_INIT)
		return false;
	LINK_API(apidata);
	using namespace gromox;
	textmaps_init(get_data_path());
	if (!E("verify_cpid", verify_cpid) ||
	    !E("cpid_to_charset", cpid_to_cset) ||
	    !E("charset_to_cpid", cset_to_cpid) ||
	    !E("ltag_to_lcid", ltag_to_lcid) ||
	    !E("lcid_to_ltag", lcid_to_ltag)) {
		fprintf(stderr, "[textmaps]: failed to register services\n");
		return FALSE;
	}
	return TRUE;
#undef E
}
SVC_ENTRY(svc_textmaps);
