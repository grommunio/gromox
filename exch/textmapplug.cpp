// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cstdio>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>

static BOOL lang_to_charset_b(const char *lang, char *cset)
{
	if (lang == nullptr)
		return false;
	auto r = gromox::lang_to_charset(lang);
	if (r == nullptr)
		return false;
	gx_strlcpy(cset, r, 32);
	return TRUE;
}

static BOOL svc_textmaps(int reason, void **apidata)
{
#define E(s, f) register_service(s, f)
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(apidata);
	using namespace gromox;
	textmaps_init(get_data_path());
	if (!E("verify_cpid", verify_cpid) ||
	    !E("cpid_to_charset", cpid_to_cset) ||
	    !E("charset_to_cpid", cset_to_cpid) ||
	    !E("lang_to_charset", lang_to_charset_b)) {
		fprintf(stderr, "[textmaps]: failed to register services\n");
		return FALSE;
	}
	return TRUE;
#undef E
}
SVC_ENTRY(svc_textmaps);
