// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// Trivial mechanism to give translations for the special per-domain ABK
// groups to NSP clients, based on CPID (which is silly - the LCID should be
// used, but clients do not pass it when reading the GAB).
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <json/reader.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/fileio.h>
#include <gromox/svc_common.h>

using namespace gromox;
static Json::Value g_cpl_dict;

static BOOL cpl_get_string(uint32_t codepage, const char *tag, char *value, int len)
{
	const auto &dict = g_cpl_dict;
	auto l1key = std::to_string(codepage);
	if (dict.isMember(l1key)) {
		const auto &l2ref = dict[l1key][tag];
		if (l2ref == Json::Value::null)
			return false;
		gx_strlcpy(value, l2ref.asString().c_str(), len);
		return TRUE;
	}
	/* use first entry as default */
	auto it = dict.begin();
	if (it == dict.end())
		return false;
	const auto &l2ref = (*it)[tag];
	if (l2ref == Json::Value::null)
		return false;
	gx_strlcpy(value, l2ref.asString().c_str(), len);
	return TRUE;
}

static BOOL svc_codepage_lang(int reason, void **data)
{
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(data);
	std::string plugname = get_plugin_name();
	auto pos = plugname.find('.');
	if (pos != plugname.npos)
		plugname.erase(pos);
	auto filename = plugname + std::string(".json");
	auto filp = fopen_sd(filename.c_str(), get_data_path());
	if (filp == nullptr) {
		fprintf(stderr, "[codepage_lang]: fopen_sd %s: %s\n",
		       filename.c_str(), strerror(errno));
		return false;
	}
	size_t sl = 0;
	std::unique_ptr<char[], stdlib_delete> sd(HX_slurp_fd(fileno(filp.get()), &sl));
	if (sd == nullptr) {
		fprintf(stderr, "[codepage_lang]: slurp %s: %s\n",
		       filename.c_str(), strerror(errno));
		return false;
	}
	std::string sd2(sd.get(), sl);
	sd.reset();
	std::istringstream ss(sd2);
	if (!Json::parseFromStream(Json::CharReaderBuilder(), ss, &g_cpl_dict, nullptr)) {
		fprintf(stderr, "[codepage_lang]: invalid json in %s\n", filename.c_str());
		return false;
	}
	if (!register_service("get_lang", cpl_get_string)) {
		fprintf(stderr, "[codepage_lang]: failed to register \"get_lang\" service\n");
		return false;
	}
	return TRUE;
}
SVC_ENTRY(svc_codepage_lang);
