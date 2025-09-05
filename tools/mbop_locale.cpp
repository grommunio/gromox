// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/textmaps.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace set_locale {

static const char *g_language;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'l', HXTYPE_STRING, &g_language, {}, {}, 0, "XPG/POSIX-style locale code (e.g. ja_JP)", "CODE"},
	{nullptr, 'v', HXTYPE_NONE, &global::g_verbose_mode, {}, {}, 0, "Verbose mode"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	auto cl_0a = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	if (g_language == nullptr) {
		mbop_fprintf(stderr, "You need to specify the -l option\n");
		return EXIT_PARAM;
	}
	textmaps_init();
	if (!mysql_adaptor_set_user_lang(g_dstuser.c_str(), g_language)) {
		mbop_fprintf(stderr, "Update of UI language rejected\n");
		return EXIT_FAILURE;
	}

	auto lang = folder_namedb_resolve(g_language);
	if (lang == nullptr) {
		fprintf(stderr, "No folder name translations for locale \"%s\" available.\n", g_language);
		return EXIT_SUCCESS;
	}
	unsigned int start_gcv = 1;
	unsigned int end_gcv   = g_public_folder ? PUBLIC_FID_UNASSIGNED_START : PRIVATE_FID_UNASSIGNED_START;
	for (unsigned int gcv = start_gcv; gcv < end_gcv; ++gcv) {
		auto new_name = folder_namedb_get(lang, gcv);
		if (new_name == nullptr)
			continue;
		auto folder_id = rop_util_make_eid_ex(1, gcv);
		if (global::g_verbose_mode) {
			static constexpr uint32_t tags[] = {PR_DISPLAY_NAME};
			static constexpr PROPTAG_ARRAY taghdr = {std::size(tags), deconst(tags)};
			TPROPVAL_ARRAY props{};
			if (!exmdb_client->get_folder_properties(g_storedir,
			    CP_ACP, folder_id, &taghdr, &props)) {
				mbop_fprintf(stderr, "get_folder_props failed\n");
				return EXIT_FAILURE;
			}
			auto orig_name = props.get<const char>(PR_DISPLAY_NAME);
			mbop_fprintf(stdout, "[0x%02x] %s -> %s\n", gcv, znul(orig_name), new_name);
		}
		TAGGED_PROPVAL tp = {PR_DISPLAY_NAME, deconst(new_name)};
		const TPROPVAL_ARRAY new_props = {1, &tp};
		PROBLEM_ARRAY probs{};
		if (!exmdb_client->set_folder_properties(g_storedir, CP_ACP,
		    folder_id, &new_props, &probs)) {
			mbop_fprintf(stderr, "set_folder_props failed\n");
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

}
