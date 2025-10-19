// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <libHX/option.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/textmaps.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace set_locale {

static constexpr HXoption g_options_table[] = {
	{{}, 'T', HXTYPE_NONE, {}, {}, {}, 0, "Run EXRPC performance test"},
	{{}, 'l', HXTYPE_STRING, {}, {}, {}, 0, "XPG/POSIX-style locale code (e.g. ja_JP)", "CODE"},
	{nullptr, 'v', HXTYPE_NONE, &global::g_verbose_mode, {}, {}, 0, "Verbose mode"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int set_names(const char *lang, size_t &);

static void do_perftest(const char *lang)
{
	size_t fcount = 0;
	auto t_start = tp_now();
	while (true) {
		if (set_names(lang, fcount) != 0)
			/* ignore */;
		auto now = tp_now();
		auto delta = now - t_start;
		if (delta < std::chrono::seconds(1))
			continue;
		auto d = std::chrono::duration_cast<std::chrono::microseconds>(delta) / fcount;
		fprintf(stderr, "\r\e[2K%llu µs\e[K", static_cast<unsigned long long>(d.count()));
		t_start = now;
		fcount = 0;
	}
}

int main(int argc, char **argv)
{
	const char *g_language = nullptr;
	bool run_perftest = false;
	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i) {
		if (result.desc[i]->sh == 'l')
			g_language = result.oarg[i];
		else if (result.desc[i]->sh == 'T')
			run_perftest = true;
	}
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

	if (run_perftest) {
		do_perftest(lang);
		return EXIT_SUCCESS;
	}
	size_t ignored = 0;
	return set_names(lang, ignored) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int set_names(const char *lang, size_t &fcount)
{
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
		++fcount;
	}
	return EXIT_SUCCESS;
}

}
