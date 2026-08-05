// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/mapitags.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace msgcopy {

struct flagdesc {
	proptag_t tag;
	const char *name;
	char opt;
};

/*
 * One record per setting, so that the proptag, the label and the option letter
 * cannot drift apart the way parallel arrays do.
 */
static constexpr flagdesc g_flags[] = {
	{PR_MESSAGE_COPY_FOR_SENT_AS, "sent-as", 'a'},
	{PR_MESSAGE_COPY_FOR_SEND_ON_BEHALF, "send-on-behalf", 'b'},
};

static constexpr HXoption g_set_options[] = {
	{{}, 'a', HXTYPE_STRING, {}, {}, {}, 0,
		"Retain a copy when sending as this mailbox", "BOOL"},
	{{}, 'b', HXTYPE_STRING, {}, {}, {}, 0,
		"Retain a copy when sending on behalf of this mailbox", "BOOL"},
	{nullptr, 'v', HXTYPE_NONE, &global::g_verbose_mode, {}, {}, 0, "Verbose mode"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr HXoption g_clear_options[] = {
	{{}, 'a', HXTYPE_NONE, {}, {}, {}, 0, "Clear only the sent-as setting"},
	{{}, 'b', HXTYPE_NONE, {}, {}, {}, 0, "Clear only the on-behalf setting"},
	{nullptr, 'v', HXTYPE_NONE, &global::g_verbose_mode, {}, {}, 0, "Verbose mode"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

/**
 * Unlike parse_bool, an unrecognized word is rejected rather than taken to mean
 * "true". Enabling this by way of a typo would silently start copying mail into
 * someone else's mailbox.
 */
static bool parse_strict_bool(const char *s, uint8_t *out)
{
	static constexpr const char *yes[] = {"1", "yes", "on", "true"};
	static constexpr const char *no[] = {"0", "no", "off", "false"};
	for (auto v : yes)
		if (strcasecmp(s, v) == 0) {
			*out = 1;
			return true;
		}
	for (auto v : no)
		if (strcasecmp(s, v) == 0) {
			*out = 0;
			return true;
		}
	return false;
}

static int show()
{
	proptag_t tags[std::size(g_flags)];
	for (size_t i = 0; i < std::size(g_flags); ++i)
		tags[i] = g_flags[i].tag;
	TPROPVAL_ARRAY props{};
	if (!exmdb_client->get_store_properties(g_storedir, CP_ACP,
	    tags, &props)) {
		mbop_fprintf(stderr, "get_store_prop RPC unsuccessful\n");
		return EXIT_FAILURE;
	}
	for (const auto &f : g_flags) {
		auto flag = props.get<const uint8_t>(f.tag);
		/*
		 * An absent property is not the same statement as an explicit 0,
		 * even though both switch the behavior off, so do not collapse
		 * them into one another. clear-msgcopy restores the former.
		 */
		mbop_fprintf(stdout, "%s: %s\n", f.name,
			flag == nullptr ? "unset (off)" : *flag != 0 ? "on" : "off");
	}
	return EXIT_SUCCESS;
}

/**
 * Report the state after a change. A read-back failure says nothing about
 * whether the change itself went through, so spell that out instead of leaving
 * the operator to guess from a bare "RPC unsuccessful".
 */
static int show_after_write()
{
	if (show() == EXIT_SUCCESS)
		return EXIT_SUCCESS;
	mbop_fprintf(stderr, "The change was applied, but reading it back "
		"failed, so it could not be confirmed.\n");
	return EXIT_FAILURE;
}

static int do_set(int argc, char **argv)
{
	const char *arg[std::size(g_flags)]{};
	HXopt6_auto_result result;
	if (HX_getopt6(g_set_options, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i)
		for (size_t k = 0; k < std::size(g_flags); ++k)
			if (result.desc[i]->sh == g_flags[k].opt)
				arg[k] = result.oarg[i];
	if (std::none_of(std::begin(arg), std::end(arg),
	    [](const char *s) { return s != nullptr; })) {
		mbop_fprintf(stderr, "You need to specify the -a and/or -b option\n");
		return EXIT_PARAM;
	}

	TAGGED_PROPVAL pv[std::size(g_flags)]{};
	uint8_t val[std::size(g_flags)]{};
	TPROPVAL_ARRAY tpa = {0, pv};
	for (size_t i = 0; i < std::size(g_flags); ++i) {
		if (arg[i] == nullptr)
			continue;
		if (!parse_strict_bool(arg[i], &val[i])) {
			mbop_fprintf(stderr, "\"%s\" is not a boolean; use "
				"one of 0/1, no/yes, off/on, false/true\n", arg[i]);
			return EXIT_PARAM;
		}
		pv[tpa.count].proptag = g_flags[i].tag;
		pv[tpa.count++].pvalue = &val[i];
	}
	PROBLEM_ARRAY prob{};
	if (!exmdb_client->set_store_properties(g_storedir, CP_ACP, &tpa, &prob)) {
		mbop_fprintf(stderr, "set_store_prop RPC unsuccessful\n");
		return EXIT_FAILURE;
	} else if (prob.count > 0) {
		mbop_fprintf(stderr, "set_store_prop action unsuccessful / property rejected\n");
		return EXIT_FAILURE;
	}
	return show_after_write();
}

static int do_clear(int argc, char **argv)
{
	bool sel[std::size(g_flags)]{};
	HXopt6_auto_result result;
	if (HX_getopt6(g_clear_options, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
		return EXIT_PARAM;
	for (int i = 0; i < result.nopts; ++i)
		for (size_t k = 0; k < std::size(g_flags); ++k)
			if (result.desc[i]->sh == g_flags[k].opt)
				sel[k] = true;
	/* Naming none of them means all of them, as with the other clear-* commands. */
	if (std::none_of(std::begin(sel), std::end(sel), [](bool b) { return b; }))
		for (auto &s : sel)
			s = true;

	std::vector<proptag_t> tags;
	for (size_t i = 0; i < std::size(g_flags); ++i)
		if (sel[i])
			tags.push_back(g_flags[i].tag);
	if (!exmdb_client->remove_store_properties(g_storedir, tags)) {
		mbop_fprintf(stderr, "remove_store_prop RPC unsuccessful\n");
		return EXIT_FAILURE;
	}
	return show_after_write();
}

int main(int argc, char **argv)
{
	if (strcmp(argv[0], "get-msgcopy") == 0) {
		if (HX_getopt6(empty_options_table, argc, argv, nullptr,
		    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS || g_exit_after_optparse)
			return EXIT_PARAM;
		return show();
	} else if (strcmp(argv[0], "clear-msgcopy") == 0) {
		return do_clear(argc, argv);
	}
	return do_set(argc, argv);
}

}
