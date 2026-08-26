// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/mapidefs.h>
#include <gromox/sent_copy.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace msgcopy {

struct flagdesc {
	const char *npname;
	const char *name;
	char opt;
};

/*
 * One record per setting, so that the named property, the label and the option
 * letter cannot drift apart the way parallel arrays do.
 */
static constexpr flagdesc g_flags[] = {
	{msgcopy_np_sentas, "sent-as", 'a'},
	{msgcopy_np_sendonbehalf, "send-on-behalf", 'b'},
	{msgcopy_np_exclusive, "exclusive", 'x'},
};

/**
 * Resolve the settings to proptags in the mailbox being operated on. The
 * entries are named properties, so their ids are per-store and have to be
 * looked up rather than known.
 *
 * @create is only ever set on the write path, as a mailbox must not acquire
 * the named property merely by being inspected. An entry the store does not
 * have is reported as tag 0, which on the read path is the ordinary "never
 * configured" state and on the write path is a failure (see do_set).
 */
static errno_t resolve_flags(bool create, const bool *sel,
    proptag_t (&out)[std::size(g_flags)])
{
	for (size_t i = 0; i < std::size(g_flags); ++i) {
		out[i] = 0;
		if (sel != nullptr && !sel[i])
			continue;
		propid_t propid = 0;
		auto err = resolvename(PSETID_Gromox, g_flags[i].npname, create, &propid);
		if (err == ENOENT)
			continue;
		else if (err != 0)
			return err;
		out[i] = PROP_TAG(PT_BOOLEAN, propid);
	}
	return 0;
}

static constexpr HXoption g_set_options[] = {
	{{}, 'a', HXTYPE_STRING, {}, {}, {}, 0,
		"Retain a copy when sending as this mailbox", "BOOL"},
	{{}, 'b', HXTYPE_STRING, {}, {}, {}, 0,
		"Retain a copy when sending on behalf of this mailbox", "BOOL"},
	{{}, 'x', HXTYPE_STRING, {}, {}, {}, 0,
		"Let this mailbox's copy be the only one", "BOOL"},
	{nullptr, 'v', HXTYPE_NONE, &global::g_verbose_mode, {}, {}, 0, "Verbose mode"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr HXoption g_clear_options[] = {
	{{}, 'a', HXTYPE_NONE, {}, {}, {}, 0, "Clear only the sent-as setting"},
	{{}, 'b', HXTYPE_NONE, {}, {}, {}, 0, "Clear only the on-behalf setting"},
	{{}, 'x', HXTYPE_NONE, {}, {}, {}, 0, "Clear only the exclusive setting"},
	{nullptr, 'v', HXTYPE_NONE, &global::g_verbose_mode, {}, {}, 0, "Verbose mode"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int show()
{
	proptag_t tag[std::size(g_flags)];
	if (resolve_flags(false, nullptr, tag) != 0) {
		mbop_fprintf(stderr, "get_named_propids RPC unsuccessful\n");
		return EXIT_FAILURE;
	}
	proptag_t req[std::size(g_flags)];
	size_t nreq = 0;
	for (auto t : tag)
		if (t != 0)
			req[nreq++] = t;
	TPROPVAL_ARRAY props{};
	if (nreq > 0 && !exmdb_client->get_store_properties(g_storedir, CP_ACP,
	    {req, nreq}, &props)) {
		mbop_fprintf(stderr, "get_store_prop RPC unsuccessful\n");
		return EXIT_FAILURE;
	}
	for (size_t i = 0; i < std::size(g_flags); ++i) {
		/*
		 * An absent property is not the same statement as an explicit 0,
		 * even though both switch the behavior off, so do not collapse
		 * them into one another. clear-msgcopy restores the former, and a
		 * name the store never minted is absent in the same sense.
		 */
		auto flag = tag[i] == 0 ? nullptr : props.get<const uint8_t>(tag[i]);
		mbop_fprintf(stdout, "%s: %s\n", g_flags[i].name,
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
		mbop_fprintf(stderr, "You need to specify at least one of the "
			"-a, -b and -x options\n");
		return EXIT_PARAM;
	}

	uint8_t val[std::size(g_flags)]{};
	bool sel[std::size(g_flags)]{};
	for (size_t i = 0; i < std::size(g_flags); ++i) {
		if (arg[i] == nullptr)
			continue;
		/*
		 * parse_bool_strict rather than parse_bool, because enabling
		 * this by way of a typo would start copying mail into someone
		 * else's mailbox.
		 */
		auto bv = parse_bool_strict(arg[i]);
		if (!bv.has_value()) {
			mbop_fprintf(stderr, "\"%s\" is not a boolean, use "
				"one of 0/1, no/yes, off/on, false/true\n", arg[i]);
			return EXIT_PARAM;
		}
		val[i] = *bv;
		sel[i] = true;
	}

	/* Create the named property, but only for the settings actually named. */
	proptag_t tag[std::size(g_flags)];
	if (resolve_flags(true, sel, tag) != 0) {
		mbop_fprintf(stderr, "get_named_propids RPC unsuccessful\n");
		return EXIT_FAILURE;
	}
	TAGGED_PROPVAL pv[std::size(g_flags)]{};
	TPROPVAL_ARRAY tpa = {0, pv};
	for (size_t i = 0; i < std::size(g_flags); ++i) {
		if (!sel[i])
			continue;
		if (tag[i] == 0) {
			mbop_fprintf(stderr, "Cannot create the named property "
				"for \"%s\". the mailbox's named-property table "
				"is full.\n", g_flags[i].name);
			return EXIT_FAILURE;
		}
		pv[tpa.count].proptag = tag[i];
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

	proptag_t tag[std::size(g_flags)];
	if (resolve_flags(false, sel, tag) != 0) {
		mbop_fprintf(stderr, "get_named_propids RPC unsuccessful\n");
		return EXIT_FAILURE;
	}
	std::vector<proptag_t> tags;
	for (auto t : tag)
		if (t != 0)
			tags.push_back(t);
	if (!tags.empty() &&
	    !exmdb_client->remove_store_properties(g_storedir, tags)) {
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
