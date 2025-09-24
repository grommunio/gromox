// SPDX-License-Identifier: AGPL-3.0-or-later 
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <sys/stat.h>
#include <gromox/paths.h>
#include <gromox/textmaps.hpp>

using namespace gromox;

static void help(const char *a0)
{
	fprintf(stderr, "Usage: %s ...\n", a0);
	fprintf(stderr, "\tcpidtocset cpid[...]   Codepage lookup (e.g. 437)\n");
	fprintf(stderr, "\tmapitags proptag[...]  MAPI property mnemonic name lookup (e.g. 3001001f)\n");
}

static int q_generic(int argc, char **argv, std::function<std::string(const char *arg)> xlat)
{
	if (argc < 3) {
		help(argv[0]);
		return EXIT_FAILURE;
	}
	for (int k = 2; k < argc; ++k)
		printf("%s: %s\n", argv[k], xlat(argv[k]).c_str());
	return EXIT_SUCCESS;
}

static int q_generic(int argc, char **argv, const char *(*xlat)(const char *))
{
	return q_generic(argc, argv, [=](const char *a) -> std::string {
		auto out = xlat(a);
		return out != nullptr ? out : "?";
	});
}

static int q_generic(int argc, char **argv, unsigned int (*xlat)(const char *))
{
	return q_generic(argc, argv, [=](const char *a) {
		return std::to_string(xlat(a));
	});
}

static int q_generic(int argc, char **argv, const char *(*xlat)(unsigned int))
{
	return q_generic(argc, argv, [=](const char *a) {
		auto out = xlat(strtoul(a, nullptr, 0));
		return out != nullptr ? out : "?";
	});
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		help(argv[0]);
		return EXIT_FAILURE;
	}
	textmaps_init(PKGDATADIR);
	if (strcmp(argv[1], "cpidtocset") == 0)
		return q_generic(argc, argv, +[](const char *a) { return cpid_to_cset(static_cast<cpid_t>(strtoul(a, nullptr, 0))); });
	if (strcmp(argv[1], "csettocpid") == 0)
		return q_generic(argc, argv, +[](const char *a) { return static_cast<unsigned int>(cset_to_cpid(a)); });
	if (strcmp(argv[1], "lcidtoltag") == 0)
		return q_generic(argc, argv, lcid_to_ltag);
	if (strcmp(argv[1], "ltagtolcid") == 0)
		return q_generic(argc, argv, ltag_to_lcid);
	if (strcmp(argv[1], "exttomime") == 0)
		return q_generic(argc, argv, extension_to_mime);
	if (strcmp(argv[1], "langtocset") == 0)
		return q_generic(argc, argv, lang_to_charset);
	if (strcmp(argv[1], "mimetoext") == 0)
		return q_generic(argc, argv, mime_to_extension);
	if (strcmp(argv[1], "mapitags") == 0)
		return q_generic(argc, argv, mapitags_namelookup);
	fprintf(stderr, "Unknown subcommand \"%s\"\n", argv[1]);
	return EXIT_FAILURE;
}
