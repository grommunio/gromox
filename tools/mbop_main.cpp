// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

static int help(const char *argv0)
{
	fprintf(stderr, "Usage: %s ...\n", argv0);
	fprintf(stderr, "\tunload $maildir    Execute the UNLOAD RPC for the given mailbox\n");
	return EXIT_FAILURE;
}

static int do_simple_rpc(BOOL (*f)(const char *), const char *dir)
{
	if (!f(dir)) {
		fprintf(stderr, "unload: the operation failed\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, const char **argv)
{
	if (argc < 2)
		return help(*argv);
	exmdb_client_init(1, 0);
	auto cl_0 = make_scope_exit(exmdb_client_stop);
	auto ret = exmdb_client_run(PKGSYSCONFDIR, 0);
	if (ret < 0)
		return EXIT_FAILURE;
	if (strcmp(argv[1], "vacuum") == 0) {
		if (argc < 3)
			return help(*argv);
		do_simple_rpc(&exmdb_client::vacuum, argv[2]);
	} else if (strcmp(argv[1], "unload") == 0) {
		if (argc < 3)
			return help(*argv);
		do_simple_rpc(&exmdb_client::unload_store, argv[2]);
	} else {
		help(*argv);
	}
	return EXIT_SUCCESS;
}
