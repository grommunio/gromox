// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <libHX/option.h>
#include <sys/shm.h>

static long g_key;
static constexpr struct HXoption g_options_table[] = {
	{nullptr, 'i', HXTYPE_LONG, &g_key, nullptr, nullptr, 0, "Resource element to obtain", "ID"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv)
{
	HXopt6_auto_result argp;
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	auto id = shmget(g_key, 0, 0);
	if (id < 0) {
		fprintf(stderr, "shmget(0x%lx): %s\n", g_key, strerror(errno));
		return EXIT_FAILURE;
	}
	struct shmid_ds ds;
	if (shmctl(id, IPC_STAT, &ds) < 0) {
		fprintf(stderr, "shmctl(0x%lx): %s\n", g_key, strerror(errno));
		return EXIT_FAILURE;
	}

	struct shm_delete { void operator()(void *x) const { shmdt(x); } };
	std::unique_ptr<void, shm_delete> addr(shmat(id, nullptr, SHM_RDONLY));
	if (addr.get() == (void *)-1) {
		fprintf(stderr, "shmat(0x%lx): %s\n", g_key, strerror(errno));
		return EXIT_FAILURE;
	}
	write(STDOUT_FILENO, addr.get(), ds.shm_segsz);
	return EXIT_SUCCESS;
}
