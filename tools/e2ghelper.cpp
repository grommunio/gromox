// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
/*
 * e2ghelper performs the equivalent of
 *
 * 	gromox-pff2mt [...] | gromox-mt2exm [...];
 * 	test ${PIPESTATUS[0]} = 0 && test ${PIPESTATUS[1]} = 0
 *
 * e2ghelper exists because replicating that behavior in POSIX sh is awkward -
 * https://unix.stackexchange.com/a/470884 .
 */
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <spawn.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <sys/wait.h>
#include "genimport.hpp"

extern "C" {
extern char **environ;
}

namespace {
struct file_actions {
	file_actions() { posix_spawn_file_actions_init(&m_act); }
	~file_actions() { posix_spawn_file_actions_destroy(&m_act); }
	posix_spawn_file_actions_t *operator&() { return &m_act; }
	posix_spawn_file_actions_t m_act;
};
}

static char *g_username;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv) try
{
	if (argc == 0)
		return EXIT_FAILURE;
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0 = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	int pfd[2] = {-1, -1};
	if (pipe(pfd) < 0) {
		perror("pipe");
		return EXIT_FAILURE;
	}

	/* Arguments for subprograms */
	std::unique_ptr<const char *[]> pff_argv(new const char *[argc+2]);
	const char *import_argv[4];
	int pff_argc = 0, import_argc = 0;
	pff_argv[pff_argc++] = "gromox-pff2mt";
	for (int i = 1; i < argc; ++i)
		pff_argv[pff_argc++] = argv[i];
	pff_argv[pff_argc] = nullptr;

	import_argv[import_argc++] = "gromox-mt2exm";
	if (g_username != nullptr) {
		import_argv[import_argc++] = "-u";
		import_argv[import_argc++] = g_username;
	}
	import_argv[import_argc] = nullptr;

	/* File descriptor control block */
	file_actions pff_actions, import_actions;
	if (pfd[0] != STDIN_FILENO) {
		if (posix_spawn_file_actions_adddup2(&import_actions, pfd[0], STDIN_FILENO) != 0 ||
		    posix_spawn_file_actions_addclose(&import_actions, pfd[0]) != 0 ||
		    posix_spawn_file_actions_addclose(&import_actions, pfd[1]) != 0) {
			perror("file_actions");
			return EXIT_FAILURE;
		}
	}
	if (pfd[1] != STDOUT_FILENO) {
		if (posix_spawn_file_actions_adddup2(&pff_actions, pfd[1], STDOUT_FILENO) != 0 ||
		    posix_spawn_file_actions_addclose(&pff_actions, pfd[0]) != 0 ||
		    posix_spawn_file_actions_addclose(&pff_actions, pfd[1]) != 0) {
			perror("file_actions");
			return EXIT_FAILURE;
		}
	}

	/* Process spin-up */
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) {};
	sact.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sact, nullptr) < 0) {
		perror("sigaction");
		return EXIT_FAILURE;
	}
	pid_t pff_id = -1, import_pid = -1;
	auto ret = posix_spawnp(&pff_id, pff_argv[0], &pff_actions, nullptr,
	           const_cast<char **>(pff_argv.get()), environ);
	if (ret != 0) {
		fprintf(stderr, "spawnp %s: %s\n", pff_argv[0], strerror(ret));
		return EXIT_FAILURE;
	}
	ret = posix_spawnp(&import_pid, import_argv[0], &import_actions, nullptr,
	      const_cast<char **>(import_argv), environ);
	if (ret != 0) {
		fprintf(stderr, "spawnp %s: %s\n", import_argv[0], strerror(ret));
		return EXIT_FAILURE;
	}
	close(pfd[0]);
	close(pfd[1]);

	/* Wait for completion */
	int status = 0;
	if (waitpid(pff_id, &status, 0) < 0) {
		perror("waitpid 1");
		return EXIT_FAILURE;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return EXIT_FAILURE;
	if (waitpid(import_pid, &status, 0) < 0) {
		perror("waitpid 2");
		return EXIT_FAILURE;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "ENOMEM\n");
	return EXIT_FAILURE;
}
