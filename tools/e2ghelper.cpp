// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <spawn.h>
#include <libHX/option.h>
#include <sys/wait.h>
#include <gromox/scope.hpp>
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

static unsigned int g_splice;
static char *g_username;
static constexpr HXoption g_options_table[] = {
	{nullptr, 's', HXTYPE_NONE, &g_splice, nullptr, nullptr, 0, "Splice objects into existing store hierarchy"},
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
	auto cl_0 = gromox::make_scope_exit([=]() { HX_zvecfree(argv); });
	int pfd[2] = {-1, -1};
	if (pipe(pfd) < 0) {
		perror("pipe");
		return EXIT_FAILURE;
	}
	std::unique_ptr<const char *[]> p1argv(new const char *[argc+2]);
	const char *p2argv[4];
	int p1argc = 0, p2argc = 0;
	p1argv[p1argc++] = "gromox-pff2mt";
	if (g_splice)
		p1argv[p1argc++] = "-s";
	for (int i = 1; i < argc; ++i)
		p1argv[p1argc++] = argv[i];
	p1argv[p1argc] = nullptr;
	p2argv[p2argc++] = "gromox-mt2exm";
	if (g_username != nullptr) {
		p2argv[p2argc++] = "-u";
		p2argv[p2argc++] = g_username;
	}
	p2argv[p2argc] = nullptr;
	file_actions p1fa, p2fa;
	if (pfd[0] != STDIN_FILENO) {
		if (posix_spawn_file_actions_adddup2(&p2fa, pfd[0], STDIN_FILENO) != 0 ||
		    posix_spawn_file_actions_addclose(&p2fa, pfd[0]) != 0 ||
		    posix_spawn_file_actions_addclose(&p2fa, pfd[1]) != 0) {
			perror("file_actions");
			return EXIT_FAILURE;
		}
	}
	if (pfd[1] != STDOUT_FILENO) {
		if (posix_spawn_file_actions_adddup2(&p1fa, pfd[1], STDOUT_FILENO) != 0 ||
		    posix_spawn_file_actions_addclose(&p1fa, pfd[0]) != 0 ||
		    posix_spawn_file_actions_addclose(&p1fa, pfd[1]) != 0) {
			perror("file_actions");
			return EXIT_FAILURE;
		}
	}
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) {};
	sact.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sact, nullptr) < 0) {
		perror("sigaction");
		return EXIT_FAILURE;
	}
	pid_t p1id = -1, p2id = -1;
	auto ret = posix_spawnp(&p1id, p1argv[0], &p1fa, nullptr,
	           const_cast<char **>(p1argv.get()), environ);
	if (ret != 0) {
		fprintf(stderr, "spawnp %s: %s\n", p1argv[0], strerror(ret));
		return EXIT_FAILURE;
	}
	ret = posix_spawnp(&p2id, p2argv[0], &p2fa, nullptr,
	      const_cast<char **>(p2argv), environ);
	if (ret != 0) {
		fprintf(stderr, "spawnp %s: %s\n", p2argv[0], strerror(ret));
		return EXIT_FAILURE;
	}
	close(pfd[0]);
	close(pfd[1]);
	int status = 0;
	if (waitpid(p1id, &status, 0) < 0) {
		perror("waitpid 1");
		return EXIT_FAILURE;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return EXIT_FAILURE;
	if (waitpid(p2id, &status, 0) < 0) {
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
