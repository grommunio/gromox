// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/proc.h>
#include <gromox/defs.h>
#include <gromox/svc_common.h>

static int at_add_timer(const char *command, int seconds)
{
	char buf[HXSIZEOF_Z32+20];
	snprintf(buf, sizeof(buf), "now + %d minutes", seconds / 60);
	const char *cmd[] = {"at", "-M", buf, nullptr};
	struct HXproc proc{};
	proc.p_flags = HXPROC_STDIN | HXPROC_NULL_STDOUT | HXPROC_STDERR;
	if (HXproc_run_async(cmd, &proc) < 0)
		return 0;
	write(proc.p_stdin, command, strlen(command));
	close(proc.p_stdin);
	proc.p_stdin = -1;
	FILE *fp = fdopen(proc.p_stderr, "r");
	if (fp == nullptr) {
		HXproc_wait(&proc);
		return 0;
	}
	int jobnr = 0, j;
	bool sol = true;
	while (fgets(buf, sizeof(buf), fp) != nullptr) {
		if (jobnr == 0 && sol && sscanf(buf, "job %d", &j) == 1)
			jobnr = j;
		sol = strchr(buf, '\n');
	}
	fclose(fp);
	proc.p_stdout = -1;
	HXproc_wait(&proc);
	return jobnr;
}

static BOOL at_del_timer(int id)
{
	char idstr[HXSIZEOF_Z32];
	snprintf(idstr, sizeof(idstr), "%d", id);
	const char *cmd[] = {"atrm", idstr, nullptr};
	return HXproc_run_sync(cmd, HXPROC_NULL_STDIN | HXPROC_NULL_STDOUT | HXPROC_NULL_STDERR) == 0;
}

static BOOL svc_atclient(int reason, void **data)
{
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(data);
	if (!register_service("add_timer", at_add_timer) ||
	    !register_service("cancel_timer", at_del_timer)) {
		printf("[at_client]: failed to register timer functions\n");
		return false;
	}
	return TRUE;
}
SVC_ENTRY(svc_atclient);
