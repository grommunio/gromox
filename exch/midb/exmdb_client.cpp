// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include "common_util.h"
#include "exmdb_client.h"

using namespace gromox;

static void (*exmdb_client_event_proc)(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify);

static void buildenv(const remote_svr &)
{
	common_util_build_environment("");
}

static void event_proc(const char *dir, BOOL thing,
    uint32_t notify_id, const DB_NOTIFY *notify)
{
	common_util_set_maildir(dir);
	exmdb_client_event_proc(dir, thing, notify_id, notify);
}

int exmdb_client_run_front(const char *dir)
{
	return exmdb_client_run(dir, EXMDB_CLIENT_SKIP_PUBLIC |
	       EXMDB_CLIENT_SKIP_REMOTE | EXMDB_CLIENT_ASYNC_CONNECT, buildenv,
	       common_util_free_environment, event_proc);
}

void exmdb_client_register_proc(void *pproc)
{
	exmdb_client_event_proc = reinterpret_cast<decltype(exmdb_client_event_proc)>(pproc);
}
