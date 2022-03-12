// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <memory>
#include <pthread.h>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "common_util.h"
#include "db_engine.h"
#include "exmdb_server.h"

namespace {

struct ENVIRONMENT_CONTEXT {
	BOOL b_local;
	ALLOC_CONTEXT alloc_ctx;
	BOOL b_private;
	const char *dir;
	int account_id;
};

}

static thread_local const char *g_id_key;
static thread_local const char *g_public_username_key;
static thread_local ENVIRONMENT_CONTEXT *g_env_key;
static std::unique_ptr<LIB_BUFFER> g_ctx_allocator;

void (*exmdb_server_event_proc)(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify);

int exmdb_server_run()
{
	g_ctx_allocator = LIB_BUFFER::create(sizeof(ENVIRONMENT_CONTEXT),
	                  2 * get_context_num());
	if (NULL == g_ctx_allocator) {
		printf("[exmdb_provider]: Failed to init environment allocator\n");
		return -1;
	}
	return 0;
}

void exmdb_server_stop()
{
	g_ctx_allocator.reset();
}

void exmdb_server_build_environment(BOOL b_local,
	BOOL b_private, const char *dir)
{
	common_util_build_tls();
	auto pctx = g_ctx_allocator->get<ENVIRONMENT_CONTEXT>();
	pctx->b_local = b_local;
	if (!b_local)
		alloc_context_init(&pctx->alloc_ctx);
	pctx->b_private = b_private;
	pctx->dir = dir;
	pctx->account_id = -1;
	g_env_key = pctx;
}

void exmdb_server_free_environment()
{
	auto pctx = g_env_key;
	if (pctx == nullptr)
		return;
	if (!pctx->b_local)
		alloc_context_free(&pctx->alloc_ctx);
	g_env_key = nullptr;
	g_ctx_allocator->put(pctx);
}

void exmdb_server_set_remote_id(const char *remote_id)
{
	g_id_key = remote_id;
}

ALLOC_CONTEXT* exmdb_server_get_alloc_context()
{
	auto pctx = g_env_key;
	if (pctx == nullptr || pctx->b_local)
		return NULL;
	return &pctx->alloc_ctx;
}

const char* exmdb_server_get_remote_id()
{
	return g_id_key;
}

void exmdb_server_set_public_username(const char *username)
{
	g_public_username_key = username;
}

const char* exmdb_server_get_public_username()
{
	return g_public_username_key;
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
BOOL exmdb_server_check_private()
{
	auto pctx = g_env_key;
	return pctx->b_private;
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
const char* exmdb_server_get_dir()
{
	auto pctx = g_env_key;
	return pctx->dir;
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
void exmdb_server_set_dir(const char *dir)
{
	auto pctx = g_env_key;
	pctx->dir = dir;
}

int exmdb_server_get_account_id()
{
	int account_id;
	
	auto pctx = g_env_key;
	if (pctx->account_id < 0) {
		if (pctx->b_private) {
			if (common_util_get_id_from_maildir(pctx->dir, &account_id))
				pctx->account_id = account_id;	
		} else {
			if (common_util_get_id_from_homedir(pctx->dir, &account_id))
				pctx->account_id = account_id;	
		}
	}
	return pctx->account_id;
}

const GUID* exmdb_server_get_handle()
{
	auto pctx = g_env_key;
	if (pctx == nullptr || !pctx->b_local)
		return NULL;
	return common_util_get_handle();
}

void exmdb_server_register_proc(void *pproc)
{
	exmdb_server_event_proc = reinterpret_cast<decltype(exmdb_server_event_proc)>(pproc);
}
