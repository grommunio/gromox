// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <memory>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "common_util.h"
#include "db_engine.h"
#include "exmdb_server.h"

namespace {

struct env_context {
	alloc_context alloc_ctx;
	const char *dir = nullptr;
	int account_id = 0;
	bool b_local = false, b_private = false;
};
using ENVIRONMENT_CONTEXT = env_context;

}

static thread_local const char *g_id_key;
static thread_local const char *g_public_username_key;
static alloc_limiter<ENVIRONMENT_CONTEXT> g_ctx_allocator{"exmdb.ctx_allocator.d"};

namespace {
struct envctx_delete {
	void operator()(env_context *x) const { g_ctx_allocator->put(x); }
};
}

static thread_local std::unique_ptr<env_context, envctx_delete> g_env_key;

void (*exmdb_server_event_proc)(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify);

int exmdb_server_run()
{
	g_ctx_allocator = alloc_limiter<ENVIRONMENT_CONTEXT>(2 * get_context_num(),
	                  "exmdb_envctx_allocator", "http.cfg:context_num");
	return 0;
}

void exmdb_server_build_env(unsigned int flags, const char *dir)
{
	common_util_build_tls();
	std::unique_ptr<env_context, envctx_delete> pctx(g_ctx_allocator.get());
	pctx->b_local = flags & EM_LOCAL;
	pctx->b_private = flags & EM_PRIVATE;
	pctx->dir = dir;
	pctx->account_id = -1;
	g_env_key = std::move(pctx);
}

void exmdb_server_free_environment()
{
	g_env_key.reset();
}

void exmdb_server_set_remote_id(const char *remote_id)
{
	g_id_key = remote_id;
}

ALLOC_CONTEXT* exmdb_server_get_alloc_context()
{
	auto pctx = g_env_key.get();
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
	/* Only ever used by readstate tracking */
	return g_public_username_key;
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
bool exmdb_server_is_private()
{
	return g_env_key->b_private;
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
const char* exmdb_server_get_dir()
{
	return g_env_key->dir;
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
void exmdb_server_set_dir(const char *dir)
{
	g_env_key->dir = dir;
}

int exmdb_server_get_account_id()
{
	int account_id;
	
	auto pctx = g_env_key.get();
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
	auto pctx = g_env_key.get();
	if (pctx == nullptr || !pctx->b_local)
		return NULL;
	return common_util_get_handle();
}

void exmdb_server_register_proc(void *pproc)
{
	exmdb_server_event_proc = reinterpret_cast<decltype(exmdb_server_event_proc)>(pproc);
}
