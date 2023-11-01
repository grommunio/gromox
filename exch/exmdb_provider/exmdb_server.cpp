// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <memory>
#include <vector>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "db_engine.h"

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

namespace exmdb_server {

struct envctx_delete {
	void operator()(env_context *x) const { g_ctx_allocator->put(x); }
};

using evproc_t = void (*)(const char *, BOOL, uint32_t, const DB_NOTIFY *);
static thread_local std::unique_ptr<env_context, envctx_delete> g_env_key;
static std::vector<evproc_t> event_proc_handlers;

int run()
{
	g_ctx_allocator = alloc_limiter<ENVIRONMENT_CONTEXT>(2 * get_context_num(),
	                  "exmdb_envctx_allocator", "http.cfg:context_num");
	return 0;
}

void build_env(unsigned int flags, const char *dir)
{
	common_util_build_tls();
	std::unique_ptr<env_context, envctx_delete> pctx(g_ctx_allocator.get());
	pctx->b_local = flags & EM_LOCAL;
	pctx->b_private = flags & EM_PRIVATE;
	pctx->dir = dir;
	pctx->account_id = -1;
	g_env_key = std::move(pctx);
}

void free_env()
{
	g_env_key.reset();
}

void set_remote_id(const char *remote_id)
{
	g_id_key = remote_id;
}

ALLOC_CONTEXT *get_alloc_context()
{
	auto pctx = g_env_key.get();
	if (pctx == nullptr || pctx->b_local)
		return NULL;
	return &pctx->alloc_ctx;
}

const char *get_remote_id()
{
	return g_id_key;
}

void set_public_username(const char *username)
{
	g_public_username_key = username;
}

const char *get_public_username()
{
	/* Only ever used by readstate tracking */
	return g_public_username_key;
}

/* can not be called in local rpc thread without
	invoking exmdb_server::build_environment before! */
bool is_private()
{
	return g_env_key->b_private;
}

/* can not be called in local rpc thread without invoking exmdb_server::build_env before! */
const char *get_dir()
{
	return g_env_key->dir;
}

/* can not be called in local rpc thread without invoking exmdb_server::build_env before! */
void set_dir(const char *dir)
{
	g_env_key->dir = dir;
}

int get_account_id()
{
	unsigned int account_id = 0;
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

const GUID *get_handle()
{
	auto pctx = g_env_key.get();
	if (pctx == nullptr || !pctx->b_local)
		return NULL;
	return common_util_get_handle();
}

void register_proc(void *f)
{
	event_proc_handlers.emplace_back(reinterpret_cast<evproc_t>(f));
	/*
	 * All modifications of event_proc_handlers happen during process startup,
	 * so exmdb_server::event_proc can run lock-free.
	 */
}

void event_proc(const char *dir, BOOL is_table,
    uint32_t notify_id, const DB_NOTIFY *datagram)
{
	for (auto f : event_proc_handlers)
		f(dir, is_table, notify_id, datagram);
}

}
