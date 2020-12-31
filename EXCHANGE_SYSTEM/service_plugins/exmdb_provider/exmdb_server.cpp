// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/svc_common.h>
#include "exmdb_server.h"
#include "common_util.h"
#include "lib_buffer.h"
#include "db_engine.h"
#include <pthread.h>
#include <cstdio>

typedef struct _ENVIRONMENT_CONTEXT {
	BOOL b_local;
	ALLOC_CONTEXT alloc_ctx;
	BOOL b_private;
	const char *dir;
	int account_id;
} ENVIRONMENT_CONTEXT;


static pthread_key_t g_id_key;
static pthread_key_t g_env_key;
static LIB_BUFFER *g_ctx_allocator;
static pthread_key_t g_public_username_key;

void (*exmdb_server_event_proc)(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify);

void exmdb_server_init()
{
	pthread_key_create(&g_id_key, NULL);
	pthread_key_create(&g_env_key, NULL);
	pthread_key_create(&g_public_username_key, NULL);
}

int exmdb_server_run()
{
	g_ctx_allocator = lib_buffer_init(sizeof(ENVIRONMENT_CONTEXT),
										2*get_context_num(), TRUE);
	if (NULL == g_ctx_allocator) {
		printf("[exmdb_provider]: Failed to init environment allocator\n");
		return -1;
	}
	return 0;
}

int exmdb_server_stop()
{
	if (NULL != g_ctx_allocator) {
		lib_buffer_free(g_ctx_allocator);
		g_ctx_allocator = NULL;
	}
	return 0;
}

void exmdb_server_free()
{
	pthread_key_delete(g_id_key);
	pthread_key_delete(g_env_key);
	pthread_key_delete(g_public_username_key);
}

void exmdb_server_build_environment(BOOL b_local,
	BOOL b_private, const char *dir)
{
	common_util_build_tls();
	auto pctx = static_cast<ENVIRONMENT_CONTEXT *>(lib_buffer_get(g_ctx_allocator));
	pctx->b_local = b_local;
	if (FALSE == b_local) {
		alloc_context_init(&pctx->alloc_ctx);
	}
	pctx->b_private = b_private;
	pctx->dir = dir;
	pctx->account_id = -1;
	pthread_setspecific(g_env_key, pctx);
}

void exmdb_server_free_environment()
{
	auto pctx = static_cast<ENVIRONMENT_CONTEXT *>(pthread_getspecific(g_env_key));
	if (FALSE == pctx->b_local) {
		alloc_context_free(&pctx->alloc_ctx);
	}
	pthread_setspecific(g_env_key, NULL);
	lib_buffer_put(g_ctx_allocator, pctx);
}

void exmdb_server_set_remote_id(const char *remote_id)
{
	pthread_setspecific(g_id_key, remote_id);
}

ALLOC_CONTEXT* exmdb_server_get_alloc_context()
{
	auto pctx = static_cast<ENVIRONMENT_CONTEXT *>(pthread_getspecific(g_env_key));
	if (NULL == pctx || TRUE == pctx->b_local) {
		return NULL;
	}
	return &pctx->alloc_ctx;
}

const char* exmdb_server_get_remote_id()
{
	return static_cast<char *>(pthread_getspecific(g_id_key));
}

void exmdb_server_set_public_username(const char *username)
{
	pthread_setspecific(g_public_username_key, username);
}

const char* exmdb_server_get_public_username()
{
	return static_cast<char *>(pthread_getspecific(g_public_username_key));
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
BOOL exmdb_server_check_private()
{
	auto pctx = static_cast<ENVIRONMENT_CONTEXT *>(pthread_getspecific(g_env_key));
	return pctx->b_private;
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
const char* exmdb_server_get_dir()
{
	auto pctx = static_cast<ENVIRONMENT_CONTEXT *>(pthread_getspecific(g_env_key));
	return pctx->dir;
}

/* can not be called in local rpc thread without
	invoking exmdb_server_build_environment before! */
void exmdb_server_set_dir(const char *dir)
{
	auto pctx = static_cast<ENVIRONMENT_CONTEXT *>(pthread_getspecific(g_env_key));
	pctx->dir = dir;
}

int exmdb_server_get_account_id()
{
	int account_id;
	
	auto pctx = static_cast<ENVIRONMENT_CONTEXT *>(pthread_getspecific(g_env_key));
	if (pctx->account_id < 0) {
		if (TRUE == pctx->b_private) {
			if (TRUE == common_util_get_id_from_maildir(
				pctx->dir, &account_id)) {
				pctx->account_id = account_id;	
			}
		} else {
			if (TRUE == common_util_get_id_from_homedir(
				pctx->dir, &account_id)) {
				pctx->account_id = account_id;	
			}
		}
	}
	return pctx->account_id;
}

const GUID* exmdb_server_get_handle()
{
	auto pctx = static_cast<ENVIRONMENT_CONTEXT *>(pthread_getspecific(g_env_key));
	if (NULL == pctx || FALSE == pctx->b_local) {
		return NULL;
	}
	return common_util_get_handle();
}

void exmdb_server_register_proc(void *pproc)
{
	exmdb_server_event_proc = reinterpret_cast<decltype(exmdb_server_event_proc)>(pproc);
}
