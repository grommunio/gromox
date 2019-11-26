#ifndef _H_EXMDB_CLIENT_
#define _H_EXMDB_CLIENT_
#include "mapi_types.h"

void exmdb_client_init(const char *list_path);

int exmdb_client_run();

int exmdb_client_stop();

void exmdb_client_free();

BOOL exmdb_client_get_store_properties(const char *dir,
	uint32_t cpid, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_client_set_store_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_unload_store(const char *dir);

#endif
