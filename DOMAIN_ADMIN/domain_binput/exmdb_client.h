#pragma once
#include "mapi_types.h"

void exmdb_client_init(const char *list_path);
extern int exmdb_client_run(void);
extern int exmdb_client_stop(void);
extern void exmdb_client_free(void);
BOOL exmdb_client_set_store_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_unload_store(const char *dir);
