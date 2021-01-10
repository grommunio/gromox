#pragma once
#include "common_util.h"
#include <gromox/ext_buffer.hpp>

#ifdef __cplusplus
extern "C" {
#endif

int exmdb_ext_pull_request(const BINARY *pbin_in,
	EXMDB_REQUEST *prequest);

int exmdb_ext_push_request(const EXMDB_REQUEST *prequest,
	BINARY *pbin_out);

int exmdb_ext_pull_response(const BINARY *pbin_in,
	EXMDB_RESPONSE *presponse);

int exmdb_ext_push_response(const EXMDB_RESPONSE *presponse,
	BINARY *pbin_out);

int exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	DB_NOTIFY_DATAGRAM *pnotify);

int exmdb_ext_push_db_notify(const DB_NOTIFY_DATAGRAM *pnotify,
	BINARY *pbin_out);

#ifdef __cplusplus
} /* extern "C" */
#endif
