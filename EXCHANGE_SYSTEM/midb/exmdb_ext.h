#pragma once
#include "common_util.h"
#include "ext_buffer.h"

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
