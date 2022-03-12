#pragma once
#include <gromox/ext_buffer.hpp>
#include "common_util.h"
int exmdb_ext_push_request(const EXMDB_REQUEST *prequest,
	BINARY *pbin_out);
int exmdb_ext_pull_response(const BINARY *pbin_in,
	EXMDB_RESPONSE *presponse);
int exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	DB_NOTIFY_DATAGRAM *pnotify);
