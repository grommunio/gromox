#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include "common_util.h"
#include <gromox/ext_buffer.hpp>

struct DB_NOTIFY_DATAGRAM {
	char *dir;
	BOOL b_table;
	LONG_ARRAY id_array;
	DB_NOTIFY db_notify;
};

int exmdb_ext_push_request(const EXMDB_REQUEST *prequest,
	BINARY *pbin_out);

int exmdb_ext_pull_response(const BINARY *pbin_in,
	EXMDB_RESPONSE *presponse);
int exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	DB_NOTIFY_DATAGRAM *pnotify);
