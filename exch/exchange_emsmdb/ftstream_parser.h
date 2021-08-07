#pragma once
#include <memory>
#include <string>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include "logon_object.h"

struct FASTUPCTX_OBJECT;
typedef gxerr_t (*RECORD_MARKER)(FASTUPCTX_OBJECT *, uint32_t);
typedef gxerr_t (*RECORD_PROPVAL)(FASTUPCTX_OBJECT *, const TAGGED_PROPVAL *);

struct FTSTREAM_PARSER {
	~FTSTREAM_PARSER();
	BOOL write_buffer(const BINARY *transfer_data);
	gxerr_t process(RECORD_MARKER, RECORD_PROPVAL, void *param);

	int fd = -1;
	uint32_t offset = 0, st_size = 0;
	std::string path;
	LOGON_OBJECT *plogon = nullptr; /* plogon is a protected member */
};

extern std::unique_ptr<FTSTREAM_PARSER> ftstream_parser_create(LOGON_OBJECT *);
