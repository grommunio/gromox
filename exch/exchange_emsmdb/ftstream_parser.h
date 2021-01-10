#pragma once
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include "logon_object.h"

struct FASTUPCTX_OBJECT;
typedef gxerr_t (*RECORD_MARKER)(FASTUPCTX_OBJECT *, uint32_t);
typedef gxerr_t (*RECORD_PROPVAL)(FASTUPCTX_OBJECT *, const TAGGED_PROPVAL *);

struct FTSTREAM_PARSER {
	int fd;
	uint32_t offset;
	uint32_t st_size;
	char path[256];
	LOGON_OBJECT *plogon;	/* plogon is a protected member */
};

#ifdef __cplusplus
extern "C" {
#endif

FTSTREAM_PARSER* ftstream_parser_create(LOGON_OBJECT *plogon);
	
void ftstream_parser_free(FTSTREAM_PARSER *pstream);

BOOL ftstream_parser_write_buffer(
	FTSTREAM_PARSER *pstream,
	const BINARY *ptransfer_data);
extern gxerr_t ftstream_parser_process(FTSTREAM_PARSER *, RECORD_MARKER, RECORD_PROPVAL, void *param);

#ifdef __cplusplus
} /* extern "C" */
#endif
