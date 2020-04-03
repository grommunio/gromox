#pragma once
#include <gromox/defs.h>
#include "mapi_types.h"
#include "logon_object.h"

struct _FASTUPCTX_OBJECT;
typedef BOOL (*RECORD_MARKER)(struct _FASTUPCTX_OBJECT *, uint32_t);
typedef BOOL (*RECORD_PROPVAL)(struct _FASTUPCTX_OBJECT *, const TAGGED_PROPVAL *);

typedef struct _FTSTREAM_PARSER {
	int fd;
	uint32_t offset;
	uint32_t st_size;
	char path[256];
	LOGON_OBJECT *plogon;	/* plogon is a protected member */
} FTSTREAM_PARSER;

FTSTREAM_PARSER* ftstream_parser_create(LOGON_OBJECT *plogon);
	
void ftstream_parser_free(FTSTREAM_PARSER *pstream);

BOOL ftstream_parser_write_buffer(
	FTSTREAM_PARSER *pstream,
	const BINARY *ptransfer_data);
extern gxerr_t ftstream_parser_process(FTSTREAM_PARSER *, RECORD_MARKER, RECORD_PROPVAL, void *param);
