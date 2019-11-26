#ifndef _H_FTSTREAM_PARSER_
#define _H_FTSTREAM_PARSER_
#include "mapi_types.h"
#include "logon_object.h"


typedef BOOL (*RECORD_MARKER)(void*, uint32_t);
typedef BOOL (*RECORD_PROPVAL)(void*, const TAGGED_PROPVAL*);

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

BOOL ftstream_parser_process(FTSTREAM_PARSER *pstream,
	RECORD_MARKER record_marker, RECORD_PROPVAL record_propval,
	void *pparam);

#endif /* _H_FTSTREAM_PARSER_ */
