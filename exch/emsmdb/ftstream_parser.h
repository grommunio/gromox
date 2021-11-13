#pragma once
#include <memory>
#include <string>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

struct fastupctx_object;
struct logon_object;
using RECORD_MARKER = gxerr_t (*)(fastupctx_object *, uint32_t);
using RECORD_PROPVAL = gxerr_t (*)(fastupctx_object *, const TAGGED_PROPVAL *);

struct FTSTREAM_PARSER {
	protected:
	FTSTREAM_PARSER() = default;
	NOMOVE(FTSTREAM_PARSER);

	public:
	~FTSTREAM_PARSER();
	static std::unique_ptr<FTSTREAM_PARSER> create(logon_object *);
	BOOL write_buffer(const BINARY *transfer_data);
	gxerr_t process(RECORD_MARKER, RECORD_PROPVAL, void *param);

	int fd = -1;
	uint32_t offset = 0, st_size = 0;
	std::string path;
	logon_object *plogon = nullptr; /* plogon is a protected member */
};
using ftstream_parser = FTSTREAM_PARSER;
