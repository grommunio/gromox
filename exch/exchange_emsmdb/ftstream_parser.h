#pragma once
#include <memory>
#include <string>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

struct FASTUPCTX_OBJECT;
struct LOGON_OBJECT;
using RECORD_MARKER = gxerr_t (*)(FASTUPCTX_OBJECT *, uint32_t);
using RECORD_PROPVAL = gxerr_t (*)(FASTUPCTX_OBJECT *, const TAGGED_PROPVAL *);

struct FTSTREAM_PARSER {
	protected:
	FTSTREAM_PARSER() = default;

	public:
	~FTSTREAM_PARSER();
	static std::unique_ptr<FTSTREAM_PARSER> create(LOGON_OBJECT *);
	BOOL write_buffer(const BINARY *transfer_data);
	gxerr_t process(RECORD_MARKER, RECORD_PROPVAL, void *param);

	int fd = -1;
	uint32_t offset = 0, st_size = 0;
	std::string path;
	LOGON_OBJECT *plogon = nullptr; /* plogon is a protected member */
};
using ftstream_parser = FTSTREAM_PARSER;
