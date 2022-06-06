#pragma once
#include <memory>
#include <string>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

struct fastupctx_object;
struct logon_object;

struct fxstream_parser {
	protected:
	fxstream_parser() = default;
	NOMOVE(fxstream_parser);

	public:
	~fxstream_parser();
	static std::unique_ptr<fxstream_parser> create(logon_object *);
	BOOL write_buffer(const BINARY *transfer_data);
	gxerr_t process(fastupctx_object &);

	int fd = -1;
	uint32_t offset = 0, st_size = 0;
	std::string path;
	logon_object *plogon = nullptr; /* plogon is a protected member */
};
using FTSTREAM_PARSER = fxstream_parser;
using ftstream_parser = fxstream_parser;
