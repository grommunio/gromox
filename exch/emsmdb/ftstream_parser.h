#pragma once
#include <memory>
#include <gromox/fileio.h>
#include <gromox/mapi_types.hpp>
#include <gromox/mapierr.hpp>

struct fastupctx_object;
struct logon_object;

struct fxstream_parser {
	protected:
	fxstream_parser() = default;
	NOMOVE(fxstream_parser);

	public:
	static std::unique_ptr<fxstream_parser> create(logon_object *);
	BOOL write_buffer(const BINARY *transfer_data);
	ec_error_t process(fastupctx_object &);

	gromox::tmpfile fd;
	uint32_t offset = 0, st_size = 0;
	logon_object *plogon = nullptr; /* plogon is a protected member */
};
