#pragma once
enum {
	MIDB_RESULT_OK = 0,
	MIDB_NO_SERVER,
	MIDB_RDWR_ERROR,
	MIDB_RESULT_ERROR,
};
enum {
	FLAG_RECENT   = 0x1,
	FLAG_ANSWERED = 0x2,
	FLAG_FLAGGED  = 0x4,
	FLAG_DELETED  = 0x8,
	FLAG_SEEN     = 0x10,
	FLAG_DRAFT    = 0x20,
	/* bits for controlling of f_digest, if not set, 
	means mem_file is not initialized. */
	FLAG_LOADED   = 0x80,
};
