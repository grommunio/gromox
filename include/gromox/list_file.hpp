#pragma once
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <gromox/defs.h>
#include <gromox/fileio.h>

struct LIST_FILE {
	LIST_FILE() = default;
	~LIST_FILE();
	NOMOVE(LIST_FILE);
	void *get_list() { return pfile; }
	size_t get_size() const { return item_num; }

	std::unique_ptr<FILE, gromox::file_deleter> file_ptr;
    char        format[32];
    int         type_size[32];
    int         type_num;
	size_t item_size = 0, item_num = 0;
    void*       pfile;
};

enum {
	EMPTY_ON_ABSENCE = 0,
	ERROR_ON_ABSENCE,
};

struct EXMDB_ITEM {
	std::string prefix, host;
	uint16_t port = 0;
	enum {
		EXMDB_PRIVATE,
		EXMDB_PUBLIC,
	} type;
	bool local = false;
};

extern GX_EXPORT std::unique_ptr<LIST_FILE> list_file_initd(const char *filename, const char *sdlist, const char *format, unsigned int mode = EMPTY_ON_ABSENCE);
extern GX_EXPORT gromox::errno_t list_file_read_fixedstrings(const char *filename, const char *sdlist, std::vector<std::string> &out);
extern GX_EXPORT gromox::errno_t list_file_read_exmdb(const char *filename, const char *sdlist, std::vector<EXMDB_ITEM> &out);
