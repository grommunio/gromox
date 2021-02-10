#pragma once
#include <cstdio>
#include <memory>
#include <gromox/defs.h>
#include <gromox/fileio.h>

struct LIST_FILE {
	~LIST_FILE();
	void *get_list() { return pfile; }
	int get_size() { return item_num; }

	std::unique_ptr<FILE, gromox::file_deleter> file_ptr;
    char        format[32];
    int         type_size[32];
    int         type_num;
    int         item_size;
    int         item_num;
    void*       pfile;
};

extern GX_EXPORT std::unique_ptr<LIST_FILE> list_file_init(const char *filename, const char *format, bool require = true);
