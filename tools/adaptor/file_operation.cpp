// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/scope.hpp>
#include "file_operation.h"
#include <gromox/list_file.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <dirent.h>

using namespace gromox;

int file_operation_compare(const char *file1, const char *file2)
{
	struct stat node_stat1, node_stat2;

	auto fd1 = open(file1, O_RDONLY);
	if (fd1 < 0)
		return errno == ENOENT ? FILE_COMPARE_DIFFERENT : FILE_COMPARE_FAIL;
	auto cl_1 = make_scope_exit([&]() { close(fd1); });
	auto fd2 = open(file2, O_RDONLY);
	if (fd2 < 0)
		return errno == ENOENT ? FILE_COMPARE_DIFFERENT : FILE_COMPARE_FAIL;
	auto cl_2 = make_scope_exit([&]() { close(fd2); });
	if (fstat(fd1, &node_stat1) != 0 || fstat(fd2, &node_stat2) != 0)
		return FILE_COMPARE_FAIL;
	if (node_stat1.st_size != node_stat2.st_size) {
		return FILE_COMPARE_DIFFERENT;
	}
	auto ptr = static_cast<char *>(malloc(2 * node_stat1.st_size));
	if (NULL == ptr) {
		return FILE_COMPARE_FAIL;
	}
	if (node_stat1.st_size != read(fd1, ptr, node_stat1.st_size) ||
		node_stat2.st_size != read(fd2, ptr + node_stat1.st_size,
		node_stat2.st_size)) {
		free(ptr);
		return FILE_COMPARE_FAIL;
	}
	if (0 == memcmp(ptr, ptr + node_stat1.st_size, node_stat1.st_size)) {
		free(ptr);
		return FILE_COMPARE_SAME;
	} else {
		free(ptr);
		return FILE_COMPARE_DIFFERENT;
	}
}
