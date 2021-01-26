// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "file_operation.h"
#include <gromox/list_file.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <dirent.h>

int file_operation_compare(const char *file1, const char *file2)
{
	int fd1, fd2;
	struct stat node_stat1, node_stat2;

	if (0 != stat(file1, &node_stat1) || 0 != stat(file2, &node_stat2)) {
		return FILE_COMPARE_DIFFERENT;
	}
	if (node_stat1.st_size != node_stat2.st_size) {
		return FILE_COMPARE_DIFFERENT;
	}
	auto ptr = static_cast<char *>(malloc(2 * node_stat1.st_size));
	if (NULL == ptr) {
		return FILE_COMPARE_FAIL;
	}
	fd1 = open(file1, O_RDONLY);
	if (-1 == fd1) {
		free(ptr);
		return FILE_COMPARE_FAIL;
	}
	fd2 = open(file2, O_RDONLY);
	if (-1 == fd2) {
		free(ptr);
		close(fd1);
		return FILE_COMPARE_FAIL;
	}
	if (node_stat1.st_size != read(fd1, ptr, node_stat1.st_size) ||
		node_stat2.st_size != read(fd2, ptr + node_stat1.st_size,
		node_stat2.st_size)) {
		free(ptr);
		close(fd1);
		close(fd2);
		return FILE_COMPARE_FAIL;
	}
	close(fd1);
	close(fd2);
	if (0 == memcmp(ptr, ptr + node_stat1.st_size, node_stat1.st_size)) {
		free(ptr);
		return FILE_COMPARE_SAME;
	} else {
		free(ptr);
		return FILE_COMPARE_DIFFERENT;
	}
}
