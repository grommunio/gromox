#include <libHX/defs.h>
#include "file_operation.h"
#include "list_file.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

static char g_gateway_path[256];

void file_operation_init(const char *gateway_path)
{
	strcpy(g_gateway_path, gateway_path);
}

int file_operation_compare(const char *file1, const char *file2)
{
	char *ptr;
	int fd1, fd2;
	struct stat node_stat1, node_stat2;

	if (0 != stat(file1, &node_stat1) || 0 != stat(file2, &node_stat2)) {
		return FILE_COMPARE_DIFFERENT;
	}
	if (node_stat1.st_size != node_stat2.st_size) {
		return FILE_COMPARE_DIFFERENT;
	}
	ptr = malloc(2*node_stat1.st_size);
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

void file_operation_broadcast(const char *src_file, const char *dst_file)
{
	int fd;
	DIR *dirp;
	char *pbuff;
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;

	if (0 != stat(src_file, &node_stat)) {
		return;
	}
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		return;
	}
	fd = open(src_file, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		free(pbuff);
		close(fd);
		return;
	}
	close(fd);

	dirp = opendir(g_gateway_path);
	if (NULL == dirp){
		free(pbuff);
		return;
	}
	/*
	 * enumerate the sub-directory of source director each
	 * sub-directory represents one MTA
	 */
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s/%s", g_gateway_path,
			direntp->d_name, dst_file);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			continue;
		}
		write(fd, pbuff, node_stat.st_size);
		close(fd);
	}
	closedir(dirp);
	free(pbuff);
}
