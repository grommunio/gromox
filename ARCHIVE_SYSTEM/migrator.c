#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#define VDIR_PER_PARTITION		200
#define SUBDIR_PER_VDIR			250
#define DEF_MODE                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


static void move_file(char *src_file, char *dst_file, int size)
{
	int fd;
	char *pbuff;

	pbuff = (char*)malloc(size);
	if (NULL == pbuff) {
		return;
	}
	fd = open(src_file, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	if (size != read(fd, pbuff, size)) {
		free(pbuff);
		close(fd);
		return;
	}
	close(fd);
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	write(fd, pbuff, size);
	free(pbuff);
	close(fd);
	remove(src_file);
}

static void do_migration(const char *src_path, const char *dst_path)
{
	int i, j;
	DIR *dirp;
	char temp_path[256];
	char temp_path1[256];
	struct stat node_stat;
	struct dirent *direntp;

	umask(0);
	for (i=1; i<=VDIR_PER_PARTITION; i++) {
		for (j=1; j<=SUBDIR_PER_VDIR; j++) {
			snprintf(temp_path, 255, "%s/v%d/%d", src_path, i, j);
			dirp = opendir(temp_path);
			if (NULL == dirp) {
				continue;
			}
			while ((direntp = readdir(dirp)) != NULL) {
				if (0 == strcmp(direntp->d_name, ".") ||
					0 == strcmp(direntp->d_name, "..")) {
					continue;
				}
				snprintf(temp_path, 255, "%s/v%d/%d/%s", src_path,
					i, j, direntp->d_name);
				snprintf(temp_path1, 255, "%s/v%d/%d/%s", dst_path,
					i, j, direntp->d_name);
				if (0 == stat(temp_path1, &node_stat)) {
					continue;
				}
				if (0 != stat(temp_path, &node_stat) ||
					0 == S_ISREG(node_stat.st_mode)) {
					continue;
				}
				move_file(temp_path, temp_path1, node_stat.st_size);
			}
			closedir(dirp);
		}
	}

}

int main(int argc, char **argv)
{
	struct stat node_stat;

	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("usage: %s src-path dst-path\n", argv[0]);
		return 0;
	}

	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}

	if (3 != argc) {
		printf("usage: %s src-path dst-path\n", argv[0]);
		return -1;

	}

	if (0 != stat(argv[1], &node_stat)) {
		printf("fail to find source path %s\n", argv[1]);
		return -2;
	}
	
	if (0 == S_ISDIR(node_stat.st_mode)) {
		printf("%s is not directory\n", argv[1]);
		return -3;
	}

	if (0 != stat(argv[2], &node_stat)) {
		printf("fail to find destination path %s\n", argv[2]);
		return -2;
	}
	
	if (0 == S_ISDIR(node_stat.st_mode)) {
		printf("%s is not directory\n", argv[2]);
		return -3;
	}

	do_migration(argv[1], argv[2]);
	printf("migration is completed OK!\n");
	return 0;
}


