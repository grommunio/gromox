#include <libHX/defs.h>
#include "file_operation.h"
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static char g_gateway_path[256];

void file_operation_init(const char *gateway_path)
{
	strcpy(g_gateway_path, gateway_path);
}

int file_operation_run()
{
	/* do nothing */
	return 0;
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

void file_operation_broadcast_dir(const char *src_dir, const char *dst_dir)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;

	dirp = opendir(g_gateway_path);
	if (NULL == dirp){
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
			direntp->d_name, dst_dir);
		file_operation_copy_dir(src_dir, temp_path);
	}
	closedir(dirp);
}

void file_operation_compress(const char *src_path, const char *dst_file)
{
	pid_t pid;
	int status;
	const char *args[] = {"tar", "czf", NULL, "-C", NULL, ".", NULL};

	pid = fork();
	if (0 == pid) {
		args[2] = dst_file;
		args[4] = src_path;
		execvp("tar", const_cast(char **, args));
		_exit(-1);
	} else if (pid > 0) {
		waitpid(pid, &status, 0);
	}
}

void file_operation_decompress(const char *src_file, const char *dst_dir)
{
	pid_t pid;
	int status;
	const char *args[] = {"tar", "zxf", NULL, "-C", NULL, NULL};

	pid = fork();
	if (0 == pid) {
		args[2] = src_file;
		args[4] = dst_dir;
		execvp("tar", const_cast(char **, args));
		_exit(-1);
	} else if (pid > 0) {
		waitpid(pid, &status, 0);
	}
}

void file_operation_copy_file(const char *src_file, const char *dst_file)
{
	int fd;
	char *pbuff;
	struct stat node_stat;

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
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	write(fd, pbuff, node_stat.st_size);
	free(pbuff);
	close(fd);
}

void file_operation_copy_dir(const char *src_dir, const char *dst_dir)
{
	DIR *dirp;
	int fd, fd1;
	char *pbuff;
	char temp_path[256];
	char temp_path1[256];
	struct stat node_stat;
	struct dirent *direntp;
	
	dirp = opendir(src_dir);
	if (NULL == dirp) {
		return;
	}
	
	if (0 == stat(dst_dir, &node_stat)) {
		if (0 != S_ISDIR(node_stat.st_mode)) {
			file_operation_remove_dir(dst_dir);
		} else {
			remove(dst_dir);
		}
	}
	mkdir(dst_dir, 0777);
	
	
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s", src_dir, direntp->d_name);
		if (0 != stat(temp_path, &node_stat)) {
			continue;
		}
		if (0 == S_ISDIR(node_stat.st_mode)) {
			pbuff = malloc(node_stat.st_size);
			if (NULL == pbuff) {
				continue;
			}
			fd = open(temp_path, O_RDONLY);
			if (-1 == fd) {
				free(pbuff);
				continue;
			}
			if (node_stat.st_size == read(fd, pbuff, node_stat.st_size)) {
				sprintf(temp_path, "%s/%s", dst_dir, direntp->d_name);
				fd1 = open(temp_path, O_CREAT|O_WRONLY|O_TRUNC, DEF_MODE);
				if (-1 != fd1) {
					write(fd1, pbuff, node_stat.st_size);
					close(fd1);
				}
			}
			close(fd);
			free(pbuff);
		} else {
			sprintf(temp_path, "%s/%s", src_dir, direntp->d_name);
			sprintf(temp_path1, "%s/%s", dst_dir, direntp->d_name);
			file_operation_copy_dir(temp_path, temp_path1);
		}
	}
	closedir(dirp);
}

void file_operation_remove_dir(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;

	if (0 != stat(path, &node_stat)) {
		return;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		remove(path);
		return;
	}
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s", path, direntp->d_name);
		file_operation_remove_dir(temp_path);
	}
	closedir(dirp);
	remove(path);
}

int file_operation_stop()
{
	/* do nothing */
	return 0;
}

void file_operation_free()
{
	/* do nothing */
}

