#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "util.h"
#include "list_file.h"
#include "double_list.h"

#define TYPE_USER_AREA			0
#define TYPE_DOMAIN_AREA		1
#define TYPE_MEDIA_AREA		    2
#define VDIR_PER_PARTITION		200


typedef struct _PARTITION_ITEM {
	DOUBLE_LIST_NODE node;
	pthread_t thr_id;
	int type;
	char master[256];
	char database[256];
	char slave[256];
} PARTITION_ITEM;

typedef struct _AREA_ITEM {
	char type[12];
	char master[256];
	char slave[256];
	int space;
	int files;
} AREA_ITEM;


static void remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;

	if (0 != lstat(path, &node_stat)) {
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
		snprintf(temp_path, 255, "%s/%s", path, direntp->d_name);
		remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}

static void copy_file(char *src_file, char *dst_file, size_t size)
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
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	write(fd, pbuff, size);
	free(pbuff);
	close(fd);
}

static void copy_dir(char *src_dir, char *dst_dir)
{
	DIR *dirp;
	char temp_path[256];
	char temp_path1[256];
	struct stat node_stat;
	struct dirent *direntp;
	
	dirp = opendir(src_dir);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", src_dir, direntp->d_name);
		snprintf(temp_path1, 255, "%s/%s", dst_dir, direntp->d_name);
		if (0 != stat(temp_path, &node_stat)) {
			continue;
		}
		if (0 != S_ISDIR(node_stat.st_mode)) {
			copy_dir(temp_path, temp_path1);
		} else {
			copy_file(temp_path, temp_path1, node_stat.st_size);
		}
	}
	closedir(dirp);
}

static void *thread_work_func(void *param)
{
	int i;
	DIR *dirp;
	char link_buff[256];
	char temp_path[256];
	char temp_path1[256];
	struct stat node_stat;
	struct dirent *direntp;
	PARTITION_ITEM *ppartition;
	
	
	ppartition = (PARTITION_ITEM*)param;
	for (i=1; i<=VDIR_PER_PARTITION; i++) {
		sprintf(temp_path, "%s/v%d", ppartition->master, i);
		dirp = opendir(temp_path);
		if (NULL == dirp) {
			continue;
		}
		while ((direntp = readdir(dirp)) != NULL) {
			if (0 == strcmp(direntp->d_name, ".") ||
				0 == strcmp(direntp->d_name, "..") ||
				0 == strcmp(direntp->d_name, "vinfo")) {
				continue;
			}
			sprintf(temp_path, "%s/v%d/%s",
				ppartition->master, i, direntp->d_name);
			if (0 != lstat(temp_path, &node_stat)) {
				continue;
			}
			if ((TYPE_USER_AREA == ppartition->type ||
				TYPE_DOMAIN_AREA == ppartition->type)
				&& 0 != S_ISLNK(node_stat.st_mode)) {
				continue;
			}
			sprintf(temp_path, "%s/v%d/%s/exmdb",
				ppartition->master, i, direntp->d_name);
			if (0 != lstat(temp_path, &node_stat)) {
				continue;
			}
			if ('\0' == ppartition->database[0]) {
				if (0 == S_ISLNK(node_stat.st_mode)) {
					continue;
				}
				memset(temp_path1, 0, 256);
				if (readlink(temp_path, temp_path1, 256) <= 0) {
					continue;
				}
				remove(temp_path);
				mkdir(temp_path, 0777);
				copy_dir(temp_path1, temp_path);
				remove_inode(temp_path1);
			} else {
				sprintf(temp_path1, "%s/v%d/%s",
					ppartition->database, i, direntp->d_name);
				if (0 == S_ISLNK(node_stat.st_mode)) {
					mkdir(temp_path1, 0777);
					copy_dir(temp_path, temp_path1);
					remove_inode(temp_path);
					symlink(temp_path1, temp_path);
				} else {
					memset(link_buff, 0, 256);
					if (readlink(temp_path, link_buff, 256) > 0
						&& 0 == strcmp(temp_path1, link_buff)) {
						continue;
					}
					mkdir(temp_path1, 0777);
					copy_dir(link_buff, temp_path1);
					remove_inode(link_buff);
					remove(temp_path);
					symlink(temp_path1, temp_path);
				}
			}
		}
		closedir(dirp);
	}
	pthread_exit(0);
}

int main(int argc, char **argv)
{
	int i, item_num;
	AREA_ITEM *pitem;
	LIST_FILE *pfile;
	char *pdb_storage;
	char list_path[256];
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST partition_list;
	PARTITION_ITEM *ppartition;
	
	umask(0);
	sprintf(list_path, "../data/area_list.txt");
	pfile = list_file_init(list_path, "%s:12%s:256%s:256%d%d");
	if (NULL == pfile) {
		printf("[engine]: fail to init list file area_list.txt\n");
		exit(-1);
	}
	pitem = (AREA_ITEM*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	double_list_init(&partition_list);
	for (i=0; i<item_num; i++) {
		ppartition = (PARTITION_ITEM*)malloc(sizeof(PARTITION_ITEM));
		if (NULL == ppartition) {
			continue;
		}
		if (0 == strcmp(pitem[i].type, "USER")) {
			ppartition->type = TYPE_USER_AREA;
		} else if (0 == strcmp(pitem[i].type, "DOMAIN")) {
			ppartition->type = TYPE_DOMAIN_AREA;
		} else if (0 == strcmp(pitem[i].type, "MEDIA")) {
			ppartition->type = TYPE_MEDIA_AREA;
		} else {
			free(ppartition);
			continue;
		}
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL != pdb_storage) {
			*pdb_storage = '\0';
			pdb_storage ++;
		}
		strcpy(ppartition->master, pitem[i].master);
		if (NULL != pdb_storage) {
			strcpy(ppartition->database, pdb_storage);
		} else {
			ppartition->database[0] = '\0';
		}
		strcpy(ppartition->slave, pitem[i].slave);
		ppartition->node.pdata = ppartition;
		if (0 != pthread_create(&ppartition->thr_id,
			NULL, thread_work_func, ppartition)) {
			free(ppartition);
		} else {
			double_list_append_as_tail(&partition_list, &ppartition->node);
		}
	}
	list_file_free(pfile);
	
	while ((pnode = double_list_get_from_head(&partition_list)) != NULL) {
		ppartition = (PARTITION_ITEM*)pnode->pdata;
		pthread_join(ppartition->thr_id, NULL);	
		free(ppartition);
	}
	double_list_free(&partition_list);
	exit(0);
}
