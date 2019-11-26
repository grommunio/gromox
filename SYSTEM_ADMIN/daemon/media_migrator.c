#include "media_migrator.h"
#include "data_source.h"
#include <gromox/locker_client.h>
#include "list_file.h"
#include "system_log.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define DEF_MODE                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define VDIR_PER_PARTITION      200

#define MEDIADIR_PER_VDIR		250

typedef struct _AREA_ITEM {
	char type[12];
	char master[256];
	char slave[256];
	int space;
	int files;
} AREA_ITEM;

typedef struct _AREA_NODE {
	DOUBLE_LIST_NODE node;
	char master[256];
	char slave[256];
	int max_space;
	int used_space;
	int used_files;
	int homes;
} AREA_NODE;


static char g_list_path[256];

static void media_migrator_copydir(char *src_path, char *dst_path);

static void media_migrator_copyfile(char *src_file, char *dst_file, int size);

static BOOL media_migrator_allocate_mediadir(const char *media_area,
	char *path_buff);

static void media_migrator_free_mediadir(const char *dir);

static void media_migrator_partition_info(char *s, int *pmegas, int *pfiles,
	int *phomes);

static void media_migrator_remove_inode(const char *path);

void media_migrator_init(const char *area_path)
{
	strcpy(g_list_path, area_path);
}

int media_migrator_run()
{
	LOCKD lockd;
	char temp_path[256];
	struct stat node_stat;
	DATA_COLLECT *pcollect;
	DATA_COLLECT *pcollect1;
	USER_INFO *puser_info;
	MEDIA_DOMAIN *pdomain_info;
	

	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		system_log_info("[media_migrator]: fail to run media "
			"migration, allocate memory error");
		return 0;
	}
	if (TRUE == data_source_get_media_domain(
		MEDIA_TYPE_IMMIGRATION, pcollect)) {
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_info = (MEDIA_DOMAIN*)data_source_collect_get_value(pcollect);
			if ('\0' == pdomain_info->media[0]) {
				system_log_info("[media_migrator]: fail to immigrate domain %s"
					" and it's users, \"media\" field error",
					pdomain_info->domainname);
				continue;
			}
			if (FALSE == data_source_status_media(pdomain_info->domainname,
				MEDIA_STATUS_IMMIGRATING)) {
				system_log_info("[media_migrator]: fail to immigrate domain %s"
					" and it's users, database operation error",
					pdomain_info->domainname);
				continue;
			}
			if (0 != lstat(pdomain_info->homedir, &node_stat)) {
				system_log_info("[media_migrator]: fail to immigrate "
					"domain %s, stat %s error", pdomain_info->domainname,
					pdomain_info->homedir);
				goto IMMIGRATE_USERS;
			}
			if (0 != S_ISLNK(node_stat.st_mode)) {
				/* alread link to media area */
				goto IMMIGRATE_USERS;
			}
			if (FALSE == media_migrator_allocate_mediadir(
				pdomain_info->media, temp_path)) {
				system_log_info("[media_migrator]: fail to allocat media "
					"directory for domain %s", pdomain_info->domainname);
				goto IMMIGRATE_USERS;
			}
			media_migrator_copydir(pdomain_info->homedir, temp_path);
			media_migrator_remove_inode(pdomain_info->homedir);
			symlink(temp_path, pdomain_info->homedir);
			
IMMIGRATE_USERS:
			pcollect1 = data_source_collect_init();
			if (NULL == pcollect1) {
				system_log_info("[media_migrator]: fail to immigrate "
					"users of domain %s, allocate memory error",
					pdomain_info->domainname);
				data_source_status_media(pdomain_info->domainname,
					MEDIA_STATUS_IMMIGRATED);
				continue;
			}
			
			if (FALSE == data_source_get_user_list(
				pdomain_info->domainname, pcollect1)) {
				system_log_info("[media_migrator]: fail to immigrate "
					"users of domain %s, load user list from database error",
					pdomain_info->domainname);
				data_source_collect_free(pcollect1);
				data_source_status_media(pdomain_info->domainname,
					MEDIA_STATUS_IMMIGRATED);
				continue;
			}
			
			for (data_source_collect_begin(pcollect1);
				!data_source_collect_done(pcollect1);
				data_source_collect_forward(pcollect1)) {
				puser_info = (USER_INFO*)data_source_collect_get_value(pcollect1);
				if (0 != lstat(puser_info->maildir, &node_stat)) {
					system_log_info("[media_migrator]: fail to immigrate "
						"user %s, stat %s error", puser_info->username,
						puser_info->maildir);
					continue;
				}
				if (0 != S_ISLNK(node_stat.st_mode)) {
					/* alread link to media area */
					continue;
				}
				if (FALSE == media_migrator_allocate_mediadir(
					pdomain_info->media, temp_path)) {
					system_log_info("[media_migrator]: fail to allocat media "
						"directory for user %s", puser_info->username);
					continue;
				}
				media_migrator_copydir(puser_info->maildir, temp_path);
				media_migrator_remove_inode(puser_info->maildir);
				symlink(temp_path, puser_info->maildir);		
			}
			data_source_collect_free(pcollect1);

			data_source_status_media(pdomain_info->domainname,
				MEDIA_STATUS_IMMIGRATED);
		}

	}
	data_source_collect_free(pcollect);

	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		system_log_info("[media_migrator]: fail to run media "
			"emigration, allocate memory error");
		return 0;
	}
	
	lockd = locker_client_lock("MEDIA-AREA");

	if (TRUE == data_source_get_media_domain(
		MEDIA_TYPE_EMIGRATION, pcollect)) {
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_info = (MEDIA_DOMAIN*)data_source_collect_get_value(pcollect);
			if (FALSE == data_source_status_media(pdomain_info->domainname,
				MEDIA_STATUS_EMIGRATING)) {
				system_log_info("[media_migrator]: fail to emigrate domain %s"
					" and it's users, database operation error",
					pdomain_info->domainname);
				continue;
			}
			if (0 != lstat(pdomain_info->homedir, &node_stat)) {
				system_log_info("[media_migrator]: fail to emigrate "
					"domain %s, stat %s error", pdomain_info->domainname,
					pdomain_info->homedir);
				goto EMIGRATE_USERS;
			}
			if (0 != S_ISDIR(node_stat.st_mode)) {
				/* alread directory */
				goto EMIGRATE_USERS;
			}

			memset(temp_path, 0, 256);
			if (readlink(pdomain_info->homedir, temp_path, 256) <= 0) {
				system_log_info("[media_migrator]: fail to emigrate "
					"domain %s, read symbol link of  %s error",
					pdomain_info->domainname, pdomain_info->homedir);
				goto EMIGRATE_USERS;
			}
			remove(pdomain_info->homedir);
			mkdir(pdomain_info->homedir, 0777);

			media_migrator_copydir(temp_path, pdomain_info->homedir);
			media_migrator_free_mediadir(temp_path);
			
EMIGRATE_USERS:
			pcollect1 = data_source_collect_init();
			if (NULL == pcollect1) {
				system_log_info("[media_migrator]: fail to emigrate "
					"users of domain %s, allocate memory error",
					pdomain_info->domainname);
				data_source_status_media(pdomain_info->domainname,
					MEDIA_STATUS_EMIGRATED);
				continue;
			}
			
			if (FALSE == data_source_get_user_list(
				pdomain_info->domainname, pcollect1)) {
				system_log_info("[media_migrator]: fail to emigrate "
					"users of domain %s, load user list from database error",
					pdomain_info->domainname);
				data_source_collect_free(pcollect1);
				data_source_status_media(pdomain_info->domainname,
					MEDIA_STATUS_EMIGRATED);
				continue;
			}
			
			for (data_source_collect_begin(pcollect1);
				!data_source_collect_done(pcollect1);
				data_source_collect_forward(pcollect1)) {
				puser_info = (USER_INFO*)data_source_collect_get_value(pcollect1);
				if (0 != lstat(puser_info->maildir, &node_stat)) {
					system_log_info("[media_migrator]: fail to emigrate "
						"user %s, stat %s error", puser_info->username,
						puser_info->maildir);
					continue;
				}
				if (0 != S_ISDIR(node_stat.st_mode)) {
					/* alread directory */
					continue;
				}

				memset(temp_path, 0, 256);
				if (readlink(puser_info->maildir, temp_path, 256) <= 0) {
					system_log_info("[media_migrator]: fail to emigrate "
						"user %s, read symbol link of  %s error",
						puser_info->username, puser_info->maildir);
					continue;
				}
				remove(puser_info->maildir);
				mkdir(puser_info->maildir, 0777);

				media_migrator_copydir(temp_path, puser_info->maildir);
				media_migrator_free_mediadir(temp_path);
			}
			data_source_collect_free(pcollect1);

			data_source_status_media(pdomain_info->domainname,
				MEDIA_STATUS_EMIGRATED);
		}

	}
	data_source_collect_free(pcollect);

	locker_client_unlock(lockd);
	return 0;
}

int media_migrator_stop()
{
	/* do nothing */
	return 0;
}

void media_migrator_free()
{
	/* do nothing */
}


static void media_migrator_free_mediadir(const char *dir)
{	
	int fd, len;
	int space, files, homes;
	time_t cur_time;
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[1204];
	struct stat node_stat;


	if (0 != lstat(dir, &node_stat)) {
		return;
	}


	time(&cur_time);
	sprintf(temp_path, "%s/../vinfo", dir);
	sprintf(temp_path1, "%s/../vinfo.%d", dir, cur_time);
	fd = open(temp_path, O_RDONLY);
	
	if (-1 == fd) {
		return;
	}
	
	len = read(fd, temp_buff, 1024);
	close(fd);
	if (len <= 0) {
		return;
	}
	temp_buff[len] = '\0';
	homes = atoi(temp_buff);
	
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	len = sprintf(temp_buff, "%dH", homes - 1);
	write(fd, temp_buff, len);
	close(fd);
	rename(temp_path1, temp_path);
	
	sprintf(temp_path, "%s/../../pinfo", dir);
	sprintf(temp_path1, "%s/../../pinfo.%d", dir, cur_time);
	fd = open(temp_path, O_RDONLY);

	if (-1 == fd) {
		return;
	}
	
	len = read(fd, temp_buff, 1024);
	close(fd);
	if (len <= 0) {
		return;
	}
	temp_buff[len] = '\0';
	
	media_migrator_partition_info(temp_buff, &space, &files, &homes);
	if (-1 == space || -1== files || -1 == homes) {
		return;
	}
	
	fd = open(temp_path1, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		return;
	}

	len = sprintf(temp_buff, "%dM,%dC,%dH", space, files, homes - 1);
	write(fd, temp_buff, len);
	close(fd);
	rename(temp_path1, temp_path);
	
	media_migrator_remove_inode(dir);
}

static void media_migrator_remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;

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
		snprintf(temp_path, 256, "%s/%s", path, direntp->d_name);
		media_migrator_remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}


static BOOL media_migrator_allocate_mediadir(const char *media_area,
	char *path_buff)
{
	time_t cur_time;
	LOCKD lockd;
	int v_index;
	int mini_vdir;
	int mini_homes;
	int total_space;
	int total_used;
	int total_homes;
	int i, fd, len, item_num;
	int space, files, homes;
	int average_space;
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[1024];
	struct stat node_stat;
	LIST_FILE *pfile;
	AREA_ITEM *pitem;
	AREA_NODE *parea;
	DOUBLE_LIST_NODE *pnode;
	AREA_NODE *pleast_area;
	DOUBLE_LIST temp_list;

	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");

	if (NULL == pfile) {
		system_log_info("[media_migrator]: fail to init list file %s",
			g_list_path);
		return FALSE;
	}
	lockd = locker_client_lock("MEDIA-AREA");
	total_space = 0;
	total_used = 0;
	total_homes = 0;
	double_list_init(&temp_list);
	pitem = (AREA_ITEM*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<item_num; i++) {
		if (0 != strcmp(pitem[i].type, "MEDIA") ||
			0 != strcmp(pitem[i].master, media_area)) {
			continue;
		}
		sprintf(temp_path, "%s/pinfo", pitem[i].master);
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			continue;
		}
		len = read(fd, temp_buff, 1024);
		close(fd);
		if (len <= 0) {
			close(fd);
			continue;
		}
		temp_buff[len] = '\0';
		
		media_migrator_partition_info(temp_buff, &space, &files, &homes);
		
		if (-1 == space || -1 == files || -1 == homes) {
			continue;
		}
		total_space += pitem[i].space;
		total_used += space;
		total_homes += homes;
		if (space < pitem[i].space && files < pitem[i].files &&
			homes < VDIR_PER_PARTITION*MEDIADIR_PER_VDIR) {
			parea = (AREA_NODE*)malloc(sizeof(AREA_NODE));
			if (NULL == parea) {
				continue;
			}
			parea->node.pdata = parea;
			strcpy(parea->master, pitem[i].master);
			parea->max_space = pitem[i].space;
			parea->used_space = space;
			parea->used_files = files;
			parea->homes = homes;
			double_list_append_as_tail(&temp_list, &parea->node);
		}
	}
	list_file_free(pfile);
	
	if (0 == double_list_get_nodes_num(&temp_list)) {
		double_list_free(&temp_list);
		system_log_info("[media_migrator]: cannot find a available data area for "
			"domain");
		locker_client_unlock(lockd);
		return FALSE;
	}
	if (0 == total_homes) {
		average_space = 1;
	} else {
		average_space = total_space / total_homes;
	}
	if (average_space < 1) {
		average_space = 1;
	}
	pleast_area = NULL;
	for (pnode=double_list_get_head(&temp_list); NULL!=pnode;
		pnode=double_list_get_after(&temp_list, pnode)) {
		parea = (AREA_NODE*)pnode->pdata;
		if (NULL == pleast_area) {
			pleast_area = parea;
		} else {
			if (parea->homes/(((double)parea->max_space)/average_space) <
				pleast_area->homes/(((double)pleast_area->max_space)/average_space)) {
				pleast_area = parea;
			}
		}
	}
	mini_homes = -1;
	for (i=1; i<=VDIR_PER_PARTITION; i++) {
		sprintf(temp_path, "%s/v%d/vinfo", pleast_area->master, i);
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			continue;
		}

		len = read(fd, temp_buff, 1024);
		
		close(fd);
		
		if (len <= 0) {
			continue;
		}
		temp_buff[len] = '\0';
		homes = atoi(temp_buff);
		if (mini_homes < 0) {
			mini_homes = homes;
			mini_vdir = i;
		} else if (mini_homes > homes) {
			mini_homes = homes;
			mini_vdir = i;
		}
	}
	if (-1 == mini_homes || mini_homes >= MEDIADIR_PER_VDIR) {
		system_log_info("[media_migrator]: seems allocation information of data area "
			"%s or it's vdir information error, please check it!",
			pleast_area->master);
		while ((pnode = double_list_get_from_head(&temp_list)) != NULL)
			free(pnode->pdata);
		double_list_free(&temp_list);
		locker_client_unlock(lockd);
		return FALSE;
	}
	
	for (i=1; i<=MEDIADIR_PER_VDIR; i++) {
		sprintf(temp_path, "%s/v%d/%d", pleast_area->master, mini_vdir, i);
		if (0 != lstat(temp_path, &node_stat)) {
			break;
		}
	}
	if (i > MEDIADIR_PER_VDIR) {
		system_log_info("[media_migrator]: seems allocation information of vdir %d "
			"under data area %s error, please check it!", mini_vdir,
			pleast_area->master);
		while ((pnode = double_list_get_from_head(&temp_list)) != NULL)
			free(pnode->pdata);
		double_list_free(&temp_list);
		locker_client_unlock(lockd);
		return FALSE;	
	}
	
	v_index = i;
	
	time(&cur_time);
	sprintf(temp_path, "%s/v%d/vinfo.%d", pleast_area->master,
		mini_vdir, cur_time);
	sprintf(temp_path1, "%s/v%d/vinfo", pleast_area->master, mini_vdir);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 != fd) {
		len = sprintf(temp_buff, "%dH", mini_homes + 1);
		write(fd, temp_buff, len);
		close(fd);
		rename(temp_path, temp_path1);
	}
	sprintf(temp_path, "%s/pinfo.%d", pleast_area->master, cur_time);
	sprintf(temp_path1, "%s/pinfo", pleast_area->master);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 != fd) {
		len = sprintf(temp_buff, "%dM,%dC,%dH", pleast_area->used_space,
				pleast_area->used_files, pleast_area->homes + 1);
		write(fd, temp_buff, len);
		close(fd);
		rename(temp_path, temp_path1);
	}
	
	sprintf(temp_path, "%s/v%d/%d", pleast_area->master, mini_vdir, v_index);
	while ((pnode = double_list_get_from_head(&temp_list)) != NULL)
		free(pnode->pdata);
	double_list_free(&temp_list);
	
	if (0 == mkdir(temp_path, 0777)) {
		strcpy(path_buff, temp_path);
		locker_client_unlock(lockd);
		return TRUE;
	}
	system_log_info("[media_migrator]: fail to make directory under %s/v%d",
		temp_path1, mini_vdir);
	locker_client_unlock(lockd);
	return FALSE;
}


static void media_migrator_partition_info(char *s, int *pmegas, int *pfiles,
	int *phomes)
{
	char *plast;
	char *ptoken;

	plast = s;
	ptoken = strchr(plast, 'M');
	if (NULL == ptoken) {
		*pmegas = -1;
	} else {
		*ptoken = '\0';
		*pmegas = atoi(plast);
		if (',' == *(ptoken + 1)) {
			ptoken ++;
		}
		plast = ptoken + 1;
	}
	ptoken = strchr(plast, 'C');
	if (NULL == ptoken) {
		*pfiles = -1;
	} else {
		*ptoken = '\0';
		*pfiles = atoi(plast);
		if (',' == *(ptoken + 1)) {
			ptoken ++;
		}
		plast = ptoken + 1;
	}
	ptoken = strchr(plast, 'H');
	if (NULL == ptoken) {
		*phomes = -1;
	} else {
		*ptoken = '\0';
		*phomes = atoi(plast);
	}
}


static void media_migrator_copydir(char *src_path, char *dst_path)
{
	DIR *dirp;
	char temp_path[256];
	char temp_path1[256];
	struct dirent *direntp;
	struct stat node_stat;

	dirp = opendir(src_path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", src_path, direntp->d_name);
		snprintf(temp_path1, 255, "%s/%s", dst_path, direntp->d_name);
		if (0 != stat(temp_path, &node_stat)) {
			continue;
		}
		if (0 == S_ISDIR(node_stat.st_mode)) {
			media_migrator_copyfile(temp_path, temp_path1, node_stat.st_size);
		} else {
			mkdir(temp_path1, 0777);
			media_migrator_copydir(temp_path, temp_path1);
		}
	}
	closedir(dirp);

}

static void media_migrator_copyfile(char *src_file, char *dst_file, int size)
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
}

