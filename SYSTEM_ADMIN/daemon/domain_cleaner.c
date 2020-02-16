#include <stdlib.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include "domain_cleaner.h"
#include "data_source.h"
#include <gromox/locker_client.h>
#include "message.h"
#include "smtp_sender.h"
#include "util.h"
#include "config_file.h"
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static time_t g_now_time;

static void domain_cleaner_delete_domain(const char *domainname,
	const char *homedir);

static void domain_cleaner_free_dir(const char *dir);

static void domain_cleaner_partition_info(char *s, int *pmegas, int *pfiles,
	int *phomes);

static void domain_cleaner_remove_inode(const char *path);

void domain_cleaner_init(time_t now_time)
{
	g_now_time = now_time;

}

int domain_cleaner_run()
{
	char *str_value;
	char sender[256];
	char language[32];
	char temp_path[256];
	char admin_mailbox[256];
	char message_buff[MESSAGE_BUFF_SIZE];
	DATA_COLLECT *pcollect;
	DELETED_DOMAIN *pdeleted;
	DOMAIN_INFO	*pdomain_info;
	CONFIG_FILE *pconfig;
	
	data_source_clean_deleted_alias();

	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		return 0;
	}
	if (TRUE == data_source_get_deleted_domain(pcollect)) {
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdeleted = (DELETED_DOMAIN*)data_source_collect_get_value(pcollect);
			domain_cleaner_delete_domain(pdeleted->domainname,
				pdeleted->homedir);
		}

	}
	data_source_collect_free(pcollect);

	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		return 0;
	}
	if (TRUE == data_source_get_domain_list(pcollect)) {
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_info = (DOMAIN_INFO*)data_source_collect_get_value(pcollect);
			if (RECORD_STATUS_OUTOFDATE == pdomain_info->status &&
				g_now_time > pdomain_info->end_day &&
				g_now_time - pdomain_info->end_day > 7*24*60*60) {
				domain_cleaner_delete_domain(pdomain_info->domainname,
					pdomain_info->homedir);
			} else if (RECORD_STATUS_NORMAL == pdomain_info->status &&
				pdomain_info->end_day < g_now_time) {
				data_source_make_outofdate(pdomain_info->domainname);
				sprintf(temp_path, "%s/domain.cfg", pdomain_info->homedir);
				pconfig = config_file_init2(NULL, temp_path);
				if (NULL != pconfig) {
					str_value = config_file_get_value(pconfig, "ADMIN_MAILBOX");
					if (NULL != str_value) {
						strcpy(admin_mailbox, str_value);
						str_value = config_file_get_value(pconfig,
										"REPORT_LANGUAGE");
						if (NULL == str_value) {
							strcpy(language, "en");
						} else {
							strcpy(language, str_value);
						}
						message_make(message_buff, MESSAGE_TURN_OUTOFDATE,
							language, pdomain_info->domainname, admin_mailbox);
						sprintf(sender, "notifier@%s", pdomain_info->domainname);
						smtp_sender_send(sender, admin_mailbox, message_buff,
							strlen(message_buff));
					}
					config_file_free(pconfig);	
				}
			} else if (RECORD_STATUS_NORMAL == pdomain_info->status &&
				pdomain_info->end_day > g_now_time &&
				pdomain_info->end_day - g_now_time >= 6*24*60*60 &&
				pdomain_info->end_day - g_now_time <= 7*24*60*60) {
				sprintf(temp_path, "%s/domain.cfg", pdomain_info->homedir);
				pconfig = config_file_init2(NULL, temp_path);
				if (NULL != pconfig) {
					str_value = config_file_get_value(pconfig, "ADMIN_MAILBOX");
					if (NULL != str_value) {
						strcpy(admin_mailbox, str_value);
						str_value = config_file_get_value(pconfig,
										"REPORT_LANGUAGE");
						if (NULL == str_value) {
							strcpy(language, "en");
						} else {
							strcpy(language, str_value);
						}
						message_make(message_buff, MESSAGE_WILL_OUTOFDATE,
							language, pdomain_info->domainname, admin_mailbox);
						sprintf(sender, "notifier@%s", pdomain_info->domainname);
						smtp_sender_send(sender, admin_mailbox, message_buff,
							strlen(message_buff));
					}
					config_file_free(pconfig);	
				}
			}

		}
	}
	data_source_collect_free(pcollect);
	return 0;
}

int domain_cleaner_stop()
{
	/* do nothing */
	return 0;
}

void domain_cleaner_free()
{
	/* do nothing */
}

static void domain_cleaner_delete_domain(const char *domainname,
	const char *homedir)
{
	LOCKD lockd;
	LOCKD lockd1;
	char mediadir[128];
	USER_INFO *puser_info;
	struct stat node_stat;
	DATA_COLLECT *pcollect;
	char resource_name[256];
	
	sprintf(resource_name, "DATABASE-%s", domainname);
	HX_strupper(resource_name);
	lockd = locker_client_lock(resource_name);
	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		locker_client_unlock(lockd);
		return;
	}
	if (FALSE == data_source_get_user_list(domainname, pcollect)) {
		data_source_collect_free(pcollect);
		locker_client_unlock(lockd);
		return;
	}
	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		puser_info = (USER_INFO*)data_source_collect_get_value(pcollect);
		if (0 == lstat(puser_info->maildir, &node_stat) &&
			0 != S_ISLNK(node_stat.st_mode)) {
			memset(mediadir, 0, 128);
			if (readlink(puser_info->maildir, mediadir, 128) > 0) {
				lockd1 = locker_client_lock("MEDIA-AREA");
				domain_cleaner_free_dir(mediadir);
				locker_client_unlock(lockd1);
				remove(puser_info->maildir);
				mkdir(puser_info->maildir, 0777);
			}
		}
		lockd1 = locker_client_lock("USER-AREA");
		domain_cleaner_free_dir(puser_info->maildir);
		locker_client_unlock(lockd1);
	}
	data_source_collect_free(pcollect);

	if (0 == lstat(homedir, &node_stat) &&
		0 != S_ISLNK(node_stat.st_mode)) {
		memset(mediadir, 0, 128);
		if (readlink(homedir, mediadir, 128) > 0) {
			lockd1 = locker_client_lock("MEDIA-AREA");
			domain_cleaner_free_dir(mediadir);
			locker_client_unlock(lockd1);
			remove(homedir);
			mkdir(homedir, 0777);
		}
	}
			
	lockd1 = locker_client_lock("DOMAIN-AREA");
	domain_cleaner_free_dir(homedir);
	locker_client_unlock(lockd1);

	data_source_delete_domain(domainname);
	locker_client_unlock(lockd);

}

static void domain_cleaner_free_dir(const char *dir)
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
	snprintf(temp_path1, sizeof(temp_path1), "%s/../vinfo.%lld",
	         dir, static_cast(long long, cur_time));
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
	snprintf(temp_path1, sizeof(temp_path1), "%s/../../pinfo.%lld",
	         dir, static_cast(long long, cur_time));
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
	
	domain_cleaner_partition_info(temp_buff, &space, &files, &homes);
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
	sprintf(temp_path, "%s/exmdb", dir);
	if (0 == lstat(temp_path, &node_stat) &&
		0 != S_ISLNK(node_stat.st_mode)) {
		memset(temp_path1, 0, 256);
		if (readlink(temp_path, temp_path1, 256) > 0) {
			domain_cleaner_remove_inode(temp_path1);
		}
	}
	domain_cleaner_remove_inode(dir);
}

static void domain_cleaner_partition_info(char *s, int *pmegas, int *pfiles,
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


static void domain_cleaner_remove_inode(const char *path)
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
		domain_cleaner_remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}

