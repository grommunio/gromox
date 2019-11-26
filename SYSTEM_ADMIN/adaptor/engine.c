#include <ctype.h>
#include <stdlib.h>
#include "engine.h"
#include "file_operation.h"
#include "gateway_control.h"
#include "data_source.h"
#include "config_file.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static BOOL g_notify_stop;
static pthread_t g_thread_id1;
static pthread_t g_thread_id2;
static char g_mount_path[256];
static char g_domainlist_path[256];
static char g_aliasaddress_path[256];
static char g_aliasdomain_path[256];
static char g_backup_path[256];
static char g_unchkusr_path[256];
static char g_collector_path[256];
static char g_subsystem_path[256];

static void* thread_work_func1(void *param);

static void* thread_work_func2(void *param);

void engine_init(const char *mount_path, const char *domainlist_path,
	const char *aliasaddress_path, const char *aliasdomain_path,
	const char *backup_path, const char *unchkusr_path,
	const char *collector_path, const char *subsystem_path)
{
	strcpy(g_mount_path, mount_path);
	strcpy(g_domainlist_path, domainlist_path);
	strcpy(g_aliasaddress_path, aliasaddress_path);
	strcpy(g_aliasdomain_path, aliasdomain_path);
	strcpy(g_backup_path, backup_path);
	strcpy(g_unchkusr_path, unchkusr_path);
	strcpy(g_collector_path, collector_path);
	strcpy(g_subsystem_path, subsystem_path);
}


int engine_run()
{
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_thread_id1, NULL, thread_work_func1, NULL) ||
		0 != pthread_create(&g_thread_id2, NULL, thread_work_func2, NULL)) {
		g_notify_stop = TRUE;
		printf("[engine]: fail to create work thread\n");
		return -1;
	}
	return 0;
}

int engine_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id1, NULL);
		pthread_join(g_thread_id2, NULL);
	}
	return 0;
}

void engine_free()
{
	/* do nothing */
}

static void* thread_work_func1(void *param)
{
	int count;
	int fd, fd1, len;
	char *str_value;
	char temp_domain[257];
	char temp_line[1024];
	char temp_path[256];
	char temp_path1[256];
	CONFIG_FILE *pconfig;
	DOMAIN_ITEM *pdomain_item;
	ALIAS_ITEM *palias_item;
	DATA_COLLECT *pcollect;

	remove(g_domainlist_path);
	remove(g_aliasaddress_path);
	remove(g_aliasdomain_path);
	remove(g_backup_path);
	remove(g_unchkusr_path);
	remove(g_collector_path);
	remove(g_subsystem_path);
	
	count = 0;
	while (FALSE == g_notify_stop) {
		if (count < 30) {
			count ++;
			sleep(1);
			continue;
		}
		
DOMAIN_LIST:		
		pcollect = data_source_collect_init();
	
		if (NULL == pcollect) {
			goto NEXT_LOOP;
		}
		
		if (FALSE == data_source_get_domain_list(pcollect)) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		sprintf(temp_path, "%s.tmp", g_domainlist_path);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
	
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(
							pcollect);
			len = sprintf(temp_domain, "%s\n", pdomain_item->domainname);
			write(fd, temp_domain, len);
		}
		close(fd);

		if (0 != file_operation_compare(temp_path, g_domainlist_path)) {
			rename(temp_path, g_domainlist_path);
			file_operation_broadcast(g_domainlist_path,
				"data/smtp/domain_list.txt");
			file_operation_broadcast(g_domainlist_path,
				"data/delivery/domain_list.txt");
			gateway_control_notify("domain_list.svc reload",
				NOTIFY_SMTP|NOTIFY_DELIVERY);
		}
		
ALIAS_LIST:
		data_source_collect_clear(pcollect);

		if (FALSE == data_source_get_alias_list(pcollect)) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		sprintf(temp_path, "%s.tmp", g_aliasaddress_path);
		sprintf(temp_path1, "%s.tmp", g_aliasdomain_path);
		
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		fd1 = open(temp_path1, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd1) {
			close(fd);
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}

		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			palias_item = (ALIAS_ITEM*)data_source_collect_get_value(pcollect);
			len = sprintf(temp_line, "%s\t%s\n", palias_item->aliasname,
				palias_item->mainname);
			if (NULL != strchr(palias_item->aliasname, '@')) {
				write(fd, temp_line, len);
			} else {
				write(fd1, temp_line, len);
			}
		}
		close(fd);
		close(fd1);

		if (0 != file_operation_compare(temp_path, g_aliasaddress_path)) {
			rename(temp_path, g_aliasaddress_path);
			file_operation_broadcast(g_aliasaddress_path,
				"data/delivery/alias_addresses.txt");
			gateway_control_notify("alias_translator.hook reload addresses",
				NOTIFY_DELIVERY);
		}

		if (0 != file_operation_compare(temp_path1, g_aliasdomain_path)) {
			rename(temp_path1, g_aliasdomain_path);
			file_operation_broadcast(g_aliasdomain_path,
				"data/delivery/alias_domains.txt");
			gateway_control_notify("alias_translator.hook reload domains",
				NOTIFY_DELIVERY);
		}
		
BACKUP_LIST:
		data_source_collect_clear(pcollect);

		if (FALSE == data_source_get_backup_list(pcollect)) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		sprintf(temp_path, "%s.tmp", g_backup_path);
		
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(pcollect);
			len = sprintf(temp_line, "%s\n", pdomain_item->domainname);
			write(fd, temp_line, len);
		}
		close(fd);
		
		if (0 != file_operation_compare(temp_path, g_backup_path)) {
			rename(temp_path, g_backup_path);
			file_operation_broadcast(g_backup_path,
				"data/delivery/backup_list.txt");
			gateway_control_notify("backup_list.svc reload",
				NOTIFY_DELIVERY);
		}

UNCHKUSR_LIST:
		data_source_collect_clear(pcollect);

		if (FALSE == data_source_get_uncheckusr_list(pcollect)) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		sprintf(temp_path, "%s.tmp", g_unchkusr_path);
		
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(pcollect);
			len = sprintf(temp_line, "%s\n", pdomain_item->domainname);
			write(fd, temp_line, len);
		}
		close(fd);
		
		if (0 != file_operation_compare(temp_path, g_unchkusr_path)) {
			rename(temp_path, g_unchkusr_path);
			file_operation_broadcast(g_unchkusr_path,
				"data/smtp/uncheck_domains.txt");
			gateway_control_notify("mysql_adaptor.svc reload uncheck-domains",
				NOTIFY_SMTP);
		}
	
		sprintf(temp_path, "%s.tmp", g_collector_path);

		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}

		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(pcollect);
			sprintf(temp_path1, "%s/domain.cfg", pdomain_item->homedir);
			pconfig = config_file_init(temp_path1);
			if (NULL != pconfig) {
				str_value = config_file_get_value(pconfig, "COLLECTOR_MAILBOX");
				if (NULL != str_value) {
					len = sprintf(temp_line, "%s\t%s\n",
							pdomain_item->domainname, str_value);
					write(fd, temp_line, len);
				}
				config_file_free(pconfig);
			}
		}
		close(fd);
		
		if (0 != file_operation_compare(temp_path, g_collector_path)) {
			rename(temp_path, g_collector_path);
			file_operation_broadcast(g_collector_path,
				"data/delivery/mailbox_collector.txt");
			gateway_control_notify("mailbox_collector.hook reload",
				NOTIFY_DELIVERY);
		}
		
SUBSYSTEM_LIST:
		data_source_collect_clear(pcollect);

		if (FALSE == data_source_get_subsystem_list(pcollect)) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		sprintf(temp_path, "%s.tmp", g_subsystem_path);
		
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}

		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(pcollect);
			sprintf(temp_path1, "%s/domain.cfg", pdomain_item->homedir);
			pconfig = config_file_init(temp_path1);
			if (NULL != pconfig) {
				str_value = config_file_get_value(pconfig, "SUBSYSTEM_ADDRESS");
				if (NULL != str_value) {
					len = sprintf(temp_line, "%s\t%s\n",
							pdomain_item->domainname, str_value);
					write(fd, temp_line, len);
				}
				config_file_free(pconfig);
			}
		}
		close(fd);
		
		if (0 != file_operation_compare(temp_path, g_subsystem_path)) {
			rename(temp_path, g_subsystem_path);
			file_operation_broadcast(g_subsystem_path,
				"data/delivery/domain_subsystem.txt");
			gateway_control_notify("domain_subsystem.hook reload",
				NOTIFY_DELIVERY);
		}
		
		data_source_collect_free(pcollect);
		
NEXT_LOOP:
		count = 0;
	}
	return NULL;
}

static void* thread_work_func2(void *param)
{
	BOOL b_found;
	int count;
	int i, len;
	DIR *dirp, *dirp1;
	char *str_value;
	char *pdomain;
	char fake_group[128];
	char temp_domain[257];
	char temp_group[257];
	char temp_path[256];
	char temp_path1[256];
	char command_string[256];
	struct dirent *direntp;
	struct dirent *direntp1;
	struct stat node_stat;
	CONFIG_FILE *pconfig;
	DOMAIN_ITEM *pdomain_item;
	GROUP_ITEM *pgroup_item;
	DATA_COLLECT *pcollect;

	
	count = 0;
	while (FALSE == g_notify_stop) {
		if (count < 3600) {
			count ++;
			sleep(1);
			continue;
		}
		
		pcollect = data_source_collect_init();
	
		if (NULL == pcollect) {
			goto NEXT_LOOP;
		}
		
		if (FALSE == data_source_get_domain_list(pcollect)) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(
							pcollect);
			sprintf(temp_path, "%s/limit.txt", pdomain_item->homedir);
			if (0 != stat(temp_path, &node_stat)) {
				pdomain_item->type = 0;
				continue;
			}
			sprintf(temp_path, "%s/domain.cfg", pdomain_item->homedir);
			
			pconfig = config_file_init(temp_path);
			if (NULL == pconfig) {
				pdomain_item->type = 0;	
			} else {
				str_value = config_file_get_value(pconfig, "LIMIT_TYPE");
				if (NULL == str_value) {
					pdomain_item->type = 0;	
				} else {
					if (2 == atoi(str_value)) {
						pdomain_item->type = 2;
					} else {
						if (0 == node_stat.st_size) {
							pdomain_item->type = 0;
						} else {
							pdomain_item->type = 1;
						}
					}
				}
				config_file_free(pconfig);
			}
		}
		
		dirp = opendir(g_mount_path);
		if (NULL == dirp) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		while ((direntp = readdir(dirp)) != NULL) {
			if (0 == strcmp(".", direntp->d_name) ||
				0 == strcmp("..", direntp->d_name)) {
				continue;
			}
			for (data_source_collect_begin(pcollect);
				!data_source_collect_done(pcollect);
				data_source_collect_forward(pcollect)) {
				pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(
								pcollect);
				if (1 == pdomain_item->type) {
					sprintf(temp_path, "%s/%s/data/smtp/domain_limit/deny/%s.txt",
						g_mount_path, direntp->d_name, pdomain_item->domainname);
					sprintf(command_string, "domain_limit.pas add deny %s",
						pdomain_item->domainname);
				} else if (2 == pdomain_item->type) {
					sprintf(temp_path, "%s/%s/data/smtp/domain_limit/allow/%s.txt",
						g_mount_path, direntp->d_name, pdomain_item->domainname);
					sprintf(command_string, "domain_limit.pas add allow %s",
						pdomain_item->domainname);
				} else {
					continue;
				}
				if (0 == stat(temp_path, &node_stat)) {
					continue;
				}
				
				sprintf(temp_path1, "%s/limit.txt", pdomain_item->homedir);
				file_operation_transfer(temp_path1, temp_path);
				gateway_control_notify(command_string, NOTIFY_SMTP);
			}
		
			sprintf(temp_path, "%s/%s/data/smtp/domain_limit/deny",
				g_mount_path, direntp->d_name);
			dirp1 = opendir(temp_path);
			if (NULL == dirp1) {
				continue;
			}
			while ((direntp1 = readdir(dirp1)) != NULL) {
				if (0 == strcmp(".", direntp1->d_name) ||
					0 == strcmp("..", direntp1->d_name)) {
					continue;
				}
				strcpy(temp_domain, direntp1->d_name);
				len = strlen(temp_domain);
				if (len <= 4 && 0 != strcasecmp(temp_domain + len - 4, ".txt")) {
					continue;
				}
				temp_domain[len - 4] = '\0';
				for (i=0; i<len-4; i++) {
					if (0 != isupper(temp_domain[i])) {
						break;
					}
				}
				if (i < len - 4) {
					continue;
				}
				b_found = FALSE;
				for (data_source_collect_begin(pcollect);
					!data_source_collect_done(pcollect);
					data_source_collect_forward(pcollect)) {
					pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(
									pcollect);
					if (0 == strcmp(pdomain_item->domainname, temp_domain) &&
						1 == pdomain_item->type) {
						b_found = TRUE;
						break;
					}
				}
				if (FALSE == b_found) {
					sprintf(command_string, "domain_limit.pas remove deny %s",
						temp_domain);
					gateway_control_notify(command_string, NOTIFY_SMTP);			
				}
			}
			closedir(dirp1);

			
			sprintf(temp_path, "%s/%s/data/smtp/domain_limit/allow",
				g_mount_path, direntp->d_name);
			dirp1 = opendir(temp_path);
			if (NULL == dirp1) {
				continue;
			}
			while ((direntp1 = readdir(dirp1)) != NULL) {
				if (0 == strcmp(".", direntp1->d_name) ||
					0 == strcmp("..", direntp1->d_name)) {
					continue;
				}
				strcpy(temp_domain, direntp1->d_name);
				len = strlen(temp_domain);
				if (len <= 4 && 0 != strcasecmp(temp_domain + len - 4, ".txt")) {
					continue;
				}
				temp_domain[len - 4] = '\0';
				for (i=0; i<len-4; i++) {
					if (0 != isupper(temp_domain[i])) {
						break;
					}
				}
				if (i < len - 4) {
					continue;
				}
				b_found = FALSE;
				for (data_source_collect_begin(pcollect);
					!data_source_collect_done(pcollect);
					data_source_collect_forward(pcollect)) {
					pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(
									pcollect);
					if (0 == strcmp(pdomain_item->domainname, temp_domain) &&
						2 == pdomain_item->type) {
						b_found = TRUE;
						break;
					}
				}
				if (FALSE == b_found) {
					sprintf(command_string, "domain_limit.pas remove allow %s",
						temp_domain);
					gateway_control_notify(command_string, NOTIFY_SMTP);			
				}
			}
			closedir(dirp1);
		}
		closedir(dirp);
		
		

MONITOR_DOMAIN_LIST:
		data_source_collect_clear(pcollect);
		
		if (FALSE == data_source_get_monitor_domains(pcollect)) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(
							pcollect);
			sprintf(temp_path, "%s/monitor.txt", pdomain_item->homedir);
			if (0 != stat(temp_path, &node_stat) || 0 == node_stat.st_size) {
				pdomain_item->type = 0;
			} else {
				pdomain_item->type = 1;
			}
		}

		dirp = opendir(g_mount_path);
		if (NULL == dirp) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		while ((direntp = readdir(dirp)) != NULL) {
			if (0 == strcmp(".", direntp->d_name) ||
				0 == strcmp("..", direntp->d_name)) {
				continue;
			}
			for (data_source_collect_begin(pcollect);
				!data_source_collect_done(pcollect);
				data_source_collect_forward(pcollect)) {
				pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(
								pcollect);
				if (1 == pdomain_item->type) {
					sprintf(temp_path, "%s/%s/data/delivery/domain_monitor/%s.txt",
						g_mount_path, direntp->d_name, pdomain_item->domainname);
					sprintf(command_string, "domain_monitor.hook add %s",
						pdomain_item->domainname);
				} else {
					continue;
				}
				if (0 == stat(temp_path, &node_stat)) {
					continue;
				}
				
				sprintf(temp_path1, "%s/monitor.txt", pdomain_item->homedir);
				file_operation_copy_monitor(temp_path1, temp_path);
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		
			sprintf(temp_path, "%s/%s/data/delivery/domain_monitor",
				g_mount_path, direntp->d_name);
			dirp1 = opendir(temp_path);
			if (NULL == dirp1) {
				continue;
			}
			while ((direntp1 = readdir(dirp1)) != NULL) {
				if (0 == strcmp(".", direntp1->d_name) ||
					0 == strcmp("..", direntp1->d_name)) {
					continue;
				}
				strcpy(temp_domain, direntp1->d_name);
				len = strlen(temp_domain);
				if (len <= 4 && 0 != strcasecmp(temp_domain + len - 4, ".txt")) {
					continue;
				}
				temp_domain[len - 4] = '\0';
				for (i=0; i<len-4; i++) {
					if (0 != isupper(temp_domain[i])) {
						break;
					}
				}
				if (i < len - 4) {
					continue;
				}
				b_found = FALSE;
				for (data_source_collect_begin(pcollect);
					!data_source_collect_done(pcollect);
					data_source_collect_forward(pcollect)) {
					pdomain_item = (DOMAIN_ITEM*)data_source_collect_get_value(
									pcollect);
					if (0 == strcmp(pdomain_item->domainname, temp_domain) &&
						1 == pdomain_item->type) {
						b_found = TRUE;
						break;
					}
				}
				if (FALSE == b_found) {
					sprintf(command_string, "domain_monitor.hook remove %s",
						temp_domain);
					gateway_control_notify(command_string, NOTIFY_DELIVERY);			
				}
			}
			closedir(dirp1);
		}
		closedir(dirp);	

MONITOR_GROUP_LIST:
		data_source_collect_clear(pcollect);
		
		if (FALSE == data_source_get_monitor_groups(pcollect)) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		
		for (data_source_collect_begin(pcollect);
			!data_source_collect_done(pcollect);
			data_source_collect_forward(pcollect)) {
			pgroup_item = (GROUP_ITEM*)data_source_collect_get_value(
							pcollect);
			strcpy(fake_group, pgroup_item->groupname);
			pdomain = strchr(fake_group, '@');
			if (NULL != pdomain) {
				*pdomain = '\0';
			}
			sprintf(temp_path, "%s/%s/monitor.txt", pgroup_item->homedir,
				fake_group);
			if (0 != stat(temp_path, &node_stat) || 0 == node_stat.st_size) {
				pgroup_item->type = 0;
			} else {
				pgroup_item->type = 1;
			}
		}

		dirp = opendir(g_mount_path);
		if (NULL == dirp) {
			data_source_collect_free(pcollect);
			goto NEXT_LOOP;
		}
		while ((direntp = readdir(dirp)) != NULL) {
			if (0 == strcmp(".", direntp->d_name) ||
				0 == strcmp("..", direntp->d_name)) {
				continue;
			}
			for (data_source_collect_begin(pcollect);
				!data_source_collect_done(pcollect);
				data_source_collect_forward(pcollect)) {
				pgroup_item = (GROUP_ITEM*)data_source_collect_get_value(
								pcollect);
				strcpy(fake_group, pgroup_item->groupname);
				pdomain = strchr(fake_group, '@');
				if (NULL != pdomain) {
					*pdomain = '\0';
				}
				if (1 == pgroup_item->type) {
					sprintf(temp_path, "%s/%s/data/delivery/group_monitor/%s.txt",
						g_mount_path, direntp->d_name, pgroup_item->groupname);
					sprintf(command_string, "group_monitor.hook add %s",
						pgroup_item->groupname);
				} else {
					continue;
				}
				if (0 == stat(temp_path, &node_stat)) {
					continue;
				}
				
				sprintf(temp_path1, "%s/%s/monitor.txt", pgroup_item->homedir,
					fake_group);
				file_operation_copy_monitor(temp_path1, temp_path);
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		
			sprintf(temp_path, "%s/%s/data/delivery/group_monitor",
				g_mount_path, direntp->d_name);
			dirp1 = opendir(temp_path);
			if (NULL == dirp1) {
				continue;
			}
			while ((direntp1 = readdir(dirp1)) != NULL) {
				if (0 == strcmp(".", direntp1->d_name) ||
					0 == strcmp("..", direntp1->d_name)) {
					continue;
				}
				strcpy(temp_group, direntp1->d_name);
				len = strlen(temp_group);
				if (len <= 4 && 0 != strcasecmp(temp_domain + len - 4, ".txt")) {
					continue;
				}
				temp_group[len - 4] = '\0';
				for (i=0; i<len-4; i++) {
					if (0 != isupper(temp_group[i])) {
						break;
					}
				}
				if (i < len - 4) {
					continue;
				}
				b_found = FALSE;
				for (data_source_collect_begin(pcollect);
					!data_source_collect_done(pcollect);
					data_source_collect_forward(pcollect)) {
					pgroup_item = (GROUP_ITEM*)data_source_collect_get_value(
									pcollect);
					if (0 == strcmp(pgroup_item->groupname, temp_group) &&
						1 == pgroup_item->type) {
						b_found = TRUE;
						break;
					}
				}
				if (FALSE == b_found) {
					sprintf(command_string, "group_monitor.hook remove %s",
						temp_group);
					gateway_control_notify(command_string, NOTIFY_DELIVERY);			
				}
			}
			closedir(dirp1);
		}
		closedir(dirp);	

		data_source_collect_free(pcollect);
NEXT_LOOP:
		count = 0;
	}
	return NULL;
}
