#include "match_engine.h"
#include "system_log.h"
#include "util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

static char g_mount_path[256];

void match_engine_init(const char *mount_path)
{
	strcpy(g_mount_path, mount_path);
}

int match_engine_run()
{
	struct stat node_stat;

	if (0 != stat(g_mount_path, &node_stat)) {
		system_log_info("[match_engine]: mount entry %s does not"
				        "exist, please check it ASAP!!!", g_mount_path);
		return -1;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		system_log_info("[match_engine]: mount entry %s is not directory, "
				        "please check it ASAP!!!", g_mount_path);
		return -2;
	}
	return 0;
}

int match_engine_stop()
{
	return 0;
}

void match_engine_free()
{
	/* do nothing */
}

MATCH_COLLECT* match_engine_collect_init()
{
	MATCH_COLLECT *pcollect;

	pcollect = (MATCH_COLLECT*)malloc(sizeof(MATCH_COLLECT));
	if (NULL == pcollect) {
		return NULL;
	}
	single_list_init(&pcollect->list);
	pcollect->pnode = NULL;
	return pcollect;
}

void match_engine_collect_free(MATCH_COLLECT *pcollect)
{
	SINGLE_LIST_NODE *pnode;

	if (NULL == pcollect) {
		return;
	}
	while ((pnode = single_list_get_from_head(&pcollect->list)) != NULL)
		free(pnode->pdata);
	single_list_free(&pcollect->list);
	free(pcollect);
}

int match_engine_collect_total(MATCH_COLLECT *pcollect)
{
	return single_list_get_nodes_num(&pcollect->list);
}

void match_engine_collect_begin(MATCH_COLLECT *pcollect)
{
	pcollect->pnode = single_list_get_head(&pcollect->list);

}

int match_engine_collect_done(MATCH_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return 1;
	}
	return 0;
}

int match_engine_collect_forward(MATCH_COLLECT *pcollect)
{
	SINGLE_LIST_NODE *pnode;


	pnode = single_list_get_after(&pcollect->list, pcollect->pnode);
	if (NULL == pnode) {
		pcollect->pnode = NULL;
		return -1;
	}
	pcollect->pnode = pnode;
	return 1;
}

char* match_engine_collect_get_value(MATCH_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return NULL;
	}
	return ((MATCH_NODE*)(pcollect->pnode->pdata))->line;
}

BOOL match_engine_match(time_t start_time, time_t end_time, const char *ip,
	const char *from, const char *to, MATCH_COLLECT *pcollect)
{
	FILE *fp;
	int ip_len;
	time_t itime;
	char *pdomain;
	char *ptr, *ptr1;
	DIR *dirp, *dirp1;
	MATCH_NODE *pmatch;
	struct tm tm_time;
	struct dirent *direntp;
	struct dirent *direntp1;
	struct stat node_stat;
	char temp_file[256];
	char temp_path[256];
	char temp_address[256];
	char temp_buff[64*1024];
	char to_address[260];
	const char *from_domain;
	
	if (0 == start_time || 0 == end_time) {
		system_log_info("[match_engine]: time condition error!");
		return FALSE;
	}
	if (NULL != ip) {
		ip_len = strlen(ip);
	}
	if (NULL != from && NULL == strchr(from, '@')) {
		from_domain = from;
	} else {
		from_domain = NULL;
	}
	if (NULL != to) {
		if (NULL == strchr(to, '@')) {
			snprintf(to_address, 259, "@%s ", to);
		} else {
			snprintf(to_address, 259, " %s ", to);
		}
		to_address[259] = '\0';
	}
	
	/* check the directory of source and destination path */
	if (0 != stat(g_mount_path, &node_stat)) {
		system_log_info("[match_engine]: %s not exist\n", g_mount_path); 
		return FALSE;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		system_log_info("[match_engine]: %s is not directory\n", g_mount_path);
		return FALSE;
	}

	dirp = opendir(g_mount_path);
	if (NULL == dirp){
		system_log_info("[match_engine]: fail to open directory %s\n",
			g_mount_path);
		return FALSE;
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
		sprintf(temp_path, "%s/%s/logs/smtp", g_mount_path, direntp->d_name);
		if (0 != stat(temp_path, &node_stat)) {
			continue;
		}
		if (0 == S_ISDIR(node_stat.st_mode)) {
			continue;
		}
		dirp1 = opendir(temp_path);
		if (NULL == dirp1) {
			system_log_info("[match_engine]: fail to open directory %s\n",
				temp_path);
			continue;
		}
		while ((direntp1 = readdir(dirp1)) != NULL) {
			if  (0 == strcmp(direntp1->d_name, ".") ||
				 0 == strcmp(direntp1->d_name, "..")) {
				continue;
			}
			for (itime=start_time; itime<=end_time; itime+=24*3600) {
				strftime(temp_file, 256, "smtp_log%m%d.txt", localtime(&itime));
				if (0 == strcmp(direntp1->d_name, temp_file)) {
					goto MATCH_SMTP;						    
				}
			}
			continue;

MATCH_SMTP:
			sprintf(temp_path, "%s/%s/logs/smtp/%s", g_mount_path,
					direntp->d_name, temp_file);
			fp = fopen(temp_path, "r");
			if (NULL == fp) {
				continue;
			}
			/* parse each line in log file */
			while (NULL != fgets(temp_buff, 64*1024, fp)) {
				/* convert string to time epoch */
				ptr = strptime(temp_buff, "%Y/%m/%d %H:%M:%S\t", &tm_time);
				if (NULL == ptr) {
					continue;
				}
				itime = mktime(&tm_time);
				if (itime > end_time || itime < start_time) {
					continue;
				}
				if (0 == strncmp(ptr, "new connection ", 15)) {
					if (NULL == from && NULL == to && NULL != ip) {
						ptr += 15;
						if (0 != strncmp(ptr, ip, ip_len)) {
							continue;
						}
					} else {
						continue;
					}
				} else if (0 == strncmp(ptr, "remote MTA IP: ", 15)) {
					if (NULL != ip) {
						ptr = strstr(ptr, "IP: ");
						ptr += 4;
						if (0 != strncmp(ptr, ip, ip_len)) {
							continue;
						}
						ptr += ip_len;
					}
					if (NULL != from) {
						ptr = strstr(ptr, ", FROM: ");
						if (NULL == ptr) {
							continue;
						}
						ptr += 8;
						ptr1 = strstr(ptr, ", TO: ");
						if (NULL == ptr1) {
							continue;
						}
						if (ptr1 - ptr > 255) {
							continue;
						}
						memcpy(temp_address, ptr, ptr1 - ptr);
						temp_address[ptr1 - ptr] = '\0';
						ptr = ptr1;
						if (NULL != from_domain) {
							pdomain = strchr(temp_address, '@');
							if (NULL == pdomain) {
								continue;
							}
							pdomain ++;
							if (0 != strcasecmp(pdomain, from_domain)) {
								continue;
							}
						} else {
							if (0 != strcasecmp(from, temp_address)) {
								continue;
							}
						}
					}
					if (NULL != to) {
						ptr = strstr(ptr, ", TO:");
						if (NULL == ptr) {
							continue;
						}
						ptr += 5;
						ptr1 = strstr(ptr, "  ");
						if (NULL == ptr1) {
							continue;
						}
						if (NULL == search_string(ptr, to_address,
							ptr1 - ptr + 2)) {
							continue;
						}
					}
				} else if (0 == strncmp(ptr, "user: ", 6)) {
					if (NULL != from) {
						ptr += 6;
						ptr1 = strstr(ptr, ", IP: ");
						if (NULL == ptr1 || ptr1 == ptr) {
							continue;
						}
						if (ptr1 - ptr > 255) {
							continue;
						}
						memcpy(temp_address, ptr, ptr1 - ptr);
						temp_address[ptr1 - ptr] = '\0';
						ptr = ptr1;
						if (NULL != from_domain) {
							pdomain = strchr(temp_address, '@');
							if (NULL == pdomain || 0 != strcasecmp(pdomain + 1,
								from_domain)) {
								continue;
							}
						} else {
							if (0 != strcasecmp(from, temp_address)) {
								continue;
							}
						}
					}
					if (NULL != ip) {
						ptr = strstr(ptr, "IP: ");
						ptr += 4;
						if (0 != strncmp(ptr, ip, ip_len)) {
							continue;
						}
						ptr += ip_len;
					}
					if (NULL != to) {
						ptr = strstr(ptr, ", TO:");
						if (NULL == ptr) {
							continue;
						}
						ptr += 5;
						ptr1 = strstr(ptr, "  ");
						if (NULL == ptr1) {
							continue;
						}
						if (NULL == search_string(ptr, to_address,
							ptr1 - ptr + 2)) {
							continue;
						}
					}
				} else {
					continue;
				}
				pmatch = (MATCH_NODE*)malloc(sizeof(MATCH_NODE));
				if (NULL == pmatch) {
					continue;
				}
				pmatch->node.pdata = pmatch;
				strncpy(pmatch->line, temp_buff, MAX_LINE_LENGTH);
				pmatch->line[MAX_LINE_LENGTH] = '\0';
				single_list_append_as_tail(&pcollect->list, &pmatch->node);
				if (single_list_get_nodes_num(&pcollect->list) >= MAX_ITEM_NUMBER) {
					return TRUE;
				}
			}
		}
		if ((NULL == from && NULL == to) || NULL != ip) {
			continue;
		}
		sprintf(temp_path, "%s/%s/logs/delivery",g_mount_path, direntp->d_name);
		if (0 != stat(temp_path, &node_stat)) {
			continue;
		}
		if (0 == S_ISDIR(node_stat.st_mode)) {
			continue;
		}
		dirp1 = opendir(temp_path);
		if (NULL == dirp1) {
			system_log_info("[match_engine]: fail to open directory %s\n",
				temp_path);
			continue;
		}
		while ((direntp1 = readdir(dirp1)) != NULL) {
			if  (0 == strcmp(direntp1->d_name, ".") ||
				 0 == strcmp(direntp1->d_name, "..")) {
				continue;
			}
			for (itime=start_time; itime<=end_time; itime+=24*3600) {
				strftime(temp_file, 256, "delivery_log%m%d.txt",
					localtime(&itime));
				if (0 == strcmp(direntp1->d_name, temp_file)) {
					goto MATCH_DELIVERY;						    
				}
			}
			continue;

MATCH_DELIVERY:
			sprintf(temp_path, "%s/%s/logs/delivery/%s", g_mount_path,
					direntp->d_name, temp_file);
			fp = fopen(temp_path, "r");
			if (NULL == fp) {
				continue;
			}
			/* parse each line in log file */
			while (NULL != fgets(temp_buff, 64*1024, fp)) {
				/* convert string to time epoch */
				ptr = strptime(temp_buff, "%Y/%m/%d %H:%M:%S\t", &tm_time);
				if (NULL == ptr) {
					continue;
				}
				itime = mktime(&tm_time);
				if (itime > end_time || itime < start_time) {
					continue;
				}
				if (NULL != from) {
					ptr = strstr(ptr, ", FROM: ");
					if (NULL == ptr) {
						continue;
					}
					ptr += 8;
					ptr1 = strstr(ptr, ", TO: ");
					if (NULL == ptr1) {
						continue;
					}
					if (ptr1 - ptr > 255) {
						continue;
					}
					memcpy(temp_address, ptr, ptr1 - ptr);
					temp_address[ptr1 - ptr] = '\0';
					ptr = ptr1;
					if (NULL != from_domain) {
						pdomain = strchr(temp_address, '@');
						if (NULL == pdomain) {
							continue;
						}
						pdomain ++;
						if (0 != strcasecmp(pdomain, from_domain)) {
							continue;
						}
					} else {
						if (0 != strcasecmp(from, temp_address)) {
							continue;
						}
					}
				}
				if (NULL != to) {
					ptr = strstr(ptr, ", TO:");
					if (NULL == ptr) {
						continue;
					}
					ptr += 5;
					ptr1 = strstr(ptr, "  ");
					if (NULL == ptr1) {
						continue;
					}
					if (NULL == search_string(ptr, to_address,
						ptr1 - ptr + 2)) {
						continue;
					}
				}
				pmatch = (MATCH_NODE*)malloc(sizeof(MATCH_NODE));
				if (NULL == pmatch) {
					continue;
				}
				pmatch->node.pdata = pmatch;
				strncpy(pmatch->line, temp_buff, MAX_LINE_LENGTH);
				pmatch->line[MAX_LINE_LENGTH] = '\0';
				single_list_append_as_tail(&pcollect->list, &pmatch->node);
				if (single_list_get_nodes_num(&pcollect->list) >= MAX_ITEM_NUMBER) {
					return TRUE;
				}
			}
		}

	}
	return TRUE;
}

