#include "search_engine.h"
#include "system_log.h"
#include "util.h"
#include "data_source.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#define MAX_ITEM_NUM			3000


SEARCH_COLLECT* search_engine_collect_init()
{
	SEARCH_COLLECT *pcollect;

	pcollect = (SEARCH_COLLECT*)malloc(sizeof(SEARCH_COLLECT));
	if (NULL == pcollect) {
		return NULL;
	}
	double_list_init(&pcollect->list);
	pcollect->pnode = NULL;
	return pcollect;
}

void search_engine_collect_free(SEARCH_COLLECT *pcollect)
{
	DOUBLE_LIST_NODE *pnode;
	
	if (NULL == pcollect) {
		return;
	}
	while ((pnode = double_list_get_from_head(&pcollect->list)) != NULL)
		free(pnode->pdata);
	double_list_free(&pcollect->list);
	free(pcollect);
}

int search_engine_collect_total(SEARCH_COLLECT *pcollect)
{
	return double_list_get_nodes_num(&pcollect->list);
}

void search_engine_collect_begin(SEARCH_COLLECT *pcollect)
{
	pcollect->pnode = double_list_get_head(&pcollect->list);
}

int search_engine_collect_done(SEARCH_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return 1;
	}
	return 0;
}

int search_engine_collect_forward(SEARCH_COLLECT *pcollect)
{
	DOUBLE_LIST_NODE *pnode;
	

	pnode = double_list_get_after(&pcollect->list, pcollect->pnode);
	if (NULL == pnode) {
		pcollect->pnode = NULL;
		return -1;
	}
	pcollect->pnode = pnode;
	return 1;
}

ITEM_DATA* search_engine_collect_get_value(SEARCH_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return NULL;
	}
	return &((SEARCH_NODE*)(pcollect->pnode->pdata))->item;
}

void search_engine_init()
{
	/* do nothing */
}

int search_engine_run()
{
	/* do nothing */
	return 0;
}

int search_engine_stop()
{
	return 0;
}

void search_engine_free()
{
	/* do nothing */
}

BOOL search_engine_search(const char *domain, const char *ip, const char *from,
	const char *rcpt, time_t start_point, time_t end_point,
	SEARCH_COLLECT *pcollect)
{
	DIR *dirp;
	int fd, len;
	time_t itime;
	char *pdomain;
	const char *pip;
	char *pfrom, *prcpt;
	char *from_domain;
	char *rcpt_domain;
	char temp_from[256];
	char temp_rcpt[256];
	char temp_path[256];
	char temp_file[256];
	char temp_domain[256];
	char temp_logname[256];
	struct in_addr addr;
	struct stat node_stat;
	struct dirent *direntp;
	ITEM_DATA temp_item;
	SEARCH_NODE *psearch;
	SEARCH_NODE *psearch1;
	DOUBLE_LIST_NODE *pnode;
	
	if (NULL != pcollect->pnode ||
		0 != double_list_get_nodes_num(&pcollect->list)) {
		system_log_info("[search_engine]: parameter pcollect is not clean in "
			"search_engine_search!");
		return FALSE;
	}
	
	strcpy(temp_domain, domain);
	lower_string(temp_domain);
	
	if (NULL == ip || '\0' == ip[0]) {
		pip = NULL;
	} else {
		pip = ip;
		len = strlen(ip);
	}

	if (NULL == from || '\0' == from[0]) {
		pfrom = NULL;
		from_domain = NULL;
	} else {
		strcpy(temp_from, from);
		lower_string(temp_from);
		if (NULL == strchr(temp_from, '@')) {
			pfrom = NULL;
			from_domain = temp_from;
		} else {
			pfrom = temp_from;
			from_domain = NULL;
		}
	}
	if (NULL == rcpt || '\0' == rcpt[0]) {
		prcpt = NULL;
		rcpt_domain = NULL;
	} else {
		strcpy(temp_rcpt, rcpt);
		lower_string(temp_rcpt);
		if (NULL == strchr(temp_rcpt, '@')) {
			prcpt = NULL;
			rcpt_domain = temp_rcpt;
		} else {
			prcpt = temp_rcpt;
			rcpt_domain = NULL;
		}
	}
	
	if (0 == end_point && start_point > 0) {
		time(&end_point);
	}
	if (end_point < start_point) {
		system_log_info("[search_engine]: parameter start_point is later than "
			"end_point in search_engine_search!");
		return FALSE;
	}
	
	if (FALSE == data_source_get_homedir(temp_domain, temp_path) ||
		'\0' == temp_path[0]) {
		return TRUE;
	}
	strcat(temp_path, "/log");

	if (0 != stat(temp_path, &node_stat)) {
		return TRUE;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		system_log_info("[search_engine]: database error! %s is not directory",
			temp_path);
		return FALSE;
	}
	dirp = opendir(temp_path);
	if (NULL == dirp) {
		system_log_info("[search_engine]: fail to open %s for enumerating",
			temp_path);
		return FALSE;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		if (0 == start_point && 0 == end_point) {
			if (0 == strncmp(direntp->d_name, "log", 3) &&
				0 == strcmp(direntp->d_name + strlen(direntp->d_name) - 4, ".dat")) {
				goto MATCH_FILE;
			}
		} else if (0 == start_point) {
			for (itime=end_point; itime>=end_point-365*24*3600;itime-=24*3600) {
				strftime(temp_file, 256, "log%m%d.dat", localtime(&itime));
				if (0 == strcmp(direntp->d_name, temp_file)) {
					goto MATCH_FILE;
				}
			}
		} else {
			for (itime=start_point; itime<=end_point; itime+=24*3600) {
				strftime(temp_file, 256, "log%m%d.dat", localtime(&itime));
				if (0 == strcmp(direntp->d_name, temp_file)) {
					goto MATCH_FILE;
				}
			}
		}
		continue;
MATCH_FILE:
		sprintf(temp_logname, "%s/%s", temp_path, direntp->d_name);
		fd = open(temp_logname, O_RDONLY);
		if (-1 == fd) {
			system_log_info("[search_engine]: fail to open %s", temp_logname);
			continue;
		}
		memset(&temp_item, 0, sizeof(temp_item));
		while (read(fd, &temp_item, sizeof(temp_item)) > 0) {
			if (0 == start_point && 0 == end_point) {
				/* do nothing */
			} else if (0 == start_point) {
				if (temp_item.time > end_point) {
					continue;
				}
			} else {
				if (temp_item.time < start_point ||
					temp_item.time > end_point) {
					continue;
				}
			}
			
			if (NULL != pip) {
				addr.s_addr = temp_item.ip;
				if (0 != strncmp(inet_ntoa(addr), ip, len)) {
					continue;
				}
			}
			
			if (NULL != from_domain) {
				pdomain = strchr(temp_item.from, '@');
				if (NULL == pdomain) {
					continue;
				}
				pdomain ++;
				if (0 != strcasecmp(pdomain, from_domain)) {
					continue;
				}
			}

			if (NULL != pfrom) {
				if (0 != strcasecmp(pfrom, temp_item.from)) {
					continue;
				}
			}

			if (NULL != rcpt_domain) {
				pdomain = strchr(temp_item.to, '@');
				if (NULL == pdomain) {
					continue;
				}
				pdomain ++;
				if (0 != strcasecmp(pdomain, rcpt_domain)) {
					continue;
				}
			}

			if (NULL != prcpt) {
				if (0 != strcasecmp(prcpt, temp_item.to)) {
					continue;
				}
			}
			
			psearch = (SEARCH_NODE*)malloc(sizeof(SEARCH_NODE));
			if (NULL == psearch) {
				continue;
			}
			psearch1 = NULL;
			psearch->node.pdata = psearch;
			memcpy(&psearch->item, &temp_item, sizeof(ITEM_DATA));
			for (pnode=double_list_get_head(&pcollect->list); NULL!=pnode;
				pnode=double_list_get_after(&pcollect->list, pnode)) {
				psearch1 = (SEARCH_NODE*)pnode->pdata;
				if (psearch1->item.time > psearch->item.time) {
					break;
				}
			}
			if (NULL == psearch1) {
				double_list_insert_as_head(&pcollect->list, &psearch->node);
			} else {
				if (NULL != pnode) {
					if (&psearch1->node != double_list_get_head(
						&pcollect->list)) {
						double_list_insert_before(&pcollect->list,
							&psearch1->node, &psearch->node);
					} else {
						double_list_insert_as_head(&pcollect->list,
							&psearch->node);
					}
				} else {
					double_list_append_as_tail(&pcollect->list, &psearch->node);
				}
			}
			if (double_list_get_nodes_num(&pcollect->list) >= MAX_ITEM_NUM) {
				close(fd);
				return TRUE;
			}
		}
		close(fd);
	}
	return TRUE;
}


