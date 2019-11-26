#include <errno.h>
#include <string.h>
#include "message_lookup.h"
#include <gromox/system_log.h>
#include "mail_func.h"
#include "util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>

#define MAX_ITEM_NUMBER				1024

static char g_mount_path[256];

static void message_lookup_compare(const char *from, const char *to,
	const char *reason, const char *path, LOOKUP_COLLECT *pcollect);

void message_lookup_init(const char *mount_path)
{
	strcpy(g_mount_path, mount_path);
}

int message_lookup_run()
{
	struct stat node_stat;

	if (0 != stat(g_mount_path, &node_stat)) {
		system_log_info("[message_lookup]: mount entry %s does not"
			"exist", g_mount_path);
		return -1;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		system_log_info("[message_lookup]: mount entry %s is not a directory",
			g_mount_path);
		return -2;
	}
	return 0;
}

int message_lookup_stop()
{
	return 0;
}

void message_lookup_free()
{
	/* do nothing */
}

LOOKUP_COLLECT* message_lookup_collect_init()
{
	LOOKUP_COLLECT *pcollect;

	pcollect = (LOOKUP_COLLECT*)malloc(sizeof(LOOKUP_COLLECT));
	if (NULL == pcollect) {
		return NULL;
	}
	double_list_init(&pcollect->list);
	pcollect->pnode = NULL;
	return pcollect;
}

void message_lookup_collect_free(LOOKUP_COLLECT *pcollect)
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

int message_lookup_collect_total(LOOKUP_COLLECT *pcollect)
{
	return double_list_get_nodes_num(&pcollect->list);
}

void message_lookup_collect_begin(LOOKUP_COLLECT *pcollect)
{
	pcollect->pnode = double_list_get_head(&pcollect->list);

}

int message_lookup_collect_done(LOOKUP_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return TRUE;
	}
	return FALSE;
}

int message_lookup_collect_forward(LOOKUP_COLLECT *pcollect)
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

MESSAGE_ITEM* message_lookup_collect_get_value(LOOKUP_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return NULL;
	}
	return (MESSAGE_ITEM*)(pcollect->pnode->pdata);
}

BOOL message_lookup_match(char *from, char *to, const char *reason,
	LOOKUP_COLLECT *pcollect)
{
	DIR *dirp, *dirp1;
	struct dirent *direntp;
	struct dirent *direntp1;
	struct stat node_stat;
	char temp_path[256];
	char file_name[256];
	
	
	/* check the directory of source and destination path */
	if (0 != stat(g_mount_path, &node_stat)) {
		system_log_info("[message_lookup]: %s not exist\n", g_mount_path); 
		return FALSE;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		system_log_info("[message_lookup]: %s is not a directory\n", g_mount_path);
		return FALSE;
	}

	dirp = opendir(g_mount_path);
	if (NULL == dirp) {
		system_log_info("[message_lookup]: failed to open directory %s: %s",
			g_mount_path, strerror(errno));
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
		sprintf(temp_path, "%s/%s/queue/insulation", g_mount_path,
			direntp->d_name);
		dirp1 = opendir(temp_path);
		if (NULL == dirp1) {
			continue;
		}
		while ((direntp1 = readdir(dirp1)) != NULL) {
			if (0 == strcmp(direntp1->d_name, ".") ||
				0 == strcmp(direntp1->d_name, "..")) {
				continue;
			}
			sprintf(file_name, "%s/%s", temp_path, direntp1->d_name);
			message_lookup_compare(from, to, reason, file_name, pcollect);
			if (double_list_get_nodes_num(&pcollect->list) >= MAX_ITEM_NUMBER) {
				return TRUE;
			}
		}
		closedir(dirp1);
	}
	closedir(dirp);
	return TRUE;
}


static void message_lookup_compare(const char *from, const char *to,
	const char *reason, const char *path, LOOKUP_COLLECT *pcollect)
{
	BOOL b_from;
	BOOL b_reason;
	BOOL b_rcpt;
	int fd, read_len;
	int offset, parsed_len;
	time_t tmp_time;
	char *pdomain;
	char *ptr1, *ptr2;
	char *file_name;
	char *to_domain;
	char *from_domain;
	char time_str[32];
	char temp_from[256];
	char temp_recipient[256];
	char temp_reason[4096];
	char temp_buff[64*1024];
	MESSAGE_ITEM *pmatch;
	MESSAGE_ITEM *pitem;
	DOUBLE_LIST_NODE *pnode;
	MIME_FIELD mime_field;

	file_name = strrchr(path, '/');
	if (NULL == file_name) {
		return;
	}
	file_name ++;
	ptr1 = strchr(file_name, '.');
	if (NULL == ptr1) {
		return;
	}
	ptr1 ++;
	ptr2 = strchr(ptr1, '.');
	if (NULL == ptr2) {
		return;
	}
	ptr1 = ptr2 + 1;
	ptr2 = strchr(ptr1, '.');
	if (NULL == ptr2 || ptr2 - ptr1 > 16) {
		return;
	}
	memcpy(time_str, ptr1, ptr2 - ptr1);
	time_str[ptr2 - ptr1] = '\0';
	tmp_time = atoi(time_str);
	if (NULL != from) {
		from_domain = strchr(from, '@');
		if (NULL == from_domain) {
			from_domain = (char*)from;
		} else {
			from_domain = NULL;
		}
		b_from = FALSE;
	} else {
		b_from = TRUE;
	}

	if (NULL != to) {
		to_domain = strchr(to, '@');
		if (NULL == to_domain) {
			to_domain = (char*)to;
		} else {
			to_domain = NULL;
		}
		b_rcpt = FALSE;
	} else {
		b_rcpt = TRUE;
	}
		
	if (NULL != reason) {
		b_reason = FALSE;
	} else {
		b_reason = TRUE;
	}
	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		return;
	}
	read_len = read(fd, temp_buff, 64*1024 - 1);
	offset = 0;
	while (offset < read_len && (parsed_len= parse_mime_field(
		temp_buff + offset, read_len - offset, &mime_field))) {
		/* check if mime head is over */
		offset += parsed_len;
		if (19 == mime_field.field_name_len && 0 == strncasecmp(
			mime_field.field_name, "X-Insulation-Reason", 19)) {
			if (mime_field.field_value_len > 1024) {
				mime_field.field_value_len = 1024;
			}
			memcpy(temp_reason, mime_field.field_value,
				mime_field.field_value_len);
			temp_reason[mime_field.field_value_len] = '\0';
			if (FALSE == b_reason) {
				if (0 == strncasecmp(mime_field.field_value, reason,
					mime_field.field_value_len)) {
					b_reason = TRUE;
				} else {
					close(fd);
					return;
				}
			}
		} else if (14 == mime_field.field_name_len &&
			0 == strncasecmp(mime_field.field_name, "X-Envelop-From", 14)) {
			mime_field.field_value[mime_field.field_value_len] = '\0';
			strncpy(temp_from, mime_field.field_value, 255);
			temp_from[255] = '\0';
			if (FALSE == b_from) {
				if (NULL != from_domain) {
					pdomain = strchr(temp_from, '@');
					if (NULL == pdomain) {
						continue;
					}
					pdomain ++;
					if (0 == strcasecmp(pdomain, from_domain)) {
						b_from = TRUE;
					} else {
						close(fd);
						return;
					}
				} else {
					if (0 == strcasecmp(temp_from, from)) {
						b_from = TRUE;
					} else {
						close(fd);
						return;
					}
				}
			}
		} else if (14 == mime_field.field_name_len &&
			0 == strncasecmp(mime_field.field_name, "X-Envelop-Rcpt", 14)) {
			mime_field.field_value[mime_field.field_value_len] = '\0';
			strncpy(temp_recipient, mime_field.field_value, 255);
			temp_recipient[255] = '\0';
			if (FALSE == b_rcpt) {
				if (NULL != to_domain) {
					pdomain = strchr(temp_recipient, '@');
					if (NULL == pdomain) {
						continue;
					}
					pdomain ++;
					if (0 == strcasecmp(pdomain, to_domain)) {
						b_rcpt = TRUE;
						continue;
					}
				} else {
					if (0 == strcasecmp(temp_recipient, to)) {
						b_rcpt = TRUE;
						continue;
					}
				}
			}
		}
		if ('\r' == temp_buff[offset] && '\n' == temp_buff[offset + 1]) {
			break;
		}
	}
	if (FALSE == b_from || FALSE == b_rcpt || FALSE == b_reason) {
		close(fd);
		return;
	}
	pmatch = (MESSAGE_ITEM*)malloc(sizeof(MESSAGE_ITEM));
	if (NULL == pmatch) {
		close(fd);
		return;
	}
	pmatch->node.pdata = pmatch;
	pmatch->time = tmp_time;
	strcpy(pmatch->from, temp_from);
	strcpy(pmatch->recipient, temp_recipient);
	strcpy(pmatch->reason, temp_reason);
	memcpy(pmatch->dir, path, file_name - 1 - path);
	pmatch->dir[file_name - 1 - path] = '\0';
	strcpy(pmatch->file_name, file_name);
	pitem = NULL;
	for (pnode=double_list_get_head(&pcollect->list); NULL!=pnode;
		pnode=double_list_get_after(&pcollect->list, pnode)) {
		pitem = (MESSAGE_ITEM*)pnode->pdata;
		if (pitem->time > pmatch->time) {
			break;
		}
	}
	if (NULL == pitem) {
		double_list_insert_as_head(&pcollect->list, &pmatch->node);
	} else {
		if (NULL != pnode) {
			if (&pitem->node != double_list_get_head(&pcollect->list)) {
				double_list_insert_before(&pcollect->list, &pitem->node,
					&pmatch->node);
			} else {
				double_list_insert_as_head(&pcollect->list, &pmatch->node);
			}
		} else {
			double_list_append_as_tail(&pcollect->list, &pmatch->node);
		}
	}
	close(fd);
}


