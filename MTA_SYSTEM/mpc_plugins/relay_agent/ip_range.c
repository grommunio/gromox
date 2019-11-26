#include "ip_range.h"
#include "double_list.h"
#include "list_file.h"
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>


#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct _RANGE_NODE {
	DOUBLE_LIST_NODE node;
	unsigned int min;
	unsigned int max;
} RANGE_NODE;

static BOOL g_notify_stop = TRUE;
static BOOL g_main_site;
static char g_list_path[256];
static char g_url_path[256];
static char g_country_code[16];
static DOUBLE_LIST g_range_list;
static pthread_t g_thr_id;
static pthread_rwlock_t g_list_lock;
static int g_download_interval;
static BOOL g_range_table[256];

static void *thread_work_func(void *param);

static unsigned int ip_range_trans(const char *ip);

static unsigned int ip_range_log2(unsigned int val);

void ip_range_init(const char *list_path, const char *url_path, int interval,
	const char *country, BOOL b_main)
{
	g_download_interval = interval;
	strcpy(g_list_path, list_path);
	strcpy(g_url_path, url_path);
	strcpy(g_country_code, country);
	g_main_site = b_main;
	double_list_init(&g_range_list);
	pthread_rwlock_init(&g_list_lock, NULL);

}

int ip_range_run()
{
	char *pitem;
	int i, item_num;
	LIST_FILE *pfile;
	RANGE_NODE *prange;

	memset(g_range_table, 0, 256*sizeof(BOOL));
	pfile = list_file_init(g_list_path, "%s:16%s:16");
	if (NULL != pfile) {
		item_num = list_file_get_item_num(pfile);
		pitem = list_file_get_list(pfile);
		for (i=0; i<item_num; i++) {
			prange = (RANGE_NODE*)malloc(sizeof(RANGE_NODE));
			prange->node.pdata = prange;
			prange->min = ip_range_trans(pitem + 32*i);
			g_range_table[prange->min / 0x1000000] = TRUE;
			prange->max = ip_range_trans(pitem + 32*i + 16);
			g_range_table[prange->max / 0x1000000] = TRUE;
			double_list_append_as_tail(&g_range_list, &prange->node);
		}
		
		list_file_free(pfile);
	}

	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_thr_id, NULL, thread_work_func, NULL)) {
		g_notify_stop = TRUE;
		return -1;
	}
	return 0;
}

BOOL ip_range_check(const char *ip)
{
	RANGE_NODE *prange;
	DOUBLE_LIST_NODE *pnode;
	unsigned int value;

	value = ip_range_trans(ip);
	if (0 == value) {
		if (TRUE == g_main_site) {
			return TRUE;
		} else {
			return FALSE;
		}
	}
	if ((value >= 0xA000000 && value <= 0xAFFFFFF) ||
		(value >= 0xAC100000 && value <= 0xAC830000) ||
		(value >= 0xC0A80000 && value <= 0xC0A8FFFF) ||
		(value >= 0x7F000000 && value <= 0x7FFFFFFF)) {
		if (TRUE == g_main_site) {
			return TRUE;
		} else {
			return FALSE;
		}
	}
	pthread_rwlock_rdlock(&g_list_lock);
	if (FALSE == g_range_table[value / 0x1000000]) {
		pthread_rwlock_unlock(&g_list_lock);
		return FALSE;
	}
	for (pnode=double_list_get_head(&g_range_list); NULL!=pnode;
		pnode=double_list_get_after(&g_range_list, pnode)) {
		prange = (RANGE_NODE*)pnode->pdata;
		if (value <= prange->max && value >= prange->min) {
			pthread_rwlock_unlock(&g_list_lock);
			return TRUE;
		}
	}
	pthread_rwlock_unlock(&g_list_lock);
	return FALSE;
}

int ip_range_stop()
{
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thr_id, NULL);
	}
	
	while (pnode=double_list_get_from_head(&g_range_list)) {
		free(pnode->pdata);
	}

	return 0;
}

void ip_range_free()
{
	g_list_path[0] = '\0';
	g_url_path[0] = '\0';
	double_list_free(&g_range_list);
	pthread_rwlock_destroy(&g_list_lock);
}

static unsigned int ip_range_trans(const char *ip)
{
	char temp_ip[16];
	char num_string[10];
	char *pdot1, *pdot2, *pdot3;
	int num1, num2, num3, num4;

	strcpy(temp_ip, ip);
	pdot1 = strchr(temp_ip, '.');
	if (NULL == pdot1) {
		return 0;
	}
	*pdot1 = '\0';
	pdot1 ++;
	pdot2 = strchr(pdot1, '.');
	if (NULL == pdot2) {
		return 0;
	}
	*pdot2 = '\0';
	pdot2 ++;
	pdot3 = strchr(pdot2, '.');
	if (NULL == pdot3) {
		return 0;
	}
	pdot3 ++;
	
	num1 = atoi(temp_ip);
	num2 = atoi(pdot1);
	num3 = atoi(pdot2);
	num4 = atoi(pdot3);
	
	if (num1 > 255 || num2 > 255 || num3 > 255 || num4 > 255) {
		return 0;
	}
	
	sprintf(num_string, "%02x%02x%02x%02x", num1, num2, num3, num4);
	return (unsigned int)strtoul(num_string, NULL, 16);
	
}

static void *thread_work_func(void *param)
{
	FILE *fp;
	pid_t pid;
	int i, j, status;
	int item_num;
	int fd, len;
	unsigned int bits;
	unsigned int a,b,c,d;
	unsigned int number;
	char *ptr, *ptr1;
	char *pitem;
	char temp_line[128];
	char country[128];
	char temp_path[256];
	char option_buff[512];
	char *args[] = {"wget", NULL, NULL, NULL, NULL};
	DOUBLE_LIST_NODE *pnode;
	LIST_FILE *pfile;
	RANGE_NODE *prange;

	if (g_download_interval > 300) {
		i = g_download_interval - 300;
	} else {
		i = g_download_interval;
	}
	while (FALSE == g_notify_stop) {
		if (i < g_download_interval) {
			i ++;
			sleep(1);
			continue;
		}
		
		pid = fork();
		if (0 == pid) {
			for (fd=getdtablesize(); fd>=0; fd--) {
				close(fd);
			}
			snprintf(option_buff, sizeof(option_buff), "-O%s.tmp", g_list_path);
			args[1] = "-q";
			args[2] = g_url_path;
			args[3] = option_buff;
			if (-1 == execvp("wget", args)) {
				exit(EXIT_FAILURE);
			}
		} else if (pid > 0) {
			waitpid(pid, &status, 0);
			if (0 != WEXITSTATUS(status)) {
				i = 0;
				continue;
			}
			sprintf(temp_path, "%s.tmp", g_list_path);
			fp = fopen(temp_path, "r");
			if (NULL == fp) {
				i = 0;
				continue;
			}
			fd = open(g_list_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
			if (-1 == fd) {
				fclose(fp);
				i = 0;
				continue;
			}
			
			while (NULL != fgets(temp_line, 128, fp)) {
				if ('#' == temp_line[0]) {
					continue;
				}

				if (0 != strncmp(temp_line, "apnic|", 6) ||
					NULL == strstr(temp_line + 6, "|ipv4|") ||
					NULL == strstr(temp_line + 6, "|allocated")) {
					continue;
				}

				ptr = temp_line + 6;
				ptr1 = strchr(ptr, '|');
				if (NULL == ptr1) {
					continue;
				}
				*ptr1 = '\0';
				if (0 != strcasecmp(ptr, g_country_code)) {
					continue;
				}

				ptr = ptr1 + 6;
				ptr1 = strchr(ptr, '.');
				if (NULL == ptr1) {
					continue;
				}
				*ptr1 = '\0';
				a = atoi(ptr);

				ptr = ptr1 + 1;
				ptr1 = strchr(ptr, '.');
				if (NULL == ptr1) {
					continue;
				}
				*ptr1 = '\0';
				b = atoi(ptr);

				ptr = ptr1 + 1;
				ptr1 = strchr(ptr, '.');
				if (NULL == ptr1) {
					continue;
				}
				*ptr1 = '\0';
				c = atoi(ptr);

				ptr = ptr1 + 1;
				ptr1 = strchr(ptr, '|');
				if (NULL == ptr1) {
					continue;
				}
				*ptr1 = '\0';
				d = atoi(ptr);

				ptr = ptr1 + 1;
				ptr1 = strchr(ptr, '|');
				if (NULL == ptr1) {
					continue;
				}
				*ptr1 = '\0';
				number = atoi(ptr);
				bits = ip_range_log2(number);

				if (bits < 0) {
					continue;
				} else if (bits <= 8) {
					len = sprintf(temp_line, "%d.%d.%d.%d %d.%d.%d.%d\n",
							a, b, c, d, a, b, c, (1 << bits) - 1);
				} else if (bits > 8 && bits <= 16) {
					len = sprintf(temp_line, "%d.%d.%d.%d %d.%d.%d.255\n",
							a, b, c, d, a, b, c + (1 << (bits - 8)) - 1);
				} else if (bits > 16 && bits <= 24) {
					len = sprintf(temp_line, "%d.%d.%d.%d %d.%d.255.255\n",
							a, b, c, d, a, b + (1 << (bits - 16)) - 1);
				} else if (bits > 24 && bits , 32) {
					len = sprintf(temp_line, "%d.%d.%d.%d %d.255.255.255\n",
							a, b, c, d, a + (1 << (bits - 24)) - 1);
				} else {
					continue;
				}

				write(fd, temp_line, len);
			}
			
			fclose(fp);
			close(fd);

			pfile = list_file_init(g_list_path, "%s:16%s:16");
			if (NULL == pfile) {
				i = 0;
				continue;
			}
			pitem = list_file_get_list(pfile);
			item_num = list_file_get_item_num(pfile);
			pthread_rwlock_wrlock(&g_list_lock);
			while (pnode=double_list_get_from_head(&g_range_list)) {
				free(pnode->pdata);
			}
			memset(g_range_table, 0, 256*sizeof(BOOL));
			for (j=0; j<item_num; j++) {
				prange = (RANGE_NODE*)malloc(sizeof(RANGE_NODE));
				prange->node.pdata = prange;
				prange->min = ip_range_trans(pitem + 32*j);
				g_range_table[prange->min / 0x1000000] = TRUE;
				prange->max = ip_range_trans(pitem + 32*j + 16);
				g_range_table[prange->max / 0x1000000] = TRUE;
				double_list_append_as_tail(&g_range_list, &prange->node);
			}
			pthread_rwlock_unlock(&g_list_lock);
		}

		i = 0;
		
	}
	return NULL;
}

void ip_range_set_param(int param, int val)
{
	if (DOWNLOAD_INTERVAL == param) {
		g_download_interval = val;
	}
}

int ip_range_get_param(int param)
{
	if (DOWNLOAD_INTERVAL == param) {
		return g_download_interval;
	} else if (SITE_TYPE == param) {
		return g_main_site;
	}
	return 0;
}

const char *ip_range_country()
{
	return g_country_code;
}

const char *ip_range_url()
{
	return g_url_path;
}

static unsigned int ip_range_log2(unsigned int val)
{
	unsigned int ret = -1;
	
	while (val != 0) {
		val >>= 1;
		ret++;
	}
	return ret;
}

