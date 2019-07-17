#include "list_file.h"
#include "double_list.h"
#include "retrying_table.h"
#include "proxy_retrying.h"
#include "multiple_retrying.h"
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#define MAXINTERFACES           16

typedef struct _UNIT_SITE {
	BOOL is_local;
	char ip_addr[16];
	pthread_mutex_t lock;
	DOUBLE_LIST valid_list;
	DOUBLE_LIST invalid_list;
} UNIT_SITE;

typedef struct _UNIT_CHANNEL {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_temp;
	int sockd;
	BOOL in_using;
	time_t time_stamp;
} UNIT_CHANNEL;

static int g_port;
static int g_time_out;
static int g_unit_num;
static int g_channel_num;
static int g_ping_interval;
static pthread_t g_thr_id;
static UNIT_SITE *g_unit_list;
static char g_list_path[256];
static BOOL g_notify_stop = TRUE;

static BOOL proxy_retrying_host_islocal(const char *ip);

static void proxy_retrying_sort_array(size_t *parray, int array_num);

static int proxy_retrying_connect_unit(const char *ip);

static void* scanning_work_func(void *param);

void proxy_retrying_init(const char *list_path, int port, int time_out,
	int ping_interval, int channel_num)
{
	g_port = port;
	g_time_out = time_out;
	g_channel_num = channel_num;
	g_ping_interval = ping_interval;
	strcpy(g_list_path, list_path);
	g_unit_list = NULL;
	g_unit_num = 0;
	g_notify_stop = TRUE;
}

int proxy_retrying_run()
{
	char *pitem;
	int i, j, item_num;
	size_t *temp_array;
	LIST_FILE *plist;
	struct in_addr addr;
	UNIT_CHANNEL *pchannel;
	
	plist = list_file_init(g_list_path, "%s:16");
	if (NULL == plist) {
		printf("[multiple_retrying]: fail to init list file %s\n", g_list_path);
		return -1;
	}
	pitem = list_file_get_list(plist);
	item_num = list_file_get_item_num(plist);
	g_unit_list = (UNIT_SITE*)malloc(sizeof(UNIT_SITE)*item_num);
	if (NULL == g_unit_list) {
		printf("[multiple_retrying]: fail to allocate memory for unit list\n");
		list_file_free(plist);
		return -2;
	}
	temp_array = (size_t*)malloc(sizeof(size_t)*item_num);
	if (NULL == temp_array) {
		printf("[multiple_retrying]: fail to allocate memory for sort array\n");
		list_file_free(plist);
		free(g_unit_list);
		g_unit_list = NULL;
		return -3;
	}
	for (i=0; i<item_num; i++) {
		temp_array[i] = inet_addr(pitem + 16*i);
	}
	list_file_free(plist);
	proxy_retrying_sort_array(temp_array, item_num);
	g_unit_num = item_num;
	for (i=0; i<item_num; i++) {
		addr.s_addr = temp_array[i];
		strcpy(g_unit_list[i].ip_addr, inet_ntoa(addr));
		g_unit_list[i].is_local = proxy_retrying_host_islocal(
									g_unit_list[i].ip_addr);
		if (FALSE == g_unit_list[i].is_local) {
			double_list_init(&g_unit_list[i].valid_list);
			double_list_init(&g_unit_list[i].invalid_list);
			pthread_mutex_init(&g_unit_list[i].lock, NULL);
			for (j=0; j<g_channel_num; j++) {
				pchannel = (UNIT_CHANNEL*)malloc(sizeof(UNIT_CHANNEL));
				if (NULL == pchannel) {
					printf("[multiple_retrying] fail to allocate memory for "
						"channel unit\n");
					continue;
				}
				pchannel->node.pdata = pchannel;
				pchannel->node_temp.pdata = pchannel;
				pchannel->in_using = FALSE;
				pchannel->sockd = proxy_retrying_connect_unit(
									g_unit_list[i].ip_addr);
				if (-1 == pchannel->sockd) {
					double_list_append_as_tail(&g_unit_list[i].invalid_list,
						&pchannel->node);
				} else {
					time(&pchannel->time_stamp);
					double_list_append_as_tail(&g_unit_list[i].valid_list,
						&pchannel->node);
				}
			}
		}
	}
	free(temp_array);
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_thr_id, NULL, scanning_work_func, NULL)) {
		printf("[multiple_retrying]: fail to create scanning thread\n");
		g_notify_stop = TRUE;
		return -4;
	}
	return 0;
}

static void *scanning_work_func(void *param)
{
	int i, read_len;
	time_t cur_time;
	char temp_buff[256];
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	UNIT_CHANNEL *pchannel;
	
	double_list_init(&temp_list);
	while (FALSE == g_notify_stop) {
		for (i=0; i<g_unit_num; i++) {
			if (TRUE == g_unit_list[i].is_local) {
				continue;
			}
			pthread_mutex_lock(&g_unit_list[i].lock);
			for (pnode=double_list_get_head(&g_unit_list[i].valid_list);
				pnode!=NULL; pnode=double_list_get_after(
				&g_unit_list[i].valid_list, pnode)) {
				pchannel = (UNIT_CHANNEL*)pnode->pdata;
				time(&cur_time);
				if (FALSE == pchannel->in_using &&
					cur_time - pchannel->time_stamp >= g_ping_interval) {
					pchannel->in_using = TRUE;
					double_list_append_as_tail(&temp_list,&pchannel->node_temp);
				}
			}
			pthread_mutex_unlock(&g_unit_list[i].lock);
			
			while (pnode=double_list_get_from_head(&temp_list)) {
				pchannel = (UNIT_CHANNEL*)pnode->pdata;
				if (FALSE == multiple_retrying_writeline_timeout(
					pchannel->sockd, "PING", 1) ||
					FALSE == multiple_retrying_readline_timeout(
					pchannel->sockd, temp_buff, 256, 1) ||
					0 != strcmp(temp_buff, "OK")) {
					pthread_mutex_lock(&g_unit_list[i].lock);
					double_list_remove(&g_unit_list[i].valid_list,
						&pchannel->node);
					close(pchannel->sockd);
					pchannel->sockd = -1;
					pchannel->in_using = FALSE;
					double_list_append_as_tail(&g_unit_list[i].invalid_list,
						&pchannel->node);
					pthread_mutex_unlock(&g_unit_list[i].lock);
					continue;
				}
				
				pthread_mutex_lock(&g_unit_list[i].lock);
				time(&pchannel->time_stamp);
				pchannel->in_using = FALSE;
				pthread_mutex_unlock(&g_unit_list[i].lock);
			}
			
			pthread_mutex_lock(&g_unit_list[i].lock);
			while (pnode=double_list_get_from_head(
					&g_unit_list[i].invalid_list)) {
				pchannel = (UNIT_CHANNEL*)pnode->pdata;
				double_list_append_as_tail(&temp_list, &pchannel->node_temp);
			}
			pthread_mutex_unlock(&g_unit_list[i].lock);
			
			while (pnode=double_list_get_from_head(&temp_list)) {
				pchannel = (UNIT_CHANNEL*)pnode->pdata;
				pchannel->sockd = proxy_retrying_connect_unit(
									g_unit_list[i].ip_addr);
				pthread_mutex_lock(&g_unit_list[i].lock);
				if (-1 == pchannel->sockd) {
					double_list_append_as_tail(&g_unit_list[i].invalid_list,
						&pchannel->node);
				} else {
					time(&pchannel->time_stamp);
					double_list_append_as_tail(&g_unit_list[i].valid_list,
						&pchannel->node);
				}
				pthread_mutex_unlock(&g_unit_list[i].lock);
			}
			
		}
		sleep(1);
	}
	pthread_exit(0);
}

int proxy_retrying_stop()
{
	int i;
	UNIT_CHANNEL *pchannel;
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thr_id, NULL);
	}
	if (NULL == g_unit_list) {
		return 0;
	}
	for (i=0; i<g_unit_num; i++) {
		while (pnode=double_list_get_from_head(&g_unit_list[i].valid_list)) {
			pchannel = (UNIT_CHANNEL*)pnode->pdata;
			close(pchannel->sockd);
			free(pchannel);
		}
		while (pnode=double_list_get_from_head(&g_unit_list[i].invalid_list)) {
			pchannel = (UNIT_CHANNEL*)pnode->pdata;
			free(pchannel);
		}
		double_list_free(&g_unit_list[i].valid_list);
		double_list_free(&g_unit_list[i].invalid_list);
		pthread_mutex_destroy(&g_unit_list[i].lock);
	}
	free(g_unit_list);
	g_unit_list = NULL;
	return 0;
}

void proxy_retrying_free()
{
	g_port = 0;
	g_time_out = 0;
	g_ping_interval = 0;
	g_unit_list = NULL;
	g_unit_num = 0;
}

static BOOL proxy_retrying_host_islocal(const char *ip)
{
	int fd, intrface;
	struct ifreq buf[MAXINTERFACES];
	struct ifconf ifc;
	
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
		ifc.ifc_len = sizeof(buf);
		ifc.ifc_buf = (caddr_t)buf;
		if (0 == ioctl(fd, SIOCGIFCONF, (char *)&ifc)) {
			intrface = ifc.ifc_len / sizeof(struct ifreq);
			while (intrface-- > 0) {
				/*Get IP of the net card */
				if (0 == (ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface])) &&
					0 == strcmp(ip, inet_ntoa(((struct sockaddr_in*)(
					&buf[intrface].ifr_addr))->sin_addr))) {
					return TRUE;
				}
			}
		}
		close (fd);
	}
	return FALSE;
}

static void proxy_retrying_sort_array(size_t *parray, int array_num)
{
	int low, high;
	size_t list_separator;
	size_t temp;

	low = 0;
	high = array_num - 1;
	list_separator = parray[array_num/2];
	do {
		while (parray[low] < list_separator) {
			low ++;
		}
		while (parray[high] > list_separator) {
			high --;
		}
		if (low <= high) {
			temp = parray[low];
			parray[low] = parray[high];
			parray[high] = temp;
			low ++;
			high --;
		}
	} while (low <= high);
	if (high > 0) {
		proxy_retrying_sort_array(parray, high + 1);
	}
	if (low < array_num - 1) {
		proxy_retrying_sort_array(parray + low, array_num - low);
	}
}

static int proxy_retrying_connect_unit(const char *ip)
{
	int sockd;
	char buff[256];
	struct sockaddr_in servaddr;
	
	/* try to connect to the destination UNIT */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(g_port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
		close(sockd);
		return -1;
	}
	fcntl(sockd, F_SETFL, O_NONBLOCK);
	if (FALSE == multiple_retrying_readline_timeout(sockd, buff, 256, 1)) {
		close(sockd);
		return -1;
	}
	if (0 != strcmp("OK", buff)) {
		close(sockd);
		return -1;
	}
	return sockd;
}

BOOL proxy_retrying_check(const char *ip, const char *from, MEM_FILE *pfile)
{
	size_t temp_num;
	int i, rcpt_num;
	time_t first_time;
	time_t last_time;
	BOOL found_channel;
	const char *pdot;
	char temp_ip[16];
	char temp_rcpt[256];
	char temp_result[32];
	char temp_string[256];
	DOUBLE_LIST_NODE *pnode;
	UNIT_CHANNEL *pchannel;
	
	rcpt_num = 0;
	mem_file_seek(pfile, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(pfile, temp_rcpt, 256)) {
		rcpt_num ++;
	}
	pdot = ip - 1;
	for (i=0; i<2; i++) {
		pdot = strchr(pdot + 1, '.');
	}
	memcpy(temp_ip, ip, pdot - ip);
	temp_ip[pdot - ip] = '\0';
	snprintf(temp_string, 255, "%s:%s:%s:%d", temp_ip, from, temp_rcpt,
		rcpt_num);
	if (0 == g_unit_num) {
		return retrying_table_check(temp_string);
	}
	temp_string[255] = '\0';
	strcat(temp_ip, ".0.0");
	temp_num = inet_addr(temp_ip);
	temp_num %= g_unit_num;
	if (TRUE == g_unit_list[temp_num].is_local) {
		return retrying_table_check(temp_string);
	} else {
		time(&first_time);
FIND_CHANNEL:
		found_channel = FALSE;
		pthread_mutex_lock(&g_unit_list[temp_num].lock);
		if (0 == double_list_get_nodes_num(&g_unit_list[temp_num].valid_list)) {
			pthread_mutex_unlock(&g_unit_list[temp_num].lock);
			return FALSE;
		}
		for (pnode=double_list_get_head(&g_unit_list[temp_num].valid_list);
			pnode!=NULL; pnode=double_list_get_after(
			&g_unit_list[temp_num].valid_list, pnode)) {
			pchannel = (UNIT_CHANNEL*)pnode->pdata;
			if (FALSE == pchannel->in_using) {
				pchannel->in_using = TRUE;
				found_channel = TRUE;
				break;
			}
		}
		pthread_mutex_unlock(&g_unit_list[temp_num].lock);
		if (FALSE == found_channel) {
			time(&last_time);
			if (last_time - first_time > g_time_out) {
				return FALSE;
			} else {
				usleep(5000);
				goto FIND_CHANNEL;
			}
		}
		if (FALSE == multiple_retrying_writeline_timeout(pchannel->sockd,
			temp_string, g_time_out)
			|| FALSE == multiple_retrying_readline_timeout(pchannel->sockd,
			temp_result, 32, g_time_out)) {
			pthread_mutex_lock(&g_unit_list[temp_num].lock);
			pchannel->in_using = FALSE;
			close(pchannel->sockd);
			pchannel->sockd = -1;
			double_list_remove(&g_unit_list[temp_num].valid_list,
				&pchannel->node);
			double_list_append_as_tail(&g_unit_list[temp_num].invalid_list,
				&pchannel->node);
			pthread_mutex_unlock(&g_unit_list[temp_num].lock);
			return FALSE;
		}
		pthread_mutex_lock(&g_unit_list[temp_num].lock);
		time(&pchannel->time_stamp);
		pchannel->in_using = FALSE;
		pthread_mutex_unlock(&g_unit_list[temp_num].lock);
		if (0 == strcmp(temp_result, "TRUE")) {
			return TRUE;
		} else {
			return FALSE;
		}
	}
}

int proxy_retrying_get_param(int param)
{
	if (PROXY_RETRYING_PING_INTERVAL == param) {
		return g_ping_interval;
	} else if (PROXY_RETRYING_TIME_OUT == param) {
		return g_time_out;
	} else if (PROXY_RETRYING_UNIT_NUM == param) {
		return g_unit_num;
	} else if (PROXY_RETRYING_CHANNEL_NUM == param) {
		return g_channel_num;
	} else {
		return 0;
	}
}

void proxy_retrying_set_param(int param, int value)
{
	switch (param) {
	case PROXY_RETRYING_PING_INTERVAL:
		g_ping_interval = value;
		break;
	case PROXY_RETRYING_TIME_OUT:
		g_time_out = value;
		break;
	}
}


