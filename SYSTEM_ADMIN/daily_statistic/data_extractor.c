#include "data_extractor.h"
#include "single_list.h"
#include "util.h"
#include "list_file.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define CONTROL_COMMAND		"spam_statistic.svc report\r\n"

typedef struct _CONSOLE_PORT {
	SINGLE_LIST_NODE node;
	char smtp_ip[16];
	int smtp_port;
	char delivery_ip[16];
	int delivery_port;
} CONSOLE_PORT;

static char g_list_path[256];
static SINGLE_LIST g_console_list;

static BOOL data_extractor_send(const char *ip, int port, char *buff, int len);

static void data_extractor_get_time(char *buff_in, time_t *time_out);

static int data_extractor_parse_buffer(char *buff_in, STATISTIC_ITEM *pitem);

void data_extractor_init(const char *path)
{
	if (NULL != path) {
		strcpy(g_list_path, path);
	} else {
		g_list_path[0] = '\0';
	}
	single_list_init(&g_console_list);
}

int data_extractor_run()
{
	LIST_FILE *plist_file;
	char *pitem;
	int i, list_len;
	CONSOLE_PORT *pport;
	
	plist_file = list_file_init(g_list_path, "%s:16%d%s:16%d");
	if (NULL == plist_file) {
		printf("[data_extractor]: fail to open console list file, will not" 
			"notify server to reload list\n");
		return 0;
	}
	
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	for (i=0; i<list_len; i++) {
		pport = (CONSOLE_PORT*)malloc(sizeof(CONSOLE_PORT));
		if (NULL== pport) {
			continue;
		}
		pport->node.pdata = pport;
		strcpy(pport->smtp_ip, pitem);
		pport->smtp_port = *(int*)(pitem + 16);
		strcpy(pport->delivery_ip, pitem + 16 + sizeof(int));
		pport->delivery_port = *(int*)(pitem + 32 + sizeof(int));
		pitem += 32 + 2*sizeof(int);
		single_list_append_as_tail(&g_console_list, &pport->node);
	}
	list_file_free(plist_file);
	return 0;
}

void data_extractor_retrieve(const char *console_ip,
	STATISTIC_ITEM *psmtp_item, int *smtp_num, time_t *smtp_time,
	STATISTIC_ITEM *pdelivery_item, int *delivery_num, time_t *delivery_time)
{
	SINGLE_LIST_NODE *pnode;
	CONSOLE_PORT *pconsole;
	char temp_buff[65536];
	
	*smtp_num = 0;
	*smtp_time = 0;
	*delivery_num = 0;
	*delivery_time = 0;
	for (pnode=single_list_get_head(&g_console_list); NULL!=pnode;
		pnode=single_list_get_after(&g_console_list, pnode)) {
		pconsole = (CONSOLE_PORT*)pnode->pdata;
		if (NULL == console_ip || 0 == strcmp(console_ip, pconsole->smtp_ip)) {
			data_extractor_send(pconsole->smtp_ip, pconsole->smtp_port,
				temp_buff, sizeof(temp_buff));
			*smtp_num = data_extractor_parse_buffer(temp_buff, psmtp_item);
			data_extractor_get_time(temp_buff, smtp_time);
			data_extractor_send(pconsole->delivery_ip, pconsole->delivery_port,
				temp_buff, sizeof(temp_buff));
			*delivery_num = data_extractor_parse_buffer(temp_buff, pdelivery_item);
			data_extractor_get_time(temp_buff, delivery_time);
			return;
		}
	}
}

int data_extractor_stop()
{
	SINGLE_LIST_NODE *pnode;

	while ((pnode = single_list_get_from_head(&g_console_list)) != NULL)
		free(pnode->pdata);
	return 0;
}

void data_extractor_free()
{
	single_list_free(&g_console_list);

}

static BOOL data_extractor_send(const char *ip, int port, char *buff, int len)
{
	int sockd;
	int read_len, offset;
	struct sockaddr_in servaddr;

	sockd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
		close(sockd);
		return FALSE;
	}
	offset = 0;
	memset(buff, 0, len);
	/* read welcome information */
	do {
		read_len = read(sockd, buff + offset, len - offset);
		if (-1 == read_len || 0 == read_len) {
			close(sockd);
			return FALSE;
		}
		offset += read_len;
		if (NULL != search_string(buff, "console> ", offset)) {
			break;
		}
	} while (offset < 1024);
	if (offset >= 1024) {
		close(sockd);
		return FALSE;
	}

	/* send command */
	write(sockd, CONTROL_COMMAND, sizeof(CONTROL_COMMAND) - 1);
	offset = 0;
	memset(buff, 0, len);
	/* read prompt information */
	do {
		read_len = read(sockd, buff + offset, len - offset);
		if (-1 == read_len || 0 == read_len) {
			close(sockd);
			return FALSE;
		}
		offset += read_len;
		if (NULL != search_string(buff, "console> ", offset)) {
			break;
		}
	} while (offset < len);
	buff[offset] = '\0';
	write(sockd, "quit\r\n", 6);
	close(sockd);
	return TRUE;
}


static void data_extractor_get_time(char *buff_in, time_t *time_out)
{
	int i, j, buff_len;
	char temp_buff[256];
	struct tm tm_time;

	buff_len = strlen(buff_in);
	for (i=buff_len-1,j=0; i>=0; i--) {
		if (':' == buff_in[i]) {
			j++;
			if (3 == j) {
				break;
			}
		}
	}
	if (i < 0) {
		return;
	}
	memcpy(temp_buff, buff_in + i + 2, buff_len - i - 4);
	temp_buff[buff_len - i - 4] = '\0';
	memset(&tm_time, 0, sizeof(tm_time));
	if (NULL == strptime(temp_buff, "%Y/%m/%d %H:%M:%S", &tm_time)) {
		*time_out = 0;
	} else {
	   *time_out = mktime(&tm_time);
	}
}


static int data_extractor_parse_buffer(char *buff_in, STATISTIC_ITEM *pitem)
{
	char *temp_ptr;
	char temp_buff[64];
	int buff_len, last_crlf;
	int  start_pos, end_pos;
	int i, j, item_num;
	
	buff_len = strlen(buff_in);
	for (i=0; i<buff_len; i++) {
		if ('\n' == buff_in[i]) {
			break;
		}
	}
	if (i == buff_len) {
		return 0;
	}
	start_pos = i + 1;
	temp_ptr = strstr(buff_in, "* last statistic time:");
	if (NULL == temp_ptr) {
		return 0;
	}
	end_pos = temp_ptr - buff_in;
	
	for (i=start_pos,last_crlf=start_pos-1,item_num=0; i<end_pos; i++) {
		if ('\r' == buff_in[i]) {
			for (j=i; j>last_crlf; j--) {
				if (' ' == buff_in[j]) {
					break;
				}
			}
			if (j > last_crlf) {
				memcpy(pitem->tag, buff_in + last_crlf + 1, j - last_crlf);
				pitem->tag[j - last_crlf - 1] = '\0';
				rtrim_string(pitem->tag);
				if (i - j - 1 >= 64) {
					return 0;
				}
				memcpy(temp_buff, buff_in + j + 1, i - j - 1);
				temp_buff[i - j - 1] = '\0';
				pitem->number = atoi(temp_buff);
				item_num ++;
				pitem ++;
			}
			last_crlf = i + 1;
		}
	}
	return item_num;
}
