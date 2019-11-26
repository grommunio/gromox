#include "data_extractor.h"
#include "single_list.h"
#include "util.h"
#include "list_file.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define CONTROL_COMMAND		"status_forms.hook report\r\n"

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

static int data_extractor_parse_buffer(char *buff_in, STATUS_ITEM *pitem);

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
	SINGLE_LIST_NODE *pnode;
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
int data_extractor_retrieve(const char *console_ip, STATUS_ITEM *items)
{
	SINGLE_LIST_NODE *pnode;
	CONSOLE_PORT *pconsole;
	char temp_buff[4096];
	
	for (pnode=single_list_get_head(&g_console_list); NULL!=pnode;
		pnode=single_list_get_after(&g_console_list, pnode)) {
		pconsole = (CONSOLE_PORT*)pnode->pdata;
		if (NULL == console_ip || 0 == strcmp(console_ip, pconsole->smtp_ip)) {
			data_extractor_send(pconsole->delivery_ip, pconsole->delivery_port,
				temp_buff, sizeof(temp_buff));
			return data_extractor_parse_buffer(temp_buff, items);
		}
	}
}

int data_extractor_stop()
{
	SINGLE_LIST_NODE *pnode;

	while (pnode=single_list_get_from_head(&g_console_list)) {
		free(pnode->pdata);
	}
	return 0;
}

void data_extractor_free()
{
	single_list_free(&g_console_list);

}

static BOOL data_extractor_send(const char *ip, int port, char *buff, int len)
{
	int sockd, cmd_len;
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
	read_len = read(sockd, buff, len);
	buff[read_len] = '\0';
	write(sockd, "quit\r\n", 6);
	close(sockd);
	return TRUE;
}

static int data_extractor_parse_buffer(char *buff_in, STATUS_ITEM *pitem)
{
	char *pspace;
	char *ppercent;
	char *temp_ptr;
	char *last_ptr;
	char temp_buff[128];
	int i, j;
	int temp_len;
	int buff_len;
	int start_pos;
	int end_pos;
	
	last_ptr = 0;
	buff_len = strlen(buff_in);
	temp_ptr = strstr(buff_in, "250 ");
	if (NULL == temp_ptr) {
		return 0;
	}
	temp_ptr = strstr(temp_ptr, "\r\n");
	if (NULL == temp_ptr) {
		return 0;
	}
	last_ptr = temp_ptr + 2;
	start_pos = last_ptr - buff_in;
	temp_ptr = strstr(temp_ptr, "\r\n\r\n");
	if (NULL == temp_ptr) {
		return 0;
	}
	end_pos = temp_ptr - buff_in;
	for (i=start_pos,j=0; i<=end_pos; i++) {
		if ('\r' != buff_in[i]) {
			continue;
		}
		temp_len = buff_in + i - last_ptr;
		if (temp_len > 127) {
			temp_len = 127;
		}
		memcpy(temp_buff, last_ptr, temp_len);
		temp_buff[temp_len] = '\0';
		pspace = strchr(temp_buff, ' ');
		if (NULL == pspace) {
			return 0;
		}
		for (temp_ptr=pspace; temp_ptr<temp_buff+temp_len; temp_ptr++) {
			if (*temp_ptr != ' ') {
				break;
			}
		}
		if (temp_ptr == temp_buff + temp_len) {
			return 0;
		}
		ppercent = strchr(temp_ptr, '%');
		if (NULL == ppercent) {
			return 0;
		}
		*ppercent = '\0';
		pitem[j].cpu = atoi(temp_ptr);
		for (temp_ptr=ppercent+1; temp_ptr<temp_buff+temp_len; temp_ptr++) {
			if (*temp_ptr != ' ') {
				break;
			}
		}
		if (temp_ptr == temp_buff + temp_len) {
			return 0;
		}
		pspace = strchr(temp_ptr, ' ');
		if (NULL == pspace) {
			return 0;
		}
		*pspace = '\0';
		pitem[j].network = atof(temp_ptr);
		for (temp_ptr=pspace+1; temp_ptr<temp_buff+temp_len; temp_ptr++) {
			if (*temp_ptr != ' ') {
				break;
			}
		}
		if (temp_ptr == temp_buff + temp_len) {
			return 0;
		}
		pitem[j].connection = atoi(temp_ptr);
		last_ptr = buff_in + i + 2;
		j ++;
	}
	return j;
}
