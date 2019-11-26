#include "keyword_cleaning.h"
#include "util.h"
#include "list_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define CONTROL_COMMAND		"anonymous_keyword.hook status\r\n"
#define CLEAN_COMMAND		"anonymous_keyword.hook clear\r\n"

typedef struct _CONSOLE_PORT {
	char smtp_ip[16];
	int smtp_port;
	char delivery_ip[16];
	int delivery_port;
} CONSOLE_PORT;

static time_t g_now_time;
static char g_group_path[256];
static char g_console_path[256];
static char g_statistic_path[256];

static BOOL keyword_cleaning_send(const char *ip, int port, char *buff, int len);

static void keyword_cleaning_parse_buffer(char *buff_in, int *array,
	int array_num);

void keyword_cleaning_init(time_t now_time, const char *group_path,
	const char *console_path, const char *statistic_path)
{
	g_now_time = now_time;
	strcpy(g_group_path, group_path);
	strcpy(g_console_path, console_path);
	strcpy(g_statistic_path, statistic_path);
}

int keyword_cleaning_run()
{
	char *pgroup;
	char time_str[32];
	char temp_buff[4096];
	char *group_array;
	int *statistic_array;
	CONSOLE_PORT *pitem;
	LIST_FILE *plist_file;
	int i, len, fd;
	int list_len, group_num;
	

	plist_file = list_file_init(g_group_path, "%s:256%l");
	if (NULL == plist_file) {
		return 0;
	}
	pgroup = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	
	for (i=0, group_num=0; i<list_len; i++) {
		if (0 == strncmp(pgroup, "--------", 8)) {
			group_num ++;
		}
		pgroup += 256 + sizeof(long);
	}
	group_array = (char*)malloc(32*group_num);
	statistic_array = (int*)malloc(sizeof(int)*group_num);
	if (NULL == group_array || NULL == statistic_array) {
		return 0;
	}
	memset(statistic_array, 0, sizeof(int)*group_num);
	
	pgroup = (char*)list_file_get_list(plist_file);
	for (i=0, group_num=-1; i<list_len; i++) {
		if (0 == strncmp(pgroup, "--------", 8)) {
			group_num ++;
			strcpy(group_array + 32*group_num, pgroup + 8);
		}
		pgroup += 256 + sizeof(long);
	}
	group_num ++;
	list_file_free(plist_file);
	
	plist_file = list_file_init(g_console_path, "%s:16%d%s:16%d");
	if (NULL == plist_file) {
		printf("[keyword_cleaning]: fail to open console list file, will not" 
			"notify server to reload list\n");
		return 0;
	}
	
	pitem = (CONSOLE_PORT*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	for (i=0; i<list_len; i++) {	
		keyword_cleaning_send(pitem[i].delivery_ip, pitem[i].delivery_port,
			temp_buff, sizeof(temp_buff));
		keyword_cleaning_parse_buffer(temp_buff, statistic_array, group_num);
	}
	list_file_free(plist_file);
	strftime(time_str, 32, "%Y-%m-%d", localtime(&g_now_time));
	fd = open(g_statistic_path, O_WRONLY|O_APPEND);
	for (i=0; i<group_num; i++) {
		len = sprintf(temp_buff, "%s\t%s\t%d\n", time_str, group_array + 32*i,
				statistic_array[i]);
		write(fd, temp_buff, len);
	}
	close(fd);
	free(group_array);
	free(statistic_array);
	return 0;
}

int keyword_cleaning_stop()
{
	/* do nothing */
	return 0;
}

void keyword_cleaning_free()
{
	/* do nothing */
}

static BOOL keyword_cleaning_send(const char *ip, int port, char *buff, int len)
{
	int sockd;
	int read_len, offset;
	char temp_buff[256];
	struct sockaddr_in servaddr;

	sockd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
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
	write(sockd, CLEAN_COMMAND, sizeof(CLEAN_COMMAND) - 1);
	read(sockd, temp_buff, 256);
	write(sockd, "quit\r\n", 6);
	close(sockd);
	return TRUE;
}

static void keyword_cleaning_parse_buffer(char *buff_in, int *array,
	int array_num)
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
		return;
	}
	start_pos = i + 1;
	temp_ptr = strstr(buff_in, "* last statistic time:");
	if (NULL == temp_ptr) {
		return;
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
				if (i - j - 1 >= 64) {
					return;
				}
				memcpy(temp_buff, buff_in + j + 1, i - j - 1);
				temp_buff[i - j - 1] = '\0';
				if (item_num < array_num) {
					array[item_num] += atoi(temp_buff);
				}
				item_num ++;
			}
			last_crlf = i + 1;
		}
	}
}

