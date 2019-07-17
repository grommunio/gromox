#include "util.h"
#include "list_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define NOTIFYSEND_VERSION			"1.0"


static BOOL control_send(const char *ip, int port, const char *command);

int main(int argc, char **argv)
{
	char *pitem;
	int i, list_len;
	char command[1024];
	LIST_FILE *plist_file;

	
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		 printf("usage: %s maildir message-id\n",  argv[0]);
		 exit(0);
	}

	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", NOTIFYSEND_VERSION);
		exit(0);
	}

	if (3 != argc) {
		printf("usage: %s maildir message-id\n",  argv[0]);
		exit(-1);
	}

	snprintf(command, 1024, "exchange_emsmdb.proc sendmail %s %s",
		argv[1], argv[2]);
	
	plist_file = list_file_init("../data/http_consoles.txt", "%s:16%d");
	if (NULL == plist_file) {
		printf("fail to open console list file!");
		exit(-2);
	}
	
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	for (i=0; i<list_len; i++) {
		if (TRUE == control_send(pitem, *(int*)(pitem + 16), command)) {
			list_file_free(plist_file);
			exit(0);
		}
		pitem += 16 + sizeof(int);
	}
	list_file_free(plist_file);
	exit(-3);
	
}

static BOOL control_send(const char *ip, int port, const char *command)
{
	int sockd, cmd_len;
	int read_len, offset;
	struct sockaddr_in servaddr;
	char temp_buff[1024];

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
	memset(temp_buff, 0, 1024);
	/* read welcome information */
	do {
		read_len = read(sockd, temp_buff + offset, 1024 - offset);
		if (-1 == read_len || 0 == read_len) {
			close(sockd);
			return FALSE;
		}
		offset += read_len;
		if (NULL != search_string(temp_buff, "console> ", offset)) {
			break;
		}
	} while (offset < 1024);
	if (offset >= 1024) {
		close(sockd);
		return FALSE;
	}

	/* send command */
	cmd_len = sprintf(temp_buff, "%s\r\n", command);
	write(sockd, temp_buff, cmd_len);
	if (read(sockd, temp_buff, 1024) <= 0) {
		close(sockd);
		return FALSE;
	}
	write(sockd, "quit\r\n", 6);
	close(sockd);
	if (0 == strncmp(temp_buff, "250 ", 4)) {
		return TRUE;
	}
	return FALSE;
}

