#include "pop3.h"
#include "smtp.h"
#include "mail_func.h"
#include "list_file.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

static void term_handler(int signo);

int main(int argc, char **argv)
{
	LIST_FILE *plist;
	int pop_port;
	int smtp_port;
	int i, j, k;
	int item_num;
	char pop_address[16];
	char smtp_address[16];
	int list_nums[16*1024];
	char *pcolon, *pitem, *pbuff;
	POP3_SESSION pop_session;
	SMTP_SESSION smtp_session;
	

	if (4 != argc) {
		printf("%s pop_addr:port smtp_addr:port <list file>\n", argv[0]);
		return -1;
	}
	if (4 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <list file>\n", argv[0]);
		return 0;
	}

	pcolon = strchr(argv[1], ':');
	if (NULL == pcolon) {
		pop_port = 110;
	} else {
		pop_port = atoi(pcolon + 1);
		if (pop_port <= 0) {
			pop_port = 110;
		}
	}

	if (NULL == extract_ip(argv[1], pop_address)) {
		printf("pop server address format error!\n");
		return -2;
	}

	pcolon = strchr(argv[2], ':');
	if (NULL == pcolon) {
		smtp_port = 25;
	} else {
		smtp_port = atoi(pcolon + 1);
		if (smtp_port <= 0) {
			smtp_port = 25;
		}
	}

	if (NULL == extract_ip(argv[2], smtp_address)) {
		printf("smtp server address format error!\n");
		return -3;

	}

	smtp_init(&smtp_session, smtp_address, smtp_port);
	
	plist = list_file_init(argv[3], "%s:256%s:256");
	if (NULL == plist) {
		printf("fail to init list file %s\n", argv[3]);
		return -4;
	}

	pbuff = malloc(128*1024*1024);
	if (NULL == pbuff) {
		printf("fail to allocate memory for retrieving email\n");
		return -5;
	}

	pitem = list_file_get_list(plist);
	item_num = list_file_get_item_num(plist);
	
	for (i=0; i<item_num; i++) {
		pop3_init(&pop_session, pop_address, pop_port, pitem + 512*i,
			pitem + 512*i + 256);
		if (FALSE == pop3_login(&pop_session)) {
			printf("fail to login with account %s\n", pitem + 512*i);
			pop3_free(&pop_session);
			continue;
		}
		if (FALSE == pop3_list(&pop_session, list_nums)) {
			printf("fail to list pop server with account %s\n", pitem + 512*i);
			pop3_free(&pop_session);
			continue;
		}
		
		for (j=0,k=0; j<16*1024; j++) {
			if (-1 == list_nums[j]) {
				break;
			}
			if (FALSE == pop3_retr(&pop_session, list_nums[j],
				pbuff, 128*1024*1024)) {
				printf("fail to retrieve %d\n", list_nums[j]);
				continue;
			}
			if (FALSE == smtp_send(&smtp_session, "pop_agent@system.mail",
				pitem + 512*i, pbuff)) {
				printf("fail to send mail %d via smtp server\n", list_nums[j]);
				continue;
			}
			k++;
			
		}
		pop3_free(&pop_session);
		printf("%d mails ported into new system for %s\n", k, pitem + 512*i);
	}

	list_file_free(plist);
	
}

