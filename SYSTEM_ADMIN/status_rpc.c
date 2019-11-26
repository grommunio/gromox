#include "config_file.h"
#include "list_file.h"
#include "util.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

#define XML_TEXT	\
"<?xml version=\"1.0\" encoding=\"iso-8859-1\" ?>\n\
<statusinfo>\n\
<cpu>%d</cpu>\n\
<network>%d</network>\n\
<connection>%d</connection>\n\
<ham>%d</ham>\n\
<spam>%d</spam>\n\
</statusinfo>\n"
 

#define SHARE_MEMORY_SIZE   64*1024

typedef struct _CONSOLE_ITEM {
	char smtp_ip[16];
	int smtp_port;
	char delivery_ip[16];
	int delivery_port;
} CONSOLE_ITEM;

int main(int argc, const char **argv)
{
	key_t k_shm;
	int len;
	int *pitem;
	int total_num;
	int i, shm_id;
	int *shm_begin;
	char *ptr;
	char *query;
	char *request;
	const char *str_value;
	char console[16];
	char temp_path[256];
	char data_path[256];
	char work_path[256];
	LIST_FILE *plist;
	CONFIG_FILE *pconfig;
	CONSOLE_ITEM *pconsole;
	

	if (NULL == getcwd(work_path, 256)) {
		return 1;
	}
	sprintf(temp_path, "%s/../config/athena.cfg", work_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		printf("Content-Type:text/html\n\n");
		printf("Cannot init configure file %s\n", temp_path);
		exit(0);
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, "../data");
	} else {
		strcpy(data_path, str_value);
	}
	str_value = config_file_get_value(pconfig, "TOKEN_FILE_PATH");
	if (NULL == str_value) {
		str_value = "../token";
	}
	sprintf(temp_path, "%s/%s/monitor.shm", work_path, str_value);
	config_file_free(pconfig);
	k_shm = ftok(temp_path, 1);
	if (-1 == k_shm) {
		printf("Content-Type:text/html\n\n");
		printf("Cannot init token file %s\n", temp_path);
		exit(0);
	}
	shm_id = shmget(k_shm, SHARE_MEMORY_SIZE, 0666);
	if (-1 == shm_id) {
		printf("Content-Type:text/html\n\n");
		printf("Cannot open share memory\n");
		exit(0);
	}
	shm_begin = shmat(shm_id, NULL, 0);
	if (NULL == shm_begin) {
		printf("Content-Type:text/html\n\n");
		printf("Fail to attach share memory\n");
		exit(0);
	}
	total_num = *shm_begin;
	shm_begin ++;
	
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		printf("Content-Type:text/html\n\n");
		printf("Cannot get request method!\n");
		shmdt(shm_begin);
		exit(0);
	}
	if (0 != strcmp(request, "GET")) {
		printf("Content-Type:text/html\n\n");
		printf("Only GET method can be accepted by cgi program\n");
		shmdt(shm_begin);
		exit(0);
	}
	query = getenv("QUERY_STRING");
	if (NULL == query) {
		printf("Content-Type:text/html\n\n");
		printf("parameter error!\n");
		shmdt(shm_begin);
		exit(0);
	}
	len = strlen(query);
	ptr = search_string(query, "console=", len);
	if (NULL == ptr) {
		printf("Content-Type:text/html\n\n");
		printf("parameter error!\n");
		shmdt(shm_begin);
		exit(0);
	}
	ptr += 8;
	if (query + len - ptr > 16) {
		printf("Content-Type:text/html\n\n");
		printf("parameter error!\n");
		shmdt(shm_begin);
		exit(0);
	}
	memcpy(console, ptr, query + len - ptr);
	console[query + len - ptr] = '\0';
	sprintf(temp_path, "%s/%s/console_table.txt", work_path, data_path);
	plist = list_file_init(temp_path, "%s:16%d%s:16%d");
	pconsole = (CONSOLE_ITEM*)list_file_get_list(plist);
	len = list_file_get_item_num(plist);
	if (len > total_num) {
		len = total_num;
	}
	for (i=0; i<len; i++) {
		if (0 == strcmp(pconsole[i].smtp_ip, console)) {
			break;
		}
	}
	list_file_free(plist);
	printf("Content-Type:text/xml\n\n");
	if (i == len) {
		printf(XML_TEXT, -1, -1, -1, -1, -1);
	} else {
		pitem = shm_begin + i*5;
		printf(XML_TEXT, pitem[0], pitem[1], pitem[2], pitem[3], pitem[4]);
	}
	shmdt(shm_begin);
	exit(0);
}

