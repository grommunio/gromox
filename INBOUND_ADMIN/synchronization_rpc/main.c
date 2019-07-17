#include "config_file.h"
#include "list_file.h"
#include "util.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(int argc, char **argv)
{
	int fd;
	int i, len;
	char *ptr;
	char *pitem;
	char *query;
	char *request;
	char *str_value;
	char *remote_ip;
	char temp_path[256];
	char data_path[256];
	char work_path[256];
	struct stat node_stat;
	LIST_FILE *plist;
	CONFIG_FILE *pconfig;
	

	if (NULL == getcwd(work_path, 256)) {
		exit(-1);
	}
	sprintf(temp_path, "%s/../config/athena.cfg", work_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		exit(-1);
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, "../data");
	} else {
		strcpy(data_path, str_value);
	}
	config_file_free(pconfig);
	remote_ip = getenv("REMOTE_ADDR");
	if (NULL == remote_ip) {
		exit(-1);
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		exit(-1);
	}
	if (0 != strcmp(request, "GET")) {
		exit(-1);
	}
	query = getenv("QUERY_STRING");
	if (NULL == query) {
		exit(-1);
	}
	
	sprintf(temp_path, "%s/synchronization_allow.txt", data_path);
	plist = list_file_init(temp_path, "%s:16%s:256");
	if (NULL == plist) {
		exit(-1);
	}
	len = list_file_get_item_num(plist);
	pitem = list_file_get_list(plist);
	for (i=0; i<len; i++) {
		if (0 == strcmp(remote_ip, pitem + (16 + 256)*i)) {
			break;
		}
	}
	list_file_free(plist);
	
	if (i >= len) {
		exit(-1);
	}
	if (0 == strcmp(query, "athena.cfg")) {
		sprintf(temp_path, "%s/../config/athena.cfg", work_path);
	} else if (0 == strcmp(query, "local_setup.txt")) {
		sprintf(temp_path, "%s/local_setup.txt", data_path);
	} else if (0 == strcmp(query, "domain_list.txt")) {
		sprintf(temp_path, "%s/domain_list.txt", data_path);
	} else if (0 == strcmp(query, "backend_table.txt")) {
		sprintf(temp_path, "%s/backend_table.txt", data_path);
	} else if (0 == strcmp(query, "dns_table.txt")) {
		sprintf(temp_path, "%s/dns_table.txt", data_path);
	} else if (0 == strcmp(query, "forward_table.txt")) {
		sprintf(temp_path, "%s/forward_table.txt", data_path);
	} else if (0 == strcmp(query, "from_replace.txt")) {
		sprintf(temp_path, "%s/from_replace.txt", data_path);
	} else if (0 == strcmp(query, "domain_mailbox.txt")) {
		sprintf(temp_path, "%s/domain_mailbox.txt", data_path);
	} else if (0 == strcmp(query, "domain_acl.txt")) {
		sprintf(temp_path, "%s/domain_acl.txt", data_path);
	} else if (0 == strcmp(query, "system_users.txt")) {
		sprintf(temp_path, "%s/system_users.txt", data_path);
	} else {
		exit(-1);
	}
	if (0 != stat(temp_path, &node_stat)) {
		exit(-1);
	}
	ptr = malloc(node_stat.st_size + 1);
	if (NULL == ptr) {
		exit(-1);
	}
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		exit(-1);
	}
	if (node_stat.st_size != read(fd, ptr, node_stat.st_size)) {
		free(ptr);
		close(fd);
		exit(-1);
	}
	ptr[node_stat.st_size] = '\0';
	printf("Content-Type:text/plain\n\n");
	printf(ptr);
	exit(0);
}

