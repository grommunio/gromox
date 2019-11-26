#include "config_file.h"
#include "util.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char **argv)
{
	int fd;
	int offset;
	char *ptr;
	char *query;
	char *request;
	char *str_value;
	char temp_path[256];
	char data_path[256];
	char work_path[256];
	char temp_buff[4096];
	struct stat node_stat;
	CONFIG_FILE *pconfig;
	

	if (NULL == getcwd(work_path, 256)) {
		return 1;
	}
	sprintf(temp_path, "%s/../config/athena.cfg", work_path);
	pconfig = config_file_init2(NULL, temp_path);
	if (NULL == pconfig) {
		return 1;
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, "../data");
	} else {
		strcpy(data_path, str_value);
	}
	request = getenv("REQUEST_METHOD");
	if (NULL == request) {
		return 1;
	}
	if (0 != strcmp(request, "GET")) {
		return 1;
	}
	query = getenv("QUERY_STRING");
	if (NULL == query) {
		return 1;
	}
	
	if (0 == strcmp(query, "athena.cfg")) {
		offset = 0;
		str_value = config_file_get_value(pconfig, "DEFAULT_DOMAIN");
		if (NULL != str_value) {
			offset += sprintf(temp_buff + offset, "DEFAULT_DOMAIN = %s\n",
						str_value);
		}
		str_value = config_file_get_value(pconfig, "LOG_VALID_DAYS");
		if (NULL != str_value) {
			offset += sprintf(temp_buff + offset, "LOG_VALID_DAYS = %s\n",
						str_value);
		}
		str_value = config_file_get_value(pconfig, "BACKUP_VALID_DAYS");
		if (NULL != str_value) {
			offset += sprintf(temp_buff + offset, "BACKUP_VALID_DAYS = %s\n",
						str_value);
		}
		config_file_free(pconfig);
		printf("Content-Type:text/plain\n\n");
		printf(temp_buff);
		exit(0);
	} else if (0 == strcmp(query, "area_list.txt")) {
		config_file_free(pconfig);
		sprintf(temp_path, "%s/area_list.txt", data_path);
		if (0 != stat(temp_path, &node_stat)) {
			return 1;
		}
		ptr = malloc(node_stat.st_size + 1);
		if (NULL == ptr) {
			return 1;
		}
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			return 1;
		}
		if (node_stat.st_size != read(fd, ptr, node_stat.st_size)) {
			free(ptr);
			close(fd);
			return 1;
		}
		ptr[node_stat.st_size] = '\0';
		printf("Content-Type:text/plain\n\n");
		printf(ptr);
		exit(0);
	} else if (0 == strcmp(query, "cidb_list.txt")) {
		config_file_free(pconfig);
		sprintf(temp_path, "%s/cidb_list.txt", data_path);
		if (0 != stat(temp_path, &node_stat)) {
			return 1;
		}
		ptr = malloc(node_stat.st_size + 1);
		if (NULL == ptr) {
			return 1;
		}
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			return 1;
		}
		if (node_stat.st_size != read(fd, ptr, node_stat.st_size)) {
			free(ptr);
			close(fd);
			return 1;
		}
		ptr[node_stat.st_size] = '\0';
		printf("Content-Type:text/plain\n\n");
		printf(ptr);
		exit(0);
	} else {
		return 1;
	}
}

