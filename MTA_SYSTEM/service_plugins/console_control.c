#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/svc_common.h>
#include "util.h"
#include "mail_func.h"
#include "config_file.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>


DECLARE_API;

static char g_console_ip[16];
static int g_console_port;
static pthread_mutex_t g_control_lock;

static BOOL console_server_control(const char* cmdline, char *result,
	int length);

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256], tmp_path[256];
	char config_file_path[256];
	const char *str_value;
	char *psearch;
	char service_name[256];
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		pthread_mutex_init(&g_control_lock, NULL);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, tmp_path);
		if (NULL == pfile) {
			printf("[%s]: config_file_init %s: %s\n", file_name, tmp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "CONFIG_FILE_PATH");
		if (NULL == str_value) {
			printf("[%s] failed to get console config file path\n", file_name);
			config_file_free(pfile);
			return FALSE;
		} else {
			strcpy(config_file_path, str_value);
		}
		str_value = config_file_get_value(pfile, "SERVICE_NAME");
		if (NULL != str_value) {
			strcpy(service_name, str_value);
		} else {
			printf("[%s] failed to get service name\n", file_name);
			config_file_free(pfile);
			return FALSE;
		}
		config_file_free(pfile);
		pfile = config_file_init2(NULL, config_file_path);
		if (NULL == pfile) {
			printf("[%s]: fail to open %s\n", file_name, config_file_path);
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "CONSOLE_SERVER_IP");
		if (NULL == str_value) {
			str_value = "127.0.0.1";
			config_file_set_value(pfile, "CONSOLE_SERVER_IP", str_value);
		} else {
			if (NULL == extract_ip(str_value, g_console_ip)) {
				printf("[%s]: console server ipaddr \"%s\" format error\n",
					file_name, str_value);
				config_file_free(pfile);
				return FALSE;
			}
			strcpy(g_console_ip, str_value);
			printf("[%s]: console server ipaddr is %s\n", file_name, g_console_ip);
		}
		str_value = config_file_get_value(pfile, "CONSOLE_SERVER_PORT");
		if (NULL == str_value) {
			g_console_port = 6677;
			config_file_set_value(pfile, "CONSOLE_SERVER_PORT", "6677");
		} else {
			g_console_port = atoi(str_value);
			if (g_console_port <= 0) {
				printf("[%s]: console server port %s format error\n",
					file_name, str_value);
				config_file_free(pfile);
				return FALSE;
			}
			printf("[%s]: console server port is %d\n", file_name,
				g_console_port);
		}
		config_file_free(pfile);
		if (FALSE == register_service(service_name, console_server_control)) {
			printf("[%s]: failed to register \"%s\" service\n", file_name,
				service_name);
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		pthread_mutex_destroy(&g_control_lock);
		return TRUE;
	}
	return false;
}

static BOOL console_server_control(const char *cmdline, char *result,
	int length)
{
	int sockd, cmd_len;
	int read_len, offset;
	struct sockaddr_in servaddr;
	char temp_buff[1024];
	char command[1026];

	cmd_len = strlen(cmdline);
	if (cmd_len > 1024) {
		return FALSE;
	}
	pthread_mutex_lock(&g_control_lock);
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(g_console_port);
	inet_pton(AF_INET, g_console_ip, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
		close(sockd);
		pthread_mutex_unlock(&g_control_lock);
		return FALSE;
	}
	offset = 0;
	memset(temp_buff, 0, 1024);
	/* read welcome information */
	do {
		read_len = read(sockd, temp_buff + offset, 1024 - offset);
		if (-1 == read_len || 0 == read_len) {
			close(sockd);
			pthread_mutex_unlock(&g_control_lock);
			return FALSE;
		}
		offset += read_len;
		if (NULL != search_string(temp_buff, "console> ", offset)) {
			break;
		}
	} while (offset < 1024);
	if (offset >= 1024) {
		close(sockd);
		pthread_mutex_unlock(&g_control_lock);
		return FALSE;
	}
	
	/* send command */
	memcpy(command, cmdline, cmd_len);
	memcpy(command + cmd_len, "\r\n", 2);
	cmd_len += 2;
	if (cmd_len != write(sockd, command, cmd_len)) {
		close(sockd);
		pthread_mutex_unlock(&g_control_lock);
		return FALSE;
	}

	memset(result, 0, length);
	read_len = read(sockd, result, length - 1);
	write(sockd, "quit\r\n", 6);
	close(sockd);
	if (-1 == read_len || 0 == read_len) {
		pthread_mutex_unlock(&g_control_lock);
		return FALSE;
	}
	/* trim "console> " */
	if (read_len >= 9 && 0 == strcmp(result + read_len - 9, "console> ")) {
		read_len -= 9;
	}
	result[read_len] = '\0';
	pthread_mutex_unlock(&g_control_lock);
	return TRUE;
}

