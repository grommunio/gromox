#include "common_types.h"
#include "sensor_client.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#define SOCKET_TIMEOUT		60

static char g_sensor_ip[16];
static int g_sensor_port;

static int sensor_client_connect(const char *ip_addr, int port);

static BOOL sensor_client_readline(int sockd, char *buff, int length);

void sensor_client_init(const char *sensor_ip, int sensor_port)
{
	strcpy(g_sensor_ip, sensor_ip);
	g_sensor_port = sensor_port;
}

int sensor_client_run()
{
	/* do nothing */
	return 0;
}

int sensor_client_stop()
{
	/* do nothing */
	return 0;
}

void sensor_client_add(const char *username, int num)
{
	int len;
	int sockd;
	char temp_buff[1024];
	

	sockd = sensor_client_connect(g_sensor_ip, g_sensor_port);
	if (-1 == sockd) {
		return;
	}

	len = snprintf(temp_buff, 1024, "ADD %s %d\r\n", username, num);
	if (len != write(sockd, temp_buff, len)) {
		close(sockd);
	}
	
	if (FALSE == sensor_client_readline(sockd, temp_buff, 1024)) {
		close(sockd);
		return;
	}
	write(sockd, "QUIT\r\n", 6);
	close(sockd);
}

void sensor_client_free()
{
	/* do nothing */

}

static int sensor_client_connect(const char *ip_addr, int port)
{
	int sockd;
	int offset;
	int read_len;
	char temp_buff[1024];
	struct sockaddr_in servaddr;


	sockd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip_addr, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
		close(sockd);
		return -1;
	}
	read_len = read(sockd, temp_buff, 1024);
	if (read_len <= 0) {
		close(sockd);
		return -1;
	}
	temp_buff[read_len] = '\0';
	if (0 != strcasecmp(temp_buff, "OK\r\n")) {
		close(sockd);
		return -1;
	}
	return sockd;
}

static BOOL sensor_client_readline(int sockd, char *buff, int length)
{
	int offset;
	int read_len;
	fd_set myset;
	struct timeval tv;

	offset = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(sockd, buff + offset, length - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			buff[offset - 2] = '\0';
			return TRUE;
		}
		if (length == offset) {
			return FALSE;
		}	
	}
}

