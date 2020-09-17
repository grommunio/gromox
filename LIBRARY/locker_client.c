#include <time.h>
#include <unistd.h>
#include <gromox/locker_client.h>
#include <gromox/socket.h>
#include "common_types.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

static char g_locker_ip[16];
static int g_locker_port;
static int g_max_interval;

static BOOL locker_client_readline_timeout(int sockd, char *buff, int length);

void locker_client_init(const char *ip, int port, int max_interval)
{
	strcpy(g_locker_ip, ip);
	g_locker_port = port;
	g_max_interval = max_interval;
}

LOCKD locker_client_lock(const char *resource)
{
	char temp_buff[1024];
	int sockd = gx_inet_connect(g_locker_ip, g_locker_port, O_NONBLOCK);
	if (sockd < 0)
		return -1;
	if (FALSE == locker_client_readline_timeout(sockd, temp_buff, 1024)) {
		close(sockd);
		return -1;
	}
	if (0 != strcasecmp(temp_buff, "OK")) {
		close(sockd);
		return -1;
	}
	int len = snprintf(temp_buff, 1024, "LOCK %s\r\n", resource);
	write(sockd, temp_buff, len);
	
	if (FALSE == locker_client_readline_timeout(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "TRUE")) {
		close(sockd);
		return -1;
	}
	return sockd;
}

void locker_client_unlock(LOCKD lockd)
{
	if (-1 != lockd) {
		write(lockd, "QUIT\r\n", 6);
		close(lockd);
	}
}

static BOOL locker_client_readline_timeout(int sockd, char *buff, int length)
{
    int offset;
    int temp_len;
    int i, read_len;
    time_t first_time;
    time_t last_time;
    char temp_line[1024];

    offset = 0;
    time(&first_time);
    while (TRUE) {
        read_len = read(sockd, temp_line, 1024 - offset);
        if (-1 == read_len) {
            read_len = 0;
        }
        offset += read_len;
        for (i=0; i<offset; i++) {
            if ('\r' == temp_line[i] && '\n' == temp_line[i + 1]) {
                temp_len = (i < length - 1) ? i : length - 1;
                memcpy(buff, temp_line, temp_len);
                buff[temp_len] = '\0';
                return TRUE;
            }
        }
        time(&last_time);
        if (last_time - first_time > g_max_interval || 1024 == offset) {
            return FALSE;
        }
        usleep(10000);
    }
}

