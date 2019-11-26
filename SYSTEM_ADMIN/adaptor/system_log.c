#include <unistd.h>
#include <gromox/system_log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static char g_log_path[256];

void system_log_init(const char *path)
{
	strcpy(g_log_path, path);
}

int system_log_run()
{
	return 0;
}

void system_log_info(char *format, ...)
{
	va_list ap;
	int len, log_fd;
	char log_buf[4096];
	time_t time_now;
	struct stat node_stat;
	
	if (0 != stat(g_log_path, &node_stat)) {
		log_fd = open(g_log_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	} else {
		if (node_stat.st_size > 16*1024*1024) {
			log_fd = open(g_log_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
		} else {
			log_fd = open(g_log_path, O_WRONLY|O_APPEND);
		}
	}
	if (-1 == log_fd) {
		return;
	}
	
	time(&time_now);
	len = strftime(log_buf, 32, "%Y/%m/%d %H:%M:%S\t",
			localtime(&time_now));
	va_start(ap, format);
	len += vsnprintf(log_buf + len, sizeof(log_buf) - len - 1, format, ap);
	log_buf[len++]  = '\n';
	write(log_fd, log_buf, len);
	close(log_fd);
}

int system_log_stop()
{
	return 0;
}

void system_log_free()
{
	g_log_path[0] = '\0';
}

