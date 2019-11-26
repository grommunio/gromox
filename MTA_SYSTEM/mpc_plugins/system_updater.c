#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "stream.h"
#include "util.h"
#include "config_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
#define SOCKET_TIMEOUT		180
#define MAXLINE             4096   /* max line size */
#define MAXARGS             128    /* max args on a command line */
#define MAX_CMD_LENGTH      32
#define MAX_CMD_NUMBER      64

typedef void (*COMMAND_HANDLER)(int argc, char** argv);

typedef struct _COMMAND_ENTRY {
	char cmd[MAX_CMD_LENGTH];
	COMMAND_HANDLER cmd_handler;
} COMMAND_ENTRY;

DECLARE_API;

static void singnal_restart();

static void install_command();

static void update_log(const char *format, ...);

static BOOL do_update(MAIL *pmail);

static BOOL update_hook(MESSAGE_CONTEXT *pcontext);

static BOOL check_mask(const char *last_hop, const char *date,
		const char *update_string);

static void save_attachments(MIME *pmime, BOOL* result);

static BOOL execve_command(char *cmdline);

static COMMAND_ENTRY g_cmd_entry[MAX_CMD_NUMBER + 1];
static int g_cmd_num;
static int g_smtp_port;
static int g_delivery_port;
static int g_log_offset;
static char g_smtp_ip[16];
static char g_delivery_ip[16];
static char g_log_buffer[64*1024];
static char g_plugin_name[256];
static BOOL g_is_updating;
static BOOL g_should_restart;
static pthread_mutex_t	g_update_lock;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char *str_value;
	
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		pfile = config_file_init("../config/smtp.cfg");
		if (NULL == pfile) {
			printf("[system_updater]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "CONSOLE_SERVER_IP");
		if (NULL == str_value) {
			strcpy(g_smtp_ip, "127.0.0.1");
		} else {
			strncpy(g_smtp_ip, str_value, 16);
		}
		printf("[system_updater]: smtp console ip is %s\n", g_smtp_ip);
		str_value = config_file_get_value(pfile, "CONSOLE_SERVER_PORT");
		if (NULL == str_value) {
			g_smtp_port = 5566;
		} else {
			g_smtp_port = atoi(str_value);
			if (g_smtp_port <=0) {
				g_smtp_port = 5566;
			}
		}
		printf("[system_updater]: smtp console port is %d\n", g_smtp_port);
		config_file_free(pfile);
		pfile = config_file_init("../config/delivery.cfg");
		str_value = config_file_get_value(pfile, "CONSOLE_SERVER_IP");
		if (NULL == str_value) {
			strcpy(g_delivery_ip, "127.0.0.1");
		} else {
			strncpy(g_delivery_ip, str_value, 16);
		}
		printf("[system_updater]: delivery console ip is %s\n", g_delivery_ip);
		str_value = config_file_get_value(pfile, "CONSOLE_SERVER_PORT");
		if (NULL == str_value) {
			g_delivery_port = 6677;
		} else {
			g_delivery_port = atoi(str_value);
			if (g_delivery_port <= 0) {
				g_delivery_port = 6677;
			}
		}
		printf("[system_updater]: delivery console port is %d\n",
			g_delivery_port);
		config_file_free(pfile);
		strcpy(g_plugin_name, get_plugin_name());
		g_cmd_num = 0;
		g_is_updating = FALSE;
		install_command();
		pthread_mutex_init(&g_update_lock, NULL);
        if (FALSE == register_hook(update_hook)) {
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		pthread_mutex_destroy(&g_update_lock);
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}

static BOOL update_hook(MESSAGE_CONTEXT *pcontext)
{
	MIME *pmime;
	char subject[128];
	char return_address[256];
	char update_string[256];
	char date[256];
	char last_hop[16];
	char date_buff[128];
	BOOL update_result;
	time_t cur_time;
	struct tm time_buff;
	MESSAGE_CONTEXT *presult_context;
	
	if (BOUND_IN != pcontext->pcontrol->bound_type ||
		0 != strcasecmp(pcontext->pcontrol->from, "UPDATE-PACKAGE@MAIL.SYSTEM")) {
		return FALSE;
	}
	/* get necessary mime field from mail head: X-Lasthop, Date; X-Update */
	pmime = mail_get_head(pcontext->pmail);
	if (FALSE == mime_get_field(pmime, "X-Lasthop", last_hop, 16)) {
		return TRUE;
	}
	if (FALSE == mime_get_field(pmime, "Date", date, 256)) {
		date[0] = '\0';
	}
	if (FALSE == mime_get_field(pmime, "X-Update", update_string, 256)) {
		update_string[0] = '\0';
	}
	if (FALSE == mime_get_field(pmime, "Subject", subject, 128)) {
		strcpy(subject, "none-title update package");
	}
	/* check if the update package is legal */
	if (FALSE == check_mask(last_hop, date, update_string)) {
		printf("[system_updater]: illegal upadte package %s\n", subject);
		return TRUE;
	}
	/*	check if there's another thread is updating system, only
	 *	one thread is allowed to update the system in the same time
	 */
	pthread_mutex_lock(&g_update_lock);
	if (FALSE == g_is_updating) {
		g_is_updating = TRUE;
	} else {
		pthread_mutex_unlock(&g_update_lock);
		printf("[system_updater]: system is updating\n");
		return TRUE;
	}
	pthread_mutex_unlock(&g_update_lock);

	/*	set g_should_restart to FALSE, after packet is installed
     *	if there's "restart" command in scipt text, this variable
	 *	will be set to TRUE and restart signal will be sent to
     *  supervisor
	 */
	g_should_restart = FALSE;
	g_log_offset = 0;
	/*	try to get from field in mail's head for sending the result
	 *	of updating
	 */
	if (FALSE == mime_get_field(pmime, "From", return_address, 256)) {
		return_address[0] = '\0';
	}
	
	update_result = do_update(pcontext->pmail);
	
	pthread_mutex_lock(&g_update_lock);
	g_is_updating = FALSE;
	pthread_mutex_unlock(&g_update_lock);
	

	if (TRUE == update_result) {
		printf("[system_updater]: update package: \"%s\" is installed "
			"successfully\n", subject);
	} else {
		printf("[system_updater]: update package: \"%s\" cannot be "
			"installed correctly\n", subject);
	}
	if ('\0' == return_address[0]) {
		if (TRUE == g_should_restart) {
            singnal_restart();
        }
        return TRUE;
	}
	/* produce the result bounce mail */
	presult_context = get_context();
	if (NULL == presult_context) {
		printf("[system_updater]: fail to get a context for report update "
			"result\n");
		if (TRUE == g_should_restart) {
			singnal_restart();
		}
		return TRUE;
	}
	pmime = mail_add_head(presult_context->pmail);
	if (NULL == pmime) {
		printf("[system_updater]: fail to add mail head\n");
		put_context(presult_context);
		if (TRUE == g_should_restart) {
			singnal_restart();
		}
		return TRUE;
	}
	sprintf(presult_context->pcontrol->from, "UPDATE-RESULT@%s", get_host_ID());
	mem_file_writeline(&presult_context->pcontrol->f_rcpt_to, return_address);
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
		"(unkown@127.0.0.1)\r\n\tby herculiz with SMTP");
	mime_set_field(pmime, "From", presult_context->pcontrol->from);
	mime_set_field(pmime, "To", return_address);
	time(&cur_time);
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
		localtime_r(&cur_time, &time_buff));
	mime_set_field(pmime, "Date", date_buff);
	if (TRUE == update_result) {
		mime_set_field(pmime, "Subject", "Package is installed successfully!");
	} else {
		mime_set_field(pmime, "Subject", "Package cannot be correctly "
			"installed!");
	}
	mime_set_content_type(pmime, "text/plain");
	mime_set_content_param(pmime, "charset", "\"ascii\"");
	mime_write_content(pmime, g_log_buffer, g_log_offset, MIME_ENCODING_NONE);
	if (FALSE == throw_context(presult_context)) {
		printf("[system_updater]: throw context fail");
	}
	if (TRUE == g_should_restart) {
		singnal_restart();
	}
	return TRUE;
}


static BOOL check_mask(const char *last_hop, const char *date,
	const char *update_string)
{
	//TODO	
	return TRUE;
}

static void update_log(const char *format, ...)
{
	va_list ap;
	int len;

	va_start(ap, format);
	len = vsnprintf(g_log_buffer + g_log_offset, 64*1024 - g_log_offset,
			format, ap);
	g_log_offset += len;
	strcpy(g_log_buffer + g_log_offset, "\r\n");
	g_log_offset += 2;
}

static void singnal_restart()
{
	int fd, read_len, pid;
	char pid_content[16];
	struct stat node_stat;	
	
	if (0 != stat("../queue/token.pid", &node_stat) ||
		0 == S_ISREG(node_stat.st_mode || 15 < node_stat.st_size)) {
		return;
	}
	fd = open("../queue/token.pid", O_RDONLY);
	if (-1 == fd) {
		return;
	}
	read_len = read(fd, pid_content, node_stat.st_size);
	close(fd);
	if (read_len != node_stat.st_size) {
		return;
	}
	pid_content[read_len] = '\0';
	pid = atoi(pid_content);
	if (pid <= 1) {
		return;
	}
	/* signal SIGALRM is used to indicate the supervisor to start */
	kill(pid, SIGALRM);
}

static BOOL do_update(MAIL *pmail)
{
	MIME *pmime;
	char line[1024];
	char *ptr;
	size_t length;
	int blk_length;
	int copy_result;
	LIB_BUFFER *pallocator;
	STREAM stream;
	BOOL save_result;

	pmime = mail_get_head(pmail);
	/* try to get script text in the mail */
	if (0 != strcasecmp("text/plain", mime_get_content_type(pmime))) {
		pmime = mail_get_mime_horizontal(pmail, pmime, 1, 0);
		if (NULL == pmime) {
			update_log("there's no script mime");
			return FALSE;
		}
		if (0 != strcasecmp("text/plain", mime_get_content_type(pmime))) {
			pmime = mail_get_mime_horizontal(pmail, pmime, 1, 0);
			if (NULL == pmime) {
				update_log("there's no script mime");
				return FALSE;
			}
			if (0 != strcasecmp("text/plain", mime_get_content_type(pmime))) {
				update_log("there's no script mime");
				return FALSE;
			}
		}
	}
	/* init a stream object and read mail content into stream's buffer */
	length = mime_get_length(pmime);
	if (length <= 0) {
		update_log("fail to get script mime length");
		return FALSE;
	}
	if (length > STREAM_BLOCK_SIZE) {
		update_log("script mime too long");
		return FALSE;
	}
	pallocator = lib_buffer_init(STREAM_ALLOC_SIZE, 2, FALSE);
	if (NULL == pallocator) {
		update_log("fail to allocate lib buffer for script");
		return FALSE;
	}
	stream_init(&stream, pallocator);
	blk_length = STREAM_BLOCK_SIZE;
	ptr = stream_getbuffer_for_writing(&stream, &blk_length);
	length = blk_length;
	if (FALSE == mime_read_content(pmime, ptr, &length)) {
		update_log("fail to read script");
		stream_free(&stream);
		lib_buffer_free(pallocator);
		return FALSE;
	}
	blk_length = length;
	stream_forward_writing_ptr(&stream, blk_length);
	/* save attachments into /tmp directory */
	save_result = TRUE;
	mail_enum_mime(pmail, (MAIL_MIME_ENUM)save_attachments, &save_result);
	if (FALSE == save_result) {
		stream_free(&stream);
		lib_buffer_free(pallocator);
		return FALSE;
	}
	while (TRUE) {
		memset(line, 0, 1024);
		blk_length = 1024;
		copy_result = stream_copyline(&stream, line, &blk_length);
		if (STREAM_COPY_END == copy_result) {
			break;
		}
		line[blk_length] = '\0';
		ltrim_string(line);
		rtrim_string(line);
		if ('\0' == line[0] || '#' == line[0]) {
			continue;
		}
		if (FALSE == execve_command(line)) {
			update_log("unknown command line: %s", line);
		}
	}
	stream_free(&stream);
	lib_buffer_free(pallocator);
	return TRUE;
}

static void save_attachments(MIME *pmime, BOOL* result)
{
	char name[1024];
	int name_len;
	char tmp_path[256];
	char *pbegin, *pend;
	char *pbuff;
	size_t mime_len;
	int fd, write_len;

	if (FALSE == *result) {
		return;
	}
	if (FALSE == mime_get_content_param(pmime, "name", name, 1024)) {
		if (FALSE == mime_get_field(pmime, "Content-Disposition", name,
			1024)) {
			return;
		}
		name_len = strlen(name);
		pbegin = search_string(name, "filename=", name_len);
		if (NULL == pbegin) {
			return;
		}
		pbegin += 9;
		pend = name + name_len;
		memmove(name, pbegin, pend - pbegin);
		name[pend - pbegin] = '\0';
	}
	pbegin = name;
	if ('"' == *pbegin) {
    	pbegin ++;
        pend = strchr(pbegin, '"');
        if (NULL == pend) {
        	return;
        }
		memmove(name, pbegin, pend - pbegin);
		name[pend - pbegin] = '\0';
	}
	mime_len = mime_get_length(pmime);
	if (mime_len <= 0) {
		*result = FALSE;
		update_log("fail to get mime %s's length", name);
		return;
	}
	pbuff = malloc(mime_len);
	if (NULL == pbuff) {
		*result = FALSE;
		update_log("fail to allocate memory for mime %s", name);
		return;
	}
	if (FALSE == mime_read_content(pmime, pbuff, &mime_len)) {
		*result = FALSE;
		update_log("fail to read mime %s", name);
		return;
	}
	sprintf(tmp_path, "/tmp/%s", name);
	fd = open(tmp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		free(pbuff);
		update_log("fail to create file %s", name);
		*result = FALSE;
		return;
	}
	write_len = write(fd, pbuff, mime_len);
	close(fd);
	free(pbuff);
	if (write_len != mime_len) {
		update_log("fail to write mime %s into file", name);
		*result = FALSE;
	}
	return;
}

static int parse_line(const char* cmdline, char** argv)
{
    static char array[MAXLINE]; /* holds local copy of command line */
	int string_len;
    char *ptr;                   /* ptr that traverses command line  */
    int argc;                   /* number of args */
	char *last_space;
	char *last_quota;

    memset(array, 0, sizeof(array));
	string_len = strlen(cmdline);
	memcpy(array, cmdline, string_len);
	array[string_len] = ' ';
	string_len ++;
	array[string_len] = '\0';
	ptr = array;
    /* Build the argv list */
    argc = 0;
	last_quota = NULL;
	last_space = array;
    while (*ptr != '\0') {
		/* back slash should be treated as transferred meaning */
		if (('\\' == *ptr && '\"' == *(ptr + 1)) ||
			('\\' == *ptr && '\\' == *(ptr + 1))) {
			strcpy(ptr, ptr + 1);
			ptr ++;
		}
		if ('\"' == *ptr) {
			if (NULL == last_quota) {
				last_quota = ptr + 1;
			} else {
				/* ignore "" */
				if (ptr == last_quota) {
					last_quota = NULL;
					last_space = ptr + 1;
				} else {
					argv[argc] = last_quota;
					*ptr = '\0';
					last_quota = NULL;
					last_space = ptr + 1;
					argc ++;
				}
			}
		}
		if (' ' == *ptr && NULL == last_quota) {
			/* ignore leading spaces */
			if (ptr == last_space) {
				last_space ++;
			} else {
				argv[argc] = last_space;
				*ptr = '\0';
				last_space = ptr + 1;
				argc ++;
			}
		}
		ptr ++;
    }
	/* only one quota is found, error */
	if (NULL != last_quota) {
		argc = 0;
	}
    argv[argc] = NULL;
    return argc;
}

/*
*  takes the command line and compare if the command name is correct, then
*  call its handler function to execute the command
*  @param
*      cmdline [in]        the command line to execute
*/
static BOOL execve_command(char* cmdline)
{
    char *argv[MAXARGS]; /* cmd argv to do */
    size_t  i, argc;
    char *cmd;

    memset(argv, 0, sizeof(argv));
    /*	parse command line command "smtp-control" or "delivery-control"
	 *	will be considered as two arguments
	 */
	if (0 == strncmp("smtp-control ", cmdline, 13)) {
		argc = 2;
		argv[0] = cmdline;
		cmdline[12] = '\0';
		argv[1] = cmdline + 13;
		ltrim_string(argv[1]);
	} else if (0 == strncmp("delivery-control ", cmdline, 17)) {
		argc = 2;
		argv[0] = cmdline;
		cmdline[16] = '\0';
		argv[1] = cmdline + 17;
		ltrim_string(argv[1]);
	} else {
		argc = parse_line(cmdline, argv);
	}
    cmd = argv[0];
    if (0 == argc) {
        return FALSE; /* ignore empty lines */
    }
	/* compare build-in command */
    for (i=0; i<g_cmd_num; i++) {
		if (0 == strcmp(g_cmd_entry[i].cmd, cmd)) {
			g_cmd_entry[i].cmd_handler(argc, argv);
			return TRUE;
        }
    }
	return FALSE;	
}

static BOOL register_command(const char *cmd, COMMAND_HANDLER handler)
{
	if (g_cmd_num >= MAX_CMD_NUMBER || NULL == cmd ||
		0 == strlen(cmd) || NULL == handler) {
		return FALSE;
	}
	strcpy(g_cmd_entry[g_cmd_num].cmd, cmd);
	g_cmd_entry[g_cmd_num].cmd_handler = handler;
	g_cmd_num ++;
	return TRUE;
}

static BOOL console_control(const char *ip, int port, const char *cmdline,
    char *result, int length)
{
	int sockd, cmd_len;
	int read_len;
	char command[1024];
	struct sockaddr_in servaddr;
	fd_set myset;
	struct timeval tv;

	sockd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr,sizeof(servaddr))) {
		close(sockd);
		return FALSE;
	}
	
	/* read welcome information */
	do {
		tv.tv_sec = SOCKET_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			close(sockd);
			return FALSE;
		}
		memset(result, 0, length);
		read_len = read(sockd, result, length - 1);
		if (-1 == read_len || 0 == read_len) {
			close(sockd);
			return FALSE;
		}
	} while (read_len < 9 || 0 != strcmp(result + read_len - 9, "console> "));

	/* send command */
	strncpy(command, cmdline, 1022);
	command[1022] = '\0';
	cmd_len = strlen(command);
	memcpy(command + cmd_len, "\r\n", 2);
	cmd_len += 2;
	if (cmd_len != write(sockd, command, cmd_len)) {
		close(sockd);
		return FALSE;
	}

	/* read excute result */
	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		close(sockd);
		return FALSE;
	}
	memset(result, 0, length);
	read_len = read(sockd, result, length - 1);
	write(sockd, "quit\r\n", 6);
	close(sockd);
	if (-1 == read_len || 0 == read_len) {
		return FALSE;
	}
	/* trim "console> " */
	if (read_len >= 9 && 0 == strcmp(result + read_len - 9, "console> ")) {
		read_len -= 9;
	}
	result[read_len] = '\0';
	return TRUE;
}

/*=============================================================================
 *	
 *				fill your command implementation here
 *
 *============================================================================*/
static void cmd_merge(int argc, char **argv)
{
	char tmp_file[256], *ptr;
	char source_file[256];
	int fd, len;
	struct stat node_stat;	
	
	if (3 != argc) {
		update_log("command \"merge\" usage should look like: merge source "
			"destination");
		return;
	}
	sprintf(tmp_file, "%s.usr", argv[2]);
	sprintf(source_file, "/tmp/%s", argv[1]);
	if (0 != stat(source_file, &node_stat)) {
		update_log("there's no %s under /tmp directory", source_file);
		return;
	}
	/* first append .usr file to source file */
	if (0 == stat(tmp_file, &node_stat)) {
		ptr = malloc(node_stat.st_size);
		if (NULL == ptr) {
			update_log("fail to allocate memory for %s", tmp_file);
			return;
		}
		fd = open(tmp_file, O_RDONLY);
		if (-1 == fd) {
			free(ptr);
			update_log("fail to open %s for reading", tmp_file);
			return;
		}
		if (node_stat.st_size != read(fd, ptr, node_stat.st_size)) {
			update_log("fail to read data from %s", tmp_file);
			close(fd);
			free(ptr);
			return;
		}
		close(fd);
		fd = open(source_file, O_APPEND|O_WRONLY);
		if (-1 == fd) {
			free(ptr);
			update_log("fail to open %s for appending", source_file);
			return;
		}
		len = write(fd, ptr, node_stat.st_size);
		free(ptr);
		close(fd);
		if (len != node_stat.st_size) {
			update_log("fail to append data to %s", source_file);
			return;
		}
	}
	/* remove the destination file */
	remove(argv[2]);
	/* link source file to destination file */
	if (0 != link(source_file, argv[2])) {
		update_log("fatal error!!! unable to link %s", argv[2]);
		return;
	}
	/* remove the source file reference count */
	remove(source_file);
	update_log("OK to merge %s to %s", argv[1], argv[2]);
	return;
}

static void cmd_copy(int argc, char **argv)
{
	char source_file[256];
	struct stat node_stat;
	char command[512];
	int len;
	
	if (3 != argc) {
		update_log("command \"copy\" usage should look like: copy source "
			"destination");
		return;
	}
	sprintf(source_file, "/tmp/%s", argv[1]);
	if (0 != stat(source_file, &node_stat)) {
		update_log("there's no %s under /tmp directory", source_file);
		return;
	}
	
	len = strlen(argv[1]);
	if (0 == strncmp(argv[1] + len - 6, "tar.gz", 6) ||
		0 == strncmp(argv[1] + len - 4, ".tgz", 4)) {
		snprintf(command, 511, "gunzip -c %s | tar xf - -C %s", 
			source_file, argv[2]);
		command[511] = '\0';
		if (0 != system(command)) {
			update_log("fail to extract %s", source_file);
			return;
		}
	} else {
		/* remove the destination file if exist */
		remove(argv[2]);
		if (0 != link(source_file, argv[2])) {
			update_log("fatal error!!! unable to link %s", argv[2]);
			return;
		}
	}
	remove(source_file);
	update_log("OK to copy %s to %s", argv[1], argv[2]);
	return;
}

static void cmd_delete(int argc, char **argv)
{
	struct stat node_stat;

	if (2 != argc) {
		update_log("command \"delete\" usage should look like: delete file");
		return;
	}
	if (0 == stat(argv[1], &node_stat) && 0 != remove(argv[1])) {
		update_log("fail to delete %s", argv[1]);
		return;
	}
	update_log("OK to delete %s", argv[1]);
	return;
}

static void cmd_smtp_control(int argc, char **argv)
{
	char response_buff[4096];

	if (0 == strlen(argv[1])) {
		update_log("empty smtp-control command");
		return;
	}
	if (FALSE == console_control(g_smtp_ip, g_smtp_port, argv[1],
		response_buff, 4096)) {
		update_log("socket error when send command %s to smtp server",
			argv[0]);
	} else {
		update_log("smtp server answer:\r\n%s\r\naccording command: %s",
			response_buff, argv[1]);
	}
	return;
}

static void cmd_delivery_control(int argc, char **argv)
{
	char response_buff[4096];

	if (0 == strlen(argv[1])) {
		update_log("empty delivery-control command");
		return;
	}
	if (0 == strncmp("system stop", argv[1], 11)) {
		update_log("cannot excute system stop command for delivery server");
		return;
	}
	if (FALSE == console_control(g_delivery_ip, g_delivery_port, argv[1],
		response_buff, 4096)) {
		update_log("socket error when send command %s to delivery server",
			argv[0]);
	} else {
		update_log("delivery server answer:\r\n%s\r\naccording command: %s",
			response_buff, argv[1]);
	}
	return;
}

static void cmd_smtp_unload(int argc, char **argv)
{
	int len;
	char tmp_file[256];
	char bak_file[256];
	char command[295];
	char response_buff[4096];
	struct stat node_stat;	
	
	if (2 != argc) {
		update_log("command \"smtp-unload\" usage should like: smtp-unload "
			"plugin");
		return;
	}
	len = strlen(argv[1]);
	if (0 != strcmp(argv[1] + len - 4, ".pas")) {
		update_log("unknown plugin type %s, can not be unloaded", argv[1]);
		return;
	}
	sprintf(tmp_file, "../as_plugins/%s", argv[1]);
	sprintf(bak_file, "../as_plugins/%s.bak", argv[1]);
	if (0 != stat(tmp_file, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		update_log("there's no plug-in %s in smtp server", argv[1]);
		return;
	}
	if (FALSE == console_control(g_smtp_ip, g_smtp_port, "anti-spamming info",
		response_buff, 4096)) {
		update_log("socket error when send command for unloading plugin %s to"
			" smtp server", argv[1]);
		return;
	} else {
		if (NULL == strstr(response_buff, argv[1])) {
			remove(bak_file);
			if (0 != rename(tmp_file, bak_file)) {
				update_log("fail to rename the plugin %s", argv[1]);
				return;
			}
		} else {
			sprintf(command, "anti-spamming unload %s", argv[1]);
			if (FALSE == console_control(g_smtp_ip, g_smtp_port, command,
				response_buff, 4096)) {
				update_log("socket error when send command to smtp server");
				return;
			} else {
				if (0 != strncmp("250 ", response_buff, 4)) {
					update_log("smtp server fails to unload %s", argv[1]);
					return;
				}
				remove(bak_file);
				if (0 != rename(tmp_file, bak_file)) {
					update_log("fail to rename the plugin %s", argv[1]);
					return;
				}
				update_log("smtp server unload %s OK", argv[1]);
				return;
			}
		}
	}
}

static void cmd_delivery_unload(int argc, char **argv)
{
	int len;
	char tmp_file[256];
	char bak_file[256];
	char command[295];
	char response_buff[4096];
	struct stat node_stat;	
	
	if (2 != argc) {
		update_log("command \"delivery-unload\" usage should like: "
			"delivery-unload plugin");
		return;
	}
	len = strlen(argv[1]);
	if (0 != strcmp(argv[1] + len - 5, ".hook")) {
		update_log("unknown plugin type %s, can not be unloaded", argv[1]);
		return;
	}
	if (0 == strcmp(g_plugin_name, argv[1])) {
		update_log("can not unload plugin %s self", g_plugin_name);
		return;
	}
	sprintf(tmp_file, "../mpc_plugins/%s", argv[1]);
	sprintf(bak_file, "../mpc_plugins/%s.bak", argv[1]);
	if (0 != stat(tmp_file, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		update_log("there's no plug-in %s in delivery server", argv[1]);
		return;
	}
	if (FALSE == console_control(g_delivery_ip, g_delivery_port, "mpc info",
		response_buff, 4096)) {
		update_log("socket error when send command for unloading %s to "
			"delivery server", argv[1]);
		return;
	} else {
		if (NULL == strstr(response_buff, argv[1])) {
			remove(bak_file);
			if (0 != rename(tmp_file, bak_file)) {
				update_log("fail to rename the plugin %s", argv[1]);
				return;
			}
		} else {
			sprintf(command, "mpc unload %s", argv[1]);
			if (FALSE == console_control(g_delivery_ip, g_delivery_port,
				command, response_buff, 4096)) {
				update_log("socket error when send command to delivery server");
				return;
			} else {
				if (0 != strncmp("250 ", response_buff, 4)) {
					update_log("delivery server fails to unload %s", argv[1]);
					return;
				}
				while (TRUE) {
					if (FALSE == console_control(g_delivery_ip, g_delivery_port,
						"mpc info", response_buff, 4096)) {
						update_log("socket error when send command to "
							"delivery server");
						return;	
					}
					if (NULL == strstr(response_buff, argv[1])) {
						break;
					}
					sleep(5);
				}
				remove(bak_file);
				if (0 != rename(tmp_file, bak_file)) {
					update_log("fail to rename the plugin %s", argv[1]);
					return;
				}
				update_log("delivery server unload %s OK", argv[1]);
				return;
			}
		}
	}
}

static void cmd_smtp_update(int argc, char **argv)
{
	int len;
	char tmp_file[256];
	char plug_file[256];
	char command[295];
	char response_buff[4096];
	struct stat node_stat;	
	
	if (2 != argc) {
		update_log("command \"smtp-update\" usage should like: smtp-undate "
			"plugin");
		return;
	}
	len = strlen(argv[1]);
	if (0 != strcmp(argv[1] + len - 4, ".pas")) {
		update_log("unknown plugin type %s, can not be undated", argv[1]);
		return;
	}
	sprintf(plug_file, "/tmp/%s", argv[1]);
	if (0 != stat(plug_file, &node_stat)) {
		update_log("can not find %s in /tmp directory", argv[1]);
		return;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		update_log("%s in /tmp directory is not regulary file", argv[1]);
		return;
	}	
	if (FALSE == console_control(g_smtp_ip, g_smtp_port, "anti-spamming info",
		response_buff, 4096)) {
		update_log("socket error when send command to smtp server");
		return;
	}
	if (NULL != strstr(response_buff, argv[1])) {
		sprintf(command, "anti-spamming unload %s", argv[1]);
		if (FALSE == console_control(g_smtp_ip, g_smtp_port, command,
			response_buff, 4096)) {
			update_log("socket error when send command to smtp server");
			return;
		} else {
			if (0 != strncmp("250 ", response_buff, 4)) {
				update_log("smtp server fails to unload %s", argv[1]);
				return;
			}
		}
	}

	sprintf(tmp_file, "../as_plugins/%s", argv[1]);
	remove(tmp_file);
	if (0 != link(plug_file, tmp_file)) {
		update_log("unable to link %s", tmp_file);
		return;
	}
	remove(plug_file);
	sprintf(command, "anti-spamming load %s", argv[1]);
	if (FALSE == console_control(g_smtp_ip, g_smtp_port, command,
		response_buff, 4096)) {
		update_log("socket error when send command to smtp server");
		return;
	} else {
		if (0 != strncmp("250 ", response_buff, 4)) {
			update_log("smtp server fails to load %s", argv[1]);
			return;
		}
		update_log("smtp server update %s OK", argv[1]);
		return;
	}
}

static void cmd_delivery_update(int argc, char **argv)
{
	int len;
	char tmp_file[256];
	char plug_file[256];
	char command[295];
	char response_buff[4096];
	struct stat node_stat;	
	
	if (2 != argc) {
		update_log("command \"delivery-update\" usage should like: "
			"delivery-undate plugin");
		return;
	}
	len = strlen(argv[1]);
	if (0 != strcmp(argv[1] + len - 5, ".hook")) {
		update_log("unknown plugin type %s, can not be undated", argv[1]);
		return;
	}
	sprintf(plug_file, "/tmp/%s", argv[1]);
	if (0 != stat(plug_file, &node_stat)) {
		update_log("can not find %s in /tmp directory", argv[1]);
		return;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		update_log("%s in /tmp directory is not regulary file", argv[1]);
		return;
	}	
	if (FALSE == console_control(g_delivery_ip, g_delivery_port, "mpc info",
		response_buff, 4096)) {
		update_log("socket error when send command to delivery server");
		return;
	}
	if (NULL != strstr(response_buff, argv[1])) {
		sprintf(command, "mpc unload %s", argv[1]);
		if (FALSE == console_control(g_delivery_ip, g_delivery_port, command,
			response_buff, 4096)) {
			update_log("socket error when send command to delivery server");
			return;
		} else {
			if (0 != strncmp("250 ", response_buff, 4)) {
				update_log("delivery server fails to unload %s", argv[1]);
				return;
			}
			while (TRUE) {
				if (FALSE == console_control(g_delivery_ip, g_delivery_port,
					"mpc info", response_buff, 4096)) {
					update_log("socket error when send command to "
						"delivery server");
					return;	
				}
				if (NULL == strstr(response_buff, argv[1])) {
					break;
				}
				sleep(5);
			}
		}
	}

	sprintf(tmp_file, "../mpc_plugins/%s", argv[1]);
	remove(tmp_file);
	if (0 != link(plug_file, tmp_file)) {
		update_log("unable to link %s", tmp_file);
		return;
	}
	remove(plug_file);
	sprintf(command, "mpc load %s", argv[1]);
	if (FALSE == console_control(g_delivery_ip, g_delivery_port, command,
		response_buff, 4096)) {
		update_log("socket error when send command to delivery server");
		return;
	} else {
		if (0 != strncmp("250 ", response_buff, 4)) {
			update_log("delivery server fails to load %s", argv[1]);
			return;
		}
		update_log("delivery server update %s OK", argv[1]);
		return;
	}
}

static void cmd_restart(int argc, char **argv)
{
	g_should_restart = TRUE;
}

/*=============================================================================
 *	
 *			end of command implementation, add command to table here
 *
 *============================================================================*/

static void install_command()
{
    /* register your cmd here */
    register_command("merge", cmd_merge);
    register_command("delete", cmd_delete);
    register_command("copy", cmd_copy);
    register_command("restart", cmd_restart);
    register_command("smtp-control", cmd_smtp_control);
    register_command("delivery-control", cmd_delivery_control);
    register_command("smtp-unload", cmd_smtp_unload);
    register_command("delivery-unload", cmd_delivery_unload);
    register_command("smtp-update", cmd_smtp_update);
    register_command("delivery-update", cmd_delivery_update);
}

