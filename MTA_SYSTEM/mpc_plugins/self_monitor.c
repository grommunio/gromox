#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <gromox/hook_common.h>
#include <gromox/paths.h>
#include "config_file.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>

#define TOKEN_MONITOR_QUEUE		100

typedef struct _MSG_BUFF {
	long msg_type;
	int msg_tick;
} MSG_BUFF;

enum{
    SMTP_TIME_OUT,
    SMTP_TEMP_ERROR,
    SMTP_UNKOWN_RESPONSE,
    SMTP_PERMANENT_ERROR,
    SMTP_RESPONSE_OK
};

DECLARE_API;

static int g_smtp_port;
static int g_monitor_id;
static BOOL g_notify_stop;
static pthread_t g_thread_id;

static BOOL send_message(void);
static void* thread_work_func(void* arg);

static BOOL monitor_hook(MESSAGE_CONTEXT *pcontext);

static BOOL send_command(int sockd, const char *command, int command_len);

static int get_response(int sockd, char *response, int response_len,
	BOOL expect_3xx);

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	key_t k_msg;
	MSG_BUFF msg;
	time_t cur_time;
	char *str_value;
	pthread_attr_t  attr;
	char token_path[256];
	CONFIG_FILE *pconfig;
	
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		pconfig = config_file_init2(NULL, PKGSYSCONFDIR "/smtp.cfg");
		if (NULL == pconfig) {
			g_smtp_port = 25;
		} else {
			str_value = config_file_get_value(pconfig, "LISTEN_PORT");
			if (NULL == str_value) {
				g_smtp_port = 25;
			} else {
				g_smtp_port = atoi(str_value);
				if (g_smtp_port <= 0) {
					g_smtp_port = 25;
				}
			}
			config_file_free(pconfig);
		}
		
		g_notify_stop = TRUE;
		sprintf(token_path, "%s/token.ipc", get_queue_path());
		k_msg = ftok(token_path, TOKEN_MONITOR_QUEUE);
		if (-1 == k_msg) {
			printf("[self_monitor]: ftok %s: %s\n", token_path, strerror(errno));
			return FALSE;
		}
		g_monitor_id = msgget(k_msg, 0666|IPC_CREAT);
		if (-1 == g_monitor_id) {
			printf("[self_monitor]: msgget: %s\n", strerror(errno));
			return FALSE;
		}
		msg.msg_type = 1;
		time(&cur_time);
		msg.msg_tick = cur_time/180;
		msgsnd(g_monitor_id, &msg, sizeof(int), IPC_NOWAIT);
        if (FALSE == register_hook(monitor_hook)) {
			printf("[self_monitor]: failed to register the hook function\n");
            return FALSE;
        }
		g_notify_stop = FALSE;
		pthread_attr_init(&attr);
		int ret = pthread_create(&g_thread_id, &attr, thread_work_func, nullptr);
		if (ret != 0) {
			pthread_attr_destroy(&attr);
			printf("[self_monitor]: failed to create thread: %s\n", strerror(ret));
			return FALSE;
		}
		pthread_setname_np(g_thread_id, "self_monitor");
		pthread_attr_destroy(&attr);
        return TRUE;
    case PLUGIN_FREE:
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_cancel(g_thread_id);
		}
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}

static BOOL monitor_hook(MESSAGE_CONTEXT *pcontext)
{
	MSG_BUFF msg;
	time_t cur_time;
	
	if (0 == strcasecmp(pcontext->pcontrol->from,
			"system-monitor@system.mail")) {
		msg.msg_type = 1;
		time(&cur_time);
		msg.msg_tick = cur_time/180;
		msgsnd(g_monitor_id, &msg, sizeof(int), IPC_NOWAIT);
		return TRUE;
	}
	return FALSE;
}

static void* thread_work_func(void* arg)
{
	time_t last_tick, current_tick;
	
	time(&last_tick);
	last_tick /= 180;
	while (FALSE == g_notify_stop) {
		sleep(1);
		time(&current_tick);
		current_tick /= 180;
		if (current_tick - last_tick >= 1) {
			if (TRUE == send_message()) {
				last_tick = current_tick;
			}
		}
	}
	return NULL;
}

BOOL send_message()
{
	char command_line[1024];
	char response_line[1024];
	int	i, sockd, command_len;
	struct sockaddr_in servaddr;
	
	/* try to connect to the destination MTA */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(g_smtp_port);
	inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
		close(sockd);
        return FALSE;
	}
	/* read welcome information of MTA */
	switch (get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_TIME_OUT:
		close(sockd);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
	}

	/* send helo xxx to server */
	if (FALSE == send_command(sockd, "helo system.mail\r\n", 18)) {
		close(sockd);
		return FALSE;
	}
	switch (get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_TIME_OUT:
		close(sockd);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
	}

	/* send mail from:<...> */
	strcpy(command_line, "mail from:<system-monitor@system.mail>\r\n");
	if (FALSE == send_command(sockd, command_line, 40)) {
		close(sockd);
		return FALSE;
	}
	/* read mail from response information */
    switch (get_response(sockd, response_line, 1024, FALSE)) {
    case SMTP_TIME_OUT:
		close(sockd);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        send_command(sockd, command_line, 6);
		close(sockd);
        return FALSE;
    }

	/* send rcpt to:<...> */
	
	command_len = sprintf(command_line, "rcpt to:<system-monitor@%s>\r\n",
					get_default_domain());
	if (FALSE == send_command(sockd, command_line, command_len)) {
		close(sockd);
		return FALSE;
	}
	/* read rcpt to response information */
    switch (get_response(sockd, response_line, 1024, FALSE)) {
    case SMTP_TIME_OUT:
		close(sockd);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
	}
	
	/* send data */
	strcpy(command_line, "data\r\n");
	if (FALSE == send_command(sockd, command_line, 6)) {
		close(sockd);
		return FALSE;
	}

	/* read data response information */
    switch (get_response(sockd, response_line, 1024, TRUE)) {
    case SMTP_TIME_OUT:
		close(sockd);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
    }

	command_len = sprintf(command_line, 
							"From: system-monitor@system.mail\r\n"
							"To: system-monitor@%s\r\n"
							"Content-Type: text/plain\r\n\r\n",
							get_default_domain());
	if (FALSE == send_command(sockd, command_line, command_len)) {
		close(sockd);
		return FALSE;
	}
	for (i=0; i<2048; i++) {
		if (FALSE == send_command(sockd, "123456789012345678901234567890123456"
			"789012345678901234567890\r\n", 62)) {
			close(sockd);
			return FALSE;
		}
	}
	if (FALSE == send_command(sockd, "\r\n.\r\n", 5)) {
		close(sockd);
		return FALSE;
	}
	switch (get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_TIME_OUT:
		close(sockd);
		return FALSE;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:	
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
        send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
	case SMTP_RESPONSE_OK:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		send_command(sockd, command_line, 6);
		close(sockd);
		return TRUE;
	}
	return false;
}


/*
 *	send a command string to destination
 *	@param
 *		sockd				socket fd
 *		command [in]		command string to be sent
 *		command_len			command string length
 *	@return
 *		TRUE				OK
 *		FALSE				time out
 */
static BOOL send_command(int sockd, const char *command, int command_len)
{
	int write_len;

	write_len = write(sockd, command, command_len);
    if (write_len != command_len) {
		return FALSE;
	}
	return TRUE;
}

/*
 *	get response from server
 *	@param
 *		sockd					socket fd
 *		response [out]			buffer for save response
 *		response_len			response buffer length
 *		reason [out]			fail reason
 *	@retrun
 *		SMTP_TIME_OUT			time out
 *		SMTP_TEMP_ERROR		temp fail
 *		SMTP_UNKOWN_RESPONSE	unknown fail
 *		SMTP_PERMANENT_ERROR	permanent fail
 *		SMTP_RESPONSE_OK		OK
 */
static int get_response(int sockd, char *response, int response_len,
	BOOL expect_3xx)
{
	int read_len;

	memset(response, 0, response_len);
	read_len = read(sockd, response, response_len);
	if (-1 == read_len || 0 == read_len) {
		return SMTP_TIME_OUT;
	}
	if ('\n' == response[read_len - 1] && '\r' == response[read_len - 2]){
		/* remove /r/n at the end of response */
		read_len -= 2;
	}
	response[read_len] = '\0';
	if (FALSE == expect_3xx && '2' == response[0] &&
	    HX_isdigit(response[1]) && HX_isdigit(response[2])) {
		return SMTP_RESPONSE_OK;
	} else if(TRUE == expect_3xx && '3' == response[0] &&
	    HX_isdigit(response[1]) && HX_isdigit(response[2])) {
		return SMTP_RESPONSE_OK;
	} else {
		if ('4' == response[0]) {
           	return SMTP_TEMP_ERROR;	
		} else if ('5' == response[0]) {
			return SMTP_PERMANENT_ERROR;
		} else {
			return SMTP_UNKOWN_RESPONSE;
		}
	}
}

