/*
 *  the console server which communicate with the telnet clients
 */
#include <errno.h>
#include <libHX/defs.h>
#include <gromox/defs.h>
#include "console_server.h"
#include "console_cmd_handler.h"
#include "util.h"
#include "double_list.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define TIMEOUT             300    
#define MAXLINE             65536  /* max line size */
#define MAXARGS             128    /* max args on a command line */
#define MAX_CMD_LENGTH      32
#define MAX_CMD_NUMBER      64
#define MAX_CONSOLE_NUMBER	16
#define PROMPT_SRING		"console> "
#define WELCOME_STRING		"250 Console Server Ready!\r\n"
#define ERROR_STRING		"550 system resource error!\r\n"
#define GOODBYE_STRING      "250 goodbye!\r\n"
#define TIMEOUT_STRING		"time out!\r\n"
#define EXCEED_STRING		"550 connection limit exceed!\r\n"
#define STOP_STRING			"zcore service is going to shut down...\r\n"

typedef struct sockaddr     SA;

typedef BOOL (*COMMAND_HANDLER)(int argc, char** argv);

typedef struct _COMMAND_ENTRY {
    char    cmd[MAX_CMD_LENGTH];
    COMMAND_HANDLER cmd_handler;
} COMMAND_ENTRY;

typedef struct _CONSOLE_NODE {
	DOUBLE_LIST_NODE	node;
	pthread_t			tid;
	int					client_fd;
} CONSOLE_NODE;

extern BOOL g_notify_stop;
/* declare private global variables */
static BOOL g_terminate;
static size_t g_cmd_num;
static char g_listen_ip[16];
static int g_listen_port;
static pthread_t g_listening_tid;
static CONSOLE_NODE *g_console_buff;
static DOUBLE_LIST g_free_list;
static DOUBLE_LIST g_console_list;
static pthread_mutex_t g_list_lock;
static pthread_mutex_t g_execute_lock;
static pthread_key_t g_client_fd_key;
static COMMAND_ENTRY g_cmd_entry[MAX_CMD_NUMBER + 1];

static BOOL console_server_register_command(const char *cmd, COMMAND_HANDLER handler);
static void console_server_execve_command(char* cmdline);
static void console_server_install_command(void);
static int  console_server_parse_line(const char* cmdline, char** argv);
static void* thread_work_func(void *argp);
static void* console_work_func(void *argp);

/*
 *	console server's construct function
 *	@param
 *		bind_ip [in]		ip address to be listened
 *		port				port to be listened
 */
void console_server_init(const char* bind_ip, int port)
{
    strcpy(g_listen_ip, bind_ip);
    g_listen_port = port;
    console_server_install_command();   /* need to be implements */
	pthread_mutex_init(&g_list_lock, NULL);
	pthread_mutex_init(&g_execute_lock, NULL);
	double_list_init(&g_console_list);
	double_list_init(&g_free_list);
	pthread_key_create(&g_client_fd_key, NULL);
}

/*
 *	console server's destruct function
 */
void console_server_free()
{
	g_listen_ip[0] = '\0';
	g_listen_port = 0;
	pthread_mutex_destroy(&g_list_lock);
	pthread_mutex_destroy(&g_execute_lock);
	double_list_free(&g_console_list);
	double_list_free(&g_free_list);
	pthread_key_delete(g_client_fd_key);
}

/*
 *  start the console server
 *    @return
 *         0            run successfully
 *        <>0		failed to run the module
 */
int console_server_run()
{
    int i, sock, optval;
	CONSOLE_NODE *pnodes;
    struct sockaddr_in host;

	optval = -1;
    /* create a socket descriptor */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("[console_server]: failed to create socket: %s\n", strerror(errno));
        return -1;
	}
    /* eliminates "Address already in use" error from bind */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
		sizeof(int)) < 0) {
		printf("[console_server] fail to set socket option\n");
		close(sock);
        return -2;
	}
    /* 
	 * sock will be an endpoint for all requests
	 * to port on any IP address for this host
	 */
    memset((char*)&host, 0, sizeof(host));
    host.sin_family = AF_INET;
	host.sin_addr.s_addr = inet_addr(g_listen_ip);
    host.sin_port = htons(g_listen_port);

    if (bind(sock, (SA*)&host, sizeof(host)) < 0) {
		printf("[console_server] bind %s:%u: %s\n", g_listen_ip, g_listen_port, strerror(errno));
		close(sock);
        return -3;
	}
    /* Make it a listening socket ready to accept connection requests */
    if (listen(sock, 1024) < 0) {
		printf("[console_server] fail to listen on port %d\n", g_listen_port);
		close(sock);
        return -4;
	}
	pnodes = (CONSOLE_NODE*)malloc(MAX_CONSOLE_NUMBER*sizeof(CONSOLE_NODE));
	if (NULL == pnodes) {
		printf("[console_server]: fail to allocate console nodes buffer\n");
		close(sock);
		return -5;
	}
	for (i=0; i<MAX_CONSOLE_NUMBER; i++) {
		pnodes[i].node.pdata = pnodes + i;
		double_list_append_as_tail(&g_free_list, &pnodes[i].node);
	}
	/* create accepting thread */
	int ret = pthread_create(&g_listening_tid, nullptr, thread_work_func,
	          reinterpret_cast(void *, static_cast(intptr_t, sock)));
	if (ret != 0) {
		printf("[console_server]: failed to create accepting thread: %s\n", strerror(ret));
		free(pnodes);
		close(sock);
		return -5;
	}
	pthread_setname_np(g_listening_tid, "console/listen");
	g_console_buff = pnodes;
    return 0;
}

/*
 *  stop the console server, accepting thread will be
 *  stopped by main thread or console thread
 *  @return
 *		0				OK
 */
int console_server_stop(void)
{
	if (NULL != g_console_buff) {
		free(g_console_buff);
		g_console_buff = NULL;
	}
    return 0;
}

/*
 *  reply a multi arguments string to the telnet client the \r\n will 
 *  be automatic append
 *  @param
 *      format [in]     the format string like printf
 *  @return
 *      the number of bytes sended
 */
int console_server_reply_to_client(const char* format, ...)
{
    va_list ap;
    int bytes, client_fd;
    char message[MAXLINE];
	
	client_fd = (int)(long)pthread_getspecific(g_client_fd_key);
	if (client_fd <= 0) {
		return 0;
	}
    memset(message, 0, sizeof(message));
    va_start(ap, format);
    bytes = vsnprintf(message, sizeof(message), format, ap);
    bytes+= snprintf(message+bytes, sizeof(message) - bytes, "\r\n");
    return write(client_fd, message, bytes);
}

/*
 *  main thread function which loop and dispatch the 
 *  command.
 *  @param  
 *      vargp       server listening socket
 */
static void *thread_work_func(void *argp)
{
   
    fd_set myset;
	struct timeval tv;
	CONSOLE_NODE *pconsole;
	DOUBLE_LIST_NODE *pnode;
	int sock, client_fd;
	struct sockaddr_in client_peer;

    sock = (int)(long)argp;
    while (FALSE == g_terminate) {
		tv.tv_usec = 0;
		tv.tv_sec = 1;
		FD_ZERO(&myset);
		FD_SET(sock, &myset);
		if (select(sock + 1, &myset, NULL, NULL, &tv) <= 0) {
			continue;
		}
		socklen_t client_len = sizeof(client_peer);
        memset(&client_peer, 0, client_len);
        client_fd = accept(sock, (SA*)&client_peer, &client_len);
        if (client_fd <= 0) {
            continue;
        }
		/* try to get a free node from free list */
		pthread_mutex_lock(&g_list_lock);
		pnode = double_list_get_from_head(&g_free_list);
		if (NULL == pnode) {
			pthread_mutex_unlock(&g_list_lock);
			write(client_fd, EXCEED_STRING, sizeof(EXCEED_STRING) - 1);
			close(client_fd);
			continue;
		}
		pconsole = (CONSOLE_NODE*)pnode->pdata;
		pconsole->client_fd = client_fd;
		if (0 != pthread_create(&pconsole->tid, NULL,
			console_work_func, pconsole)) {
			double_list_append_as_tail(&g_free_list, pnode);
			pthread_mutex_unlock(&g_list_lock);
			write(client_fd, ERROR_STRING, sizeof(ERROR_STRING) - 1);
			close(client_fd);
			continue;
		}
		pthread_setname_np(pconsole->tid, "console/client");
		double_list_append_as_tail(&g_console_list, pnode);
		pthread_mutex_unlock(&g_list_lock);
    }
    close(sock);
	pthread_exit(0);
    return NULL;
}

/*
 *  thread work function for handling console request
 *  @param
 *      argp [in]        console thread information
 */
static void* console_work_func(void *argp)
{
    int offset;
    int read_len;
	int client_fd;
	int reply_len;
	char reply_buff[1024];
	CONSOLE_NODE *pconsole;
	char *pcrlf, cmd[MAXLINE];
	char last_command[MAXLINE];
	
	offset = 0;
	read_len = 0;
	pconsole = (CONSOLE_NODE*)argp;
	client_fd = pconsole->client_fd;
	pthread_setspecific(g_client_fd_key, (const void*)(long)client_fd);
    memset(cmd, 0, MAXLINE);
	memset(last_command, 0, MAXLINE);
    pthread_detach(pthread_self()); /* detach itself */
	reply_len = sprintf(reply_buff, "%s%s", WELCOME_STRING, PROMPT_SRING);
	write(client_fd, reply_buff, reply_len);
    while (TRUE) {
        read_len = read(client_fd, cmd + offset, MAXLINE - offset);
        if (read_len <= 0) {
			write(client_fd, TIMEOUT_STRING, sizeof(TIMEOUT_STRING) - 1);
			pthread_mutex_lock(&g_list_lock);
			double_list_remove(&g_console_list, &pconsole->node);
			double_list_append_as_tail(&g_free_list, &pconsole->node);
			pthread_mutex_unlock(&g_list_lock);
			close(client_fd);
			pthread_exit(0);
        }
        offset += read_len;
        if (offset >= MAXLINE) {
			console_server_reply_to_client("550 command line too long");
            memset(cmd, 0, MAXLINE);
            offset = 0;
            continue;
        }
        if (NULL == (pcrlf = strstr(cmd, "\r\n"))) {
            continue;
        }
        /*  replace \r\n at the end of the cmd line with '\0' */
		*pcrlf = '\0';
		if (0 == strcmp(cmd, "quit")) {
			break;
		}
        if ('\0' == cmd[0]) {    
			if ('\0' == last_command[0]) {
				console_server_reply_to_client("550 command not found");
			} else {
				/* type 'enter' to execute the last command */
                console_server_execve_command(last_command);
			}
			memset(cmd, 0, MAXLINE);
			offset = 0;
		} else {
			strcpy(last_command, cmd);
            console_server_execve_command(cmd);
			memset(cmd, 0, MAXLINE);
	        offset = 0;
        }
		write(client_fd, PROMPT_SRING, sizeof(PROMPT_SRING) - 1);
    }
	write(client_fd, GOODBYE_STRING, sizeof(GOODBYE_STRING) - 1);
	pthread_mutex_lock(&g_list_lock);
	double_list_remove(&g_console_list, &pconsole->node);
	double_list_append_as_tail(&g_free_list, &pconsole->node);
	pthread_mutex_unlock(&g_list_lock);
	close(client_fd);
	pthread_exit(0);
    return NULL;
}

/*
*  register a cmd with its handler function, so that it 
*  can be executed by the console server
*  @param
*      cmd     [in]        the cmd name (eg, quit, log)
*      handler [in]        the handler function of this command
*  @return
*      TRUE        register successfully
*      FALSE       fail
*/
static BOOL console_server_register_command(const char *cmd, COMMAND_HANDLER handler)
{
    if (g_cmd_num >= MAX_CMD_NUMBER + 1) {
        return FALSE;
    }
	if (NULL != cmd) {
		strcpy(g_cmd_entry[g_cmd_num].cmd, cmd);
	} else {
		*(g_cmd_entry[g_cmd_num].cmd) = '\0';
	}
    g_cmd_entry[g_cmd_num].cmd_handler = handler;
	g_cmd_num ++;
    return TRUE;
}


/*
*  parse the specified cmd line, split into into several 
*  parts and add it into the argv list
*  @param  
*      cmdline [in]        the cmdline to parse and split
*      argv    [out]       which pointer to each splited substring
*  @return
*      the number of substring in the argv list
*/
static int console_server_parse_line(const char* cmdline, char** argv)
{
    static char array[MAXLINE];  /* holds local copy of command line */
	int string_len;
    char *ptr;                   /* ptr that traverses command line  */
    int argc;                    /* number of args */
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
static void console_server_execve_command(char* cmdline)
{
    char *cmd = NULL;
    char *argv[MAXARGS]; /* cmd argv to do */
    int  i = 0, argc = 0;

    memset(argv, 0, sizeof(argv));
    /* parse command line */
	pthread_mutex_lock(&g_execute_lock);
    argc = console_server_parse_line(cmdline, argv);
    cmd = argv[0];
    if (0 == argc) {
		pthread_mutex_unlock(&g_execute_lock);
        return; /* ignore empty lines */
    }
	/* compare build-in command */
    for (i = 0; i < g_cmd_num; i++) {
        if ('\0' != *(g_cmd_entry[i].cmd) && 
			0 == strcmp(g_cmd_entry[i].cmd, cmd)) {
            g_cmd_entry[i].cmd_handler(argc, argv);
			pthread_mutex_unlock(&g_execute_lock);
            return;
        }
    }
    for (i = 0; i < g_cmd_num; i++) {
        if ('\0' == *(g_cmd_entry[i].cmd) &&
			TRUE == g_cmd_entry[i].cmd_handler(argc, argv)) {
			pthread_mutex_unlock(&g_execute_lock);
			return;
        }
    }
	pthread_mutex_unlock(&g_execute_lock);
	
    /* 
     *  unknown command, use the default unknown command handler, always at 
	 *  the end of all cmd handler   
    */
    console_server_reply_to_client("550 command not found");
}

/*
 * can only be invoked by console server thread
 */
void console_server_notify_main_stop()
{
	CONSOLE_NODE *pconsole;
	DOUBLE_LIST_NODE *pnode;
	BOOL b_console;
	
	g_terminate = TRUE;
	b_console = FALSE;
	pthread_join(g_listening_tid, NULL);
	pthread_mutex_lock(&g_list_lock);
	while ((pnode = double_list_get_from_head(&g_console_list)) != NULL) {
		pconsole = (CONSOLE_NODE*)pnode->pdata;
		if (0 == pthread_equal(pthread_self(), pconsole->tid)) {
			pthread_cancel(pconsole->tid);
		} else {
			b_console = TRUE;
		}
		write(pconsole->client_fd, STOP_STRING, sizeof(STOP_STRING) - 1);
		close(pconsole->client_fd);
	}
	while ((pnode = double_list_get_from_head(&g_free_list)) != NULL)
		/* do nothing */;
	pthread_mutex_unlock(&g_list_lock);
    g_notify_stop = TRUE;
	if (TRUE == b_console) {
		pthread_exit(0);
	}
}

static void console_server_install_command()
{
    /* register your cmd here, move to console server.c*/
    
    console_server_register_command("service",
                                    cmd_handler_service_control);
    console_server_register_command("zcore",
                                    cmd_handler_zcore_control);
    console_server_register_command("system",
                                    cmd_handler_system_control);
    console_server_register_command("help",
                                    cmd_handler_help);
	console_server_register_command(NULL,
									cmd_handler_service_plugins);
}
