// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  the console server which communicate with the telnet clients
 */
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#include <gromox/console_server.hpp>
#include <gromox/double_list.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <cstdio>
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
#define STOP_STRING "service is going to shut down...\r\n"

using namespace gromox;
using SA = struct sockaddr;

namespace {

struct CONSOLE_NODE {
	DOUBLE_LIST_NODE	node;
	pthread_t			tid;
	int					client_fd;
};

}

extern gromox::atomic_bool g_notify_stop;
static gromox::atomic_bool g_terminate;
static char g_listen_ip[40];
static uint16_t g_listen_port;
static pthread_t g_listening_tid;
static CONSOLE_NODE *g_console_buff;
static DOUBLE_LIST g_free_list;
static DOUBLE_LIST g_console_list;
static std::mutex g_list_lock, g_execute_lock;
static pthread_key_t g_client_fd_key;
static std::unordered_map<std::string, COMMAND_HANDLER> g_cmd_entry;
static std::vector<COMMAND_HANDLER> g_cmd_dynamic;

static void console_server_execve_command(char* cmdline);
static int  console_server_parse_line(const char* cmdline, char** argv);
static void *consrv_thrwork(void *);
static void *consrv_work(void *);

void console_server_init(const char *bind_ip, uint16_t port)
{
	gx_strlcpy(g_listen_ip, bind_ip, GX_ARRAY_SIZE(g_listen_ip));
    g_listen_port = port;
	double_list_init(&g_console_list);
	double_list_init(&g_free_list);
	pthread_key_create(&g_client_fd_key, NULL);
}

void console_server_free()
{
	g_listen_ip[0] = '\0';
	g_listen_port = 0;
	double_list_free(&g_console_list);
	double_list_free(&g_free_list);
	pthread_key_delete(g_client_fd_key);
}

/*
 *    @return
 *         0            run successfully
 *        <>0		failed to run the module
 */
int console_server_run()
{
	CONSOLE_NODE *pnodes;

	auto sock = gx_inet_listen(g_listen_ip, g_listen_port);
	if (sock < 0) {
		printf("[console_server]: failed to create socket [*]:%hu: %s\n",
		       g_listen_port, strerror(-sock));
        return -1;
	}
	pnodes = (CONSOLE_NODE*)malloc(MAX_CONSOLE_NUMBER*sizeof(CONSOLE_NODE));
	if (NULL == pnodes) {
		printf("[console_server]: Failed to allocate console nodes buffer\n");
		close(sock);
		return -5;
	}
	for (unsigned int i = 0; i < MAX_CONSOLE_NUMBER; ++i) {
		pnodes[i].node.pdata = pnodes + i;
		double_list_append_as_tail(&g_free_list, &pnodes[i].node);
	}
	/* create accepting thread */
	auto ret = pthread_create(&g_listening_tid, nullptr, consrv_thrwork,
	           reinterpret_cast<void *>(static_cast<intptr_t>(sock)));
	if (ret != 0) {
		printf("[console_server]: failed to create accepting thread: %s\n", strerror(ret));
		free(pnodes);
		close(sock);
		return -5;
	}
	gx_reexec_record(sock);
	pthread_setname_np(g_listening_tid, "console/accept");
	g_console_buff = pnodes;
    return 0;
}

void console_server_stop()
{
	if (NULL != g_console_buff) {
		free(g_console_buff);
		g_console_buff = NULL;
	}
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
	bytes = gx_vsnprintf(message, GX_ARRAY_SIZE(message), format, ap);
	bytes += gx_snprintf(message + bytes, GX_ARRAY_SIZE(message) - bytes, "\r\n");
	va_end(ap);
    return write(client_fd, message, bytes);
}

/*
 *  main thread function which loop and dispatch the 
 *  command.
 *  @param  
 *      vargp       server listening socket
 */
static void *consrv_thrwork(void *argp)
{
	fd_set myset;
	struct timeval tv;
	CONSOLE_NODE *pconsole;
	DOUBLE_LIST_NODE *pnode;
	int sock, client_fd;
	struct sockaddr_storage client_peer;

    sock = (int)(long)argp;
	while (!g_terminate) {
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
		std::unique_lock ll_hold(g_list_lock);
		pnode = double_list_pop_front(&g_free_list);
		if (NULL == pnode) {
			ll_hold.unlock();
			write(client_fd, EXCEED_STRING, sizeof(EXCEED_STRING) - 1);
			close(client_fd);
			continue;
		}
		pconsole = (CONSOLE_NODE*)pnode->pdata;
		pconsole->client_fd = client_fd;
		auto ret = pthread_create(&pconsole->tid, nullptr, consrv_work, pconsole);
		if (ret != 0) {
			fprintf(stderr, "W-1444: pthread_create: %s\n", strerror(ret));
			double_list_append_as_tail(&g_free_list, pnode);
			ll_hold.unlock();
			write(client_fd, ERROR_STRING, sizeof(ERROR_STRING) - 1);
			close(client_fd);
			continue;
		}
		pthread_setname_np(pconsole->tid, "console/client");
		double_list_append_as_tail(&g_console_list, pnode);
    }
    close(sock);
	return nullptr;
}

/*
 *  thread work function for handling console request
 */
static void *consrv_work(void *argp)
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
	pconsole = (CONSOLE_NODE*)argp;
	client_fd = pconsole->client_fd;
	pthread_setspecific(g_client_fd_key, (const void*)(long)client_fd);
    memset(cmd, 0, MAXLINE);
	memset(last_command, 0, MAXLINE);
    pthread_detach(pthread_self()); /* detach itself */
	reply_len = sprintf(reply_buff, "%s%s", WELCOME_STRING, PROMPT_SRING);
	write(client_fd, reply_buff, reply_len);
	while (true) {
        read_len = read(client_fd, cmd + offset, MAXLINE - offset);
        if (read_len <= 0) {
			write(client_fd, TIMEOUT_STRING, sizeof(TIMEOUT_STRING) - 1);
			std::unique_lock ll_hold(g_list_lock);
			double_list_remove(&g_console_list, &pconsole->node);
			double_list_append_as_tail(&g_free_list, &pconsole->node);
			ll_hold.unlock();
			close(client_fd);
			return nullptr;
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
	std::unique_lock ll_hold(g_list_lock);
	double_list_remove(&g_console_list, &pconsole->node);
	double_list_append_as_tail(&g_free_list, &pconsole->node);
	close(client_fd);
	return nullptr;
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
BOOL console_server_register_command(const char *cmd, COMMAND_HANDLER handler)
{
	if (cmd != nullptr)
		g_cmd_entry.emplace(cmd, handler);
	else
		g_cmd_dynamic.push_back(handler);
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
	char *last_quote = nullptr;

    memset(array, 0, sizeof(array));
	string_len = strlen(cmdline);
	memcpy(array, cmdline, string_len);
	array[string_len] = ' ';
	string_len ++;
	array[string_len] = '\0';
	ptr = array;
    /* Build the argv list */
    argc = 0;
	last_space = array;
    while (*ptr != '\0') {
		/* back slash should be treated as transferred meaning */
		if ((ptr[0] == '\\' && ptr[1] == '\"') ||
		    (ptr[0] == '\\' && ptr[1] == '\\')) {
			memmove(ptr, ptr + 1, strlen(ptr + 1) + 1);
			ptr ++;
		}
		if ('\"' == *ptr) {
			if (last_quote == nullptr) {
				last_quote = ptr + 1;
			} else {
				/* ignore "" */
				if (ptr == last_quote) {
					last_quote = nullptr;
					last_space = ptr + 1;
				} else {
					argv[argc] = last_quote;
					*ptr = '\0';
					last_quote = nullptr;
					last_space = ptr + 1;
					argc ++;
				}
			}
		}
		if (*ptr == ' ' && last_quote == nullptr) {
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
	/* only one quote is found, error */
	if (last_quote != nullptr)
		argc = 0;
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

    memset(argv, 0, sizeof(argv));
    /* parse command line */
	std::unique_lock xc_hold(g_execute_lock);
	auto argc = console_server_parse_line(cmdline, argv);
    cmd = argv[0];
    if (0 == argc) {
        return; /* ignore empty lines */
    }
	/* compare build-in command */
	auto cmd_iter = g_cmd_entry.find(cmd);
	if (cmd_iter != g_cmd_entry.end()) {
		cmd_iter->second(argc, argv);
		return;
	}
	for (auto h : g_cmd_dynamic)
		if (h(argc, argv))
			return;
	xc_hold.unlock();
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
	
	g_terminate = true;
	b_console = FALSE;
	if (g_listening_tid != 0) {
		pthread_kill(g_listening_tid, SIGALRM);
		pthread_join(g_listening_tid, NULL);
		g_listening_tid = 0;
	}
	std::unique_lock ll_hold(g_list_lock);
	while ((pnode = double_list_pop_front(&g_console_list)) != nullptr) {
		pconsole = (CONSOLE_NODE*)pnode->pdata;
		if (pthread_equal(pthread_self(), pconsole->tid) != 0)
			b_console = TRUE;
		write(pconsole->client_fd, STOP_STRING, sizeof(STOP_STRING) - 1);
		close(pconsole->client_fd);
	}
	while (double_list_pop_front(&g_free_list) != nullptr)
		/* do nothing */;
	ll_hold.unlock();
	g_notify_stop = true;
	if (TRUE == b_console) {
		pthread_exit(nullptr);
	}
}


