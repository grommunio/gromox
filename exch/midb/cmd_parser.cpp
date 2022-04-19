// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <climits>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "cmd_parser.h"
#include "common_util.h"
#define MAX_ARGS			(32*1024)

#define CONN_BUFFLEN        (257*1024)

using namespace gromox;

static unsigned int g_threads_num;
static gromox::atomic_bool g_notify_stop;
static int g_timeout_interval;
static std::vector<pthread_t> g_thread_ids;
static std::mutex g_connection_lock, g_cond_mutex;
static std::condition_variable g_waken_cond;
static DOUBLE_LIST g_connection_list;
static DOUBLE_LIST g_connection_list1;
static std::unordered_map<std::string, MIDB_CMD_HANDLER> g_cmd_entry;
unsigned int g_cmd_debug;

static void *midcp_thrwork(void *);
static int cmd_parser_generate_args(char* cmd_line, int cmd_len, char** argv);

static int cmd_parser_ping(int argc, char **argv, int sockd);

void cmd_parser_init(unsigned int threads_num, int timeout, unsigned int debug)
{
	g_threads_num = threads_num;
	g_thread_ids.reserve(g_threads_num);
	g_timeout_interval = timeout;
	g_cmd_debug = debug;
	double_list_init(&g_connection_list);
	double_list_init(&g_connection_list1);
}


void cmd_parser_free()
{

	double_list_free(&g_connection_list);
	double_list_free(&g_connection_list1);
}

MIDB_CONNECTION *cmd_parser_get_connection()
{
	std::unique_lock chold(g_connection_lock);
	if (double_list_get_nodes_num(&g_connection_list) + 1 +
		double_list_get_nodes_num(&g_connection_list1) >= g_threads_num) {
		return NULL;
	}
	chold.unlock();
	auto pconnection = me_alloc<MIDB_CONNECTION>();
	pconnection->node.pdata = pconnection;

	return pconnection;
}

void cmd_parser_put_connection(MIDB_CONNECTION *pconnection)
{	
	std::unique_lock chold(g_connection_lock);
	double_list_append_as_tail(&g_connection_list1, &pconnection->node);
	chold.unlock();
	g_waken_cond.notify_one();
}


int cmd_parser_run()
{
	pthread_attr_t thr_attr;
	pthread_attr_init(&thr_attr);
	auto cl_0 = make_scope_exit([&]() { pthread_attr_destroy(&thr_attr); });

	cmd_parser_register_command("PING", cmd_parser_ping);
	g_notify_stop = false;

	for (unsigned int i = 0; i < g_threads_num; ++i) {
		pthread_t tid;
		auto ret = pthread_create(&tid, &thr_attr, midcp_thrwork, nullptr);
		if (ret != 0) {
			printf("[cmd_parser]: failed to create pool thread: %s\n", strerror(ret));
			return -1;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "cmd_parser/%u", i);
		pthread_setname_np(tid, buf);
		g_thread_ids.push_back(tid);
	}
	return 0;
}

void cmd_parser_stop()
{
	DOUBLE_LIST_NODE *pnode;
	MIDB_CONNECTION *pconnection = nullptr;

	g_notify_stop = true;
	g_waken_cond.notify_all();
	std::unique_lock chold(g_connection_lock);
	for (pnode=double_list_get_head(&g_connection_list); NULL!=pnode;
		pnode=double_list_get_after(&g_connection_list, pnode)) {
		pconnection = static_cast<MIDB_CONNECTION *>(pnode->pdata);
		if (pconnection->is_selecting) {
			pthread_kill(pconnection->thr_id, SIGALRM);
		} else {
			close(pconnection->sockd);
			pconnection->sockd = -1;
		}	
	}
	chold.unlock();
	for (auto tid : g_thread_ids) {
		pthread_kill(tid, SIGALRM);
		pthread_join(tid, nullptr);
	}
	g_thread_ids.clear();
	while ((pnode = double_list_pop_front(&g_connection_list)) != nullptr) {
		pconnection = static_cast<MIDB_CONNECTION *>(pnode->pdata);
		if (-1 != pconnection->sockd) {
			close(pconnection->sockd);
		}
		free(pconnection);
	}

	while ((pnode = double_list_pop_front(&g_connection_list1)) != nullptr) {
		pconnection = static_cast<MIDB_CONNECTION *>(pnode->pdata);
		close(pconnection->sockd);
		free(pconnection);
	}
}


void cmd_parser_register_command(const char *command, MIDB_CMD_HANDLER handler)
{
	g_cmd_entry.emplace(command, handler);
}

static thread_local int dbg_current_argc;
static thread_local char **dbg_current_argv;

static void cmd_dump_argv(int argc, char **argv)
{
	fprintf(stderr, "<");
	for (int i = 0; i < argc; ++i)
		fprintf(stderr, " %s", argv[i]);
	fprintf(stderr, "\n");
}

static void cmd_write_x(unsigned int level, int fd, const char *buf, size_t z)
{
	::write(fd, buf, z);
	if (g_cmd_debug < level)
		return;
	if (dbg_current_argv != nullptr) {
		cmd_dump_argv(dbg_current_argc, dbg_current_argv);
		dbg_current_argv = nullptr;
	}
	if (z >= 1 && buf[z-1] == '\n')
		--z;
	if (z >= 1 && buf[z-1] == '\r')
		--z;
	if (z > INT_MAX)
		z = INT_MAX;
	fprintf(stderr, "> %.*s\n", static_cast<int>(z), buf);
} 

void cmd_write(int fd, const void *vbuf, size_t z)
{
	/* Note: cmd_write is also only called for successful responses */
	cmd_write_x(2, fd, static_cast<const char *>(vbuf), z);
}

static std::pair<bool, int> midcp_exec1(int argc, char **argv, MIDB_CONNECTION *conn)
{
	if (g_notify_stop)
		return {false, 0};
	auto cmd_iter = g_cmd_entry.find(argv[0]);
	if (cmd_iter == g_cmd_entry.end())
		return {false, 0};
	if (!common_util_build_environment(argv[1]))
		return {false, 0};
	auto err = cmd_iter->second(argc, argv, conn->sockd);
	common_util_free_environment();
	if (err == 0)
		return {true, 0};
	return {false, err};
}

static void midcp_exec(int argc, char **argv, MIDB_CONNECTION *conn)
{
	dbg_current_argc = argc;
	dbg_current_argv = argv;
	auto [replied, result] = midcp_exec1(argc, argv, conn);
	if (replied)
		return;
	char rsp[20];
	auto len = snprintf(rsp, arsizeof(rsp), "FALSE %d\r\n", result);
	cmd_write_x(1, conn->sockd, rsp, len);
}

static void *midcp_thrwork(void *param)
{
	int i, argc, offset, tv_msec, read_len;
	char *argv[MAX_ARGS];
	struct pollfd pfd_read;
//	MIDB_CONNECTION *pconnection;
	DOUBLE_LIST_NODE *pnode;
	char buffer[CONN_BUFFLEN];

 NEXT_LOOP:
	if (g_notify_stop)
		return nullptr;
	std::unique_lock cm_hold(g_cond_mutex);
	g_waken_cond.wait(cm_hold);
	cm_hold.unlock();
	if (g_notify_stop)
		return nullptr;
	std::unique_lock co_hold(g_connection_lock);
	pnode = double_list_pop_front(&g_connection_list1);
	if (NULL != pnode) {
		double_list_append_as_tail(&g_connection_list, pnode);
	}
	co_hold.unlock();
	if (NULL == pnode) {
		goto NEXT_LOOP;
	}
	auto pconnection = static_cast<MIDB_CONNECTION *>(pnode->pdata);
	offset = 0;

    while (!g_notify_stop) {
		tv_msec = g_timeout_interval * 1000;
		pfd_read.fd = pconnection->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		pconnection->is_selecting = TRUE;
		pconnection->thr_id = pthread_self();
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			pconnection->is_selecting = FALSE;
			co_hold.lock();
			double_list_remove(&g_connection_list, &pconnection->node);
			co_hold.unlock();
			close(pconnection->sockd);
			free(pconnection);
			goto NEXT_LOOP;
		}
		pconnection->is_selecting = FALSE;
		read_len = read(pconnection->sockd, buffer + offset,
					CONN_BUFFLEN - offset);
		if (read_len <= 0) {
			co_hold.lock();
			double_list_remove(&g_connection_list, &pconnection->node);
			co_hold.unlock();
			close(pconnection->sockd);
			free(pconnection);
			goto NEXT_LOOP;
		}
		offset += read_len;
		for (i=0; i<offset-1; i++) {
			if (buffer[i] != '\r' || buffer[i+1] != '\n')
				continue;
			if (4 == i && 0 == strncasecmp(buffer, "QUIT", 4)) {
				write(pconnection->sockd, "BYE\r\n", 5);
				co_hold.lock();
				double_list_remove(&g_connection_list, &pconnection->node);
				co_hold.unlock();
				close(pconnection->sockd);
				free(pconnection);
				goto NEXT_LOOP;
			}

			argc = cmd_parser_generate_args(buffer, i, argv);
			if (argc < 2) {
				write(pconnection->sockd, "FALSE 1\r\n", 9);
				offset -= i + 2;
				if (offset >= 0)
					memmove(buffer, buffer + i + 2, offset);
				i = 0;
				continue;
			}

			HX_strupper(argv[0]);
			midcp_exec(argc, argv, pconnection);
			offset -= i + 2;
			memmove(buffer, buffer + i + 2, offset);
			i = 0;
		}

		if (CONN_BUFFLEN == offset) {
			co_hold.lock();
			double_list_remove(&g_connection_list, &pconnection->node);
			co_hold.unlock();
			close(pconnection->sockd);
			free(pconnection);
			goto NEXT_LOOP;
		}
	}
	return nullptr;
}

static int cmd_parser_ping(int argc, char **argv, int sockd)
{
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static int cmd_parser_generate_args(char* cmd_line, int cmd_len, char** argv)
{
	int argc;                    /* number of args */
	char *ptr;                   /* ptr that traverses command line  */
	char *last_space;
	
	cmd_line[cmd_len] = ' ';
	cmd_line[cmd_len + 1] = '\0';
	ptr = cmd_line;
	/* Build the argv list */
	argc = 0;
	last_space = cmd_line;
	while (*ptr != '\0') {
		if ('{' == *ptr) {
			if ('}' != cmd_line[cmd_len - 1]) {
				return 0;
			}
			argv[argc] = ptr;
			cmd_line[cmd_len] = '\0';
			argc ++;
			break;
		}

		if (' ' == *ptr) {
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
	
	argv[argc] = NULL;
	return argc;
}	

