// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cerrno>
#include <string>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#include <gromox/double_list.hpp>
#include <gromox/list_file.hpp>
#include <gromox/config_file.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <csignal>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#define SOCKET_TIMEOUT		60

#define COMMAND_LENGTH		512

#define MAXARGS				128

#define DEF_MODE			S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

using namespace gromox;

struct CONNECTION_NODE {
	DOUBLE_LIST_NODE node;
	int sockd;
	int offset;
	char buffer[1024];
	char line[1024];
};

struct TIMER {
	DOUBLE_LIST_NODE node;
	int t_id;
	time_t exec_time;
	char command[COMMAND_LENGTH];
};

static BOOL g_notify_stop;
static int g_threads_num;
static int g_last_tid;
static int g_list_fd;
static char g_list_path[256];
static std::vector<std::string> g_acl_list;
static DOUBLE_LIST g_connection_list;
static DOUBLE_LIST g_connection_list1;
static DOUBLE_LIST g_exec_list;
static pthread_mutex_t g_tid_lock;
static pthread_mutex_t g_list_lock;
static pthread_mutex_t g_connection_lock;
static pthread_mutex_t g_cond_mutex;
static pthread_cond_t g_waken_cond;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void *accept_work_func(void *param);

static void *thread_work_func(void *param);

static void execute_timer(TIMER *ptimer);

static int parse_line(char *pbuff, const char* cmdline, char** argv);

static void encode_line(const char *in, char *out);

static BOOL read_mark(CONNECTION_NODE *pconnection);

static void term_handler(int signo);
static int increase_tid();
static void put_timer(TIMER *ptimer);

int main(int argc, const char **argv)
{
	int i, j;
	int temp_fd;
	int temp_len;
	int listen_port;
	time_t cur_time;
	time_t last_cltime;
	pthread_t thr_accept_id;
	pthread_t *thr_ids;
	char listen_ip[40];
	char temp_path[256];
	char temp_line[2048];
	TIMER *ptimer;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	auto pconfig = config_file_prg(opt_config_file, "timer.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}

	char config_dir[256];
	auto str_value = config_file_get_value(pconfig, "config_file_path");
	HX_strlcpy(config_dir, str_value != nullptr ? str_value :
	           PKGSYSCONFDIR "/timer:" PKGSYSCONFDIR, GX_ARRAY_SIZE(config_dir));
	str_value = config_file_get_value(pconfig, "timer_state_path");
	HX_strlcpy(g_list_path, str_value != nullptr ? str_value :
	           PKGSTATEDIR "/timer.txt", sizeof(g_list_path));
	printf("[system]: list path is %s\n", g_list_path);

	str_value = config_file_get_value(pconfig, "TIMER_LISTEN_IP");
	if (NULL == str_value) {
		HX_strlcpy(listen_ip, "::1", GX_ARRAY_SIZE(listen_ip));
	} else {
		HX_strlcpy(listen_ip, str_value, sizeof(listen_ip));
	}

	str_value = config_file_get_value(pconfig, "TIMER_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 6666;
		config_file_set_value(pconfig, "TIMER_LISTEN_PORT", "6666");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 6666;
			config_file_set_value(pconfig, "TIMER_LISTEN_PORT", "6666");
		}
	}
	printf("[system]: listen address is [%s]:%d\n",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	str_value = config_file_get_value(pconfig, "TIMER_THREADS_NUM");
	if (NULL == str_value) {
		g_threads_num = 50;
		config_file_set_value(pconfig, "TIMER_THREADS_NUM", "50");
	} else {
		g_threads_num = atoi(str_value);
		if (g_threads_num < 5) {
			g_threads_num = 5;
			config_file_set_value(pconfig, "TIMER_THREADS_NUM", "5");
		}
		if (g_threads_num > 50) {
			g_threads_num = 50;
			config_file_set_value(pconfig, "TIMER_THREADS_NUM", "50");
		}
	}

	printf("[system]: processing threads number is %d\n", g_threads_num);

	g_threads_num ++;

	struct srcitem {
		int tid;
		long exectime;
		char command[512];
	} __attribute__((packed));
	auto pfile = list_file_initd(g_list_path, "/", "%d%l%s:512");
	if (NULL == pfile) {
		printf("[system]: Failed to read timers from %s: %s\n",
			g_list_path, strerror(errno));
		return 3;
	}

	double_list_init(&g_exec_list);
	auto item_num = pfile->get_size();
	auto pitem = static_cast<srcitem *>(pfile->get_list());
	for (i=0; i<item_num; i++) {
		if (pitem[i].exectime == 0) {
			for (j=0; j<item_num; j++) {
				if (i == j) {
					continue;
				}
				if (pitem[i].tid == pitem[j].tid) {
					pitem[j].exectime = 0;
					break;
				}
			} 
		}
	}

	time(&cur_time);

	for (i=0; i<item_num; i++) {
		if (pitem[i].tid > g_last_tid)
			g_last_tid = pitem[i].tid;
		if (pitem[i].exectime == 0)
			continue;
		ptimer = (TIMER*)malloc(sizeof(TIMER));
		if (NULL == ptimer) {
			continue;
		}
		ptimer->node.pdata = ptimer;
		ptimer->t_id = pitem[i].tid;
		ptimer->exec_time = pitem[i].exectime;
		HX_strlcpy(ptimer->command, pitem[i].command, sizeof(ptimer->command));
		put_timer(ptimer);
	}
	pfile.reset();

	auto sockd = gx_inet_listen(listen_ip, listen_port);
	if (sockd < 0) {
		printf("[system]: failed to create listen socket: %s\n", strerror(-sockd));
		return 4;
	}
	g_list_fd = open(g_list_path, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
	if (-1 == g_list_fd) {
		printf("[system]: Failed to open %s: %s\n", g_list_path, strerror(errno));
		close(sockd);
		return 7;
	}

	pthread_mutex_init(&g_tid_lock, NULL);
	pthread_mutex_init(&g_list_lock, NULL);
	pthread_mutex_init(&g_connection_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);
	double_list_init(&g_connection_list);
	double_list_init(&g_connection_list1);

	thr_ids = (pthread_t*)malloc(g_threads_num*sizeof(pthread_t));

	for (i=0; i<g_threads_num; i++) {
		int ret = pthread_create(&thr_ids[i], nullptr, thread_work_func, nullptr);
		if (ret != 0) {
			printf("[system]: failed to create pool thread: %s\n", strerror(ret));
			break;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "worker/%u", i);
		pthread_setname_np(thr_ids[i], buf);
	}

	if (i != g_threads_num) {
		for (i-=1; i>=0; i--) {
			pthread_cancel(thr_ids[i]);
		}

		close(sockd);
		close(g_list_fd);
		double_list_free(&g_connection_list);
		double_list_free(&g_connection_list1);

		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_list_lock);
		pthread_mutex_destroy(&g_tid_lock);
		pthread_mutex_destroy(&g_cond_mutex);
		pthread_cond_destroy(&g_waken_cond);
		return 8;
	}

	auto ret = list_file_read_fixedstrings("timer_acl.txt", config_dir, g_acl_list);
	if (ret == -ENOENT) {
		printf("[system]: defaulting to implicit access ACL containing ::1.\n");
		g_acl_list = {"::1"};
	} else if (ret < 0) {
		printf("[system]: list_file_initd timer_acl.txt: %s\n", strerror(-ret));
		for (i = g_threads_num - 1; i >= 0; i--) {
			pthread_cancel(thr_ids[i]);
		}
		close(sockd);
		close(g_list_fd);
		double_list_free(&g_connection_list);
		double_list_free(&g_connection_list1);
		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_list_lock);
		pthread_mutex_destroy(&g_tid_lock);
		pthread_mutex_destroy(&g_cond_mutex);
		pthread_cond_destroy(&g_waken_cond);
		return 9;
	}
	
	ret = pthread_create(&thr_accept_id, nullptr, accept_work_func,
	          reinterpret_cast<void *>(static_cast<intptr_t>(sockd)));
	if (ret != 0) {
		printf("[system]: failed to create accept thread: %s\n", strerror(ret));
		for (i=g_threads_num-1; i>=0; i--) {
			pthread_cancel(thr_ids[i]);
		}

		close(sockd);
		close(g_list_fd);
		double_list_free(&g_connection_list);
		double_list_free(&g_connection_list1);

		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_list_lock);
		pthread_mutex_destroy(&g_tid_lock);
		pthread_mutex_destroy(&g_cond_mutex);
		pthread_cond_destroy(&g_waken_cond);
		return 10;
	}
	
	pthread_setname_np(thr_accept_id, "accept");
	time(&last_cltime);
	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	printf("[system]: TIMER is now running\n");

	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_list_lock);
		time(&cur_time);
		for (pnode=double_list_get_head(&g_exec_list); NULL!=pnode;
			pnode=double_list_get_after(&g_exec_list, pnode)) {
			ptimer = (TIMER*)pnode->pdata;
			if (ptimer->exec_time > cur_time) {
				break;
			}
			pnode = double_list_get_after(&g_exec_list, pnode);
			double_list_remove(&g_exec_list, &ptimer->node);
			execute_timer(ptimer);
			free(ptimer);
			if (NULL == pnode) {
				break;
			}
		}

		if (cur_time - last_cltime > 7 * 86400) {
			close(g_list_fd);
			auto pfile = list_file_initd(g_list_path, "/", "%d%l%s:512");
			if (NULL != pfile) {
				auto item_num = pfile->get_size();
				auto pitem = static_cast<srcitem *>(pfile->get_list());
				for (i=0; i<item_num; i++) {
					if (pitem[i].exectime == 0) {
						for (j=0; j<item_num; j++) {
							if (i == j) {
								continue;
							}
							if (pitem[i].tid == pitem[j].tid) {
								pitem[j].exectime = 0;
								break;
							}
						}
					} 
				}
				snprintf(temp_path, GX_ARRAY_SIZE(temp_path), "%s.tmp", g_list_path);
				temp_fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
				if (-1 != temp_fd) {
					for (i=0; i<item_num; i++) {
						if (pitem[i].exectime == 0)
							continue;
						temp_len = sprintf(temp_line, "%d\t%ld\t",
						           pitem[i].tid, pitem[i].exectime);
						encode_line(pitem[i].command, temp_line + temp_len);
						temp_len = strlen(temp_line);
						temp_line[temp_len] = '\n';
						temp_len ++;
						write(temp_fd, temp_line, temp_len);
					}
					close(temp_fd);
					remove(g_list_path);
					rename(temp_path, g_list_path);
				}
				last_cltime = cur_time;
			}
			g_list_fd = open(g_list_path, O_APPEND|O_WRONLY);
		}

		pthread_mutex_unlock(&g_list_lock);

		sleep(1);

	}


	for (i=0; i<g_threads_num; i++) {
		pthread_cancel(thr_ids[i]);
	}
	free(thr_ids);

	close(sockd);
	close(g_list_fd);
	while ((pnode = double_list_pop_front(&g_connection_list)) != nullptr) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		close(pconnection->sockd);
		free(pconnection);
	}

	double_list_free(&g_connection_list);

	while ((pnode = double_list_pop_front(&g_connection_list1)) != nullptr) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		close(pconnection->sockd);
		free(pconnection);
	}

	double_list_free(&g_connection_list1);


	pthread_mutex_destroy(&g_connection_lock);
	pthread_mutex_destroy(&g_list_lock);
	pthread_mutex_destroy(&g_tid_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_cond_destroy(&g_waken_cond);


	return 0;
}


static void put_timer(TIMER *ptimer)
{
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_exec_list); NULL!=pnode;
		pnode=double_list_get_after(&g_exec_list, pnode)) {
		if (((TIMER*)(pnode->pdata))->exec_time > ptimer->exec_time) {
			break;
		}
	}

	if (NULL == pnode) {
		double_list_append_as_tail(&g_exec_list, &ptimer->node);
	} else {
		if (pnode == double_list_get_head(&g_exec_list)) {
			double_list_insert_as_head(&g_exec_list, &ptimer->node);
		} else {
			double_list_insert_before(&g_exec_list, pnode, &ptimer->node);
		}
	}
}


static void *accept_work_func(void *param)
{
	int sockd, sockd2;
	socklen_t addrlen;
	char client_hostip[40];
	struct sockaddr_storage peer_name;
	CONNECTION_NODE *pconnection;	

	sockd = (int)(long)param;
    while (FALSE == g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd2 = accept(sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd2) {
			continue;
		}
		int ret = getnameinfo(reinterpret_cast<sockaddr *>(&peer_name),
		          addrlen, client_hostip, sizeof(client_hostip),
		          nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    client_hostip) == g_acl_list.cend()) {
			write(sockd2, "Access Deny\r\n", 13);
			close(sockd2);
			continue;
		}

		pconnection = (CONNECTION_NODE*)malloc(sizeof(CONNECTION_NODE));
		if (NULL == pconnection) {
			write(sockd2, "Internal Error!\r\n", 17);
			close(sockd2);
			continue;
		}
		pthread_mutex_lock(&g_connection_lock);
		if (double_list_get_nodes_num(&g_connection_list) + 1 +
			double_list_get_nodes_num(&g_connection_list1) >= g_threads_num) {
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			write(sockd2, "Maximum Connection Reached!\r\n", 29);
			close(sockd2);
			continue;
		}

		pconnection->node.pdata = pconnection;
		pconnection->sockd = sockd2;
		pconnection->offset = 0;
		double_list_append_as_tail(&g_connection_list1, &pconnection->node);
		pthread_mutex_unlock(&g_connection_lock);
		write(sockd2, "OK\r\n", 4);
		pthread_cond_signal(&g_waken_cond);
	}
	return nullptr;
}

static void execute_timer(TIMER *ptimer)
{
	int len;
	int argc;
	int status;
	pid_t pid;
	char result[1024];
	char temp_buff[2048];
	char* argv[MAXARGS];

	argc = parse_line(temp_buff, ptimer->command, argv);
	if (argc > 0) {
		pid = fork();
		if (0 == pid) {
			chdir("../tools");
			execve(argv[0], argv, NULL);
			_exit(-1);
		} else if (pid > 0) {
			if (waitpid(pid, &status, 0) > 0) {
				if (WIFEXITED(status) && 0 == WEXITSTATUS(status)) {
					strcpy(result, "DONE");
				} else {
					strcpy(result, "EXEC-FAILURE");
				}
			} else {
				strcpy(result, "FAIL-TO-WAIT");
			}
		} else {
			strcpy(result, "FAIL-TO-FORK");
		}
	} else {
		strcpy(result, "FORMAT-ERROR");
	}

	len = sprintf(temp_buff, "%d\t0\t%s\n", ptimer->t_id, result);

	write(g_list_fd, temp_buff, len);
}

static void *thread_work_func(void *param)
{
	int t_id;
	int temp_len;
	int exec_interval;
	TIMER *ptimer;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;	
	char *pspace, temp_line[1024];
	
 NEXT_LOOP:
	pthread_mutex_lock(&g_cond_mutex);
	pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
	pthread_mutex_unlock(&g_cond_mutex);

	pthread_mutex_lock(&g_connection_lock);
	pnode = double_list_pop_front(&g_connection_list1);
	if (NULL != pnode) {
		double_list_append_as_tail(&g_connection_list, pnode);
	}
	pthread_mutex_unlock(&g_connection_lock);

	if (NULL == pnode) {
		goto NEXT_LOOP;
	}

	pconnection = (CONNECTION_NODE*)pnode->pdata;

	while (TRUE) {
		if (FALSE == read_mark(pconnection)) {
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			goto NEXT_LOOP;
		}

		if (0 == strncasecmp(pconnection->line, "CANCEL ", 7)) {
			t_id = atoi(pconnection->line + 7);
			if (t_id <= 0) {
				write(pconnection->sockd, "FALSE 1\r\n", 9);	
				continue;
			}
			pthread_mutex_lock(&g_list_lock);
			for (pnode=double_list_get_head(&g_exec_list); NULL!=pnode;
				pnode=double_list_get_after(&g_exec_list, pnode)) {
				ptimer = (TIMER*)pnode->pdata;
				if (t_id == ptimer->t_id) {
					double_list_remove(&g_exec_list, pnode);
					temp_len = sprintf(temp_line, "%d\t0\tCANCEL\n",
								ptimer->t_id);
					free(ptimer);
					write(g_list_fd, temp_line, temp_len);
					break;
				}
			}
			pthread_mutex_unlock(&g_list_lock);
			if (NULL != pnode) {
				write(pconnection->sockd, "TRUE\r\n", 6);
			} else {
				write(pconnection->sockd, "FALSE 2\r\n", 9);
			}
		} else if (0 == strncasecmp(pconnection->line, "ADD ", 4)) {
			pspace = strchr(pconnection->line + 4, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE 1\r\n", 9);
				continue;
			}
			*pspace = '\0';
			pspace ++;

			exec_interval = atoi(pconnection->line + 4);
			if (exec_interval <= 0 || strlen(pspace) >= COMMAND_LENGTH) {
				write(pconnection->sockd, "FALSE 2\r\n", 9);
				continue;
			}

			ptimer = (TIMER*)malloc(sizeof(TIMER));
			if (NULL == ptimer) {
				write(pconnection->sockd, "FALSE 3\r\n", 9);
				continue;
			}
			ptimer->node.pdata = ptimer;
			ptimer->t_id = increase_tid();
			ptimer->exec_time = exec_interval + time(NULL);
			strcpy(ptimer->command, pspace);

			pthread_mutex_lock(&g_list_lock);
			put_timer(ptimer);

			temp_len = sprintf(temp_line, "%d\t%ld\t", ptimer->t_id,
						ptimer->exec_time);
			encode_line(ptimer->command, temp_line + temp_len);
			temp_len = strlen(temp_line);
			temp_line[temp_len] = '\n';
			temp_len ++;
			write(g_list_fd, temp_line, temp_len);
			pthread_mutex_unlock(&g_list_lock);
			temp_len = sprintf(temp_line, "TRUE %d\r\n", ptimer->t_id);
			write(pconnection->sockd, temp_line, temp_len);
		} else if (0 == strcasecmp(pconnection->line, "QUIT")) {
			write(pconnection->sockd, "BYE\r\n", 5);
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			goto NEXT_LOOP;
		} else if (0 == strcasecmp(pconnection->line, "PING")) {
			write(pconnection->sockd, "TRUE\r\n", 6);	
		} else {
			write(pconnection->sockd, "FALSE\r\n", 7);
		}
	}
	return NULL;
}

static BOOL read_mark(CONNECTION_NODE *pconnection)
{
	fd_set myset;
	int i, read_len;
	struct timeval tv;

	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pconnection->sockd, &myset);
		if (select(pconnection->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(pconnection->sockd, pconnection->buffer +
		pconnection->offset, 1024 - pconnection->offset);
		if (read_len <= 0) {
			return FALSE;
		}
		pconnection->offset += read_len;
		for (i=0; i<pconnection->offset-1; i++) {
			if ('\r' == pconnection->buffer[i] &&
				'\n' == pconnection->buffer[i + 1]) {
				memcpy(pconnection->line, pconnection->buffer, i);
				pconnection->line[i] = '\0';
				pconnection->offset -= i + 2;
				memmove(pconnection->buffer, pconnection->buffer + i + 2,
					pconnection->offset);
				return TRUE;
			}
		}
		if (1024 == pconnection->offset) {
			return FALSE;
		}
	}
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

static int parse_line(char *pbuff, const char* cmdline, char** argv)
{
	int string_len;
    char *ptr;                   /* ptr that traverses command line  */
    int argc;                    /* number of args */
	char *last_space;
	char *last_quota;

	string_len = strlen(cmdline);
	memcpy(pbuff, cmdline, string_len);
	pbuff[string_len] = ' ';
	string_len ++;
	pbuff[string_len] = '\0';
	ptr = pbuff;
    /* Build the argv list */
    argc = 0;
	last_quota = NULL;
	last_space = pbuff;
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
					if (argc >= MAXARGS) {
						return 0;
					}
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
				if (argc >= MAXARGS) {
					return 0;
				}
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

static void encode_line(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if (' ' == in[i] || '\\' == in[i] || '\t' == in[i] || '#' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

static int increase_tid()
{
	int val;

	pthread_mutex_lock(&g_tid_lock);
	g_last_tid ++;
	val = g_last_tid;
	pthread_mutex_unlock(&g_tid_lock);
	return val;
}

