// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <list>
#include <mutex>
#include <netdb.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/list_file.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include <gromox/util.hpp>

#define COMMAND_LENGTH		512

#define MAXARGS				128

#define DEF_MODE			S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

using namespace gromox;

namespace {

struct CONNECTION_NODE {
	CONNECTION_NODE() = default;
	CONNECTION_NODE(CONNECTION_NODE &&) noexcept;
	~CONNECTION_NODE();
	void operator=(CONNECTION_NODE &&) noexcept = delete;
	int sockd = -1;
	int offset = 0;
	char buffer[1024]{};
	char line[1024]{};
};

struct TIMER {
	int t_id;
	time_t exec_time;
	std::string command;
};

struct srcitem {
	int tid;
	long exectime;
	char command[512];
} __attribute__((packed));

}

static gromox::atomic_bool g_notify_stop;
static unsigned int g_threads_num;
static int g_last_tid;
static int g_list_fd = -1;
static std::string g_list_path;
static std::vector<std::string> g_acl_list;
static std::list<CONNECTION_NODE> g_connection_list, g_connection_list1;
static std::list<TIMER> g_exec_list;
static std::mutex g_tid_lock, g_list_lock, g_connection_lock, g_cond_mutex;
static std::condition_variable g_waken_cond;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void *tmr_acceptwork(void *);
static void *tmr_thrwork(void *);
static void execute_timer(TIMER *ptimer);

static int parse_line(char *pbuff, const char* cmdline, char** argv);

static void encode_line(const char *in, char *out);

static BOOL read_mark(CONNECTION_NODE *pconnection);

static void term_handler(int signo);
static int increase_tid();

CONNECTION_NODE::CONNECTION_NODE(CONNECTION_NODE &&o) noexcept :
	sockd(o.sockd), offset(o.offset)
{
	o.sockd = -1;
	memcpy(buffer, o.buffer, sizeof(buffer));
	memcpy(line, o.line, sizeof(line));
}

CONNECTION_NODE::~CONNECTION_NODE()
{
	if (sockd >= 0)
		close(sockd);
}

static void save_timers(time_t &last_cltime, const time_t &cur_time)
{
	close(g_list_fd);
	auto pfile = list_file_initd(g_list_path.c_str(), "/", "%d%l%s:512");
	if (pfile == nullptr) {
		g_list_fd = open(g_list_path.c_str(), O_APPEND | O_WRONLY);
		return;
	}
	auto item_num = pfile->get_size();
	auto pitem = static_cast<srcitem *>(pfile->get_list());
	for (size_t i = 0; i < item_num; ++i) {
		if (pitem[i].exectime != 0)
			continue;
		for (size_t j = 0; j < item_num; ++j) {
			if (i == j)
				continue;
			if (pitem[i].tid == pitem[j].tid) {
				pitem[j].exectime = 0;
				break;
			}
		}
	}
	auto temp_path = g_list_path + ".tmp";
	auto temp_fd = open(temp_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, DEF_MODE);
	if (temp_fd >= 0) {
		for (size_t i = 0; i < item_num; ++i) {
			if (pitem[i].exectime == 0)
				continue;
			char temp_line[2048];
			auto temp_len = gx_snprintf(temp_line, arsizeof(temp_line), "%d\t%ld\t",
				   pitem[i].tid, pitem[i].exectime);
			encode_line(pitem[i].command, temp_line + temp_len);
			temp_len = strlen(temp_line);
			temp_line[temp_len] = '\n';
			++temp_len;
			write(temp_fd, temp_line, temp_len);
		}
		close(temp_fd);
		if (remove(g_list_path.c_str()) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1403: remove %s: %s\n",
			        g_list_path.c_str(), strerror(errno));
		if (rename(temp_path.c_str(), g_list_path.c_str()) < 0)
			fprintf(stderr, "E-1404: rename %s %s: %s\n",
			        temp_path.c_str(), g_list_path.c_str(), strerror(errno));
	}
	last_cltime = cur_time;
	g_list_fd = open(g_list_path.c_str(), O_APPEND | O_WRONLY);
}

static TIMER *put_timer(TIMER &&ptimer)
{
	for (auto pos = g_exec_list.begin(); pos != g_exec_list.end(); ++pos) {
		if (pos->exec_time <= ptimer.exec_time)
			continue;
		std::list<TIMER> stash;
		stash.push_back(std::move(ptimer));
		g_exec_list.splice(pos, stash, stash.begin());
		return &*pos;
	}
	g_exec_list.push_back(std::move(ptimer));
	return &g_exec_list.back();
}

int main(int argc, const char **argv) try
{
	time_t cur_time;
	time_t last_cltime;
	pthread_t thr_accept_id{};
	std::vector<pthread_t> thr_ids;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	startup_banner("gromox-timer");
	if (opt_show_version)
		return EXIT_SUCCESS;
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	auto pconfig = config_file_prg(opt_config_file, "timer.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;

	static constexpr cfg_directive timer_cfg_defaults[] = {
		{"config_file_path", PKGSYSCONFDIR "/timer:" PKGSYSCONFDIR},
		{"timer_listen_ip", "::1"},
		{"timer_listen_port", "6666"},
		{"timer_state_path", PKGSTATEDIR "/timer.txt"},
		{"timer_threads_num", "50", CFG_SIZE, "5", "50"},
		CFG_TABLE_END,
	};
	config_file_apply(*pconfig, timer_cfg_defaults);

	g_list_path = pconfig->get_value("timer_state_path");
	uint16_t listen_port = pconfig->get_ll("timer_listen_port");
	auto listen_ip = pconfig->get_value("timer_listen_ip");
	printf("[system]: listen address is [%s]:%hu\n",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	g_threads_num = pconfig->get_ll("timer_threads_num");
	printf("[system]: processing threads number is %u\n", g_threads_num);
	g_threads_num ++;

	auto sockd = gx_inet_listen(listen_ip, listen_port);
	if (sockd < 0) {
		printf("[system]: failed to create listen socket: %s\n", strerror(-sockd));
		return 4;
	}
	gx_reexec_record(sockd);
	auto cl_0 = make_scope_exit([&]() { close(sockd); });
	auto ret = switch_user_exec(*pconfig, argv);
	if (ret < 0)
		return 4;

	auto pfile = list_file_initd(g_list_path.c_str(), "/", "%d%l%s:512");
	if (NULL == pfile) {
		printf("[system]: Failed to read timers from %s: %s\n",
		       g_list_path.c_str(), strerror(errno));
		return 3;
	}

	auto item_num = pfile->get_size();
	auto pitem = static_cast<srcitem *>(pfile->get_list());
	for (size_t i = 0; i < item_num; ++i) {
		if (pitem[i].exectime != 0)
			continue;
		for (size_t j = 0; j < item_num; ++j) {
			if (i == j)
				continue;
			if (pitem[i].tid == pitem[j].tid) {
				pitem[j].exectime = 0;
				break;
			}
		}
	}

	time(&cur_time);

	for (size_t i = 0; i < item_num; ++i) {
		if (pitem[i].tid > g_last_tid)
			g_last_tid = pitem[i].tid;
		if (pitem[i].exectime == 0)
			continue;
		try {
			TIMER tmr;
			tmr.t_id = pitem[i].tid;
			tmr.exec_time = pitem[i].exectime;
			tmr.command = pitem[i].command;
			put_timer(std::move(tmr));
		} catch (std::bad_alloc &) {
		}
	}
	pfile.reset();

	g_list_fd = open(g_list_path.c_str(), O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
	if (g_list_fd < 0) {
		printf("[system]: Failed to open %s: %s\n", g_list_path.c_str(), strerror(errno));
		return 7;
	}
	auto cl_1 = make_scope_exit([&]() { close(g_list_fd); });

	thr_ids.reserve(g_threads_num);
	auto cl_2 = make_scope_exit([&]() {
		/* thread might be waiting at the condvar */
		g_waken_cond.notify_all();
		for (auto tid : thr_ids) {
			/* thread might be waiting in read_mark/select */
			pthread_kill(tid, SIGALRM);
			pthread_join(tid, nullptr);
		}
	});
	for (unsigned int i = 0; i < g_threads_num; ++i) {
		pthread_t tid;
		ret = pthread_create(&tid, nullptr, tmr_thrwork, nullptr);
		if (ret != 0) {
			printf("[system]: failed to create pool thread: %s\n", strerror(ret));
			g_notify_stop = true;
			return 8;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "worker/%u", i);
		pthread_setname_np(tid, buf);
		thr_ids.push_back(tid);
	}

	ret = list_file_read_fixedstrings("timer_acl.txt",
	           pconfig->get_value("config_file_path"), g_acl_list);
	if (ret == -ENOENT) {
		printf("[system]: defaulting to implicit access ACL containing ::1.\n");
		g_acl_list = {"::1"};
	} else if (ret < 0) {
		printf("[system]: list_file_initd timer_acl.txt: %s\n", strerror(-ret));
		g_notify_stop = true;
		return 9;
	}
	
	ret = pthread_create(&thr_accept_id, nullptr, tmr_acceptwork,
	      reinterpret_cast<void *>(static_cast<intptr_t>(sockd)));
	if (ret != 0) {
		printf("[system]: failed to create accept thread: %s\n", strerror(ret));
		g_notify_stop = true;
		return 10;
	}
	auto cl_3 = make_scope_exit([&]() {
		pthread_kill(thr_accept_id, SIGALRM); /* kick accept() */
		pthread_join(thr_accept_id, nullptr);
	});
	
	pthread_setname_np(thr_accept_id, "accept");
	time(&last_cltime);
	sact.sa_handler = [](int) {};
	sact.sa_flags   = 0;
	sigaction(SIGALRM, &sact, nullptr);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	printf("[system]: TIMER is now running\n");

	while (!g_notify_stop) {
		std::unique_lock li_hold(g_list_lock);
		time(&cur_time);
		for (auto ptimer = g_exec_list.begin(); ptimer != g_exec_list.end(); ) {
			if (ptimer->exec_time > cur_time)
				break;
			std::list<TIMER> stash;
			stash.splice(stash.end(), g_exec_list, ptimer++);
			execute_timer(&stash.front());
		}

		if (cur_time - last_cltime > 7 * 86400)
			save_timers(last_cltime, cur_time);
		li_hold.unlock();
		sleep(1);

	}
	return 0;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}

static void *tmr_acceptwork(void *param)
{
	int sockd, sockd2;
	socklen_t addrlen;
	char client_hostip[40];
	struct sockaddr_storage peer_name;

	sockd = (int)(long)param;
	while (!g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd2 = accept(sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (sockd2 < 0)
			continue;
		CONNECTION_NODE conn;
		conn.sockd = sockd2;
		int ret = getnameinfo(reinterpret_cast<sockaddr *>(&peer_name),
		          addrlen, client_hostip, sizeof(client_hostip),
		          nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			continue;
		}
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    client_hostip) == g_acl_list.cend()) {
			write(sockd2, "Access Deny\r\n", 13);
			continue;
		}

		std::unique_lock co_hold(g_connection_lock);
		if (g_connection_list.size() + 1 + g_connection_list1.size() >= g_threads_num) {
			co_hold.unlock();
			write(sockd2, "Maximum Connection Reached!\r\n", 29);
			continue;
		}

		try {
			g_connection_list1.push_back(std::move(conn));
		} catch (const std::bad_alloc &) {
			write(sockd2, "Not enough memory\r\n", 19);
			continue;
		}
		co_hold.unlock();
		write(sockd2, "OK\r\n", 4);
		g_waken_cond.notify_one();
	}
	return nullptr;
}

static void execute_timer(TIMER *ptimer)
{
	int len;
	int status;
	pid_t pid;
	char result[1024];
	char temp_buff[2048];
	char* argv[MAXARGS];

	int argc = parse_line(temp_buff, ptimer->command.c_str(), argv);
	if (argc > 0) {
		pid = fork();
		if (0 == pid) {
			chdir("../tools");
			execve(argv[0], argv, NULL);
			_exit(-1);
		} else if (pid > 0) {
			if (waitpid(pid, &status, 0) > 0) {
				strcpy(result, WIFEXITED(status) && !WEXITSTATUS(status) ? "DONE" : "EXEC-FAILURE");
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

static void *tmr_thrwork(void *param)
{
	int temp_len;
	char *pspace, temp_line[1024];
	
 NEXT_LOOP:
	if (g_notify_stop)
		return nullptr;
	std::unique_lock cm_hold(g_cond_mutex);
	g_waken_cond.wait(cm_hold);
	cm_hold.unlock();
	if (g_notify_stop)
		return nullptr;
	std::unique_lock co_hold(g_connection_lock);
	if (g_connection_list1.size() == 0)
		goto NEXT_LOOP;
	g_connection_list.splice(g_connection_list.end(), g_connection_list1, g_connection_list1.begin());
	auto pconnection = std::prev(g_connection_list.end());
	co_hold.unlock();

	while (true) {
		if (!read_mark(&*pconnection)) {
			co_hold.lock();
			g_connection_list.erase(pconnection);
			co_hold.unlock();
			goto NEXT_LOOP;
		}

		if (0 == strncasecmp(pconnection->line, "CANCEL ", 7)) {
			int t_id = strtol(pconnection->line + 7, nullptr, 0);
			if (t_id <= 0) {
				write(pconnection->sockd, "FALSE 1\r\n", 9);	
				continue;
			}
			bool removed_timer = false;
			std::unique_lock li_hold(g_list_lock);
			for (auto pos = g_exec_list.begin(); pos != g_exec_list.end(); ++pos) {
				auto ptimer = &*pos;
				if (t_id == ptimer->t_id) {
					temp_len = sprintf(temp_line, "%d\t0\tCANCEL\n",
								ptimer->t_id);
					g_exec_list.erase(pos);
					removed_timer = true;
					write(g_list_fd, temp_line, temp_len);
					break;
				}
			}
			li_hold.unlock();
			if (removed_timer)
				write(pconnection->sockd, "TRUE\r\n", 6);
			else
				write(pconnection->sockd, "FALSE 2\r\n", 9);
		} else if (0 == strncasecmp(pconnection->line, "ADD ", 4)) {
			pspace = strchr(pconnection->line + 4, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE 1\r\n", 9);
				continue;
			}
			*pspace = '\0';
			pspace ++;

			int exec_interval = strtol(pconnection->line + 4, nullptr, 0);
			if (exec_interval <= 0 || strlen(pspace) >= COMMAND_LENGTH) {
				write(pconnection->sockd, "FALSE 2\r\n", 9);
				continue;
			}

			TIMER tmr;
			tmr.t_id = increase_tid();
			tmr.exec_time = exec_interval + time(nullptr);
			try {
				tmr.command = pspace;
			} catch (const std::bad_alloc &) {
				write(pconnection->sockd, "FALSE 3\r\n", 9);
				continue;
			}

			std::unique_lock li_hold(g_list_lock);
			auto ptimer = put_timer(std::move(tmr));

			temp_len = sprintf(temp_line, "%d\t%lld\t", ptimer->t_id,
			           static_cast<long long>(ptimer->exec_time));
			encode_line(ptimer->command.c_str(), temp_line + temp_len);
			temp_len = strlen(temp_line);
			temp_line[temp_len] = '\n';
			temp_len ++;
			write(g_list_fd, temp_line, temp_len);
			li_hold.unlock();
			temp_len = sprintf(temp_line, "TRUE %d\r\n", ptimer->t_id);
			write(pconnection->sockd, temp_line, temp_len);
		} else if (0 == strcasecmp(pconnection->line, "QUIT")) {
			write(pconnection->sockd, "BYE\r\n", 5);
			close(pconnection->sockd);
			co_hold.lock();
			g_connection_list.erase(pconnection);
			co_hold.unlock();
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

	while (true) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pconnection->sockd, &myset);
		if (select(pconnection->sockd + 1, &myset, nullptr, nullptr, &tv) <= 0)
			return FALSE;
		read_len = read(pconnection->sockd, pconnection->buffer +
		pconnection->offset, 1024 - pconnection->offset);
		if (read_len <= 0)
			return FALSE;
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
		if (pconnection->offset == 1024)
			return FALSE;
	}
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}

static int parse_line(char *pbuff, const char* cmdline, char** argv)
{
	int string_len;
    char *ptr;                   /* ptr that traverses command line  */
    int argc;                    /* number of args */
	char *last_space;
	char *last_quote = nullptr;

	string_len = strlen(cmdline);
	memcpy(pbuff, cmdline, string_len);
	pbuff[string_len] = ' ';
	string_len ++;
	pbuff[string_len] = '\0';
	ptr = pbuff;
    /* Build the argv list */
    argc = 0;
	last_space = pbuff;
    while (*ptr != '\0') {
		/* back slash should be treated as transferred meaning */
		if ((*ptr == '\\' && ptr[1] == '\"') ||
		    (*ptr == '\\' && ptr[1] == '\\')) {
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
					if (argc >= MAXARGS)
						return 0;
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
				if (argc >= MAXARGS)
					return 0;
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

	std::lock_guard lk(g_tid_lock);
	g_last_tid ++;
	val = g_last_tid;
	return val;
}

