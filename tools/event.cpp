// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <list>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/defs.h>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/double_list.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/single_list.hpp>
#include <gromox/socket.h>
#include <gromox/util.hpp>

#define SELECT_INTERVAL			24*60*60

#define HOST_INTERVAL			20*60

#define SCAN_INTERVAL			10*60

#define FIFO_AVERAGE_LENGTH		128

#define MAX_CMD_LENGTH			64*1024

#define HASH_CAPABILITY			10000

using namespace gromox;

namespace {

struct fifo_block {
	SINGLE_LIST_NODE list_node;
	MEM_FILE mem_file;
};

struct FIFO {
	FIFO() = default;
	FIFO(alloc_limiter<fifo_block> *, size_t data_size, size_t max_size);
	BOOL enqueue(const MEM_FILE &);
	MEM_FILE *get_front();
	void dequeue();

	alloc_limiter<fifo_block> *mbuf_pool = nullptr;
	SINGLE_LIST mlist{};
	size_t data_size = 0, cur_size = 0, max_size = 0;
};

struct qsock {
	int sockd = -1;
	ssize_t sk_write(const char *, size_t = -1);
	void sk_close();
};

struct ENQUEUE_NODE : public qsock {
	~ENQUEUE_NODE() { sk_close(); }

	int offset = 0;
	char res_id[128]{};
	char buffer[MAX_CMD_LENGTH]{};
	char line[MAX_CMD_LENGTH]{};
};

struct DEQUEUE_NODE : public qsock {
	~DEQUEUE_NODE();

	char res_id[128]{};
	FIFO fifo{};
	std::mutex lock, cond_mutex;
	std::condition_variable waken_cond;
};

struct HOST_NODE {
	DOUBLE_LIST_NODE node{};
	char res_id[128]{};
	time_t last_time = 0;
	std::unordered_map<std::string, time_t> hash;
	std::vector<std::shared_ptr<DEQUEUE_NODE>> list;
};

}

static gromox::atomic_bool g_notify_stop;
static unsigned int g_threads_num;
static alloc_limiter<fifo_block> g_fifo_alloc{"g_fifo_alloc.d"};
static alloc_limiter<file_block> g_file_alloc{"g_file_alloc.d"};
static std::vector<std::string> g_acl_list;
static std::list<ENQUEUE_NODE> g_enqueue_list, g_enqueue_list1;
static std::vector<std::shared_ptr<DEQUEUE_NODE>> g_dequeue_list1;
static std::list<HOST_NODE> g_host_list;
static std::mutex g_enqueue_lock, g_dequeue_lock, g_host_lock;
static std::mutex g_enqueue_cond_mutex, g_dequeue_cond_mutex;
static std::condition_variable g_enqueue_waken_cond, g_dequeue_waken_cond;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr cfg_directive event_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR "/event:" PKGSYSCONFDIR},
	{"event_listen_ip", "::1"},
	{"event_listen_port", "33333"},
	{"event_log_file", "-"},
	{"event_log_level", "4" /* LV_NOTICE */},
	{"event_threads_num", "50", CFG_SIZE, "1", "1000"},
	CFG_TABLE_END,
};

static void *ev_acceptwork(void *);
static void *ev_enqwork(void *);
static void *ev_deqwork(void *);
static void *ev_scanwork(void *);
static BOOL read_response(int sockd);

static BOOL read_mark(ENQUEUE_NODE *penqueue);

static void term_handler(int signo);

/**
 * A FIFO implemented using a singly-linked list. The core is maintained
 * outside the FIFO, but the FIFO will give back a node-sized memory every time
 * you call deque, unless the FIFO is empty.
 */
FIFO::FIFO(alloc_limiter<fifo_block> *pbuf_pool, size_t ds, size_t ms) :
	mbuf_pool(pbuf_pool), data_size(ds), max_size(ms)
{
	if (pbuf_pool == nullptr)
		throw std::invalid_argument("FIFO with no LIB_BUFFER");
	single_list_init(&mlist);
}

/* Returns TRUE on success, or FALSE if the FIFO is full. */
BOOL FIFO::enqueue(const MEM_FILE &mf)
{
#ifdef _DEBUG_UMTA
	if (pdata == nullptr)
		debug_info("[fifo]: fifo_enqueue, param nullptr");
#endif
	if (cur_size >= max_size)
		return false;
	auto blk = mbuf_pool->get();
	if (blk == nullptr)
		return false;
	blk->mem_file = mf;
	auto node = &blk->list_node;
	node->pdata = &blk->mem_file;
	single_list_append_as_tail(&mlist, node);
	++cur_size;
	return TRUE;
}

/**
 * Dequeues the top item from the specified FIFO, and gives back the data size
 * of memory to the outside allocator
 */
void FIFO::dequeue()
{
	if (cur_size <= 0)
		return;
	auto node = single_list_pop_front(&mlist);
	mbuf_pool->put(containerof(node, fifo_block, list_node));
	--cur_size;
}

/**
 * Returns a pointer to the data at the front of the specified FIFO, or nullptr
 * if the FIFO is empty.
 */
MEM_FILE *FIFO::get_front()
{
	if (cur_size <= 0)
		return nullptr;
	auto node = single_list_get_head(&mlist);
	return node != nullptr ? static_cast<MEM_FILE *>(node->pdata) : nullptr;
}

DEQUEUE_NODE::~DEQUEUE_NODE()
{
	if (sockd >= 0)
		close(sockd);
}

ssize_t qsock::sk_write(const char *s, size_t z)
{
	if (z == static_cast<size_t>(-1))
		z = strlen(s);
	auto ret = HXio_fullwrite(sockd, s, z);
	if (ret < 0 || static_cast<size_t>(ret) != z) {
		close(sockd);
		sockd = -1;
	}
	return ret;
}

void qsock::sk_close()
{
	if (sockd < 0)
		return;
	close(sockd);
	sockd = -1;
}

int main(int argc, const char **argv) try
{
	pthread_attr_t thr_attr;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	startup_banner("gromox-event");
	if (opt_show_version)
		return EXIT_SUCCESS;
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	auto pconfig = config_file_prg(opt_config_file, "event.cfg",
	               event_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;

	mlog_init(pconfig->get_value("event_log_file"), pconfig->get_ll("event_log_level"));
	auto listen_ip = pconfig->get_value("event_listen_ip");
	uint16_t listen_port = pconfig->get_ll("event_listen_port");
	printf("[system]: listen address is [%s]:%hu\n",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	g_threads_num = pconfig->get_ll("event_threads_num");
	printf("[system]: threads number is 2*%d\n", g_threads_num);

	auto sockd = gx_inet_listen(listen_ip, listen_port);
	if (sockd < 0) {
		printf("[system]: failed to create listen socket: %s\n", strerror(-sockd));
		return 5;
	}
	gx_reexec_record(sockd);
	auto cl_2 = make_scope_exit([&]() { close(sockd); });
	if (switch_user_exec(*pconfig, argv) != 0)
		return 7;
	
	g_threads_num ++;
	g_fifo_alloc = alloc_limiter<fifo_block>(g_threads_num * FIFO_AVERAGE_LENGTH,
	               "fifo_alloc", "event.cfg:threads_num");
	g_file_alloc = alloc_limiter<file_block>(g_threads_num * FIFO_AVERAGE_LENGTH,
	               "file_alloc", "event.cfg:threads_num");
	g_dequeue_list1.reserve(g_threads_num);
	pthread_attr_init(&thr_attr);
	auto cl_3 = make_scope_exit([&]() { pthread_attr_destroy(&thr_attr); });
	auto ret = pthread_attr_setstacksize(&thr_attr, 1U << 20);
	if (ret != 0) {
		fprintf(stderr, "pthread_attr_setstacksize: %s\n", strerror(ret));
		return 7;
	}
	
	std::vector<pthread_t> tidlist;
	tidlist.reserve(g_threads_num * 2);
	auto cl_4 = make_scope_exit([&]() {
		g_enqueue_waken_cond.notify_all();
		g_dequeue_waken_cond.notify_all();
		for (auto tid : tidlist) {
			pthread_kill(tid, SIGALRM);
			pthread_join(tid, nullptr);
		}
	});
	for (unsigned int i = 0; i < g_threads_num; ++i) {
		pthread_t tid;
		ret = pthread_create(&tid, &thr_attr, ev_enqwork, nullptr);
		if (ret != 0) {
			g_notify_stop = true;
			printf("[system]: failed to create enqueue pool thread: %s\n", strerror(ret));
			return 9;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "enqueue/%u", i);
		pthread_setname_np(tid, buf);
		tidlist.push_back(tid);

		ret = pthread_create(&tid, &thr_attr, ev_deqwork, nullptr);
		if (ret != 0) {
			g_notify_stop = true;
			printf("[system]: failed to create dequeue pool thread: %s\n", strerror(ret));
			return 9;
		}
		snprintf(buf, sizeof(buf), "dequeue/%u", i);
		pthread_setname_np(tid, buf);
		tidlist.push_back(tid);
	}

	auto err = list_file_read_fixedstrings("event_acl.txt",
	           pconfig->get_value("config_file_path"), g_acl_list);
	if (err == ENOENT) {
		printf("[system]: defaulting to implicit access ACL containing ::1.\n");
		g_acl_list = {"::1"};
	} else if (err != 0) {
		printf("[system]: list_file_initd event_acl.txt: %s\n", strerror(err));
		g_notify_stop = true;
		return 10;
	}

	pthread_t acc_thr{}, scan_thr{};
	ret = pthread_create(&acc_thr, nullptr, ev_acceptwork,
	      reinterpret_cast<void *>(static_cast<intptr_t>(sockd)));
	if (ret != 0) {
		printf("[system]: failed to create accept thread: %s\n", strerror(ret));
		g_notify_stop = true;
		return 11;
	}
	auto cl_5 = make_scope_exit([&]() {
		pthread_kill(acc_thr, SIGALRM); /* kick accept() */
		pthread_join(acc_thr, nullptr);
	});
	pthread_setname_np(acc_thr, "accept");
	ret = pthread_create(&scan_thr, nullptr, ev_scanwork, nullptr);
	if (ret != 0) {
		printf("[system]: failed to create scanning thread: %s\n", strerror(ret));
		g_notify_stop = true;
		return 11;
	}
	auto cl_6 = make_scope_exit([&]() {
		pthread_kill(scan_thr, SIGALRM); /* kick sleep() */
		pthread_join(scan_thr, nullptr);
	});
	pthread_setname_np(scan_thr, "scan");
	setup_sigalrm();
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	printf("[system]: EVENT is now running\n");
	while (!g_notify_stop) {
		sleep(1);
	}
	return 0;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}

static void *ev_scanwork(void *param)
{
	int i = 0;
	time_t cur_time;
	
	while (!g_notify_stop) {
		if (i < SCAN_INTERVAL) {
			sleep(1);
			i ++;
			continue;
		}
		i = 0;
		std::unique_lock hl_hold(g_host_lock);
		time(&cur_time);
		auto ptail = g_host_list.size() > 0 ? &g_host_list.back() : nullptr;
		while (g_host_list.size() > 0) {
			std::list<HOST_NODE> tmp_list;
			auto phost = &g_host_list.front();
			tmp_list.splice(tmp_list.end(), g_host_list, g_host_list.begin());
			if (phost->list.size() == 0 &&
				cur_time - phost->last_time > HOST_INTERVAL) {
			} else {
				for (auto it = phost->hash.begin(); it != phost->hash.end(); ) {
					if (cur_time - it->second > SELECT_INTERVAL)
						it = phost->hash.erase(it);
					else
						++it;
				}
				g_host_list.splice(g_host_list.end(), tmp_list);
			}
			if (phost == ptail)
				break;
		}
		hl_hold.unlock();
	}
	return NULL;
}

static void *ev_acceptwork(void *param)
{
	socklen_t addrlen;
	int sockd, sockd2;
	char client_hostip[40];
	struct sockaddr_storage peer_name;
	ENQUEUE_NODE *penqueue;

	sockd = (int)(long)param;
	while (!g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd2 = accept(sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (sockd2 < 0)
			continue;
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
			if (HXio_fullwrite(sockd2, "FALSE Access Deny\r\n", 19) != 19)
				/* ignore */;
			close(sockd2);
			continue;
		}

		std::unique_lock eq_hold(g_enqueue_lock);
		if (g_enqueue_list.size() + 1 + g_enqueue_list1.size() >= g_threads_num) {
			eq_hold.unlock();
			if (HXio_fullwrite(sockd2, "FALSE Maximum Connection Reached!\r\n", 35) != 35)
				/* ignore */;
			close(sockd2);
			continue;
		}
		try {
			g_enqueue_list1.emplace_back();
			penqueue = &g_enqueue_list1.back();
		} catch (const std::bad_alloc &) {
			eq_hold.unlock();
			if (HXio_fullwrite(sockd2, "FALSE Not enough memory\r\n", 25) != 25)
				/* ignore */;
			close(sockd2);
			continue;
		}

		penqueue->sockd = sockd2;
		eq_hold.unlock();
		if (HXio_fullwrite(sockd2, "OK\r\n", 4) != 4) {
			close(penqueue->sockd);
			penqueue->sockd = -1;
		}
		g_enqueue_waken_cond.notify_one();
	}
	return nullptr;
}

static void *ev_enqwork(void *param)
{
	int temp_len;
	char *pspace;
	char *pspace1;
	char *pspace2;
	BOOL b_result;
	time_t cur_time;
	MEM_FILE temp_file;
	char temp_string[256];
	
 NEXT_LOOP:
	if (g_notify_stop)
		return nullptr;
	std::unique_lock cm_hold(g_enqueue_cond_mutex);
	g_enqueue_waken_cond.wait(cm_hold);
	cm_hold.unlock();
	if (g_notify_stop)
		return nullptr;
	std::unique_lock eq_hold(g_enqueue_lock);
	if (g_enqueue_list1.size() == 0)
		goto NEXT_LOOP;
	auto eq_node = g_enqueue_list1.begin();
	auto penqueue = &*eq_node;
	g_enqueue_list.splice(g_enqueue_list.end(), g_enqueue_list1, eq_node);
	eq_hold.unlock();
	
	while (true) {
		if (!read_mark(penqueue)) {
			eq_hold.lock();
			g_enqueue_list.erase(eq_node);
			goto NEXT_LOOP;
		}
		
		if (0 == strncasecmp(penqueue->line, "ID ", 3)) {
			snprintf(penqueue->res_id, arsizeof(penqueue->res_id), "%s", penqueue->line + 3);
			penqueue->sk_write("TRUE\r\n");
			continue;
		} else if (0 == strncasecmp(penqueue->line, "LISTEN ", 7)) {
			HOST_NODE *phost = nullptr;
			std::shared_ptr<DEQUEUE_NODE> pdequeue;
			try {
				pdequeue = std::make_shared<DEQUEUE_NODE>();
			} catch (const std::bad_alloc &) {
				penqueue->sk_write("FALSE\r\n");
				continue;
			}
			snprintf(pdequeue->res_id, arsizeof(pdequeue->res_id), "%s", penqueue->line + 7);
			pdequeue->fifo = FIFO(&g_fifo_alloc, sizeof(MEM_FILE), FIFO_AVERAGE_LENGTH);
			std::unique_lock hl_hold(g_host_lock);
			auto host_it = std::find_if(g_host_list.begin(), g_host_list.end(),
			               [&](const HOST_NODE &h) { return strcmp(h.res_id, penqueue->line + 7) == 0; });
			if (host_it == g_host_list.end()) {
				try {
					g_host_list.emplace_back();
					phost = &g_host_list.back();
				} catch (const std::bad_alloc &) {
					hl_hold.unlock();
					penqueue->sk_write("FALSE\r\n");
					continue;
				}
				gx_strlcpy(phost->res_id, penqueue->line + 7, arsizeof(phost->res_id));
			} else {
				phost = &*host_it;
			}
			time(&phost->last_time);
			try {
				phost->list.push_back(pdequeue);
			} catch (const std::bad_alloc &) {
				pdequeue->sk_write("FALSE\r\n");
				continue;
			}
			try {
				std::lock_guard dq_hold(g_dequeue_lock);
				g_dequeue_list1.push_back(pdequeue);
			} catch (const std::bad_alloc &) {
				phost->list.pop_back();
				pdequeue->sk_write("FALSE\r\n");
				continue;
			}
			pdequeue->sockd = penqueue->sockd;
			penqueue->sockd = -1;
			hl_hold.unlock();
			pdequeue->sk_write("TRUE\r\n");
			g_dequeue_waken_cond.notify_one();
			eq_hold.lock();
			g_enqueue_list.erase(eq_node);
			goto NEXT_LOOP;
		} else if (0 == strncasecmp(penqueue->line, "SELECT ", 7)) {
			pspace = strchr(penqueue->line + 7, ' ');
			temp_len = pspace - (penqueue->line + 7);
			if (NULL == pspace ||  temp_len > 127 || strlen(pspace + 1) > 63) {
				penqueue->sk_write("FALSE\r\n");
				continue;
			}
			memcpy(temp_string, penqueue->line + 7, temp_len);
			temp_string[temp_len] = ':';
			temp_len ++;
			temp_string[temp_len] = '\0';
			HX_strlower(temp_string);
			strcat(temp_string, pspace + 1);
			
			b_result = FALSE;
			std::unique_lock hl_hold(g_host_lock);
			for (auto &hnode : g_host_list) {
				auto phost = &hnode;
				if (0 == strcmp(penqueue->res_id, phost->res_id)) {
					time(&cur_time);
					auto time_it = phost->hash.find(temp_string);
					if (time_it != phost->hash.end()) {
						time_it->second = cur_time;
					} else try {
						phost->hash.emplace(temp_string, cur_time);
					} catch (const std::bad_alloc &) {
					}
					b_result = TRUE;
					break;
				}
			}
			hl_hold.unlock();
			penqueue->sk_write(b_result ? "TRUE\r\n" : "FALSE\r\n");
			continue;
		} else if (0 == strncasecmp(penqueue->line, "UNSELECT ", 9)) {
			pspace = strchr(penqueue->line + 9, ' ');
			temp_len = pspace - (penqueue->line + 9);
			if (NULL == pspace ||  temp_len > 127 || strlen(pspace + 1) > 63) {
				penqueue->sk_write("FALSE\r\n");
				continue;
			}
			memcpy(temp_string, penqueue->line + 9, temp_len);
			temp_string[temp_len] = ':';
			temp_len ++;
			temp_string[temp_len] = '\0';
			HX_strlower(temp_string);
			strcat(temp_string, pspace + 1);
			
			std::unique_lock hl_hold(g_host_lock);
			auto phost = std::find_if(g_host_list.begin(), g_host_list.end(),
			             [&](const HOST_NODE &h) { return strcmp(penqueue->res_id, h.res_id) == 0; });
			if (phost != g_host_list.end())
				phost->hash.erase(temp_string);
			hl_hold.unlock();
			penqueue->sk_write("TRUE\r\n");
			continue;
		} else if (0 == strcasecmp(penqueue->line, "QUIT")) {
			penqueue->sk_write("BYE\r\n");
			eq_hold.lock();
			g_enqueue_list.erase(eq_node);
			goto NEXT_LOOP;
		} else if (0 == strcasecmp(penqueue->line, "PING")) {
			penqueue->sk_write("TRUE\r\n");
			continue;
		} else {
			pspace = strchr(penqueue->line, ' ');
			if (NULL == pspace) {
				penqueue->sk_write("FALSE\r\n");
				continue;
			}
			pspace1 = strchr(pspace + 1, ' ');
			if (NULL == pspace1) {
				penqueue->sk_write("FALSE\r\n");
				continue;
			}
			pspace2 = strchr(pspace1 + 1, ' ');
			if (pspace2 == nullptr)
				pspace2 = penqueue->line + strlen(penqueue->line);
			if (pspace1 - pspace > 128 || pspace2 - pspace1 > 64) {
				penqueue->sk_write("FALSE\r\n");
				continue;
			}
			temp_len = pspace1 - (pspace + 1);
			memcpy(temp_string, pspace + 1, temp_len);
			temp_string[temp_len] = ':';
			temp_len ++;
			temp_string[temp_len] = '\0';
			HX_strlower(temp_string);
			memcpy(temp_string + temp_len, pspace1 + 1, pspace2 - pspace1 - 1);
			temp_string[temp_len + (pspace2 - pspace1 - 1)] = '\0';

			std::unique_lock hl_hold(g_host_lock);
			for (auto &hnode : g_host_list) {
				auto phost = &hnode;
				if (0 == strcmp(penqueue->res_id, phost->res_id) ||
				    phost->hash.find(temp_string) == phost->hash.cend())
					continue;
				
				if (phost->list.size() > 0) {
					auto pdequeue = phost->list.front();
					phost->list.erase(phost->list.begin());
					mem_file_init(&temp_file, &g_file_alloc);
					temp_file.write(penqueue->line, strlen(penqueue->line));
					std::unique_lock dl_hold(pdequeue->lock);
					b_result = pdequeue->fifo.enqueue(temp_file);
					dl_hold.unlock();
					if (!b_result)
						mem_file_free(&temp_file);
					else
						pdequeue->waken_cond.notify_one();
					phost->list.push_back(pdequeue);
				}
			}
			hl_hold.unlock();
			penqueue->sk_write("TRUE\r\n");
			continue;
		}
	}
	return NULL;
}

static void *ev_deqwork(void *param)
{
	time_t cur_time;
	time_t last_time;
	MEM_FILE temp_file;
	char buff[MAX_CMD_LENGTH];
	
 NEXT_LOOP:
	std::unique_lock dc_hold(g_dequeue_cond_mutex);
	g_dequeue_waken_cond.wait(dc_hold);
	dc_hold.unlock();
	if (g_notify_stop)
		return nullptr;
	std::unique_lock dq_hold(g_dequeue_lock);
	if (g_dequeue_list1.size() == 0)
		goto NEXT_LOOP;
	auto pdequeue = g_dequeue_list1.front();
	g_dequeue_list1.erase(g_dequeue_list1.begin());
	dq_hold.unlock();
	
	time(&last_time);
	std::unique_lock hl_hold(g_host_lock);
	auto phost = std::find_if(g_host_list.begin(), g_host_list.end(),
	             [&](const HOST_NODE &h) { return strcmp(h.res_id, pdequeue->res_id) == 0; });
	if (phost == g_host_list.end())
		goto NEXT_LOOP;
	hl_hold.unlock();
	
	while (!g_notify_stop) {
		dc_hold.lock();
		pdequeue->waken_cond.wait_for(dc_hold, std::chrono::seconds(1));
		dc_hold.unlock();
		if (g_notify_stop)
			break;
		dq_hold.lock();
		auto pfile = pdequeue->fifo.get_front();
		if (NULL != pfile) {
			temp_file = *pfile;
			pdequeue->fifo.dequeue();
		}
		dq_hold.unlock();
		time(&cur_time);
		
		if (NULL == pfile) {	
			if (cur_time - last_time >= SOCKET_TIMEOUT - 3) {
				if (pdequeue->sk_write("PING\r\n") != 6 ||
				    !read_response(pdequeue->sockd)) {
					hl_hold.lock();
					auto it = std::find(phost->list.begin(), phost->list.end(), pdequeue);
					if (it != phost->list.end())
						phost->list.erase(it);
					hl_hold.unlock();
					close(pdequeue->sockd);
					pdequeue->sockd = -1;
					while ((pfile = pdequeue->fifo.get_front()) != nullptr) {
						mem_file_free(pfile);
						pdequeue->fifo.dequeue();
					}
					goto NEXT_LOOP;
				}
				last_time = cur_time;
				hl_hold.lock();
				phost->last_time = cur_time;
				hl_hold.unlock();
			}
			continue;
		}
		
		int len = temp_file.read(buff, arsizeof(buff) - 2);
		buff[len] = '\r';
		len ++;
		buff[len] = '\n';
		len ++;
		mem_file_free(&temp_file);
		if (pdequeue->sk_write(buff, len) != len ||
		    !read_response(pdequeue->sockd)) {
			hl_hold.lock();
			auto it = std::find(phost->list.begin(), phost->list.end(), pdequeue);
			if (it != phost->list.end())
				phost->list.erase(it);
			hl_hold.unlock();
			close(pdequeue->sockd);
			pdequeue->sockd = -1;
			while ((pfile = pdequeue->fifo.get_front()) != nullptr) {
				mem_file_free(pfile);
				pdequeue->fifo.dequeue();
			}
			goto NEXT_LOOP;
		}
		
		last_time = cur_time;
		hl_hold.lock();
		phost->last_time = cur_time;
		hl_hold.unlock();
	}	
	return NULL;
}

static BOOL read_response(int sockd)
{
	fd_set myset;
	int offset;
	int read_len;
	char buff[1024];
	struct timeval tv;

	offset = 0;
	while (true) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, nullptr, nullptr, &tv) <= 0)
			return FALSE;
		read_len = read(sockd, buff + offset, 1024 - offset);
		if (read_len <= 0)
			return FALSE;
		offset += read_len;
		if (offset == 6)
			return strncasecmp(buff, "TRUE\r\n", 6) == 0 ? TRUE : false;
		if (offset > 6)
			return FALSE;
	}
}

static BOOL read_mark(ENQUEUE_NODE *penqueue)
{
	fd_set myset;
	int i, read_len;
	struct timeval tv;

	while (true) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(penqueue->sockd, &myset);
		if (select(penqueue->sockd + 1, &myset, nullptr, nullptr, &tv) <= 0)
			return FALSE;
		read_len = read(penqueue->sockd, penqueue->buffer +
		penqueue->offset, MAX_CMD_LENGTH - penqueue->offset);
		if (read_len <= 0)
			return FALSE;
		penqueue->offset += read_len;
		for (i=0; i<penqueue->offset-1; i++) {
			if ('\r' == penqueue->buffer[i] &&
				'\n' == penqueue->buffer[i + 1]) {
				memcpy(penqueue->line, penqueue->buffer, i);
				penqueue->line[i] = '\0';
				penqueue->offset -= i + 2;
				memmove(penqueue->buffer, penqueue->buffer + i + 2,
					penqueue->offset);
				return TRUE;
			}
		}
		if (penqueue->offset == MAX_CMD_LENGTH)
			return FALSE;
	}
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}
