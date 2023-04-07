// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#define DECLARE_SVC_API_STATIC
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <list>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/msg_unit.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include <gromox/xarray2.hpp>
#include "midb_agent.hpp"

using namespace gromox;
using AGENT_MITEM = MITEM;

namespace {

struct BACK_SVR;
struct BACK_CONN {
	int sockd = -1;
	time_t last_time = 0;
	BACK_SVR *psvr = nullptr;
};

struct BACK_CONN_floating {
	BACK_CONN_floating() = default;
	BACK_CONN_floating(BACK_CONN_floating &&);
	~BACK_CONN_floating() { reset(true); }
	void operator=(BACK_CONN_floating &&) = delete;
	BACK_CONN *operator->() { return tmplist.size() != 0 ? &tmplist.front() : nullptr; }
	bool operator==(std::nullptr_t) const { return tmplist.size() == 0; }
	bool operator!=(std::nullptr_t) const { return tmplist.size() != 0; }
	void reset(bool lost = false);

	std::list<BACK_CONN> tmplist;
};

struct BACK_SVR {
	std::string prefix;
	char ip_addr[40]{};
	uint16_t port = 0;
	std::list<BACK_CONN> conn_list;
};

}

static void *midbag_scanwork(void *);
static ssize_t read_line(int sockd, char *buff, size_t length);
static int connect_midb(const char *host, uint16_t port);
static BOOL get_digest_string(const char *src, int length, const char *tag, char *buff, int buff_len);
static BOOL get_digest_integer(const char *src, int length, const char *tag, int *pinteger);
static int list_mail(const char *path, const char *folder, std::vector<MSG_UNIT> &, int *num, uint64_t *size);
static int delete_mail(const char *path, const char *folder, const std::vector<MSG_UNIT *> &);
static int get_mail_id(const char *path, const char *folder, const char *mid_string, unsigned int *id);
static int get_mail_uid(const char *path, const char *folder, const char *mid_string, unsigned int *uid);
static int summary_folder(const char *path, const char *folder, int *exists, int *recent, int *unseen, unsigned long *uidvalid, unsigned int *uidnext, int *first_seen, int *perrno);
static int make_folder(const char *path, const char *folder, int *perrno);
static int remove_folder(const char *path, const char *folder, int *perrno);
static int ping_mailbox(const char *path, int *perrno);
static int rename_folder(const char *path, const char *src_name, const char *dst_name, int *perrno);
static int subscribe_folder(const char *path, const char *folder, int *perrno);
static int unsubscribe_folder(const char *path, const char *folder, int *perrno);
static int enum_folders(const char *path, std::vector<std::string> &, int *perrno);
static int enum_subscriptions(const char *path, std::vector<std::string> &, int *perrno);
static int insert_mail(const char *path, const char *folder, const char *file_name, const char *flags_string, long time_stamp, int *perrno);
static int remove_mail(const char *path, const char *folder, const std::vector<MITEM *> &, int *perrno);
static int list_deleted(const char *path, const char *folder, XARRAY *, int *perrno);
static int fetch_simple(const char *path, const char *folder, const std::vector<seq_node> &, XARRAY *, int *perrno);
static int fetch_detail(const char *path, const char *folder, const std::vector<seq_node> &, XARRAY *, int *perrno);
static int fetch_simple_uid(const char *path, const char *folder, const std::vector<seq_node> &, XARRAY *, int *perrno);
static int fetch_detail_uid(const char *path, const char *folder, const std::vector<seq_node> &, XARRAY *, int *perrno);
static int set_mail_flags(const char *path, const char *folder, const char *mid_string, int flag_bits, int *perrno);
static int unset_mail_flags(const char *path, const char *folder, const char *mid_string, int flag_bits, int *perrno);
static int get_mail_flags(const char *path, const char *folder, const char *mid_string, int *pflag_bits, int *perrno);
static int copy_mail(const char *path, const char *src_folder, const char *mid_string, const char *dst_folder, char *dst_mid, int *perrno);
static int imap_search(const char *path, const char *folder, const char *charset, int argc, char **argv, std::string &ret_buff, int *perrno);
static int imap_search_uid(const char *path, const char *folder, const char *charset, int argc, char **argv, std::string &ret_buff, int *perrno);
static BOOL check_full(const char *path);

static constexpr unsigned int POLLIN_SET =
	POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR | POLLNVAL;
std::atomic<size_t> g_midb_command_buffer_size{256 * 1024};
static int g_conn_num;
static gromox::atomic_bool g_notify_stop;
static pthread_t g_scan_id;
static std::list<BACK_CONN> g_lost_list;
static std::list<BACK_SVR> g_server_list;
static std::mutex g_server_lock;
static alloc_limiter<file_block> g_file_allocator{"midb_agent.g_file_allocator.d"};
static int g_file_ratio;

static constexpr cfg_directive midb_agent_cfg_defaults[] = {
	{"connection_num", "5", CFG_SIZE, "2", "100"},
	{"context_average_mem", "1024", CFG_SIZE},
	{"midb_agent_command_buffer_size", "256K", CFG_SIZE},
	CFG_TABLE_END,
};

static bool list_file_read_midb(const char *filename) try
{
	struct MIDB_ITEM {
		char prefix[256], ip_addr[40];
		int port;
	};
	auto plist = list_file_initd(filename, get_config_path(),
	             /* MIDB_ITEM */ "%s:256%s:40%d");
	if (plist == nullptr) {
		printf("[midb_agent]: list_file_initd %s: %s\n",
		       filename, strerror(errno));
		return false;
	}
	auto list_num = plist->get_size();
	auto pitem = static_cast<MIDB_ITEM *>(plist->get_list());
	if (list_num == 0) {
		auto &svr = g_server_list.emplace_back();
		auto pserver = &svr;
		svr.prefix = "/";
		strcpy(pserver->ip_addr, "::1");
		pserver->port = 5555;
		for (decltype(g_conn_num) j = 0; j < g_conn_num; ++j) {
			g_lost_list.push_back(BACK_CONN{-1, 0, pserver});
		}
		return true;
	}
	for (decltype(list_num) i = 0; i < list_num; ++i) {
		auto &svr = g_server_list.emplace_back();
		auto pserver = &svr;
		svr.prefix = pitem[i].prefix;
		gx_strlcpy(pserver->ip_addr, pitem[i].ip_addr, arsizeof(pserver->ip_addr));
		pserver->port = pitem[i].port;
		for (decltype(g_conn_num) j = 0; j < g_conn_num; ++j) {
			g_lost_list.emplace_back(BACK_CONN{-1, 0, pserver});
		}
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1656: ENOMEM");
	return false;
}

static bool midb_agent_reload(std::shared_ptr<CONFIG_FILE> cfg) try
{
	if (cfg == nullptr)
		cfg = config_file_initd("midb_agent.cfg", get_config_path(), midb_agent_cfg_defaults);
	if (cfg == nullptr) {
		fprintf(stderr, "[midb_agent]: config_file_initd midb_agent.cfg: %s\n", strerror(errno));
		return false;
	}
	g_conn_num = cfg->get_ll("connection_num");
	g_file_ratio = cfg->get_ll("context_average_mem");
	if (g_file_ratio == 0)
		fprintf(stderr, "[midb_agent]: memory pool is switched off through config\n");
	g_midb_command_buffer_size = cfg->get_ll("midb_agent_command_buffer_size");
	return true;
} catch (const cfg_error &) {
	return false;
}

static BOOL svc_midb_agent(int reason, void **ppdata)
{
	switch(reason) {
	case PLUGIN_RELOAD:
		midb_agent_reload(nullptr);
		return TRUE;
	case PLUGIN_INIT: {
		LINK_SVC_API(ppdata);
		g_notify_stop = true;
		auto pconfig = config_file_initd("midb_agent.cfg",
		               get_config_path(), midb_agent_cfg_defaults);
		if (NULL == pconfig) {
			mlog(LV_ERR, "midb_agent: config_file_initd midb_agent.cfg: %s\n",
				strerror(errno));
			return FALSE;
		}
		if (!midb_agent_reload(pconfig))
			return false;
		if (!list_file_read_midb("midb_list.txt"))
			return false;
		if (g_file_ratio > 0) {
			g_file_allocator = alloc_limiter<file_block>(get_context_num() * g_file_ratio,
			                   "midb_agent_file_alloc",
			                   "midb.cfg:context_num,context_average_mem");
		}

		g_notify_stop = false;
		auto ret = pthread_create4(&g_scan_id, nullptr, midbag_scanwork, nullptr);
		if (ret != 0) {
			printf("[midb_agent]: failed to create scan thread: %s\n", strerror(ret));
			return FALSE;
		}
		pthread_setname_np(g_scan_id, "midb_agent");

#define E(f) register_service(#f, f)
		if (!E(list_mail) || !E(delete_mail) || !E(get_mail_id) ||
		    !E(get_mail_uid) || !E(summary_folder) || !E(make_folder) ||
		    !E(remove_folder) || !E(ping_mailbox) ||
		    !E(rename_folder) || !E(subscribe_folder) ||
		    !E(unsubscribe_folder) || !E(enum_folders) ||
		    !E(enum_subscriptions) || !E(insert_mail) ||
		    !E(remove_mail) || !E(list_deleted) ||
		    !E(fetch_simple) || !E(fetch_detail) ||
		    !E(fetch_simple_uid) || !E(fetch_detail_uid) ||
		    !E(set_mail_flags) ||
		    !E(unset_mail_flags) || !E(get_mail_flags) ||
		    !E(copy_mail) || !E(imap_search) || !E(imap_search_uid) ||
		    !E(check_full)) {
			printf("[midb_agent]: failed to register services\n");
			return FALSE;
		}
#undef E
		return TRUE;
	}
	case PLUGIN_FREE:
		if (!g_notify_stop) {
			g_notify_stop = true;
			if (!pthread_equal(g_scan_id, {})) {
				pthread_kill(g_scan_id, SIGALRM);
				pthread_join(g_scan_id, NULL);
			}
		}
		g_lost_list.clear();
		for (auto &srv : g_server_list) {
			for (auto &c : srv.conn_list) {
				auto pback = &c;
				write(pback->sockd, "QUIT\r\n", 6);
				close(pback->sockd);
			}
		}
		g_server_list.clear();
		return TRUE;
	}
	return TRUE;
}
SVC_ENTRY(svc_midb_agent);

static void *midbag_scanwork(void *param)
{
	time_t now_time;
	int tv_msec;
	char temp_buff[1024];
	struct pollfd pfd_read;
	std::list<BACK_CONN> temp_list;

	while (!g_notify_stop) {
		std::unique_lock sv_hold(g_server_lock);
		time(&now_time);
		for (auto &srv : g_server_list) {
			auto tail = srv.conn_list.size() > 0 ? &srv.conn_list.back() : nullptr;
			while (srv.conn_list.size() > 0) {
				auto pback = &srv.conn_list.front();
				if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
					temp_list.splice(temp_list.end(), srv.conn_list, srv.conn_list.begin());
				} else {
					srv.conn_list.splice(srv.conn_list.end(), srv.conn_list, srv.conn_list.begin());
				}
				if (pback == tail)
					break;
			}
		}
		sv_hold.unlock();

		while (temp_list.size() > 0) {
			auto pback = &temp_list.front();
			write(pback->sockd, "PING\r\n", 6);
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec) ||
				read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				sv_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			} else {
				time(&pback->last_time);
				sv_hold.lock();
				pback->psvr->conn_list.splice(pback->psvr->conn_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			}
		}

		sv_hold.lock();
		temp_list = std::move(g_lost_list);
		g_lost_list.clear();
		sv_hold.unlock();

		while (temp_list.size() > 0) {
			auto pback = &temp_list.front();
			pback->sockd = connect_midb(pback->psvr->ip_addr,
							pback->psvr->port);
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				sv_hold.lock();
				pback->psvr->conn_list.splice(pback->psvr->conn_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			} else {
				sv_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			}
		}
		sleep(1);
	}
	return NULL;
}

static BACK_CONN_floating get_connection(const char *prefix)
{
	BACK_CONN_floating fc;
	auto i = std::find_if(g_server_list.begin(), g_server_list.end(),
	         [&](const BACK_SVR &s) { return strncmp(prefix, s.prefix.c_str(), s.prefix.size()) == 0; });
	if (i == g_server_list.end())
		return fc;

	std::unique_lock sv_hold(g_server_lock);
	if (i->conn_list.size() > 0) {
		fc.tmplist.splice(fc.tmplist.end(), i->conn_list, i->conn_list.begin());
		return fc;
	}
	sv_hold.unlock();
	for (size_t j = 0; j < SOCKET_TIMEOUT && !g_notify_stop; ++j) {
		sleep(1);
		sv_hold.lock();
		if (i->conn_list.size() > 0) {
			fc.tmplist.splice(fc.tmplist.end(),
				i->conn_list, i->conn_list.begin());
			return fc;
		}
		sv_hold.unlock();
	}
	return fc;
}

void BACK_CONN_floating::reset(bool lost)
{
	if (tmplist.size() == 0)
		return;
	auto pconn = &tmplist.front();
	if (!lost) {
		std::unique_lock sv_hold(g_server_lock);
		pconn->psvr->conn_list.splice(pconn->psvr->conn_list.end(), tmplist, tmplist.begin());
	} else {
		close(pconn->sockd);
		pconn->sockd = -1;
		std::unique_lock sv_hold(g_server_lock);
		g_lost_list.splice(g_lost_list.end(), tmplist, tmplist.begin());
	}
	tmplist.clear();
}

BACK_CONN_floating::BACK_CONN_floating(BACK_CONN_floating &&o)
{
	reset(true);
	tmplist = std::move(o.tmplist);
}

static int list_mail(const char *path, const char *folder,
    std::vector<MSG_UNIT> &parray, int *pnum, uint64_t *psize)
{
	int i;
	int lines;
	int count;
	int offset;
	BOOL b_fail;
	int last_pos;
	int read_len;
	int line_pos;
	char *pspace;
	int tv_msec;
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto EH = make_scope_exit([&]() { parray.clear(); });
	auto length = gx_snprintf(buff, arsizeof(buff), "M-UIDL %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		return MIDB_RDWR_ERROR;
	}

	*psize = 0;
	count = 0;
	offset = 0;
	lines = -1;
	b_fail = FALSE;
	while (true) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return MIDB_RDWR_ERROR;
		}
		static_assert(std::size(buff) >= 256*1024 + 1);
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			return MIDB_RDWR_ERROR;
		}
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if (buff[i] != '\r' || buff[i+1] != '\n')
					continue;
				if (0 == strncmp(buff, "TRUE ", 5)) {
					lines = strtol(buff + 5, nullptr, 0);
					if (lines < 0) {
						return MIDB_RDWR_ERROR;
					}
					*pnum = lines;
					last_pos = i + 2;
					line_pos = 0;
					break;
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					pback.reset();
					EH.release(); // ?
					return MIDB_RESULT_ERROR;
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					return MIDB_RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
				continue;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				pspace = static_cast<char *>(memchr(temp_line, ' ', line_pos));
				if (NULL == pspace) {
					return MIDB_RDWR_ERROR;
				}
				*pspace = '\0';
				if (strlen(temp_line) > 127) {
					return MIDB_RDWR_ERROR;
				}
				pspace ++;
				temp_line[line_pos] = '\0';
				try {
					MSG_UNIT msg{temp_line};
					msg.size = strtol(pspace, nullptr, 0);
					auto msg_size = msg.size;
					parray.push_back(std::move(msg));
					*psize += msg_size;
				} catch (const std::bad_alloc &) {
					b_fail = TRUE;
				}
				line_pos = 0;
			} else if (buff[i] != '\r' || i != offset - 1) {
				temp_line[line_pos] = buff[i];
				line_pos++;
				if (line_pos >= 256) {
					return MIDB_RDWR_ERROR;
				}
			}
		}

		if (count >= lines) {
			pback.reset();
			if (b_fail)
				return MIDB_RESULT_ERROR;
			EH.release();
			return MIDB_RESULT_OK;
		}
		last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
		if (256*1024 == offset) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}
}

static int rw_command(int fd, char *buff, size_t olen, size_t ilen)
{
	auto ret = write(fd, buff, olen);
	if (ret < 0 || static_cast<size_t>(ret) != olen)
		return MIDB_RDWR_ERROR;
	ret = read_line(fd, buff, ilen);
	if (ret == -ENOBUFS) {
		mlog(LV_ERR, "E-2154: midb response is longer than expected (%zu), rejecting IMAP command. "
		        "Consider raising midb_command_buffer_size or having fewer mails in the folder.",
		        ilen);
		return MIDB_TOO_MANY_RESULTS;
	} else if (ret < 0) {
		return MIDB_RDWR_ERROR;
	}
	return 0;
}

static int delete_mail(const char *path, const char *folder,
    const std::vector<MSG_UNIT *> &plist)
{
	int cmd_len;
	int temp_len;
	char buff[128*1025];

	if (plist.size() == 0)
		return MIDB_RESULT_OK;
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-DELE %s %s", path, folder);
	cmd_len = length;
	
	for (auto pmsg : plist) {
		buff[length] = ' ';
		length ++;
		temp_len = pmsg->file_name.size();
		memcpy(buff + length, pmsg->file_name.c_str(), temp_len);
		length += temp_len;
		if (length <= 128 * 1024)
			continue;
		buff[length] = '\r';
		length ++;
		buff[length] = '\n';
		length ++;
		auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
		if (ret != 0)
			return ret;
		if (0 == strncmp(buff, "TRUE", 4)) {
			length = gx_snprintf(buff, arsizeof(buff), "M-DELE %s %s", path, folder);
			continue;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pback.reset();
			return MIDB_RESULT_ERROR;
		}
		return MIDB_RDWR_ERROR;
	}

	if (length > cmd_len) {
		buff[length] = '\r';
		length ++;
		buff[length] = '\n';
		length ++;
		auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
		if (ret != 0)
			return ret;
		if (0 == strncmp(buff, "TRUE", 4)) {
			pback.reset();
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pback.reset();
			return MIDB_RESULT_ERROR;
		} else {
			return MIDB_RDWR_ERROR;
		}
	}
	return MIDB_RDWR_ERROR;
}

static int imap_search(const char *path, const char *folder,
    const char *charset, int argc, char **argv, std::string &ret_buff,
    int *perrno) try
{
	int i;
	size_t encode_len;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto cbufsize = g_midb_command_buffer_size.load();
	auto buff   = std::make_unique<char[]>(cbufsize);
	auto buff1  = std::make_unique<char[]>(cbufsize);
	auto length = gx_snprintf(buff.get(), cbufsize,
	              "P-SRHL %s %s %s ", path, folder, charset);
	int length1 = 0;
	for (i=0; i<argc; i++) {
		length1 += gx_snprintf(&buff1[length1], cbufsize - length1,
					"%s", argv[i]) + 1;
	}
	buff1[length1] = '\0';
	length1 ++;
	encode64(buff1.get(), length1, &buff[length], cbufsize - length,
		&encode_len);
	length += encode_len;
	buff1.reset();
	
	buff[length] = '\r';
	length ++;
	buff[length] = '\n';
	length ++;
	
	auto ret = rw_command(pback->sockd, buff.get(), length, cbufsize);
	if (ret != 0)
		return ret;
	if (strncmp(buff.get(), "TRUE", 4) == 0) {
		pback.reset();
		length = strlen(&buff[4]);
		if (0 == length) {
			ret_buff.clear();
			return MIDB_RESULT_OK;
		}
		/* trim the first space */
		length--;
		ret_buff.assign(&buff[5], length);
		return MIDB_RESULT_OK;
	} else if (strncmp(buff.get(), "FALSE ", 6) == 0) {
		pback.reset();
		*perrno = strtol(&buff[6], nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
} catch (const std::bad_alloc &) {
	return MIDB_LOCAL_ENOMEM;
}

static int imap_search_uid(const char *path, const char *folder,
   const char *charset, int argc, char **argv, std::string &ret_buff,
   int *perrno) try
{
	int i;
	size_t encode_len;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto cbufsize = g_midb_command_buffer_size.load();
	auto buff   = std::make_unique<char[]>(cbufsize);
	auto buff1  = std::make_unique<char[]>(cbufsize);
	auto length = gx_snprintf(buff.get(), cbufsize,
	              "P-SRHU %s %s %s ", path, folder, charset);
	int length1 = 0;
	for (i=0; i<argc; i++) {
		length1 += gx_snprintf(&buff1[length1], cbufsize - length1,
					"%s", argv[i]) + 1;
	}
	buff1[length1] = '\0';
	length1 ++;
	encode64(buff1.get(), length1, &buff[length], cbufsize - length,
		&encode_len);
	length += encode_len;
	buff1.reset();
	
	buff[length] = '\r';
	length ++;
	buff[length] = '\n';
	length ++;
	
	auto ret = rw_command(pback->sockd, buff.get(), length, cbufsize);
	if (ret != 0)
		return ret;
	if (strncmp(buff.get(), "TRUE", 4) == 0) {
		pback.reset();
		length = strlen(&buff[4]);
		if (0 == length) {
			ret_buff.clear();
			return MIDB_RESULT_OK;
		}
		/* trim the first space */
		length--;
		ret_buff.assign(&buff[5], length);
		return MIDB_RESULT_OK;
	} else if (strncmp(buff.get(), "FALSE ", 6) == 0) {
		pback.reset();
		*perrno = strtol(&buff[6], nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
} catch (const std::bad_alloc &) {
	return MIDB_LOCAL_ENOMEM;
}

static int get_mail_id(const char *path, const char *folder,
    const char *mid_string, unsigned int *pid)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "P-OFST %s %s %s UID ASC\r\n",
				path, folder, mid_string);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		*pid = strtol(buff + 5, nullptr, 0) + 1;
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int get_mail_uid(const char *path, const char *folder,
    const char *mid_string, unsigned int *puid)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "P-UNID %s %s %s\r\n",
				path, folder, mid_string);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		*puid = strtol(buff + 5, nullptr, 0);
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int summary_folder(const char *path, const char *folder, int *pexists,
	int *precent, int *punseen, unsigned long *puidvalid,
	unsigned int *puidnext, int *pfirst_unseen, int *perrno)
{
	char buff[1024];
	int exists, recent;
	int unseen, first_unseen;
	unsigned long uidvalid;
	unsigned int uidnext;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "P-FDDT %s %s UID ASC\r\n", path, folder);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		if (6 != sscanf(buff, "TRUE %d %d %d %lu %u %d", &exists,
		    &recent, &unseen, &uidvalid, &uidnext, &first_unseen)) {
			*perrno = -1;
			pback.reset();
			return MIDB_RESULT_ERROR;
		}
		if (NULL != pexists) {
			*pexists = exists;
		}
		if (NULL != precent) {
			*precent = recent;
		}
		if (NULL != punseen) {
			*punseen = unseen;
		}
		if (NULL != puidvalid) {
			*puidvalid = uidvalid;
		}
		if (NULL != puidnext) {
			*puidnext = uidnext;
		}
		if (NULL != pfirst_unseen) {
			*pfirst_unseen = first_unseen + 1;
		}
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}
	
static int make_folder(const char *path, const char *folder, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-MAKF %s %s\r\n", path, folder);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int remove_folder(const char *path, const char *folder, int *perrno)
{
	char buff[1024];
	
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-REMF %s %s\r\n", path, folder);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int ping_mailbox(const char *path, int *perrno)
{
	char buff[1024];
	
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-PING %s\r\n", path);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int rename_folder(const char *path, const char *src_name,
    const char *dst_name, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-RENF %s %s %s\r\n", path,
				src_name, dst_name);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int subscribe_folder(const char *path, const char *folder, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "P-SUBF %s %s\r\n", path, folder);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int unsubscribe_folder(const char *path, const char *folder, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "P-UNSF %s %s\r\n", path, folder);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int enum_folders(const char *path, std::vector<std::string> &pfile,
    int *perrno) try
{
	int i;
	int lines;
	int count;
	int offset;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-ENUM %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		return MIDB_RDWR_ERROR;
	}
	
	count = 0;
	offset = 0;
	lines = -1;
	while (true) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return MIDB_RDWR_ERROR;
		}
		static_assert(std::size(buff) >= 256*1024 + 1);
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			return MIDB_RDWR_ERROR;
		}
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if (buff[i] != '\r' || buff[i+1] != '\n')
					continue;
				if (0 == strncmp(buff, "TRUE ", 5)) {
					lines = strtol(buff + 5, nullptr, 0);
					if (lines < 0) {
						return MIDB_RDWR_ERROR;
					}
					last_pos = i + 2;
					line_pos = 0;
					break;
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					pback.reset();
					*perrno = strtol(buff + 6, nullptr, 0);
					return MIDB_RESULT_ERROR;
				}
				return MIDB_RDWR_ERROR;
			}
			if (-1 == lines) {
				if (offset > 1024) {
					return MIDB_RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				pfile.emplace_back(temp_line);
				line_pos = 0;
			} else if (buff[i] != '\r' || i != offset - 1) {
				temp_line[line_pos] = buff[i];
				line_pos ++;
				if (line_pos >= 512) {
					return MIDB_RDWR_ERROR;
				}
			}
		}

		if (count >= lines) {
			pback.reset();
			return MIDB_RESULT_OK;
		}
		last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
		if (256*1024 == offset) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}
	return MIDB_RDWR_ERROR;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1812: ENOMEM");
	return MIDB_LOCAL_ENOMEM;
}

static int enum_subscriptions(const char *path, std::vector<std::string> &pfile,
    int *perrno) try
{
	int i;
	int lines;
	int count;
	int offset;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;
	
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "P-SUBL %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		return MIDB_RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	while (true) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return MIDB_RDWR_ERROR;
		}
		static_assert(std::size(buff) >= 256*1024 + 1);
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			return MIDB_RDWR_ERROR;
		}
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if (buff[i] != '\r' || buff[i+1] != '\n')
					continue;
				if (0 == strncmp(buff, "TRUE ", 5)) {
					lines = strtol(buff + 5, nullptr, 0);
					if (lines < 0) {
						return MIDB_RDWR_ERROR;
					}
					last_pos = i + 2;
					line_pos = 0;
					break;
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					pback.reset();
					*perrno = strtol(buff + 6, nullptr, 0);
					return MIDB_RESULT_ERROR;
				}
				return MIDB_RDWR_ERROR;
			}
			if (-1 == lines) {
				if (offset > 1024) {
					return MIDB_RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				pfile.emplace_back(temp_line);
				line_pos = 0;
			} else if (buff[i] != '\r' || i != offset - 1) {
				temp_line[line_pos] = buff[i];
				line_pos ++;
				if (line_pos > 150) {
					return MIDB_RDWR_ERROR;
				}
			}
		}

		if (count >= lines) {
			pback.reset();
			return MIDB_RESULT_OK;
		}
		last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
		if (256*1024 == offset) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}
	return MIDB_RDWR_ERROR;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1815: ENOMEM");
	return MIDB_LOCAL_ENOMEM;
}

static int insert_mail(const char *path, const char *folder,
    const char *file_name, const char *flags_string, long time_stamp,
    int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-INST %s %s %s %s %ld\r\n",
				path, folder, file_name, flags_string, time_stamp);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static int remove_mail(const char *path, const char *folder,
    const std::vector<MITEM *> &plist, int *perrno)
{
	int cmd_len;
	int temp_len;
	char buff[128*1025];

	if (plist.empty())
		return MIDB_RESULT_OK;
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-DELE %s %s", path, folder);
	cmd_len = length;
	
	for (auto pitem : plist) {
		buff[length] = ' ';
		length ++;
		temp_len = strlen(pitem->mid);
		memcpy(buff + length, pitem->mid, temp_len);
		length += temp_len;
		if (length <= 128*1024)
			continue;
		buff[length] = '\r';
		length ++;
		buff[length] = '\n';
		length ++;
		auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
		if (ret != 0)
			return ret;
		if (0 == strncmp(buff, "TRUE", 4)) {
			length = gx_snprintf(buff, arsizeof(buff), "M-DELE %s %s", path, folder);
			continue;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pback.reset();
			*perrno = strtol(buff + 6, nullptr, 0);
			return MIDB_RESULT_ERROR;
		}
		return MIDB_RDWR_ERROR;
	}

	if (length > cmd_len) {
		buff[length] = '\r';
		length ++;
		buff[length] = '\n';
		length ++;
		auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
		if (ret != 0)
			return ret;
		if (0 == strncmp(buff, "TRUE", 4)) {
			pback.reset();
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pback.reset();
			*perrno = strtol(buff + 6, nullptr, 0);
			return MIDB_RESULT_ERROR;
		}
		return MIDB_RDWR_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static unsigned int s_to_flagbits(const char *s)
{
	unsigned int fl = 0;
	if (strchr(s, 'A') != nullptr)
		fl |= FLAG_ANSWERED;
	if (strchr(s, 'U') != nullptr)
		fl |= FLAG_DRAFT;
	if (strchr(s, 'F') != nullptr)
		fl |= FLAG_FLAGGED;
	if (strchr(s, 'D') != nullptr)
		fl |= FLAG_DELETED;
	if (strchr(s, 'S') != nullptr)
		fl |= FLAG_SEEN;
	if (strchr(s, 'R') != nullptr)
		fl |= FLAG_RECENT;
	return fl;
}

static unsigned int di_to_flagbits(const char *ln, int pos)
{
	unsigned int fl = 0;
	int v;
	if (get_digest_integer(ln, pos, "replied", &v) && v == 1)
		fl |= FLAG_ANSWERED;
	if (get_digest_integer(ln, pos, "unsent", &v) && v == 1)
		fl |= FLAG_DRAFT;
	if (get_digest_integer(ln, pos, "flag", &v) && v == 1)
		fl |= FLAG_FLAGGED;
	if (get_digest_integer(ln, pos, "deleted", &v) && v == 1)
		fl |= FLAG_DELETED;
	if (get_digest_integer(ln, pos, "read", &v) && v == 1)
		fl |= FLAG_SEEN;
	if (get_digest_integer(ln, pos, "recent", &v) && v == 1)
		fl |= FLAG_RECENT;
	return fl;
}

static int list_deleted(const char *path, const char *folder, XARRAY *pxarray,
	int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int last_pos;
	int read_len;
	int line_pos;
	char *pspace;
	char *pspace1;
	int tv_msec;
	char temp_line[512];
	char buff[256*1025];
	BOOL b_format_error;
	struct pollfd pfd_read;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto EH = make_scope_exit([=]() { pxarray->clear(); });
	auto length = gx_snprintf(buff, arsizeof(buff), "P-DELL %s %s UID ASC\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		return MIDB_RDWR_ERROR;
	}
	
	count = 0;
	offset = 0;
	lines = -1;
	b_format_error = FALSE;
	while (true) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return MIDB_RDWR_ERROR;
		}
		static_assert(std::size(buff) >= 256*1024 + 1);
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			return MIDB_RDWR_ERROR;
		}
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if (buff[i] != '\r' || buff[i+1] != '\n')
					continue;
				if (0 == strncmp(buff, "TRUE ", 5)) {
					lines = strtol(buff + 5, nullptr, 0);
					if (lines < 0) {
						return MIDB_RDWR_ERROR;
					}
					last_pos = i + 2;
					line_pos = 0;
					break;
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					pback.reset();
					EH.release(); // ?
					*perrno = strtol(buff + 6, nullptr, 0);
					return MIDB_RESULT_ERROR;
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					return MIDB_RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				pspace = strchr(temp_line, ' ');
				if (NULL != pspace) {
					pspace1 = strchr(pspace + 1, ' ');
					if (NULL != pspace1) {
						*pspace = '\0';
						*pspace1 = '\0';
						pspace ++;
						pspace1 ++;
						MITEM mitem;
						gx_strlcpy(mitem.mid, pspace, arsizeof(mitem.mid));
						mitem.id = strtol(temp_line, nullptr, 0) + 1;
						mitem.uid = strtol(pspace1, nullptr, 0);
						mitem.flag_bits = FLAG_DELETED;
						auto mitem_uid = mitem.uid;
						pxarray->append(std::move(mitem), mitem_uid);
					} else {
						b_format_error = TRUE;
					}
				} else {
					b_format_error = TRUE;
				}
				line_pos = 0;
			} else if (buff[i] != '\r' || i != offset - 1) {
				temp_line[line_pos] = buff[i];
				line_pos ++;
				if (line_pos >= 128) {
					return MIDB_RDWR_ERROR;
				}
			}
		}

		if (count >= lines) {
			pback.reset();
			if (b_format_error) {
				*perrno = -1;
				return MIDB_RESULT_ERROR;
			}
			EH.release();
			return MIDB_RESULT_OK;
		}
		last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
		if (256*1024 == offset) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}
}

static int fetch_simple(const char *path, const char *folder,
    const std::vector<seq_node> &list, XARRAY *pxarray, int *perrno)
{
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	char *pspace;
	char *pspace1;
	char buff[1024];
	char temp_line[1024];
	BOOL b_format_error;
	struct pollfd pfd_read;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	
	for (const auto &seq : list) {
		auto pseq = &seq;
		if (pseq->max == pseq->unset) {
			if (pseq->min == pseq->unset)
				length = gx_snprintf(buff, arsizeof(buff), "P-SIML %s %s UID ASC -1 1\r\n",
						path, folder);
			else
				length = gx_snprintf(buff, arsizeof(buff), "P-SIML %s %s UID ASC %d "
						"1000000000\r\n", path, folder,
						pseq->min - 1);
		} else {
			length = gx_snprintf(buff, arsizeof(buff), "P-SIML %s %s UID ASC %d %d\r\n",
						path, folder, pseq->min - 1,
						pseq->max - pseq->min + 1);
		}
		if (length != write(pback->sockd, buff, length)) {
			return MIDB_RDWR_ERROR;
		}
		
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (true) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				return MIDB_RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, std::size(buff) - 1 - offset);
			if (read_len <= 0) {
				return MIDB_RDWR_ERROR;
			}
			offset += read_len;
			buff[offset] = '\0';
			
			if (-1 == lines) {
				for (int i = 0; i < offset - 1 && i < 36; ++i) {
					if (buff[i] != '\r' || buff[i+1] != '\n')
						continue;
					if (0 == strncmp(buff, "TRUE ", 5)) {
						lines = strtol(buff + 5, nullptr, 0);
						if (lines < 0) {
							return MIDB_RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						pback.reset();
						*perrno = strtol(buff + 6, nullptr, 0);
						return MIDB_RESULT_ERROR;
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						return MIDB_RDWR_ERROR;
					}
					continue;
				}
			}

			for (int i = last_pos; i < offset; ++i) {
				if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
					count ++;
				} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
					temp_line[line_pos] = '\0';
					pspace = strchr(temp_line, ' ');
					if (NULL != pspace) {
						pspace1 = strchr(pspace + 1, ' ');
						if (NULL != pspace1) {
							*pspace = '\0';
							*pspace1 = '\0';
							pspace ++;
							pspace1 ++;
							int uid = strtol(pspace, nullptr, 0);
							if (pxarray->append(MITEM{}, uid) >= 0) {
								auto num = pxarray->get_capacity();
								assert(num > 0);
								auto pitem = pxarray->get_item(num - 1);
								pitem->uid = uid;
								pitem->id = pseq->min + count - 1;
								gx_strlcpy(pitem->mid, temp_line, arsizeof(pitem->mid));
								pitem->flag_bits = s_to_flagbits(pspace1);
							}
						} else {
							b_format_error = TRUE;
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else if (buff[i] != '\r' || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 128) {
						return MIDB_RDWR_ERROR;
					}
				}
			}

			if (count >= lines) {
				if (!b_format_error)
					break;
				pback.reset();
				*perrno = -1;
				return MIDB_RESULT_ERROR;
			}
			last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
			if (static_cast<size_t>(offset) >= std::size(buff) - 1) {
				if ('\r' != buff[offset - 1]) {
					offset = 0;
				} else {
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}
	
	pback.reset();
	return MIDB_RESULT_OK;
}

static int fetch_detail(const char *path, const char *folder,
    const std::vector<seq_node> &list, XARRAY *pxarray, int *perrno) try
{
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	char buff[64*1025];
	char temp_line[257*1024];
	BOOL b_format_error;
	struct pollfd pfd_read;

	if (g_file_allocator.internals().item_size == 0) {
		*perrno = -2;
		return MIDB_RESULT_ERROR;
	}
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto EH = make_scope_exit([=]() {
		pxarray->clear();
	});
	
	for (const auto &seq : list) {
		auto pseq = &seq;
		if (pseq->max == pseq->unset) {
			if (pseq->min == pseq->unset)
				length = gx_snprintf(buff, arsizeof(buff), "M-LIST %s %s UID ASC -1 1\r\n",
						path, folder);
			else
				length = gx_snprintf(buff, arsizeof(buff), "M-LIST %s %s UID ASC %d "
						"1000000000\r\n", path, folder,
						pseq->min - 1);
		} else {
			length = gx_snprintf(buff, arsizeof(buff), "M-LIST %s %s UID ASC %d %d\r\n",
						path, folder, pseq->min - 1,
						pseq->max - pseq->min + 1);
		}
		if (length != write(pback->sockd, buff, length)) {
			return MIDB_RDWR_ERROR;
		}
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (true) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				return MIDB_RDWR_ERROR;
			}
			static_assert(std::size(buff) >= 64*1024 + 1);
			read_len = read(pback->sockd, buff + offset, 64*1024 - offset);
			if (read_len <= 0) {
				return MIDB_RDWR_ERROR;
			}
			offset += read_len;
			buff[offset] = '\0';
			
			if (-1 == lines) {
				for (int i = 0; i < offset - 1 && i < 36; ++i) {
					if (buff[i] != '\r' || buff[i+1] != '\n')
						continue;
					if (0 == strncmp(buff, "TRUE ", 5)) {
						lines = strtol(buff + 5, nullptr, 0);
						if (lines < 0) {
							return MIDB_RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						pback.reset();
						*perrno = strtol(buff + 6, nullptr, 0);
						return MIDB_RESULT_ERROR;
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						return MIDB_RDWR_ERROR;
					}
					continue;
				}
			}

			for (int i = last_pos; i < offset; ++i) {
				if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
					count ++;
				} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
					MITEM mitem;
					if (get_digest_string(temp_line, line_pos,
					    "file", mitem.mid, sizeof(mitem.mid)) &&
					    get_digest_integer(temp_line, line_pos,
					    "uid", &mitem.uid)) {
						auto mitem_uid = mitem.uid;
						if (pxarray->append(std::move(mitem), mitem_uid) >= 0) {
							auto num = pxarray->get_capacity();
							assert(num > 0);
							auto pitem = pxarray->get_item(num - 1);
							pitem->id = pseq->min + count - 1;
							pitem->flag_bits = FLAG_LOADED | di_to_flagbits(temp_line, line_pos);
							pitem->f_digest = std::string_view(temp_line, line_pos);
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else if (buff[i] != '\r' || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 257*1024) {
						return MIDB_RDWR_ERROR;
					}
				}
			}

			if (b_format_error) {
				EH.release();
				// no pxarray->clear?

				pback.reset();
				*perrno = -1;
				return MIDB_RESULT_ERROR;
			}
			if (count >= lines)
				break;
			last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
			if (64*1024 == offset) {
				if ('\r' != buff[offset - 1]) {
					offset = 0;
				} else {
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}

	pback.reset();
	EH.release();
	return MIDB_RESULT_OK;
} catch (const std::bad_alloc &) {
	return MIDB_LOCAL_ENOMEM;
}

static int fetch_simple_uid(const char *path, const char *folder,
    const std::vector<seq_node> &list, XARRAY *pxarray, int *perrno)
{
	int lines;
	int count;
	int offset;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	char *pspace;
	char *pspace1;
	char *pspace2;
	char buff[1024];
	char temp_line[1024];
	BOOL b_format_error;
	struct pollfd pfd_read;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	
	for (const auto &seq : list) {
		auto pseq = &seq;
		auto length = gx_snprintf(buff, arsizeof(buff), "P-SIMU %s %s UID ASC %d %d\r\n", path, folder,
					pseq->min, pseq->max);
		if (length != write(pback->sockd, buff, length)) {
			return MIDB_RDWR_ERROR;
		}
		
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (true) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				return MIDB_RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, std::size(buff) - 1 - offset);
			if (read_len <= 0) {
				return MIDB_RDWR_ERROR;
			}
			offset += read_len;
			buff[offset] = '\0';

			if (-1 == lines) {
				for (int i = 0; i < offset - 1 && i < 36; ++i) {
					if (buff[i] != '\r' || buff[i+1] != '\n')
						continue;
					if (0 == strncmp(buff, "TRUE ", 5)) {
						lines = strtol(buff + 5, nullptr, 0);
						if (lines < 0) {
							return MIDB_RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						pback.reset();
						*perrno = strtol(buff + 6, nullptr, 0);
						return MIDB_RESULT_ERROR;
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						return MIDB_RDWR_ERROR;
					}
					continue;
				}
			}

			for (int i = last_pos; i < offset; ++i) {
				if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
					count ++;
				} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
					temp_line[line_pos] = '\0';
					pspace = strchr(temp_line, ' ');
					if (NULL != pspace) {
						pspace1 = strchr(pspace + 1, ' ');
						if (NULL != pspace1) {
							pspace2 = strchr(pspace1 + 1, ' ');
							if (NULL != pspace2) {
								*pspace = '\0';
								*pspace1 = '\0';
								*pspace2 = '\0';
								pspace ++;
								pspace1 ++;
								pspace2 ++;
								int uid = strtol(pspace1, nullptr, 0);
								if (pxarray->append(MITEM{}, uid) >= 0) {
									auto num = pxarray->get_capacity();
									assert(num > 0);
									auto pitem = pxarray->get_item(num - 1);
									pitem->uid = uid;
									pitem->id = strtol(temp_line, nullptr, 0) + 1;
									gx_strlcpy(pitem->mid, pspace, arsizeof(pitem->mid));
									pitem->flag_bits = s_to_flagbits(pspace2);
								}
							} else {
								b_format_error = TRUE;
							}
						} else {
							b_format_error = TRUE;
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else if (buff[i] != '\r' || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 128) {
						return MIDB_RDWR_ERROR;
					}
				}
			}

			if (count >= lines) {
				if (!b_format_error)
					break;
				pback.reset();
				*perrno = -1;
				return MIDB_RESULT_ERROR;
			}
			last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
			if (static_cast<size_t>(offset) >= std::size(buff) - 1) {
				if ('\r' != buff[offset - 1]) {
					offset = 0;
				} else {
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}

	pback.reset();
	return MIDB_RESULT_OK;
}

static int fetch_detail_uid(const char *path, const char *folder,
    const std::vector<seq_node> &list, XARRAY *pxarray, int *perrno) try
{
	int lines;
	int count;
	int offset;
	int last_pos;
	int read_len;
	int line_pos;
	int temp_len;
	char *pspace;
	int tv_msec;
	char buff[64*1025];
	char temp_line[257*1024];
	BOOL b_format_error;
	struct pollfd pfd_read;

	if (g_file_allocator.internals().item_size == 0) {
		*perrno = -2;
		return MIDB_RESULT_ERROR;
	}
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto EH = make_scope_exit([=]() {
		pxarray->clear();
	});
	
	for (const auto &seq : list) {
		auto pseq = &seq;
		auto length = gx_snprintf(buff, arsizeof(buff), "P-DTLU %s %s UID ASC %d %d\r\n", path,
					folder, pseq->min, pseq->max);
		if (length != write(pback->sockd, buff, length)) {
			return MIDB_RDWR_ERROR;
		}
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (true) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				return MIDB_RDWR_ERROR;
			}
			static_assert(std::size(buff) >= 64*1024 + 1);
			read_len = read(pback->sockd, buff + offset, 64*1024 - offset);
			if (read_len <= 0) {
				return MIDB_RDWR_ERROR;
			}
			offset += read_len;
			buff[offset] = '\0';

			if (-1 == lines) {
				for (int i = 0; i < offset - 1 && i < 36; ++i) {
					if (buff[i] != '\r' || buff[i+1] != '\n')
						continue;
					if (0 == strncmp(buff, "TRUE ", 5)) {
						lines = strtol(buff + 5, nullptr, 0);
						if (lines < 0) {
							return MIDB_RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						pback.reset();
						*perrno = strtol(buff + 6, nullptr, 0);
						return MIDB_RESULT_ERROR;
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						return MIDB_RDWR_ERROR;
					}
					continue;
				}
			}

			for (int i = last_pos; i < offset; ++i) {
				if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
					count ++;
				} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
					pspace = search_string(temp_line, " ", 16);
					temp_len = line_pos - (pspace + 1 - temp_line);
					MITEM mitem;
					if (pspace != nullptr && get_digest_string(pspace,
					    temp_len, "file", mitem.mid, sizeof(mitem.mid)) && 
					    get_digest_integer(pspace, temp_len, "uid",
					    &mitem.uid)) {
						*pspace = '\0';
						pspace ++;
						auto mitem_uid = mitem.uid;
						if (pxarray->append(std::move(mitem), mitem_uid) >= 0) {
							auto num = pxarray->get_capacity();
							assert(num > 0);
							auto pitem = pxarray->get_item(num - 1);
							pitem->id = strtol(temp_line, nullptr, 0) + 1;
							pitem->flag_bits = FLAG_LOADED | di_to_flagbits(pspace, temp_len);
							pitem->f_digest = std::string_view(pspace, temp_len);
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else if (buff[i] != '\r' || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 257 * 1024) {
						return MIDB_RDWR_ERROR;
					}
				}
			}

			if (count >= lines) {
				if (!b_format_error)
					break;
				pback.reset();
				*perrno = -1;
				EH.release();
				// no pxarray->clear?
				return MIDB_RESULT_ERROR;
			}
			last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
			if (64*1024 == offset) {
				if ('\r' != buff[offset - 1]) {
					offset = 0;
				} else {
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}
	
	pback.reset();
	EH.release();
	return MIDB_RESULT_OK;
} catch (const std::bad_alloc &) {
	return MIDB_LOCAL_ENOMEM;
}

static int set_mail_flags(const char *path, const char *folder,
    const char *mid_string, int flag_bits, int *perrno)
{
	char buff[1024];
	char flags_string[16];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;

	flags_string[0] = '(';
	int length = 1;
	if (flag_bits & FLAG_ANSWERED) {
		flags_string[length] = 'A';
		length ++;
	}
	
	if (flag_bits & FLAG_DRAFT) {
		flags_string[length] = 'U';
		length ++;
	}
	
	if (flag_bits & FLAG_FLAGGED) {
		flags_string[length] = 'F';
		length ++;
	}
	
	if (flag_bits & FLAG_DELETED) {
		flags_string[length] = 'D';
		length ++;
	}
	
	if (flag_bits & FLAG_SEEN) {
		flags_string[length] = 'S';
		length ++;
	}
	
	if (flag_bits & FLAG_RECENT) {
		flags_string[length] = 'R';
		length ++;
	}
	flags_string[length] = ')';
	length ++;
	flags_string[length] = '\0';
	length = gx_snprintf(buff, arsizeof(buff), "P-SFLG %s %s %s %s\r\n",
				path, folder, mid_string, flags_string);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}
	
static int unset_mail_flags(const char *path, const char *folder,
    const char *mid_string, int flag_bits, int *perrno)
{
	char buff[1024];
	char flags_string[16];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;

	flags_string[0] = '(';
	int length = 1;
	if (flag_bits & FLAG_ANSWERED) {
		flags_string[length] = 'A';
		length ++;
	}
	
	if (flag_bits & FLAG_DRAFT) {
		flags_string[length] = 'U';
		length ++;
	}
	
	if (flag_bits & FLAG_FLAGGED) {
		flags_string[length] = 'F';
		length ++;
	}
	
	if (flag_bits & FLAG_DELETED) {
		flags_string[length] = 'D';
		length ++;
	}
	
	if (flag_bits & FLAG_SEEN) {
		flags_string[length] = 'S';
		length ++;
	}
	
	if (flag_bits & FLAG_RECENT) {
		flags_string[length] = 'R';
		length ++;
	}
	flags_string[length] = ')';
	length ++;
	flags_string[length] = '\0';
	length = gx_snprintf(buff, arsizeof(buff), "P-RFLG %s %s %s %s\r\n",
				path, folder, mid_string, flags_string);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}
	
static int get_mail_flags(const char *path, const char *folder,
    const char *mid_string, int *pflag_bits, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "P-GFLG %s %s %s\r\n",
				path, folder, mid_string);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		*pflag_bits = 0;
		if (buff[4] == ' ')
			*pflag_bits = s_to_flagbits(buff + 5);
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}
	
static int copy_mail(const char *path, const char *src_folder,
    const char *mid_string, const char *dst_folder, char *dst_mid, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-COPY %s %s %s %s\r\n",
				path, src_folder, mid_string, dst_folder);
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		strcpy(dst_mid, buff + 5);
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}

static ssize_t read_line(int sockd, char *buff, size_t length)
{
	if (length == 0)
		return 0;
	size_t offset = 0;
	--length;
	int tv_msec;
	struct pollfd pfd_read;

	while (true) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return -ETIMEDOUT;
		}
		auto read_len = read(sockd, buff + offset,  length - offset);
		if (read_len < 0) {
			return read_len;
		}
		buff[offset+read_len] = '\0';
		if (read_len == 0)
			return 0;
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			offset -= 2;
			buff[offset] = '\0';
			return 1;
		}
		if (length == offset) {
			return -ENOBUFS;
		}
	}
}

static BOOL check_full(const char *path)
{
	int offset;
	int read_len;
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return TRUE;
	auto length = gx_snprintf(buff, arsizeof(buff), "M-CKFL %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		return TRUE;
	}

	offset = 0;
	while (true) {
		struct pollfd pfd = {pback->sockd};
		pfd.events = POLLIN_SET;
		if (poll(&pfd, 1, SOCKET_TIMEOUT * 1000) <= 0)
			return TRUE;
		read_len = read(pback->sockd, buff + offset, 1024 - offset);
		if (read_len <= 0) {
			return TRUE;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			if (8 == offset && 0 == strncasecmp("TRUE ", buff, 5)) {
				time(&pback->last_time);
				pback.reset();
				if ('1' == buff[5]) {
					return FALSE;
				} else {
					return TRUE;
				}
			} else if (offset > 8 && 0 == strncasecmp("FALSE ", buff, 6)) {
				time(&pback->last_time);
				pback.reset();
				return TRUE;
			}
			return TRUE;
		}
		if (1024 == offset) {
			return TRUE;
		}
	}
}

static int connect_midb(const char *ip_addr, uint16_t port)
{
	int tv_msec;
    char temp_buff[1024];
	struct pollfd pfd_read;

	auto sockd = HX_inet_connect(ip_addr, port, 0);
	if (sockd < 0) {
		static std::atomic<time_t> g_lastwarn_time;
		auto prev = g_lastwarn_time.load();
		auto next = prev + 60;
		auto now = time(nullptr);
		if (next <= now && g_lastwarn_time.compare_exchange_strong(prev, now))
			fprintf(stderr, "HX_inet_connect midb_agent@[%s]:%hu: %s\n",
			        ip_addr, port, strerror(-sockd));
		return -1;
	}
	tv_msec = SOCKET_TIMEOUT * 1000;
	pfd_read.fd = sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (1 != poll(&pfd_read, 1, tv_msec)) {
		close(sockd);
		return -1;
	}
	auto read_len = read(sockd, temp_buff, std::size(temp_buff) - 1);
	if (read_len <= 0) {
        close(sockd);
        return -1;
	}
	temp_buff[read_len] = '\0';
	if (0 != strcasecmp(temp_buff, "OK\r\n")) {
		close(sockd);
		return -1;
	}
	return sockd;
}

static BOOL get_digest_string(const char *src, int length, const char *tag,
    char *buff, int buff_len)
{
	char *ptr1, *ptr2;
	char temp_tag[256];
	
	auto len = gx_snprintf(temp_tag, arsizeof(temp_tag), "\"%s\"", tag);
	ptr1 = search_string(src, temp_tag, length);
	if (NULL == ptr1) {
		return FALSE;
	}

	ptr1 += len;
	ptr1 = static_cast<char *>(memchr(ptr1, ':', length - (ptr1 - src)));
	if (NULL == ptr1) {
		return FALSE;
	}
	ptr1 ++;
	while (' ' == *ptr1 || '\t' == *ptr1) {
		ptr1 ++;
		if (ptr1 - src >= length) {
			return FALSE;
		}
	}
	ptr2 = ptr1;
	if ('"' == *ptr2) {
		do {
			ptr2 ++;
			if (ptr2 - src >= length) {
				return FALSE;
			}
		} while ('"' != *ptr2 || '\\' == *(ptr2 - 1));
	}
	while (',' != *ptr2 && '}' != *ptr2) {
		ptr2 ++;
		if (ptr2 - src >= length) {
			return FALSE;
		}
	}

	if (ptr2 - ptr1 <= buff_len - 1) {
		len = ptr2 - ptr1;
	} else {
		len = buff_len - 1;
	}
	memcpy(buff, ptr1, len);
	buff[len] = '\0';
	if ('"' == buff[0]) {
		len --;
		memmove(buff, buff + 1, len);
		buff[len] = '\0';
	}
	if ('"' == buff[len - 1]) {
		buff[len - 1] = '\0';
	}
	return TRUE;
}

static BOOL get_digest_integer(const char *src, int length, const char *tag, int *pinteger)
{
	char num_buff[32];
	
	if (get_digest_string(src, length, tag, num_buff, 32)) {
		*pinteger = strtol(num_buff, nullptr, 0);
		return TRUE;
	}
	return FALSE;
}
