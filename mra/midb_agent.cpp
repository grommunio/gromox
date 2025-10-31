// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
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
#include <fmt/core.h>
#include <libHX/ctype_helper.h>
#include <libHX/io.h>
#include <libHX/scope.hpp>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/list_file.hpp>
#include <gromox/midb.hpp>
#include <gromox/midb_agent.hpp>
#include <gromox/process.hpp>
#include <gromox/range_set.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include <gromox/xarray2.hpp>

using namespace std::string_literals;
using namespace gromox;
using AGENT_MITEM = MITEM;
DECLARE_SVC_API(,);

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

std::atomic<size_t> g_midb_command_buffer_size{256 * 1024};
static int g_conn_num;
static gromox::atomic_bool g_notify_stop;
static pthread_t g_scan_id;
static std::list<BACK_CONN> g_lost_list;
static std::list<BACK_SVR> g_server_list;
static std::mutex g_server_lock;
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
		for (decltype(g_conn_num) j = 0; j < g_conn_num; ++j)
			g_lost_list.push_back(BACK_CONN{-1, 0, pserver});
		return true;
	}
	for (decltype(list_num) i = 0; i < list_num; ++i) {
		auto &svr = g_server_list.emplace_back();
		auto pserver = &svr;
		svr.prefix = pitem[i].prefix;
		gx_strlcpy(pserver->ip_addr, pitem[i].ip_addr, std::size(pserver->ip_addr));
		pserver->port = pitem[i].port;
		for (decltype(g_conn_num) j = 0; j < g_conn_num; ++j)
			g_lost_list.emplace_back(BACK_CONN{-1, 0, pserver});
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1656: ENOMEM");
	return false;
}

static bool midb_agent_reload(std::shared_ptr<CONFIG_FILE> &&cfg)
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
}

BOOL SVC_midb_agent(enum plugin_op reason, const struct dlfuncs &ppdata)
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
			mlog(LV_ERR, "midb_agent: config_file_initd midb_agent.cfg: %s",
				strerror(errno));
			return FALSE;
		}
		if (!midb_agent_reload(std::move(pconfig)))
			return false;
		if (!list_file_read_midb("midb_list.txt"))
			return false;

		g_notify_stop = false;
		auto ret = pthread_create4(&g_scan_id, nullptr, midbag_scanwork, nullptr);
		if (ret != 0) {
			printf("[midb_agent]: failed to create scan thread: %s\n", strerror(ret));
			return FALSE;
		}
		pthread_setname_np(g_scan_id, "midb_agent");
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
				if (HXio_fullwrite(pback->sockd, "QUIT\r\n", 6) != 6)
					/* ignore */;
				close(pback->sockd);
			}
		}
		g_server_list.clear();
		return TRUE;
	default:
		return TRUE;
	}
}

static void *midbag_scanwork(void *param)
{
	char temp_buff[1024];
	struct pollfd pfd_read;
	std::list<BACK_CONN> temp_list;

	while (!g_notify_stop) {
		std::unique_lock sv_hold(g_server_lock);
		auto now_time = time(nullptr);
		for (auto &srv : g_server_list) {
			auto tail = srv.conn_list.size() > 0 ? &srv.conn_list.back() : nullptr;
			while (srv.conn_list.size() > 0) {
				auto pback = &srv.conn_list.front();
				if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3)
					temp_list.splice(temp_list.end(), srv.conn_list, srv.conn_list.begin());
				else
					srv.conn_list.splice(srv.conn_list.end(), srv.conn_list, srv.conn_list.begin());
				if (pback == tail)
					break;
			}
		}
		sv_hold.unlock();

		while (temp_list.size() > 0) {
			auto pback = &temp_list.front();
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (HXio_fullwrite(pback->sockd, "PING\r\n", 6) != 6 ||
			    poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1 ||
			    read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				sv_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			} else {
				pback->last_time = time(nullptr);
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
				pback->last_time = time(nullptr);
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

namespace midb_agent {

int list_mail(const char *path, const std::string &folder,
    std::vector<MSG_UNIT> &parray, int *pnum, uint64_t *psize) try
{
	char temp_line[512];
	struct pollfd pfd_read;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto EH = HX::make_scope_exit([&]() { parray.clear(); });
	auto buff = fmt::format("P-SIMU {} {} 1 -1\r\n", path, folder);
	auto wrret = write(pback->sockd, buff.c_str(), buff.size());
	if (wrret < 0 || static_cast<size_t>(wrret) != buff.size())
		return MIDB_RDWR_ERROR;

	buff.resize(256 * 1024);
	*psize = 0;
	int count = 0, lines = -1;
	size_t offset = 0, last_pos = 0, line_pos = 0;
	BOOL b_fail = false;
	while (true) {
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
			return MIDB_RDWR_ERROR;
		auto read_len = read(pback->sockd, &buff[offset], buff.size() - offset);
		if (read_len <= 0)
			return MIDB_RDWR_ERROR;
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (size_t i = 0; i < offset - 1 && i < 36; ++i) {
				if (buff[i] != '\r' || buff[i+1] != '\n')
					continue;
				if (strncmp(buff.c_str(), "TRUE ", 5) == 0) {
					lines = strtol(&buff[5], nullptr, 0);
					if (lines < 0)
						return MIDB_RDWR_ERROR;
					*pnum = lines;
					last_pos = i + 2;
					line_pos = 0;
					break;
				} else if (strncmp(buff.c_str(), "FALSE ", 6) == 0) {
					pback.reset();
					EH.release(); // ?
					return MIDB_RESULT_ERROR;
				}
			}
			if (-1 == lines) {
				if (offset > 1024)
					return MIDB_RDWR_ERROR;
				continue;
			}
		}

		for (size_t i = last_pos; i < offset; ++i) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
				continue;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				try {
					auto parts = gx_split(temp_line, ' ');
					if (parts.size() != 5)
						throw 0;
					MSG_UNIT msg{std::move(parts[1])};
					msg.size = strtoul(parts[4].c_str(), nullptr, 0);
					auto msg_size = msg.size;
					parray.push_back(std::move(msg));
					*psize += msg_size;
				} catch (...) {
					b_fail = TRUE;
				}
				line_pos = 0;
			} else if (buff[i] != '\r' || i != offset - 1) {
				temp_line[line_pos++] = buff[i];
				if (line_pos >= 256)
					return MIDB_RDWR_ERROR;
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
		if (offset >= buff.size()) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1780: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

static int rw_command(int fd, char *buff, size_t olen, size_t ilen)
{
	auto ret = write(fd, buff, olen);
	if (ret < 0 || static_cast<size_t>(ret) != olen)
		return MIDB_RDWR_ERROR;
	ret = read_line(fd, buff, ilen);
	if (ret == -ENOBUFS) {
		auto ilog10 = [](size_t x) -> size_t { size_t i = 0; for (; x >= 10; ++i) x /= 10; return i; };
		auto b = g_midb_command_buffer_size.load();
		size_t ap = b / (2 + ilog10(b));
		mlog(LV_ERR, "E-2154: midb response is longer than expected (%zu), rejecting IMAP command. "
		        "Consider raising midb_agent.cfg:midb_agent_command_buffer_size "
		        "or having fewer mails in the folder. (Approx. limit %zu messages.)",
		        ilen, ap);
		return MIDB_TOO_MANY_RESULTS;
	} else if (ret < 0) {
		return MIDB_RDWR_ERROR;
	}
	return 0;
}

int delete_mail(const char *path, const std::string &folder,
    const std::vector<MSG_UNIT *> &plist)
{
	char buff[128*1025];

	if (plist.size() == 0)
		return MIDB_RESULT_OK;
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "M-DELE %s %s",
	              path, folder.c_str());
	int cmd_len = length;
	
	for (auto pmsg : plist) {
		buff[length++] = ' ';
		auto temp_len = pmsg->file_name.size();
		memcpy(buff + length, pmsg->file_name.c_str(), temp_len);
		length += temp_len;
		if (length <= 128 * 1024)
			continue;
		buff[length++] = '\r';
		buff[length++] = '\n';
		auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
		if (ret != 0)
			return ret;
		if (0 == strncmp(buff, "TRUE", 4)) {
			length = gx_snprintf(buff, std::size(buff), "M-DELE %s %s",
			         path, folder.c_str());
			continue;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pback.reset();
			return MIDB_RESULT_ERROR;
		}
		return MIDB_RDWR_ERROR;
	}

	if (length > cmd_len) {
		buff[length++] = '\r';
		buff[length++] = '\n';
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

int search(const char *path, const std::string &folder,
    const char *charset, int argc, char **argv, std::string &ret_buff,
    int *perrno) try
{
	size_t encode_len;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto cbufsize = g_midb_command_buffer_size.load();
	auto buff   = std::make_unique<char[]>(cbufsize);
	auto buff1  = std::make_unique<char[]>(cbufsize);
	auto length = gx_snprintf(buff.get(), cbufsize,
	              "P-SRHL %s %s %s ", path, folder.c_str(), charset);
	int length1 = 0;
	for (int i = 0; i < argc; ++i)
		length1 += gx_snprintf(&buff1[length1], cbufsize - length1,
					"%s", argv[i]) + 1;
	buff1[length1++] = '\0';
	encode64(buff1.get(), length1, &buff[length], cbufsize - length,
		&encode_len);
	length += encode_len;
	buff1.reset();
	buff[length++] = '\r';
	buff[length++] = '\n';
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

int search_uid(const char *path, const std::string &folder,
   const char *charset, int argc, char **argv, std::string &ret_buff,
   int *perrno) try
{
	size_t encode_len;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto cbufsize = g_midb_command_buffer_size.load();
	auto buff   = std::make_unique<char[]>(cbufsize);
	auto buff1  = std::make_unique<char[]>(cbufsize);
	auto length = gx_snprintf(buff.get(), cbufsize,
	              "P-SRHU %s %s %s ", path, folder.c_str(), charset);
	int length1 = 0;
	for (int i = 0; i < argc; ++i)
		length1 += gx_snprintf(&buff1[length1], cbufsize - length1,
					"%s", argv[i]) + 1;
	buff1[length1++] = '\0';
	encode64(buff1.get(), length1, &buff[length], cbufsize - length,
		&encode_len);
	length += encode_len;
	buff1.reset();
	buff[length++] = '\r';
	buff[length++] = '\n';
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

int get_uid(const char *path, const std::string &folder,
    const std::string &mid_string, unsigned int *puid)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "P-UNID %s %s %s\r\n",
	              path, folder.c_str(), mid_string.c_str());
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

int summary_folder(const char *path, const std::string &folder, size_t *pexists,
    size_t *precent, size_t *punseen, uint32_t *puidvalid, uint32_t *puidnext,
    int *perrno)
{
	char buff[1024];
	size_t exists, recent, unseen;
	unsigned long uidvalid, uidnext;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "P-FDDT %s %s\r\n",
	              path, folder.c_str());
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (strncmp(buff, "FALSE ", 6) == 0) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	} else if (strncmp(buff, "TRUE", 4) != 0) {
		return MIDB_RDWR_ERROR;
	}

	if (sscanf(buff, "TRUE %zu %zu %zu %lu %lu", &exists,
	    &recent, &unseen, &uidvalid, &uidnext) != 5) {
		*perrno = -1;
		pback.reset();
		return MIDB_RESULT_ERROR;
	}
	if (pexists != nullptr)
		*pexists = exists;
	if (precent != nullptr)
		*precent = recent;
	if (punseen != nullptr)
		*punseen = unseen;
	if (puidvalid != nullptr)
		*puidvalid = uidvalid;
	if (puidnext != nullptr)
		*puidnext = uidnext;
	pback.reset();
	return MIDB_RESULT_OK;
}
	
int make_folder(const char *path, const std::string &folder, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "M-MAKF %s %s\r\n",
	              path, folder.c_str());
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

int remove_folder(const char *path, const std::string &folder, int *perrno)
{
	char buff[1024];
	
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "M-REMF %s %s\r\n",
	              path, folder.c_str());
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

int ping_mailbox(const char *path, int *perrno)
{
	char buff[1024];
	
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "M-PING %s\r\n", path);
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

int rename_folder(const char *path, const std::string &src_name,
    const std::string &dst_name, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "M-RENF %s %s %s\r\n",
	              path, src_name.c_str(), dst_name.c_str());
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

int subscribe_folder(const char *path, const std::string &folder, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "P-SUBF %s %s\r\n",
	              path, folder.c_str());
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

int unsubscribe_folder(const char *path, const std::string &folder, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "P-UNSF %s %s\r\n",
	              path, folder.c_str());
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

int enum_folders(const char *path, std::vector<enum_folder_t> &pfile,
    int *perrno) try
{
	char temp_line[512];
	struct pollfd pfd_read;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto buff = "M-ENUM "s + path + "\r\n";
	auto wrret = write(pback->sockd, buff.c_str(), buff.size());
	if (wrret < 0 || static_cast<size_t>(wrret) != buff.size())
		return MIDB_RDWR_ERROR;
	
	buff.resize(256 * 1024);
	int count = 0, lines = -1;
	size_t offset = 0, last_pos = 0, line_pos = 0;
	while (true) {
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
			return MIDB_RDWR_ERROR;
		auto read_len = read(pback->sockd, &buff[offset], buff.size() - offset);
		if (read_len <= 0)
			return MIDB_RDWR_ERROR;
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (size_t i = 0; i < offset - 1 && i < 36; ++i) {
				if (buff[i] != '\r' || buff[i+1] != '\n')
					continue;
				if (strncmp(buff.c_str(), "TRUE ", 5) == 0) {
					lines = strtol(&buff[5], nullptr, 0);
					if (lines < 0)
						return MIDB_RDWR_ERROR;
					last_pos = i + 2;
					line_pos = 0;
					break;
				} else if (strncmp(buff.c_str(), "FALSE ", 6) == 0) {
					pback.reset();
					*perrno = strtol(&buff[6], nullptr, 0);
					return MIDB_RESULT_ERROR;
				}
				return MIDB_RDWR_ERROR;
			}
			if (-1 == lines) {
				if (offset > 1024)
					return MIDB_RDWR_ERROR;
				continue;
			}
		}

		for (size_t i = last_pos; i < offset; ++i) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				char *end = nullptr;
				uint64_t fid = strtoul(temp_line, &end, 0);
				while (HX_isspace(*end))
					++end;
				pfile.emplace_back(fid, end);
				line_pos = 0;
			} else if (buff[i] != '\r' || i != offset - 1) {
				temp_line[line_pos++] = buff[i];
				if (line_pos >= 512)
					return MIDB_RDWR_ERROR;
			}
		}

		if (count >= lines) {
			pback.reset();
			return MIDB_RESULT_OK;
		}
		last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
		if (offset >= buff.size()) {
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

int enum_subscriptions(const char *path, std::vector<enum_folder_t> &pfile,
    int *perrno) try
{
	char temp_line[512];
	struct pollfd pfd_read;
	
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto buff = "P-SUBL "s + path + "\r\n";
	auto wrret = write(pback->sockd, buff.c_str(), buff.size());
	if (wrret < 0 || static_cast<size_t>(wrret) != buff.size())
		return MIDB_RDWR_ERROR;

	buff.resize(256 * 1024);
	int count = 0, lines = -1;
	size_t offset = 0, last_pos = 0, line_pos = 0;
	while (true) {
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
			return MIDB_RDWR_ERROR;
		auto read_len = read(pback->sockd, &buff[offset], buff.size() - offset);
		if (read_len <= 0)
			return MIDB_RDWR_ERROR;
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (size_t i = 0; i < offset - 1 && i < 36; ++i) {
				if (buff[i] != '\r' || buff[i+1] != '\n')
					continue;
				if (strncmp(buff.c_str(), "TRUE ", 5) == 0) {
					lines = strtol(&buff[5], nullptr, 0);
					if (lines < 0)
						return MIDB_RDWR_ERROR;
					last_pos = i + 2;
					line_pos = 0;
					break;
				} else if (strncmp(buff.c_str(), "FALSE ", 6) == 0) {
					pback.reset();
					*perrno = strtol(&buff[6], nullptr, 0);
					return MIDB_RESULT_ERROR;
				}
				return MIDB_RDWR_ERROR;
			}
			if (-1 == lines) {
				if (offset > 1024)
					return MIDB_RDWR_ERROR;
				continue;
			}
		}

		for (size_t i = last_pos; i < offset; ++i) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				char *end = nullptr;
				uint64_t fid = strtoul(temp_line, &end, 0);
				while (HX_isspace(*end))
					++end;
				pfile.emplace_back(fid, end);
				line_pos = 0;
			} else if (buff[i] != '\r' || i != offset - 1) {
				temp_line[line_pos++] = buff[i];
				if (line_pos > 150)
					return MIDB_RDWR_ERROR;
			}
		}

		if (count >= lines) {
			pback.reset();
			return MIDB_RESULT_OK;
		}
		last_pos = buff[offset-1] == '\r' ? offset - 1 : offset;
		if (offset >= buff.size()) {
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

int insert_mail(const char *path, const std::string &folder,
    const char *file_name, const char *flags_string, long time_stamp,
    int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "M-INST %s %s %s %s %ld\r\n",
	              path, folder.c_str(), file_name, flags_string, time_stamp);
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

int remove_mail(const char *path, const std::string &folder,
    const std::vector<MITEM *> &plist, int *perrno)
{
	char buff[128*1025];

	if (plist.empty())
		return MIDB_RESULT_OK;
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "M-DELE %s %s",
	              path, folder.c_str());
	int cmd_len = length;
	
	for (auto pitem : plist) {
		buff[length++] = ' ';
		auto temp_len = pitem->mid.size();
		memcpy(&buff[length], pitem->mid.c_str(), temp_len);
		length += temp_len;
		if (length <= 128*1024)
			continue;
		buff[length++] = '\r';
		buff[length++] = '\n';
		auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
		if (ret != 0)
			return ret;
		if (0 == strncmp(buff, "TRUE", 4)) {
			length = gx_snprintf(buff, std::size(buff), "M-DELE %s %s",
			         path, folder.c_str());
			continue;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pback.reset();
			*perrno = strtol(buff + 6, nullptr, 0);
			return MIDB_RESULT_ERROR;
		}
		return MIDB_RDWR_ERROR;
	}

	if (length > cmd_len) {
		buff[length++] = '\r';
		buff[length++] = '\n';
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

static unsigned int s_to_flagbits(std::string_view s)
{
	unsigned int fl = 0;
	if (s.find(midb_flag::answered) != s.npos) fl |= FLAG_ANSWERED;
	if (s.find(midb_flag::unsent) != s.npos)   fl |= FLAG_DRAFT;
	if (s.find(midb_flag::flagged) != s.npos)  fl |= FLAG_FLAGGED;
	if (s.find(midb_flag::deleted) != s.npos)  fl |= FLAG_DELETED;
	if (s.find(midb_flag::seen) != s.npos)     fl |= FLAG_SEEN;
	if (s.find(midb_flag::recent) != s.npos)   fl |= FLAG_RECENT;
	if (s.find(midb_flag::forwarded) != s.npos)fl |= FLAG_FORWARDED;
	return fl;
}

static std::string flagbits_to_s(unsigned int v)
{
	std::string s;
	if (v & FLAG_ANSWERED) s += midb_flag::answered;
	if (v & FLAG_DRAFT)    s += midb_flag::unsent;
	if (v & FLAG_FLAGGED)  s += midb_flag::flagged;
	if (v & FLAG_DELETED)  s += midb_flag::deleted;
	if (v & FLAG_SEEN)     s += midb_flag::seen;
	if (v & FLAG_RECENT)   s += midb_flag::recent;
	if (v & FLAG_FORWARDED)s += midb_flag::forwarded;
	return s;
}

static bool get_digest_integer(const Json::Value &jv, const char *tag, int &i)
{
	if (jv.type() != Json::ValueType::objectValue || !jv.isMember(tag))
		return false;
	i = jv[tag].asUInt();
	return true;
}

static unsigned int di_to_flagbits(const Json::Value &jv)
{
	unsigned int fl = 0, v;
	if (jv.type() != Json::ValueType::objectValue)
		return fl;
	if (jv.isMember("replied") && (v = jv["replied"].asUInt()) != 0)
		fl |= FLAG_ANSWERED;
	if (jv.isMember("unsent") && (v = jv["unsent"].asUInt()) != 0)
		fl |= FLAG_DRAFT;
	if (jv.isMember("flag") && (v = jv["flag"].asUInt()) != 0)
		fl |= FLAG_FLAGGED;
	if (jv.isMember("deleted") && (v = jv["deleted"].asUInt()) != 0)
		fl |= FLAG_DELETED;
	if (jv.isMember("read") && (v = jv["read"].asUInt()) != 0)
		fl |= FLAG_SEEN;
	if (jv.isMember("recent") && (v = jv["recent"].asUInt()) != 0)
		fl |= FLAG_RECENT;
	if (jv.isMember("forwarded") && (v = jv["forwarded"].asUInt()) != 0)
		fl |= FLAG_FORWARDED;
	return fl;
}

int list_deleted(const char *path, const std::string &folder, XARRAY *pxarray,
    int *perrno) try
{
	char *pspace;
	char *pspace1;
	char temp_line[512];
	struct pollfd pfd_read;

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto EH = HX::make_scope_exit([=]() { pxarray->clear(); });
	auto buff = fmt::format("P-DELL {} {}\r\n", path, folder);
	auto wrret = write(pback->sockd, buff.c_str(), buff.size());
	if (wrret < 0 || static_cast<size_t>(wrret) != buff.size())
		return MIDB_RDWR_ERROR;
	
	buff.resize(256 * 1024);
	int count = 0, lines = -1;
	size_t offset = 0, last_pos = 0, line_pos = 0;
	BOOL b_format_error = false;
	while (true) {
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
			return MIDB_RDWR_ERROR;
		auto read_len = read(pback->sockd, &buff[offset], buff.size() - offset);
		if (read_len <= 0)
			return MIDB_RDWR_ERROR;
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (size_t i = 0; i < offset - 1 && i < 36; ++i) {
				if (buff[i] != '\r' || buff[i+1] != '\n')
					continue;
				if (strncmp(buff.c_str(), "TRUE ", 5) == 0) {
					lines = strtol(&buff[5], nullptr, 0);
					if (lines < 0)
						return MIDB_RDWR_ERROR;
					last_pos = i + 2;
					line_pos = 0;
					break;
				} else if (strncmp(buff.c_str(), "FALSE ", 6) == 0) {
					pback.reset();
					EH.release(); // ?
					*perrno = strtol(&buff[6], nullptr, 0);
					return MIDB_RESULT_ERROR;
				}
			}
			if (-1 == lines) {
				if (offset > 1024)
					return MIDB_RDWR_ERROR;
				continue;
			}
		}

		for (size_t i = last_pos; i < offset; ++i) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				pspace = strchr(temp_line, ' ');
				if (NULL != pspace) {
					pspace1 = strchr(pspace + 1, ' ');
					if (NULL != pspace1) {
						*pspace++ = '\0';
						*pspace1++ = '\0';
						MITEM mitem;
						try {
							mitem.mid = pspace;
						} catch (...) {
							b_format_error = TRUE;
						}
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
				temp_line[line_pos++] = buff[i];
				if (line_pos >= 128)
					return MIDB_RDWR_ERROR;
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
		if (offset >= buff.size()) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1779: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

int fetch_simple_uid(const char *path, const std::string &folder,
    const imap_seq_list &list, XARRAY *pxarray, int *perrno) try
{
	char *pspace;
	char *pspace1;
	char *pspace2;
	char temp_line[1024];
	struct pollfd pfd_read;
	std::string buff;

	buff.resize(64 * 1024);
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	
	for (const auto &seq : list) {
		auto pseq = &seq;
		auto cbuf = fmt::format("P-SIMU {} {} {} {}\r\n",
		            path, folder, pseq->lo, pseq->hi);
		auto wrret = write(pback->sockd, cbuf.c_str(), cbuf.size());
		if (wrret < 0 || static_cast<size_t>(wrret) != cbuf.size())
			return MIDB_RDWR_ERROR;
		
		int count = 0, lines = -1;
		size_t offset = 0, last_pos = 0, line_pos = 0;
		BOOL b_format_error = false;
		while (true) {
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
				return MIDB_RDWR_ERROR;
			auto read_len = read(pback->sockd, &buff[offset], buff.size() - offset);
			if (read_len <= 0)
				return MIDB_RDWR_ERROR;
			offset += read_len;
			buff[offset] = '\0';

			if (-1 == lines) {
				for (size_t i = 0; i < offset - 1 && i < 36; ++i) {
					if (buff[i] != '\r' || buff[i+1] != '\n')
						continue;
					if (strncmp(buff.c_str(), "TRUE ", 5) == 0) {
						lines = strtol(&buff[5], nullptr, 0);
						if (lines < 0)
							return MIDB_RDWR_ERROR;
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (strncmp(buff.c_str(), "FALSE ", 6) == 0) {
						pback.reset();
						*perrno = strtol(&buff[6], nullptr, 0);
						return MIDB_RESULT_ERROR;
					}
				}
				if (-1 == lines) {
					if (offset > 1024)
						return MIDB_RDWR_ERROR;
					continue;
				}
			}

			for (size_t i = last_pos; i < offset; ++i) {
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
								*pspace++ = '\0';
								*pspace1++ = '\0';
								*pspace2++ = '\0';
								int uid = strtol(pspace1, nullptr, 0);
								if (pxarray->append(MITEM{}, uid) >= 0) {
									auto num = pxarray->get_capacity();
									assert(num > 0);
									auto pitem = pxarray->get_item(num - 1);
									pitem->uid = uid;
									try {
										pitem->mid = pspace;
									} catch (const std::bad_alloc &) {
										b_format_error = TRUE;
									}
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
					temp_line[line_pos++] = buff[i];
					if (line_pos >= 128)
						return MIDB_RDWR_ERROR;
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
			if (offset >= buff.size()) {
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
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1781: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

int fetch_detail_uid(const char *path, const std::string &folder,
    const imap_seq_list &list, XARRAY *pxarray, int *perrno) try
{
	char *pspace;
	char temp_line[257*1024];
	struct pollfd pfd_read;
	std::string buff;

	buff.resize(64 * 1024);
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto EH = HX::make_scope_exit([=]() {
		pxarray->clear();
	});
	
	for (const auto &seq : list) {
		auto pseq = &seq;
		auto cbuf = fmt::format("P-DTLU {} {} {} {}\r\n", path, folder, pseq->lo, pseq->hi);
		auto wrret = write(pback->sockd, cbuf.c_str(), cbuf.size());
		if (wrret < 0 || static_cast<size_t>(wrret) != cbuf.size())
			return MIDB_RDWR_ERROR;
		
		int count = 0, lines = -1;
		size_t offset = 0, last_pos = 0, line_pos = 0;
		BOOL b_format_error = false;
		while (true) {
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
				return MIDB_RDWR_ERROR;
			auto read_len = read(pback->sockd, &buff[offset], buff.size() - offset);
			if (read_len <= 0)
				return MIDB_RDWR_ERROR;
			offset += read_len;
			buff[offset] = '\0';

			if (-1 == lines) {
				for (size_t i = 0; i < offset - 1 && i < 36; ++i) {
					if (buff[i] != '\r' || buff[i+1] != '\n')
						continue;
					if (strncmp(buff.c_str(), "TRUE ", 5) == 0) {
						lines = strtol(&buff[5], nullptr, 0);
						if (lines < 0)
							return MIDB_RDWR_ERROR;
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (strncmp(buff.c_str(), "FALSE ", 6) == 0) {
						pback.reset();
						*perrno = strtol(&buff[6], nullptr, 0);
						return MIDB_RESULT_ERROR;
					}
				}
				if (-1 == lines) {
					if (offset > 1024)
						return MIDB_RDWR_ERROR;
					continue;
				}
			}

			for (size_t i = last_pos; i < offset; ++i) {
				if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
					count ++;
				} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
					pspace = strchr(temp_line, ' ');
					int temp_len = pspace == nullptr ? 0 :
					           line_pos - (pspace + 1 - temp_line);
					MITEM mitem;
					if (pspace == nullptr ||
					    !str_to_json(std::string_view(&pspace[1], temp_len), mitem.digest)) {
						b_format_error = TRUE;
					} else if (get_digest(mitem.digest, "file", mitem.mid) &&
					    get_digest_integer(mitem.digest, "uid", mitem.uid)) {
						*pspace++ = '\0';
						auto mitem_uid = mitem.uid;
						if (pxarray->append(std::move(mitem), mitem_uid) >= 0) {
							auto num = pxarray->get_capacity();
							assert(num > 0);
							auto pitem = pxarray->get_item(num - 1);
							pitem->flag_bits = FLAG_LOADED | di_to_flagbits(pitem->digest);
						}
					}
					line_pos = 0;
				} else if (buff[i] != '\r' || i != offset - 1) {
					temp_line[line_pos++] = buff[i];
					if (line_pos >= 257 * 1024)
						return MIDB_RDWR_ERROR;
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
			if (offset >= buff.size()) {
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

int set_flags(const char *path, const std::string &folder,
    const std::string &mid_string, unsigned int flag_bits,
    unsigned int *new_bits, int *perrno)
{
	char buff[1024];
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto flags_string = flagbits_to_s(flag_bits);
	auto length = gx_snprintf(buff, std::size(buff), "P-SFLG %s %s %s (%s)\r\n",
	              path, folder.c_str(), mid_string.c_str(), flags_string.c_str());
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		if (new_bits != nullptr)
			*new_bits = ~0U;
		if (buff[5] == '\r' || buff[5] == '\n')
			return MIDB_RESULT_OK;
		auto ptr = &buff[5];
		if (!HX_isspace(*ptr))
			return MIDB_RDWR_ERROR;
		while (HX_isspace(*ptr))
			++ptr;
		if (*ptr == '-')
			return MIDB_RESULT_OK;
		if (*ptr != '(')
			return MIDB_RDWR_ERROR;
		auto bg = ptr + 1;
		ptr = strchr(bg, ')');
		if (ptr == nullptr)
			return MIDB_RDWR_ERROR;
		if (new_bits != nullptr)
			*new_bits = s_to_flagbits(std::string_view(bg, ptr - bg));
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}
	
int unset_flags(const char *path, const std::string &folder,
    const std::string &mid_string, unsigned int flag_bits,
    unsigned int *new_bits, int *perrno)
{
	char buff[1024];
	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto flags_string = flagbits_to_s(flag_bits);
	auto length = gx_snprintf(buff, std::size(buff), "P-RFLG %s %s %s (%s)\r\n",
	              path, folder.c_str(), mid_string.c_str(), flags_string.c_str());
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		if (new_bits != nullptr)
			*new_bits = -1;
		if (buff[5] == '\r' || buff[5] == '\n')
			return MIDB_RESULT_OK;
		auto ptr = &buff[5];
		if (!HX_isspace(*ptr))
			return MIDB_RDWR_ERROR;
		while (HX_isspace(*ptr))
			++ptr;
		if (*ptr == '-')
			return MIDB_RESULT_OK;
		if (*ptr != '(')
			return MIDB_RDWR_ERROR;
		auto bg = ptr + 1;
		ptr = strchr(bg, ')');
		if (ptr == nullptr)
			return MIDB_RDWR_ERROR;
		if (new_bits != nullptr)
			*new_bits = s_to_flagbits(std::string_view(bg, ptr - bg));
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
}
	
int get_flags(const char *path, const std::string &folder,
    const std::string &mid_string, unsigned int *pflag_bits, int *perrno)
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "P-GFLG %s %s %s\r\n",
	              path, folder.c_str(), mid_string.c_str());
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
	
int copy_mail(const char *path, const std::string &src_folder,
    const std::string &mid_string, const std::string &dst_folder,
    std::string &dst_mid, int *perrno) try
{
	char buff[1024];

	auto pback = get_connection(path);
	if (pback == nullptr)
		return MIDB_NO_SERVER;
	auto length = gx_snprintf(buff, std::size(buff), "M-COPY %s %s %s %s\r\n",
	              path, src_folder.c_str(), mid_string.c_str(), dst_folder.c_str());
	auto ret = rw_command(pback->sockd, buff, length, std::size(buff));
	if (ret != 0)
		return ret;
	if (0 == strncmp(buff, "TRUE", 4)) {
		pback.reset();
		dst_mid = &buff[5];
		return MIDB_RESULT_OK;
	} else if (0 == strncmp(buff, "FALSE ", 6)) {
		pback.reset();
		*perrno = strtol(buff + 6, nullptr, 0);
		return MIDB_RESULT_ERROR;
	}
	return MIDB_RDWR_ERROR;
} catch (const std::bad_alloc &) {
	return MIDB_LOCAL_ENOMEM;
}

}

static ssize_t read_line(int sockd, char *buff, size_t length)
{
	if (length == 0)
		return 0;
	size_t offset = 0;
	--length;
	struct pollfd pfd_read;

	while (true) {
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
			return -ETIMEDOUT;
		auto read_len = read(sockd, buff + offset,  length - offset);
		if (read_len < 0)
			return read_len;
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
		if (length == offset)
			return -ENOBUFS;
	}
}

static int connect_midb(const char *ip_addr, uint16_t port)
{
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
	pfd_read.fd = sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1) {
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
