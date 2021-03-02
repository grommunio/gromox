// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#define DECLARE_API_STATIC
#include <mutex>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include <gromox/single_list.hpp>
#include <gromox/array.hpp>
#include <gromox/xarray.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/list_file.hpp>
#include <gromox/config_file.hpp>
#include <gromox/double_list.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <unistd.h>
#include <csignal>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <poll.h>
#define SOCKET_TIMEOUT			60

#define MIDB_RESULT_OK			0
#define MIDB_NO_SERVER			1
#define MIDB_RDWR_ERROR			2
#define MIDB_RESULT_ERROR		3
#define MIDB_MAILBOX_FULL		4

#define FLAG_RECENT				0x1
#define FLAG_ANSWERED			0x2
#define FLAG_FLAGGED			0x4
#define FLAG_DELETED			0x8
#define FLAG_SEEN				0x10
#define FLAG_DRAFT				0x20

#define FLAG_LOADED				0x80

struct MITEM {
	SINGLE_LIST_NODE node;
	char mid[128];
	int id;
	int uid;
	char flag_bits;
	MEM_FILE f_digest;
};

struct SEQUENCE_NODE {
	DOUBLE_LIST_NODE node;
	int min;
	int max;
};

struct BACK_SVR {
	DOUBLE_LIST_NODE node;
	char prefix[256];
	int prefix_len;
	char ip_addr[40];
	int port;
	DOUBLE_LIST conn_list;
};

struct BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
	BACK_SVR *psvr;
};

struct MSG_UNIT {
	SINGLE_LIST_NODE node;
	size_t size;
	char file_name[128];
	BOOL b_deleted;
};

static void* scan_work_func(void *param);

static BOOL read_line(int sockd, char *buff, int length);

static int connect_midb(const char *ip_addr, int port);
static BOOL get_digest_string(const char *src, int length, const char *tag, char *buff, int buff_len);
static BOOL get_digest_integer(const char *src, int length, const char *tag, int *pinteger);
static int list_mail(const char *path, const char *folder, ARRAY *parray, int *pnum, uint64_t *psize);
static int delete_mail(const char *path, const char *folder, SINGLE_LIST *plist);
static int get_mail_id(const char *path, const char *folder, const char *mid_string, unsigned int *id);
static int get_mail_uid(const char *path, const char *folder, const char *mid_string, unsigned int *uid);
static int summary_folder(const char *path, const char *folder, int *exists, int *recent, int *unseen, unsigned long *uidvalid, unsigned int *uidnext, int *first_seen, int *perrno);
static int make_folder(const char *path, const char *folder, int *perrno);
static int remove_folder(const char *path, const char *folder, int *perrno);
static int ping_mailbox(const char *path, int *perrno);
static int rename_folder(const char *path, const char *src_name, const char *dst_name, int *perrno);
static int subscribe_folder(const char *path, const char *folder, int *perrno);
static int unsubscribe_folder(const char *path, const char *folder, int *perrno);
static int enum_folders(const char *path, MEM_FILE *, int *perrno);
static int enum_subscriptions(const char *path, MEM_FILE *, int *perrno);
static int insert_mail(const char *path, const char *folder, const char *file_name, const char *flags_string, long time_stamp, int *perrno);
static int remove_mail(const char *path, const char *folder, SINGLE_LIST *, int *perrno);
static int list_simple(const char *path, const char *folder, XARRAY *, int *perrno);
static int list_deleted(const char *path, const char *folder, XARRAY *, int *perrno);
static int list_detail(const char *path, const char *folder, XARRAY *pxarray, int *perrno);
static void free_result(XARRAY *pxarray);
static int fetch_simple(const char *path, const char *folder, DOUBLE_LIST *, XARRAY *, int *perrno);
static int fetch_detail(const char *path, const char *folder, DOUBLE_LIST *, XARRAY *, int *perrno);
static int fetch_simple_uid(const char *path, const char *folder, DOUBLE_LIST *, XARRAY *, int *perrno);
static int fetch_detail_uid(const char *path, const char *folder, DOUBLE_LIST *, XARRAY *, int *perrno);
static int set_mail_flags(const char *path, const char *folder, const char *mid_string, int flag_bits, int *perrno);
static int unset_mail_flags(const char *path, const char *folder, const char *mid_string, int flag_bits, int *perrno);
static int get_mail_flags(const char *path, const char *folder, const char *mid_string, int *pflag_bits, int *perrno);
static int copy_mail(const char *path, const char *src_folder, const char *mid_string, const char *dst_folder, char *dst_mid, int *perrno);
static int imap_search(const char *path, const char *folder, const char *charset, int argc, char **argv, char *ret_buff, int *plen, int *perrno);
static int imap_search_uid(const char *path, const char *folder, const char *charset, int argc, char **argv, char *ret_buff, int *plen, int *perrno);
static BOOL check_full(const char *path);
static void console_talk(int argc, char **argv, char *result, int length);

static int g_conn_num;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_server_list;
static std::mutex g_server_lock;
static LIB_BUFFER *g_file_allocator;
static int g_file_ratio;

static bool list_file_read_midb(const char *filename)
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
		auto pserver = static_cast<BACK_SVR *>(malloc(sizeof(BACK_SVR)));
		if (pserver == nullptr) {
			printf("[midb_agent]: Failed to allocate memory for midb\n");
			return false;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, "/");
		pserver->prefix_len = 1;
		strcpy(pserver->ip_addr, "::1");
		pserver->port = 5555;
		double_list_init(&pserver->conn_list);
		double_list_append_as_tail(&g_server_list, &pserver->node);
		for (decltype(g_conn_num) j = 0; j < g_conn_num; ++j) {
			auto pback = static_cast<BACK_CONN *>(malloc(sizeof(BACK_CONN)));
			if (pback == nullptr)
				continue;
			pback->node.pdata = pback;
			pback->sockd = -1;
			pback->psvr = pserver;
			double_list_append_as_tail(&g_lost_list, &pback->node);
		}
		return true;
	}
	for (decltype(list_num) i = 0; i < list_num; ++i) {
		auto pserver = static_cast<BACK_SVR *>(malloc(sizeof(BACK_SVR)));
		if (pserver == nullptr) {
			printf("[midb_agent]: Failed to allocate memory for midb\n");
			return false;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, pitem[i].prefix);
		pserver->prefix_len = strlen(pserver->prefix);
		HX_strlcpy(pserver->ip_addr, pitem[i].ip_addr, GX_ARRAY_SIZE(pserver->ip_addr));
		pserver->port = pitem[i].port;
		double_list_init(&pserver->conn_list);
		double_list_append_as_tail(&g_server_list, &pserver->node);
		for (decltype(g_conn_num) j = 0; j < g_conn_num; ++j) {
			auto pback = static_cast<BACK_CONN *>(malloc(sizeof(BACK_CONN)));
			if (pback == nullptr)
				continue;
			pback->node.pdata = pback;
			pback->sockd = -1;
			pback->psvr = pserver;
			double_list_append_as_tail(&g_lost_list, &pback->node);
		}
	}
	return true;
}

static BOOL svc_midb_agent(int reason, void **ppdata)
{
	char *psearch;
	char file_name[256];
	char config_path[256];
    DOUBLE_LIST_NODE *pnode;

	switch(reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		
		g_notify_stop = TRUE;

		double_list_init(&g_server_list);
		double_list_init(&g_lost_list);
		HX_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		snprintf(config_path, GX_ARRAY_SIZE(config_path), "%s.cfg", file_name);
		auto pconfig = config_file_initd(config_path, get_config_path());
		if (NULL == pconfig) {
			printf("[midb_agent]: config_file_initd %s: %s\n",
			       config_path, strerror(errno));
			return FALSE;
		}
		
		auto str_value = config_file_get_value(pconfig, "CONNECTION_NUM");
		if (NULL == str_value) {
			g_conn_num = 5;
			config_file_set_value(pconfig, "CONNECTION_NUM", "5");
		} else {
			g_conn_num = atoi(str_value);
			if (g_conn_num < 2 || g_conn_num > 100) {
				g_conn_num = 5;
				config_file_set_value(pconfig, "CONNECTION_NUM", "5");
			}
		}
		printf("[midb_agent]: midb connection number is %d\n", g_conn_num);
		
		str_value = config_file_get_value(pconfig, "CONTEXT_AVERAGE_MEM");
		g_file_ratio = str_value == nullptr ? 1024 : strtoul(str_value, nullptr, 0);
		if (g_file_ratio > 0) {
			printf("[midb_agent]: context average number is %d\n", g_file_ratio);
		} else {
			printf("[midb_agent]: memory pool is switched off\n");
		}

		if (!list_file_read_midb("midb_list.txt"))
			return false;
		if (g_file_ratio > 0) {
			g_file_allocator = lib_buffer_init(FILE_ALLOC_SIZE, 
								get_context_num()*g_file_ratio, TRUE);
			
			if (NULL == g_file_allocator) {
				printf("[midb_agent]: failed to init memory pool\n");
				return FALSE;
			}
		}

		g_notify_stop = FALSE;
		int ret = pthread_create(&g_scan_id, nullptr, scan_work_func, nullptr);
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
		    !E(remove_mail) || !E(list_simple) || !E(list_deleted) ||
		    !E(list_detail) || !E(fetch_simple) || !E(fetch_detail) ||
		    !E(fetch_simple_uid) || !E(fetch_detail_uid) ||
		    !E(free_result) || !E(set_mail_flags) ||
		    !E(unset_mail_flags) || !E(get_mail_flags) ||
		    !E(copy_mail) || !E(imap_search) || !E(imap_search_uid) ||
		    !E(check_full)) {
			printf("[midb_agent]: failed to register services\n");
			return FALSE;
		}
#undef E
		if (FALSE == register_talk(console_talk)) {
			printf("[midb_agent]: failed to register console talk\n");
			return FALSE;
		}

		return TRUE;
	}
	case PLUGIN_FREE:
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_join(g_scan_id, NULL);
		}

		while ((pnode = double_list_pop_front(&g_lost_list)) != nullptr)
			free(pnode->pdata);

		while ((pnode = double_list_pop_front(&g_server_list)) != nullptr) {
			auto pserver = static_cast<BACK_SVR *>(pnode->pdata);
			while ((pnode = double_list_pop_front(&pserver->conn_list)) != nullptr) {
				auto pback = static_cast<BACK_CONN *>(pnode->pdata);
				write(pback->sockd, "QUIT\r\n", 6);
				close(pback->sockd);
				free(pback);
			}
			free(pserver);
		}

		double_list_free(&g_lost_list);
		double_list_free(&g_server_list);
		if (NULL != g_file_allocator) {
			lib_buffer_free(g_file_allocator);
			g_file_allocator = NULL;
		}

		return TRUE;
	}
	return false;
}
SVC_ENTRY(svc_midb_agent);

static void *scan_work_func(void *param)
{
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	DOUBLE_LIST_NODE *pnode1;
	BACK_SVR *pserver;
	BACK_CONN *pback;
	time_t now_time;
	int tv_msec;
	char temp_buff[1024];
	struct pollfd pfd_read;

	double_list_init(&temp_list);

	while (FALSE == g_notify_stop) {
		std::unique_lock sv_hold(g_server_lock);
		time(&now_time);
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			pserver = (BACK_SVR*)pnode->pdata;
			ptail = double_list_get_tail(&pserver->conn_list);
			while ((pnode1 = double_list_pop_front(&pserver->conn_list)) != nullptr) {
				pback = (BACK_CONN*)pnode1->pdata;
				if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
					double_list_append_as_tail(&temp_list, &pback->node);
				} else {
					double_list_append_as_tail(&pserver->conn_list,
						&pback->node);
				}

				if (pnode1 == ptail) {
					break;
				}
			}
		}
		sv_hold.unlock();

		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			pback = (BACK_CONN*)pnode->pdata;
			write(pback->sockd, "PING\r\n", 6);
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec) ||
				read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				sv_hold.lock();
				double_list_append_as_tail(&g_lost_list, &pback->node);
				sv_hold.unlock();
			} else {
				time(&pback->last_time);
				sv_hold.lock();
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				sv_hold.unlock();
			}
		}

		sv_hold.lock();
		while ((pnode = double_list_pop_front(&g_lost_list)) != nullptr)
			double_list_append_as_tail(&temp_list, pnode);
		sv_hold.unlock();

		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_midb(pback->psvr->ip_addr,
							pback->psvr->port);
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				sv_hold.lock();
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				sv_hold.unlock();
			} else {
				sv_hold.lock();
				double_list_append_as_tail(&g_lost_list, &pback->node);
				sv_hold.unlock();
			}
		}
		sleep(1);
	}
	return NULL;
}

static BACK_CONN *get_connection(const char *prefix)
{
	int i;
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
		pnode=double_list_get_after(&g_server_list, pnode)) {
		pserver = (BACK_SVR*)pnode->pdata;
		if (0 == strncmp(pserver->prefix, prefix, pserver->prefix_len)) {
			break;
		}
	}
	
	if (NULL == pnode) {
		return NULL;
	}

	std::unique_lock sv_hold(g_server_lock);
	pnode = double_list_pop_front(&pserver->conn_list);
	sv_hold.unlock();
	if (NULL == pnode) {
		for (i=0; i<SOCKET_TIMEOUT; i++) {
			sleep(1);
			sv_hold.lock();
			pnode = double_list_pop_front(&pserver->conn_list);
			sv_hold.unlock();
			if (NULL != pnode) {
				break;
			}
		}
		if (NULL == pnode) {
			return NULL;
		}
	}
	return (BACK_CONN*)pnode->pdata;
}

static int list_mail(const char *path, const char *folder, ARRAY *parray,
	int *pnum, uint64_t *psize)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	BOOL b_fail;
	int last_pos;
	int read_len;
	int line_pos;
	MSG_UNIT msg;
	char *pspace;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-UIDL %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	*psize = 0;
	count = 0;
	offset = 0;
	lines = -1;
	b_fail = FALSE;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
		}
		offset += read_len;
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							goto RDWR_ERROR;
						}
						*pnum = lines;
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						std::unique_lock sv_hold(g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						return MIDB_RESULT_ERROR;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					goto RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				pspace = static_cast<char *>(memchr(temp_line, ' ', line_pos));
				if (NULL == pspace) {
					goto RDWR_ERROR;
				}
				*pspace = '\0';
				if (strlen(temp_line) > 127) {
					goto RDWR_ERROR;
				}
				pspace ++;
				temp_line[line_pos] = '\0';

				strcpy(msg.file_name, temp_line);
				msg.size = atoi(pspace);
				*psize += msg.size;
				msg.b_deleted = FALSE;
				if (array_append(parray, &msg) < 0) {
					b_fail = TRUE;
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 256) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			sv_hold.unlock();
			if (TRUE == b_fail) {
				array_clear(parray);
				return MIDB_RESULT_ERROR;
			} else {
				return MIDB_RESULT_OK;
			}
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

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

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	sv_hold.unlock();
	array_clear(parray);
	return MIDB_RDWR_ERROR;
}

static int delete_mail(const char *path, const char *folder, SINGLE_LIST *plist)
{
	int length;
	int cmd_len;
	int temp_len;
	MSG_UNIT *pmsg;
	BACK_CONN *pback;
	char buff[128*1025];
	SINGLE_LIST_NODE *pnode;


	if (0 == single_list_get_nodes_num(plist)) {
		return MIDB_RESULT_OK;
	}
	
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-DELE %s %s", path, folder);
	cmd_len = length;
	
	for (pnode=single_list_get_head(plist); NULL!=pnode;
		pnode=single_list_get_after(plist, pnode)) {
		pmsg = (MSG_UNIT*)pnode->pdata;
		buff[length] = ' ';
		length ++;
		temp_len = strlen(pmsg->file_name);
		memcpy(buff + length, pmsg->file_name, temp_len);
		length += temp_len;
		if (length > 128*1024) {
			buff[length] = '\r';
			length ++;
			buff[length] = '\n';
			length ++;
			if (length != write(pback->sockd, buff, length)) {
				goto DELETE_ERROR;
			}
			if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
				goto DELETE_ERROR;
			} else {
				if (0 == strncmp(buff, "TRUE", 4)) {
					length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-DELE %s %s", path, folder);
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					std::unique_lock sv_hold(g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list,
						&pback->node);
					return MIDB_RESULT_ERROR;	
				} else {
					goto DELETE_ERROR;
				}
			}
		}
	}

	if (length > cmd_len) {
		buff[length] = '\r';
		length ++;
		buff[length] = '\n';
		length ++;
		if (length != write(pback->sockd, buff, length)) {
			goto DELETE_ERROR;
		}
		if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
			goto DELETE_ERROR;
		} else {
			if (0 == strncmp(buff, "TRUE", 4)) {
				std::unique_lock sv_hold(g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				return MIDB_RESULT_OK;
			} else if (0 == strncmp(buff, "FALSE ", 6)) {
				std::unique_lock sv_hold(g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				return MIDB_RESULT_ERROR;	
			} else {
				goto DELETE_ERROR;
			}
		}
	}

 DELETE_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int imap_search(const char *path, const char *folder,
    const char *charset, int argc, char **argv, char *ret_buff,
    int *plen, int *perrno)
{
	int i;
	int length;
	int length1;
	BACK_CONN *pback;
	size_t encode_len;
	char buff[256*1025];
	char buff1[16*1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SRHL %s %s %s ",
				path, folder, charset);
	length1 = 0;
	for (i=0; i<argc; i++) {
		length1 += gx_snprintf(buff1 + length1, GX_ARRAY_SIZE(buff1) - length1,
					"%s", argv[i]) + 1;
	}
	buff1[length1] = '\0';
	length1 ++;
	encode64(buff1, length1, buff + length, sizeof(buff) - length,
		&encode_len);
	length += encode_len;
	
	buff[length] = '\r';
	length ++;
	buff[length] = '\n';
	length ++;
	
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			sv_hold.unlock();
			length = strlen(buff + 4);
			if (0 == length) {
				*plen = 0;
				return MIDB_RESULT_OK;
			}
			/* trim the first space */
			length --;
			if (length > *plen) {
				length = *plen;
			} else {
				*plen = length;
			}
			/* ignore the first space */
			memcpy(ret_buff, buff + 4 + 1, length);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;

}

static int imap_search_uid(const char *path, const char *folder,
   const char *charset, int argc, char **argv, char *ret_buff,
   int *plen, int *perrno)
{
	int i;
	int length;
	int length1;
	BACK_CONN *pback;
	size_t encode_len;
	char buff[256*1025];
	char buff1[16*1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SRHU %s %s %s ",
				path, folder, charset);
	length1 = 0;
	for (i=0; i<argc; i++) {
		length1 += gx_snprintf(buff1 + length1, GX_ARRAY_SIZE(buff1) - length1,
					"%s", argv[i]) + 1;
	}
	buff1[length1] = '\0';
	length1 ++;
	encode64(buff1, length1, buff + length, sizeof(buff) - length,
		&encode_len);
	length += encode_len;
	
	buff[length] = '\r';
	length ++;
	buff[length] = '\n';
	length ++;
	
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			sv_hold.unlock();
			length = strlen(buff + 4);
			if (0 == length) {
				*plen = 0;
				return MIDB_RESULT_OK;
			}
			/* trim the first space */
			length --;
			if (length > *plen) {
				length = *plen;
			} else {
				*plen = length;
			}
			/* ignore the first space */
			memcpy(ret_buff, buff + 4 + 1, length);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;

}

static int get_mail_id(const char *path, const char *folder,
    const char *mid_string, unsigned int *pid)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-OFST %s %s %s UID ASC\r\n",
				path, folder, mid_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			*pid = atoi(buff + 5) + 1;
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;

}

static int get_mail_uid(const char *path, const char *folder,
    const char *mid_string, unsigned int *puid)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-UNID %s %s %s\r\n",
				path, folder, mid_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			*puid = atoi(buff + 5);
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int summary_folder(const char *path, const char *folder, int *pexists,
	int *precent, int *punseen, unsigned long *puidvalid,
	unsigned int *puidnext, int *pfirst_unseen, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	int exists, recent;
	int unseen, first_unseen;
	unsigned long uidvalid;
	unsigned int uidnext;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-FDDT %s %s UID ASC\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			if (6 != sscanf(buff, "TRUE %d %d %d %lu %u %d", &exists,
				&recent, &unseen, &uidvalid, &uidnext, &first_unseen)) {
				*perrno = -1;
				std::unique_lock sv_hold(g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
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
			
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}
	
static int make_folder(const char *path, const char *folder, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-MAKF %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int remove_folder(const char *path, const char *folder, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	

	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-REMF %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int ping_mailbox(const char *path, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	

	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-PING %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int rename_folder(const char *path, const char *src_name,
    const char *dst_name, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-RENF %s %s %s\r\n", path,
				src_name, dst_name);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int subscribe_folder(const char *path, const char *folder, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SUBF %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int unsubscribe_folder(const char *path, const char *folder, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-UNSF %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int enum_folders(const char *path, MEM_FILE *pfile, int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-ENUM %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
		}
		offset += read_len;
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							goto RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						std::unique_lock sv_hold(g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
					} else {
						goto RDWR_ERROR;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					goto RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				mem_file_writeline(pfile, temp_line);
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 512) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			return MIDB_RESULT_OK;
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

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

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;

}

static int enum_subscriptions(const char *path, MEM_FILE *pfile, int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;
	

	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SUBL %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
		}
		offset += read_len;
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							goto RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						std::unique_lock sv_hold(g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
					} else {
						goto RDWR_ERROR;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					goto RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				mem_file_writeline(pfile, temp_line);
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos > 150) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			return MIDB_RESULT_OK;
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

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

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;

}

static int insert_mail(const char *path, const char *folder,
    const char *file_name, const char *flags_string, long time_stamp,
    int *perrno)
{
	int length;
	char buff[1024];
	BACK_CONN *pback;

	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-INST %s %s %s %s %ld\r\n",
				path, folder, file_name, flags_string, time_stamp);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int remove_mail(const char *path, const char *folder,
    SINGLE_LIST *plist, int *perrno)
{
	int length;
	int cmd_len;
	int temp_len;
	MITEM *pitem;
	BACK_CONN *pback;
	char buff[128*1025];
	SINGLE_LIST_NODE *pnode;

	if (0 == single_list_get_nodes_num(plist)) {
		return MIDB_RESULT_OK;
	}
	
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-DELE %s %s", path, folder);
	cmd_len = length;
	
	for (pnode=single_list_get_head(plist); NULL!=pnode;
		pnode=single_list_get_after(plist, pnode)) {
		pitem = (MITEM*)pnode->pdata;
		buff[length] = ' ';
		length ++;
		temp_len = strlen(pitem->mid);
		memcpy(buff + length, pitem->mid, temp_len);
		length += temp_len;
		if (length > 128*1024) {
			buff[length] = '\r';
			length ++;
			buff[length] = '\n';
			length ++;
			if (length != write(pback->sockd, buff, length)) {
				goto RDWR_ERROR;
			}
			if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
				goto RDWR_ERROR;
			} else {
				if (0 == strncmp(buff, "TRUE", 4)) {
					length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-DELE %s %s", path, folder);
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					std::unique_lock sv_hold(g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list,
						&pback->node);
					*perrno = atoi(buff + 6);
					return MIDB_RESULT_ERROR;	
				} else {
					goto RDWR_ERROR;
				}
			}
		}
	}

	if (length > cmd_len) {
		buff[length] = '\r';
		length ++;
		buff[length] = '\n';
		length ++;
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
			goto RDWR_ERROR;
		} else {
			if (0 == strncmp(buff, "TRUE", 4)) {
				std::unique_lock sv_hold(g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				return MIDB_RESULT_OK;
			} else if (0 == strncmp(buff, "FALSE ", 6)) {
				std::unique_lock sv_hold(g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				*perrno = atoi(buff + 6);
				return MIDB_RESULT_ERROR;	
			} else {
				goto RDWR_ERROR;
			}
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int list_simple(const char *path, const char *folder, XARRAY *pxarray,
	int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	char *pspace;
	char *pspace1;
	MITEM mitem;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	BOOL b_format_error;
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SIML %s %s UID ASC\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	b_format_error = FALSE;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
		}
		offset += read_len;
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							goto RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						std::unique_lock sv_hold(g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					goto RDWR_ERROR;
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
						HX_strlcpy(mitem.mid, temp_line, GX_ARRAY_SIZE(mitem.mid));
						mitem.id = count;
						mitem.uid = atoi(pspace);
						mitem.flag_bits = 0;
						if (NULL != strchr(pspace1, 'A')) {
							mitem.flag_bits |= FLAG_ANSWERED;
						}
						if (NULL != strchr(pspace1, 'U')) {
							mitem.flag_bits |= FLAG_DRAFT;
						}
						if (NULL != strchr(pspace1, 'F')) {
							mitem.flag_bits |= FLAG_FLAGGED;
						}
						if (NULL != strchr(pspace1, 'D')) {
							mitem.flag_bits |= FLAG_DELETED;
						}
						if (NULL != strchr(pspace1, 'S')) {
							mitem.flag_bits |= FLAG_SEEN;
						}
						if (NULL != strchr(pspace1, 'R')) {
							mitem.flag_bits |= FLAG_RECENT;
						}
						xarray_append(pxarray, &mitem, mitem.uid);
					} else {
						b_format_error = TRUE;
					}
				} else {
					b_format_error = TRUE;
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 128) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			sv_hold.unlock();
			if (TRUE == b_format_error) {
				*perrno = -1;
				xarray_clear(pxarray);
				return MIDB_RESULT_ERROR;
			} else {
				return MIDB_RESULT_OK;
			}
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

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

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	sv_hold.unlock();
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static int list_deleted(const char *path, const char *folder, XARRAY *pxarray,
	int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	char *pspace;
	char *pspace1;
	MITEM mitem;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	BOOL b_format_error;
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-DELL %s %s UID ASC\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	b_format_error = FALSE;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
		}
		offset += read_len;
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							goto RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						std::unique_lock sv_hold(g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					goto RDWR_ERROR;
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
						HX_strlcpy(mitem.mid, pspace, GX_ARRAY_SIZE(mitem.mid));
						mitem.id = atoi(temp_line) + 1;
						mitem.uid = atoi(pspace1);
						mitem.flag_bits = FLAG_DELETED;
						xarray_append(pxarray, &mitem, mitem.uid);
					} else {
						b_format_error = TRUE;
					}
				} else {
					b_format_error = TRUE;
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 128) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			sv_hold.unlock();
			if (TRUE == b_format_error) {
				*perrno = -1;
				xarray_clear(pxarray);
				return MIDB_RESULT_ERROR;
			} else {
				return MIDB_RESULT_OK;
			}
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

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

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	sv_hold.unlock();
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static int list_detail(const char *path, const char *folder, XARRAY *pxarray,
	int *perrno)
{
	int i, num;
	int value;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	MITEM mitem;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[64*1025];
	char temp_line[257*1024];
	BOOL b_format_error;
	struct pollfd pfd_read;

	if (NULL == g_file_allocator) {
		*perrno = -2;
		return MIDB_RESULT_ERROR;
	}
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-LIST %s %s UID ASC\r\n",
				path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	b_format_error = FALSE;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 64*1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
		}
		offset += read_len;
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							goto RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						std::unique_lock sv_hold(g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					goto RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				if (TRUE == get_digest_string(temp_line, line_pos, "file",
					mitem.mid, sizeof(mitem.mid)) && TRUE == get_digest_integer(
					temp_line, line_pos, "uid", &mitem.uid)) {
					mitem.id = count;
					mitem.flag_bits = FLAG_LOADED;
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"replied", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_ANSWERED;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"unsent", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_DRAFT;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"flag", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_FLAGGED;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"deleted", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_DELETED;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"read", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_SEEN;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"recent", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_RECENT;
					}
					
					mem_file_init(&mitem.f_digest, g_file_allocator);
					mem_file_write(&mitem.f_digest, temp_line, line_pos);
					xarray_append(pxarray, &mitem, mitem.uid);
				} else {
					b_format_error = TRUE;
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 257*1024) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			sv_hold.unlock();
			if (TRUE == b_format_error) {
				num = xarray_get_capacity(pxarray);
				for (i=0; i<num; i++) {
					auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
					if (NULL != pitem) {
						mem_file_free(&pitem->f_digest);
					}
				}
				*perrno = -1;
				xarray_clear(pxarray);
				return MIDB_RESULT_ERROR;
			} else {
				return MIDB_RESULT_OK;
				
			}
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

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

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	sv_hold.unlock();
	num = xarray_get_capacity(pxarray);
	for (i=0; i<num; i++) {
		auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
		if (NULL != pitem) {
			mem_file_free(&pitem->f_digest);
		}
	}
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static void free_result(XARRAY *pxarray)
{
	int i, num;
	
	num = xarray_get_capacity(pxarray);
	for (i=0; i<num; i++) {
		auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
		if (NULL != pitem) {
			mem_file_free(&pitem->f_digest);
		}
	}
}

static int fetch_simple(const char *path, const char *folder,
    DOUBLE_LIST *plist, XARRAY *pxarray, int *perrno)
{
	int i;
	int uid;
	int num;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	MITEM mitem;
	char *pspace;
	char *pspace1;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[1024];
	char temp_line[1024];
	BOOL b_format_error;
	struct pollfd pfd_read;
	DOUBLE_LIST_NODE *pnode;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pseq = static_cast<SEQUENCE_NODE *>(pnode->pdata);
		if (pseq->max == -1) {
			if (pseq->min == -1)
				length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SIML %s %s UID ASC -1 1\r\n",
						path, folder);
			else
				length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SIML %s %s UID ASC %d "
						"1000000000\r\n", path, folder,
						pseq->min - 1);
		} else {
			length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SIML %s %s UID ASC %d %d\r\n",
						path, folder, pseq->min - 1,
						pseq->max - pseq->min + 1);
		}
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				goto RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, 1024 - offset);
			if (read_len <= 0) {
				goto RDWR_ERROR;
			}
			offset += read_len;
			
			if (-1 == lines) {
				for (i=0; i<offset-1&&i<36; i++) {
					if ('\r' == buff[i] && '\n' == buff[i + 1]) {
						if (0 == strncmp(buff, "TRUE ", 5)) {
							memcpy(num_buff, buff + 5, i - 5);
							num_buff[i - 5] = '\0';
							lines = atoi(num_buff);
							if (lines < 0) {
								goto RDWR_ERROR;
							}
							last_pos = i + 2;
							line_pos = 0;
							break;
						} else if (0 == strncmp(buff, "FALSE ", 6)) {
							std::unique_lock sv_hold(g_server_lock);
							double_list_append_as_tail(&pback->psvr->conn_list,
								&pback->node);
							*perrno = atoi(buff + 6);
							return MIDB_RESULT_ERROR;
						}
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						goto RDWR_ERROR;
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
							uid = atoi(pspace);
							if (xarray_append(pxarray, &mitem, uid) >= 0) {
								num = xarray_get_capacity(pxarray);
								auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, num - 1));
								pitem->uid = uid;
								pitem->id = pseq->min + count - 1;
								strncpy(pitem->mid, temp_line, sizeof(pitem->mid));
								pitem->flag_bits = 0;
								if (NULL != strchr(pspace1, 'A')) {
									pitem->flag_bits |= FLAG_ANSWERED;
								}
								if (NULL != strchr(pspace1, 'U')) {
									pitem->flag_bits |= FLAG_DRAFT;
								}
								if (NULL != strchr(pspace1, 'F')) {
									pitem->flag_bits |= FLAG_FLAGGED;
								}
								if (NULL != strchr(pspace1, 'D')) {
									pitem->flag_bits |= FLAG_DELETED;
								}
								if (NULL != strchr(pspace1, 'S')) {
									pitem->flag_bits |= FLAG_SEEN;
								}
								if (NULL != strchr(pspace1, 'R')) {
									pitem->flag_bits |= FLAG_RECENT;
								}
							}
						} else {
							b_format_error = TRUE;
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else {
					if ('\r' != buff[i] || i != offset - 1) {
						temp_line[line_pos] = buff[i];
						line_pos ++;
						if (line_pos >= 128) {
							goto RDWR_ERROR;
						}
					}
				}
			}

			if (count >= lines) {
				if (TRUE == b_format_error) {	
					std::unique_lock sv_hold(g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
					*perrno = -1;
					return MIDB_RESULT_ERROR;
				}
				break;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

			if (1024 == offset) {
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
	
	{
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
	}
	return MIDB_RESULT_OK;

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int fetch_detail(const char *path, const char *folder,
    DOUBLE_LIST *plist, XARRAY *pxarray, int *perrno)
{
	int i;
	int num;
	int value;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	MITEM mitem;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[64*1025];
	char temp_line[257*1024];
	BOOL b_format_error;
	DOUBLE_LIST_NODE *pnode;
	struct pollfd pfd_read;

	if (NULL == g_file_allocator) {
		*perrno = -2;
		return MIDB_RESULT_ERROR;
	}
	
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pseq = static_cast<SEQUENCE_NODE *>(pnode->pdata);
		if (pseq->max == -1) {
			if (pseq->min == -1)
				length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-LIST %s %s UID ASC -1 1\r\n",
						path, folder);
			else
				length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-LIST %s %s UID ASC %d "
						"1000000000\r\n", path, folder,
						pseq->min - 1);
		} else {
			length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-LIST %s %s UID ASC %d %d\r\n",
						path, folder, pseq->min - 1,
						pseq->max - pseq->min + 1);
		}
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				goto RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, 64*1024 - offset);
			if (read_len <= 0) {
				goto RDWR_ERROR;
			}
			offset += read_len;
			
			if (-1 == lines) {
				for (i=0; i<offset-1&&i<36; i++) {
					if ('\r' == buff[i] && '\n' == buff[i + 1]) {
						if (0 == strncmp(buff, "TRUE ", 5)) {
							memcpy(num_buff, buff + 5, i - 5);
							num_buff[i - 5] = '\0';
							lines = atoi(num_buff);
							if (lines < 0) {
								goto RDWR_ERROR;
							}
							last_pos = i + 2;
							line_pos = 0;
							break;
						} else if (0 == strncmp(buff, "FALSE ", 6)) {
							std::unique_lock sv_hold(g_server_lock);
							double_list_append_as_tail(&pback->psvr->conn_list,
								&pback->node);
							sv_hold.unlock();
							*perrno = atoi(buff + 6);
							num = xarray_get_capacity(pxarray);
							for (i=0; i<num; i++) {
								auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
								mem_file_free(&pitem->f_digest);
							}
							xarray_clear(pxarray);
							return MIDB_RESULT_ERROR;
						}
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						goto RDWR_ERROR;
					}
					continue;
				}
			}

			for (i=last_pos; i<offset; i++) {
				if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
					count ++;
				} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
					if (TRUE == get_digest_string(temp_line, line_pos, "file",
						mitem.mid, sizeof(mitem.mid)) && TRUE == get_digest_integer(
						temp_line, line_pos, "uid", &mitem.uid)) {
						if (xarray_append(pxarray, &mitem, mitem.uid) >= 0) {
							num = xarray_get_capacity(pxarray);
							auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, num - 1));
							pitem->id = pseq->min + count - 1;
							pitem->flag_bits = FLAG_LOADED;
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"replied", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_ANSWERED;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"unsent", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_DRAFT;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"flag", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_FLAGGED;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"deleted", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_DELETED;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"read", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_SEEN;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"recent", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_RECENT;
							}
							
							mem_file_init(&pitem->f_digest, g_file_allocator);
							mem_file_write(&pitem->f_digest, temp_line, line_pos);
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else {
					if ('\r' != buff[i] || i != offset - 1) {
						temp_line[line_pos] = buff[i];
						line_pos ++;
						if (line_pos >= 257*1024) {
							goto RDWR_ERROR;
						}
					}
				}
			}

			if (count >= lines) {
				if (TRUE == b_format_error) {
					std::unique_lock sv_hold(g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
					sv_hold.unlock();
					*perrno = -1;
					num = xarray_get_capacity(pxarray);
					for (i=0; i<num; i++) {
						auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
						mem_file_free(&pitem->f_digest);
					}
					return MIDB_RESULT_ERROR;
				}
				break;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

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

	{	
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
	}
	return MIDB_RESULT_OK;

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	sv_hold.unlock();
	num = xarray_get_capacity(pxarray);
	for (i=0; i<num; i++) {
		auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
		mem_file_free(&pitem->f_digest);
	}
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static int fetch_simple_uid(const char *path, const char *folder,
    DOUBLE_LIST *plist, XARRAY *pxarray, int *perrno)
{
	int i;
	int uid;
	int num;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	MITEM mitem;
	char *pspace;
	char *pspace1;
	char *pspace2;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[1024];
	char temp_line[1024];
	BOOL b_format_error;
	DOUBLE_LIST_NODE *pnode;
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pseq = static_cast<SEQUENCE_NODE *>(pnode->pdata);
		length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SIMU %s %s UID ASC %d %d\r\n", path, folder,
					pseq->min, pseq->max);
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				goto RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, 1024 - offset);
			if (read_len <= 0) {
				goto RDWR_ERROR;
			}
			offset += read_len;

			if (-1 == lines) {
				for (i=0; i<offset-1&&i<36; i++) {
					if ('\r' == buff[i] && '\n' == buff[i + 1]) {
						if (0 == strncmp(buff, "TRUE ", 5)) {
							memcpy(num_buff, buff + 5, i - 5);
							num_buff[i - 5] = '\0';
							lines = atoi(num_buff);
							if (lines < 0) {
								goto RDWR_ERROR;
							}
							last_pos = i + 2;
							line_pos = 0;
							break;
						} else if (0 == strncmp(buff, "FALSE ", 6)) {
							std::unique_lock sv_hold(g_server_lock);
							double_list_append_as_tail(&pback->psvr->conn_list,
								&pback->node);
							*perrno = atoi(buff + 6);
							return MIDB_RESULT_ERROR;
						}
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						goto RDWR_ERROR;
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
							pspace2 = strchr(pspace1 + 1, ' ');
							if (NULL != pspace2) {
								*pspace = '\0';
								*pspace1 = '\0';
								*pspace2 = '\0';
								pspace ++;
								pspace1 ++;
								pspace2 ++;
								uid = atoi(pspace1);
								if (xarray_append(pxarray, &mitem, uid) >= 0) {
									num = xarray_get_capacity(pxarray);
									auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, num - 1));
									pitem->uid = uid;
									pitem->id = atoi(temp_line) + 1;
									strncpy(pitem->mid, pspace, sizeof(pitem->mid));
									pitem->flag_bits = 0;
									if (NULL != strchr(pspace2, 'A')) {
										pitem->flag_bits |= FLAG_ANSWERED;
									}
									if (NULL != strchr(pspace2, 'U')) {
										pitem->flag_bits |= FLAG_DRAFT;
									}
									if (NULL != strchr(pspace2, 'F')) {
										pitem->flag_bits |= FLAG_FLAGGED;
									}
									if (NULL != strchr(pspace2, 'D')) {
										pitem->flag_bits |= FLAG_DELETED;
									}
									if (NULL != strchr(pspace2, 'S')) {
										pitem->flag_bits |= FLAG_SEEN;
									}
									if (NULL != strchr(pspace2, 'R')) {
										pitem->flag_bits |= FLAG_RECENT;
									}
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
				} else {
					if ('\r' != buff[i] || i != offset - 1) {
						temp_line[line_pos] = buff[i];
						line_pos ++;
						if (line_pos >= 128) {
							goto RDWR_ERROR;
						}
					}
				}
			}

			if (count >= lines) {
				if (TRUE == b_format_error) {	
					std::unique_lock sv_hold(g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
					*perrno = -1;
					return MIDB_RESULT_ERROR;
				}
				break;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

			if (1024 == offset) {
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

	{	
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
	}
	return MIDB_RESULT_OK;

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}

static int fetch_detail_uid(const char *path, const char *folder,
    DOUBLE_LIST *plist, XARRAY *pxarray, int *perrno)
{
	int i;
	int num;
	int value;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int temp_len;
	char *pspace;
	int tv_msec;
	MITEM mitem;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[64*1025];
	char temp_line[257*1024];
	BOOL b_format_error;
	DOUBLE_LIST_NODE *pnode;
	struct pollfd pfd_read;

	if (NULL == g_file_allocator) {
		*perrno = -2;
		return MIDB_RESULT_ERROR;
	}
	
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pseq = static_cast<SEQUENCE_NODE *>(pnode->pdata);
		length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-DTLU %s %s UID ASC %d %d\r\n", path,
					folder, pseq->min, pseq->max);
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				goto RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, 64*1024 - offset);
			if (read_len <= 0) {
				goto RDWR_ERROR;
			}
			offset += read_len;

			if (-1 == lines) {
				for (i=0; i<offset-1&&i<36; i++) {
					if ('\r' == buff[i] && '\n' == buff[i + 1]) {
						if (0 == strncmp(buff, "TRUE ", 5)) {
							memcpy(num_buff, buff + 5, i - 5);
							num_buff[i - 5] = '\0';
							lines = atoi(num_buff);
							if (lines < 0) {
								goto RDWR_ERROR;
							}
							last_pos = i + 2;
							line_pos = 0;
							break;
						} else if (0 == strncmp(buff, "FALSE ", 6)) {
							std::unique_lock sv_hold(g_server_lock);
							double_list_append_as_tail(&pback->psvr->conn_list,
								&pback->node);
							sv_hold.unlock();
							*perrno = atoi(buff + 6);
							num = xarray_get_capacity(pxarray);
							for (i=0; i<num; i++) {
								auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
								mem_file_free(&pitem->f_digest);
							}
							xarray_clear(pxarray);
							return MIDB_RESULT_ERROR;
						}
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						goto RDWR_ERROR;
					}
					continue;
				}
			}

			for (i=last_pos; i<offset; i++) {
				if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
					count ++;
				} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
					pspace = search_string(temp_line, " ", 16);
					temp_len = line_pos - (pspace + 1 - temp_line);
					if (NULL != pspace && TRUE == get_digest_string(pspace,
						temp_len, "file", mitem.mid, sizeof(mitem.mid)) && 
						TRUE == get_digest_integer(pspace, temp_len, "uid",
						&mitem.uid)) {
						*pspace = '\0';
						pspace ++;
						if (xarray_append(pxarray, &mitem, mitem.uid) >= 0) {
							num = xarray_get_capacity(pxarray);
							auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, num - 1));
							pitem->id = atoi(temp_line) + 1;
							pitem->flag_bits = FLAG_LOADED;
							if (TRUE == get_digest_integer(pspace, temp_len,
								"replied", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_ANSWERED;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"unsent", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_DRAFT;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"flag", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_FLAGGED;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"deleted", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_DELETED;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"read", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_SEEN;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"recent", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_RECENT;
							}
							
							mem_file_init(&pitem->f_digest, g_file_allocator);
							mem_file_write(&pitem->f_digest, pspace, temp_len);
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else {
					if ('\r' != buff[i] || i != offset - 1) {
						temp_line[line_pos] = buff[i];
						line_pos ++;
						if (line_pos >= 257*1024) {
							goto RDWR_ERROR;
						}
					}
				}
			}

			if (count >= lines) {
				if (TRUE == b_format_error) {
					std::unique_lock sv_hold(g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
					sv_hold.unlock();
					*perrno = -1;
					num = xarray_get_capacity(pxarray);
					for (i=0; i<num; i++) {
						auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
						mem_file_free(&pitem->f_digest);
					}
					return MIDB_RESULT_ERROR;
				}
				break;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

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
	
	{
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
	}
	return MIDB_RESULT_OK;

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	sv_hold.unlock();
	num = xarray_get_capacity(pxarray);
	for (i=0; i<num; i++) {
		auto pitem = static_cast<MITEM *>(xarray_get_item(pxarray, i));
		mem_file_free(&pitem->f_digest);
	}
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static int set_mail_flags(const char *path, const char *folder,
    const char *mid_string, int flag_bits, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	char flags_string[16];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	flags_string[0] = '(';
	length = 1;
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
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-SFLG %s %s %s %s\r\n",
				path, folder, mid_string, flags_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}
	
static int unset_mail_flags(const char *path, const char *folder,
    const char *mid_string, int flag_bits, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	char flags_string[16];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	flags_string[0] = '(';
	length = 1;
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
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-RFLG %s %s %s %s\r\n",
				path, folder, mid_string, flags_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;
}
	
static int get_mail_flags(const char *path, const char *folder,
    const char *mid_string, int *pflag_bits, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "P-GFLG %s %s %s\r\n",
				path, folder, mid_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			sv_hold.unlock();
			*pflag_bits = 0;
			if (NULL != strchr(buff + 5, 'A')) {
				*pflag_bits |= FLAG_ANSWERED;
			}
			if (NULL != strchr(buff + 5, 'U')) {
				*pflag_bits |= FLAG_DRAFT;
			}
			if (NULL != strchr(buff + 5, 'F')) {
				*pflag_bits |= FLAG_FLAGGED;
			}
			if (NULL != strchr(buff + 5, 'D')) {
				*pflag_bits |= FLAG_DELETED;
			}
			if (NULL != strchr(buff + 5, 'S')) {
				*pflag_bits |= FLAG_SEEN;
			}
			if (NULL != strchr(buff + 5, 'R')) {
				*pflag_bits |= FLAG_RECENT;
			}
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			sv_hold.unlock();
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;


}
	
static int copy_mail(const char *path, const char *src_folder,
    const char *mid_string, const char *dst_folder, char *dst_mid, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-COPY %s %s %s %s\r\n",
				path, src_folder, mid_string, dst_folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			sv_hold.unlock();
			strcpy(dst_mid, buff + 5);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			std::unique_lock sv_hold(g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			sv_hold.unlock();
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}

 RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return MIDB_RDWR_ERROR;

}


static BOOL read_line(int sockd, char *buff, int length)
{
	int offset;
	int tv_msec;
	int read_len;
	struct pollfd pfd_read;

	offset = 0;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return FALSE;
		}
		read_len = read(sockd, buff + offset,  length - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			offset -= 2;
			buff[offset] = '\0';
			return TRUE;
		}
		if (length == offset) {
			return FALSE;
		}
	}
	
}

static BOOL check_full(const char *path)
{
	int length;
	int offset;
	int read_len;
	fd_set myset;
	BACK_CONN *pback;
	struct timeval tv;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return TRUE;
	}
	length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "M-CKFL %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		goto CHECK_ERROR;
	}

	offset = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pback->sockd, &myset);
		if (select(pback->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			goto CHECK_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 1024 - offset);
		if (read_len <= 0) {
			goto CHECK_ERROR;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			if (8 == offset && 0 == strncasecmp("TRUE ", buff, 5)) {
				time(&pback->last_time);
				std::unique_lock sv_hold(g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				if ('1' == buff[5]) {
					return FALSE;
				} else {
					return TRUE;
				}
			} else if (offset > 8 && 0 == strncasecmp("FALSE ", buff, 6)) {
				time(&pback->last_time);
				std::unique_lock sv_hold(g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				return TRUE;
			} else {
				goto CHECK_ERROR;
			}
		}
		if (1024 == offset) {
			goto CHECK_ERROR;
		}
	}

 CHECK_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	std::unique_lock sv_hold(g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	return TRUE;
}

static int connect_midb(const char *ip_addr, int port)
{
	int tv_msec;
    int read_len;
    char temp_buff[1024];
	struct pollfd pfd_read;

	int sockd = gx_inet_connect(ip_addr, port, 0);
	if (sockd < 0)
		return -1;
	tv_msec = SOCKET_TIMEOUT * 1000;
	pfd_read.fd = sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (1 != poll(&pfd_read, 1, tv_msec)) {
		close(sockd);
		return -1;
	}
	read_len = read(sockd, temp_buff, 1024);
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

static void console_talk(int argc, char **argv, char *result, int length)
{
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;
	char help_string[] = "250 midb agent help information:\r\n"
						 "\t%s echo mp-path\r\n"
						 "\t    --print the midb server information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] = '\0';
		return;
	}
	
	if (3 == argc && 0 == strcmp("echo", argv[1])) {
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			pserver = (BACK_SVR*)pnode->pdata;
			if (0 == strcmp(argv[2], pserver->prefix)) {
				snprintf(result, length,
				"250 agent information of midb(mp:%s ip:%s port:%d):\r\n"
				"\ttotal connections       %d\r\n"
				"\tavailable connections   %zu",
				pserver->prefix, pserver->ip_addr, pserver->port,
				g_conn_num, double_list_get_nodes_num(&pserver->conn_list));
				result[length - 1] = '\0';
				return;
			}
		}
		snprintf(result, length, "250 no agent information of midb(mp:%s)",
			argv[2]);
		return;
	}
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

static BOOL get_digest_string(const char *src, int length, const char *tag,
    char *buff, int buff_len)
{
	char *ptr1, *ptr2;
	char temp_tag[256];
	
	int len = gx_snprintf(temp_tag, GX_ARRAY_SIZE(temp_tag), "\"%s\"", tag);
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
	
	if (TRUE == get_digest_string(src, length, tag, num_buff, 32)) {
		*pinteger = atoi(num_buff);
		return TRUE;
	}
	return FALSE;
}

