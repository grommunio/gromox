// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/ndr.hpp>
#include <gromox/paths.h>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "http_parser.h"
#include "mod_fastcgi.h"
#include "resource.h"
#define TRY(expr) do { int v = (expr); if (v != NDR_ERR_SUCCESS) return v; } while (false)
#define QRF(expr) do { int v = (expr); if (v != NDR_ERR_SUCCESS) return FALSE; } while (false)
#define SERVER_SOFTWARE							"medusa/1.0"

#define POLL_MILLISECONDS_FOR_CHECK				50

#define FCGI_VERSION							1

#define FCGI_REQUEST_ID							1


#define RECORD_TYPE_BEGIN_REQUEST				1
#define RECORD_TYPE_ABORT_REQUEST				2
#define RECORD_TYPE_END_REQUEST					3
#define RECORD_TYPE_PARAMS						4
#define RECORD_TYPE_STDIN						5
#define RECORD_TYPE_STDOUT						6
#define RECORD_TYPE_STDERR						7
#define RECORD_TYPE_DATA						8
#define RECORD_TYPE_GET_VALUES					9
#define RECORD_TYPE_GET_VALUES_RESULT			10
#define RECORD_TYPE_UNKNOWN_TYPE				11


#define ROLE_RESPONDER							1
#define ROLE_AUTHORIZER							2
#define ROLE_FILTER								3


#define PROTOCOL_STATUS_REQUEST_COMPLETE		0
#define PROTOCOL_STATUS_CANT_MPX_CONN			1
#define PROTOCOL_STATUS_OVERLOADED				2
#define PROTOCOL_STATUS_UNKNOWN_ROLE			3

using namespace gromox;

struct FASTCGI_NODE {
	std::string domain, path, dir, suffix, index;
	std::vector<std::string> header_list;
	std::string sock_path;
};

namespace {

struct FCGI_ENDREQUESTBODY {
	uint32_t app_status;
	uint8_t protocol_status;
	uint8_t reserved[3];
};

struct FCGI_STDSTREAM {
	uint8_t buffer[0xFFFF];
	uint16_t length;
};

struct RECORD_HEADER {
	uint8_t version;
	uint8_t type;
	uint16_t request_id;
	uint16_t content_len;
	uint8_t padding_len;
	uint8_t reserved;
};

}

static int g_context_num;
static time_duration g_exec_timeout;
static uint64_t g_max_size;
static uint64_t g_cache_size;
static std::vector<FASTCGI_NODE> g_fastcgi_list;
static std::unique_ptr<FASTCGI_CONTEXT[]> g_context_list;
static std::atomic<int> g_unavailable_times;

static const FASTCGI_NODE *mod_fastcgi_find_backend(const char *domain,
    const char *uri_path, const char *file_name, const char *suffix,
	BOOL *pb_index)
{
	for (const auto &node : g_fastcgi_list) {
		if (wildcard_match(domain, node.domain.c_str(), TRUE) == 0)
			continue;
		auto tmp_len = node.path.size();
		if (strncmp(uri_path, node.path.c_str(), tmp_len) != 0 ||
		    (uri_path[tmp_len] != '/' && uri_path[tmp_len] != '\0'))
			continue;
		if ('\0' == file_name[0] && '\0' == suffix[0]) {
			*pb_index = TRUE;
			return &node;
		}
		if (strcmp(node.suffix.c_str(), "*") != 0 &&
		    wildcard_match(suffix, node.suffix.c_str(), TRUE) == 0)
			continue;
		*pb_index = FALSE;
		return &node;
	}
	return NULL;
}

void mod_fastcgi_init(int context_num, uint64_t cache_size, uint64_t max_size,
    time_duration exec_timeout)
{
	g_context_num = context_num;
	g_unavailable_times = 0;
	g_cache_size = cache_size;
	g_max_size = max_size;
	g_exec_timeout = exec_timeout;
}

static int mod_fastcgi_defaults()
{
	mlog(LV_NOTICE, "mod_fastcgi: defaulting to built-in list of handled paths");
	FASTCGI_NODE node;
	node.domain = "*";
	node.path = "/EWS";
	node.dir = PKGDATADIR "/http/php/ews";
	node.suffix = "php";
	node.index = "index.php";
	node.header_list = {"X-MAPIHttpCapability", "X-AnchorMailbox", "X-ClientCanHandle"};
	node.sock_path = PKGRUNDIR "/php-fpm.sock";
	g_fastcgi_list.push_back(node);
	node.path = "/ews";
	g_fastcgi_list.push_back(node);
	node.path = "/sync";
	node.dir = DATADIR "/grommunio-sync";
	node.header_list.clear();
	g_fastcgi_list.push_back(node);
	node.path = "/web";
	node.dir = DATADIR "/grommunio-web";
	g_fastcgi_list.push_back(node);
	return 0;
}

static int mod_fastcgi_read_txt() try
{
	struct srcitem {
		char domain[256], path[256], dir[256], suffix[16], index[256];
		char extra_headers[304], sock_path[256];
	};
	auto pfile = list_file_initd("fastcgi.txt", resource_get_string("config_file_path"),
		"%s:256%s:256%s:256%s:16%s:256%s:304%s:256", ERROR_ON_ABSENCE);
	if (pfile == nullptr && errno == ENOENT) {
		return mod_fastcgi_defaults();
	} else if (pfile == nullptr) {
		mlog(LV_ERR, "mod_fastcgi: list_file_initd fastcgi.txt: %s", strerror(errno));
		return -1;
	}
	auto item_num = pfile->get_size();
	auto pitem = static_cast<srcitem *>(pfile->get_list());
	for (decltype(item_num) i = 0; i < item_num; ++i) {
		FASTCGI_NODE node;
		node.domain = pitem[i].domain;
		node.path = pitem[i].path;
		if (node.path.size() > 0 && node.path.back() == '/')
			node.path.pop_back();
		node.dir = pitem[i].dir;
		if (node.dir.size() > 0 && node.dir.back() == '/')
			node.dir.pop_back();
		node.suffix = pitem[i].suffix;
		node.index = pitem[i].index;
		node.header_list = gx_split(pitem[i].extra_headers, '|');
		node.sock_path = pitem[i].sock_path;
		g_fastcgi_list.push_back(std::move(node));
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1254: ENOMEM");
	return -ENOMEM;
}

int mod_fastcgi_run() try
{
	auto ret = mod_fastcgi_read_txt();
	if (ret < 0)
		return ret;
	g_context_list = std::make_unique<FASTCGI_CONTEXT[]>(g_context_num);
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1654: ENOMEM");
	return -ENOMEM;
}

void mod_fastcgi_stop()
{
	g_context_list.reset();
}

static int mod_fastcgi_push_name_value(NDR_PUSH *pndr,
    const char *pname, const char *pvalue)
{
	uint32_t tmp_len;
	uint32_t val_len;
	uint32_t name_len;
	
	name_len = strlen(pname);
	if (name_len <= 0x7F) {
		TRY(pndr->p_uint8(name_len));
	} else {
		tmp_len = name_len | 0x80000000;
		TRY(pndr->p_uint32(tmp_len));
	}
	val_len = strlen(pvalue);
	if (val_len <= 0x7F) {
		TRY(pndr->p_uint8(val_len));
	} else {
		tmp_len = val_len | 0x80000000;
		TRY(pndr->p_uint32(tmp_len));
	}
	TRY(pndr->p_uint8_a(reinterpret_cast<const uint8_t *>(pname), name_len));
	return pndr->p_uint8_a(reinterpret_cast<const uint8_t *>(pvalue), val_len);
}

static int mod_fastcgi_push_begin_request(NDR_PUSH *pndr)
{
	TRY(pndr->p_uint8(FCGI_VERSION));
	TRY(pndr->p_uint8(RECORD_TYPE_BEGIN_REQUEST));
	TRY(pndr->p_uint16(FCGI_REQUEST_ID));
	/* push content length */
	TRY(pndr->p_uint16(8));
	/* push padding length */
	TRY(pndr->p_uint8(0));
	/* reserved */
	TRY(pndr->p_uint8(0));
	/* begin request role */
	TRY(pndr->p_uint16(ROLE_RESPONDER));
	/* begin request flags */
	TRY(pndr->p_uint8(0));
	/* begin request reserved bytes */
	return pndr->p_zero(5);
}

static int mod_fastcgi_push_params_begin(NDR_PUSH *pndr)
{
	TRY(pndr->p_uint8(FCGI_VERSION));
	TRY(pndr->p_uint8(RECORD_TYPE_PARAMS));
	TRY(pndr->p_uint16(FCGI_REQUEST_ID));
	/* push fake content length */
	TRY(pndr->p_uint16(0));
	/* push fake padding length */
	TRY(pndr->p_uint8(0));
	/* reserved */
	return pndr->p_uint8(0);
}

static int mod_fastcgi_push_align_record(NDR_PUSH *pndr)
{
	uint8_t padding_len;
	
	if (!(pndr->offset & 7))
		return NDR_ERR_SUCCESS;
	padding_len = 8 - (pndr->offset & 7);
	pndr->data[6] = padding_len;
	return pndr->p_zero(padding_len);
}

static int mod_fastcgi_push_params_end(NDR_PUSH *pndr)
{
	uint16_t len;
	uint32_t offset;
	
	offset = pndr->offset;
	len = offset - 8;
	if (len > 0xFFFF)
		return NDR_ERR_FAILURE;
	pndr->offset = 4;
	TRY(pndr->p_uint16(len));
	pndr->offset = offset;
	return mod_fastcgi_push_align_record(pndr);
}

static int mod_fastcgi_push_stdin(NDR_PUSH *pndr,
    const void *pbuff, uint16_t length)
{
	TRY(pndr->p_uint8(FCGI_VERSION));
	TRY(pndr->p_uint8(RECORD_TYPE_STDIN));
	TRY(pndr->p_uint16(FCGI_REQUEST_ID));
	TRY(pndr->p_uint16(length));
	/* push padding length */
	TRY(pndr->p_uint8(0));
	/* reserved */
	TRY(pndr->p_uint8(0));
	TRY(pndr->p_uint8_a(static_cast<const uint8_t *>(pbuff), length));
	return mod_fastcgi_push_align_record(pndr);
}

static int mod_fastcgi_pull_end_request(NDR_PULL *pndr,
	uint8_t padding_len, FCGI_ENDREQUESTBODY *pend_request)
{
	TRY(ndr_pull_uint32(pndr, &pend_request->app_status));
	TRY(ndr_pull_uint8(pndr, &pend_request->protocol_status));
	TRY(ndr_pull_array_uint8(pndr, pend_request->reserved, 3));
	return ndr_pull_advance(pndr, padding_len);
}

static int mod_fastcgi_pull_stdstream(NDR_PULL *pndr,
	uint8_t padding_len, FCGI_STDSTREAM *pstd_stream)
{
	TRY(ndr_pull_array_uint8(pndr, pstd_stream->buffer, pstd_stream->length));
	return ndr_pull_advance(pndr, padding_len);
}

static int mod_fastcgi_pull_record_header(
	NDR_PULL *pndr, RECORD_HEADER *pheader)
{
	TRY(ndr_pull_uint8(pndr, &pheader->version));
	TRY(ndr_pull_uint8(pndr, &pheader->type));
	TRY(ndr_pull_uint16(pndr, &pheader->request_id));
	TRY(ndr_pull_uint16(pndr, &pheader->content_len));
	TRY(ndr_pull_uint8(pndr, &pheader->padding_len));
	return ndr_pull_uint8(pndr, &pheader->reserved);
}

static BOOL mod_fastcgi_get_others_field(MEM_FILE *pf_others,
    const char *tag, char *value, size_t length)
{
	char tmp_buff[256];
	uint32_t tag_len, val_len;
	
	pf_others->seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (pf_others->read(&tag_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		if (tag_len >= GX_ARRAY_SIZE(tmp_buff))
			return FALSE;
		pf_others->read(tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		pf_others->read(&val_len, sizeof(uint32_t));
		if (0 == strcasecmp(tag, tmp_buff)) {
			length = (length > val_len)?val_len:(length - 1);
			pf_others->read(value, length);
			value[length] = '\0';
			return TRUE;
		}
		pf_others->seek(MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
	}
	return FALSE;
}

static int mod_fastcgi_connect_backend(const char *path)
{
	int sockd, len;
	struct sockaddr_un un;

	/* create a UNIX domain stream socket */
	sockd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockd < 0)
		return -1;
	/* fill socket address structure with server's address */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	gx_strlcpy(un.sun_path, path, GX_ARRAY_SIZE(un.sun_path));
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
	if (connect(sockd, (struct sockaddr *)&un, len) < 0) {
		close(sockd);
		return -2;
	}
	return sockd;
}

bool mod_fastcgi_take_request(HTTP_CONTEXT *phttp)
{
	BOOL b_index;
	char *ptoken;
	char *ptoken1;
	BOOL b_chunked;
	char suffix[16];
	char domain[256];
	char file_name[256];
	char tmp_buff[8192];
	char request_uri[8192];
	uint64_t content_length;
	
	auto tmp_len = phttp->request.f_host.get_total_length();
	if (tmp_len >= sizeof(domain)) {
		phttp->log(LV_DEBUG, "length of "
			"request host is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		gx_strlcpy(domain, phttp->connection.server_ip, GX_ARRAY_SIZE(domain));
	} else {
		phttp->request.f_host.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_host.read(domain, tmp_len);
		domain[tmp_len] = '\0';
	}
	ptoken = strchr(domain, ':');
	if (ptoken != nullptr)
		*ptoken = '\0';
	tmp_len = phttp->request.f_request_uri.get_total_length();
	if (0 == tmp_len) {
		phttp->log(LV_DEBUG, "cannot "
			"find request uri for mod_fastcgi");
		return FALSE;
	} else if (tmp_len >= sizeof(tmp_buff)) {
		phttp->log(LV_DEBUG, "length of "
			"request uri is too long for mod_fastcgi");
		return FALSE;
	}
	phttp->request.f_request_uri.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_request_uri.read(tmp_buff, tmp_len);
	tmp_buff[tmp_len] = '\0';
	if (!parse_uri(tmp_buff, request_uri)) {
		phttp->log(LV_DEBUG, "request"
			" uri format error for mod_fastcgi");
		return FALSE;
	}
	ptoken = strrchr(request_uri, '?');
	if (ptoken != nullptr)
		*ptoken = '\0';
	ptoken = strrchr(request_uri, '.');
	if (ptoken != nullptr) {
		*ptoken = '\0';
		ptoken ++;
		ptoken1 = strchr(ptoken, '/');
		if (ptoken1 != nullptr)
			*ptoken1 = '\0';
		tmp_len = strlen(ptoken);
		if (tmp_len >= 16) {
			phttp->log(LV_DEBUG, "suffix in"
				" request uri error for mod_fastcgi");
			return FALSE;
		}
		strcpy(suffix, ptoken);
	} else {
		suffix[0] = '\0';
	}
	ptoken = strrchr(request_uri, '/');
	if (NULL != ptoken) {
		*ptoken = '\0';
		gx_strlcpy(file_name, ptoken + 1, GX_ARRAY_SIZE(file_name));
	} else {
		phttp->log(LV_DEBUG, "request uri format "
					"error, missing slash for mod_fastcgi");
		return FALSE;
	}
	auto pfnode = mod_fastcgi_find_backend(domain, request_uri, file_name, suffix, &b_index);
	if (pfnode == nullptr)
		return FALSE;
	phttp->log(LV_DEBUG, "http request \"%s\" "
		"to \"%s\" will be relayed to fastcgi back-end %s",
		tmp_buff, domain, pfnode->sock_path.c_str());
	tmp_len = phttp->request.f_content_length.get_total_length();
	if (0 == tmp_len) {
		content_length = 0;
	} else {
		if (tmp_len >= 32) {
			phttp->log(LV_DEBUG, "length of "
				"content-length is too long for mod_fastcgi");
			return FALSE;
		}
		phttp->request.f_content_length.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_content_length.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
		content_length = strtoull(tmp_buff, nullptr, 0);
	}
	if (content_length > g_max_size) {
		phttp->log(LV_DEBUG, "content-length"
			" is too long for mod_fastcgi");
		return FALSE;
	}
	b_chunked = FALSE;
	tmp_len = phttp->request.f_transfer_encoding.get_total_length();
	if (tmp_len > 0 && tmp_len < 64) {
		phttp->request.f_transfer_encoding.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_transfer_encoding.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
		if (strcasecmp(tmp_buff, "chunked") == 0)
			b_chunked = TRUE;
	}
	auto pcontext = &g_context_list[phttp->context_id];
	pcontext->last_time = tp_now();
	pcontext->pfnode = pfnode;
	if (b_chunked || content_length > g_cache_size) {
		auto path = LOCAL_DISK_TMPDIR;
		if (mkdir(path, 0777) < 0 && errno != EEXIST) {
			mlog(LV_ERR, "E-2077: mkdir %s: %s", path, strerror(errno));
			return false;
		}
		pcontext->cache_fd = open_tmpfile(path, &pcontext->tmpfile,
		                     O_RDWR | O_TRUNC);
		if (pcontext->cache_fd < 0) {
			mlog(LV_ERR, "E-2078: open_tmpfile{%s, %s}: %s",
			        path, pcontext->tmpfile.c_str(),
			        strerror(-pcontext->cache_fd));
			return FALSE;
		}
		pcontext->cache_size = 0;
	} else {
		pcontext->cache_fd = -1;
	}
	pcontext->b_index = b_index;
	pcontext->b_chunked = b_chunked;
	if (b_chunked) {
		pcontext->chunk_size = 0;
		pcontext->chunk_offset = 0;
	}
	pcontext->b_end = FALSE;
	pcontext->content_length = content_length;
	pcontext->cli_sockd = -1;
	pcontext->b_header = FALSE;
	phttp->pfast_context = pcontext;
	return true;
}

BOOL mod_fastcgi_check_end_of_read(HTTP_CONTEXT *phttp)
{
	return phttp->pfast_context->b_end;
}

BOOL mod_fastcgi_check_responded(HTTP_CONTEXT *phttp)
{
	return phttp->pfast_context->b_header;
}

static BOOL mod_fastcgi_build_params(HTTP_CONTEXT *phttp,
	uint8_t *pbuff, int *plength)
{
	char *ptoken;
	char *ptoken1;
	char *path_info;
	char domain[256];
	NDR_PUSH ndr_push;
	char uri_path[8192];
	char tmp_buff[8192];
	struct stat node_stat;
	
	ndr_push.init(pbuff, *plength, NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
	QRF(mod_fastcgi_push_params_begin(&ndr_push));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "GATEWAY_INTERFACE", "CGI/1.1"));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_SOFTWARE", SERVER_SOFTWARE));
	if (phttp->b_authed) {
		QRF(mod_fastcgi_push_name_value(&ndr_push, "REMOTE_USER", phttp->username));
		QRF(mod_fastcgi_push_name_value(&ndr_push, "USER_HOME", phttp->maildir));
		QRF(mod_fastcgi_push_name_value(&ndr_push, "USER_LANG", phttp->lang));
	}
	auto tmp_len = phttp->request.f_host.get_total_length();
	if (tmp_len >= sizeof(domain)) {
		phttp->log(LV_DEBUG, "length of "
			"request host is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		gx_strlcpy(domain, phttp->connection.server_ip, GX_ARRAY_SIZE(domain));
	} else {
		phttp->request.f_host.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_host.read(domain, tmp_len);
		domain[tmp_len] = '\0';
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_HOST", domain));
	ptoken = strchr(domain, ':');
	if (ptoken != nullptr)
		*ptoken = '\0';
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_NAME", domain));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_ADDR", phttp->connection.server_ip));
	snprintf(tmp_buff, arsizeof(tmp_buff), "%d", phttp->connection.server_port);
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_PORT", tmp_buff));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "REMOTE_ADDR", phttp->connection.client_ip));
	snprintf(tmp_buff, arsizeof(tmp_buff), "%d", phttp->connection.client_port);
	QRF(mod_fastcgi_push_name_value(&ndr_push, "REMOTE_PORT", tmp_buff));
	snprintf(tmp_buff, arsizeof(tmp_buff), "HTTP/%s", phttp->request.version);
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_PROTOCOL", tmp_buff));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "REQUEST_METHOD", phttp->request.method));
	tmp_len = phttp->request.f_request_uri.get_total_length();
	if (0 == tmp_len) {
		phttp->log(LV_DEBUG, "cannot "
			"find request uri for mod_fastcgi");
		return FALSE;
	} else if (tmp_len >= sizeof(tmp_buff)) {
		phttp->log(LV_DEBUG, "length of "
			"request uri is too long for mod_fastcgi");
		return FALSE;
	}
	phttp->request.f_request_uri.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_request_uri.read(tmp_buff, tmp_len);
	tmp_buff[tmp_len] = '\0';
	QRF(mod_fastcgi_push_name_value(&ndr_push, "REQUEST_URI", tmp_buff));
	ptoken = strchr(tmp_buff, '?');
	QRF(mod_fastcgi_push_name_value(&ndr_push, "QUERY_STRING", ptoken == nullptr ? "" : ++ptoken));
	if (!parse_uri(tmp_buff, uri_path)) {
		phttp->log(LV_DEBUG, "request"
			" uri format error for mod_fastcgi");
		return FALSE;
	}
	if (strlen(uri_path) >= 1024) {
		phttp->log(LV_DEBUG, "length of "
			"uri path is too long for mod_fastcgi");
		return FALSE;
	}
	path_info = NULL;
	ptoken = strrchr(uri_path, '.');
	if (NULL != ptoken) {
		ptoken1 = strchr(ptoken + 1, '/');
		if (ptoken1 != nullptr) {
			QRF(mod_fastcgi_push_name_value(&ndr_push, "PATH_INFO", ptoken1));
			*ptoken1 = '\0';
			path_info = ptoken1 + 1;
		}
	}
	auto pfnode = phttp->pfast_context->pfnode;
	QRF(mod_fastcgi_push_name_value(&ndr_push, "DOCUMENT_ROOT", pfnode->dir.c_str()));
	if (NULL != path_info) {
		snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%s/%s", pfnode->dir.c_str(), path_info);
		QRF(mod_fastcgi_push_name_value(&ndr_push, "PATH_TRANSLATED", tmp_buff));
	}
	tmp_len = pfnode->path.size();
	if (phttp->pfast_context->b_index) {
		snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%s%s", uri_path, pfnode->index.c_str());
		QRF(mod_fastcgi_push_name_value(&ndr_push, "SCRIPT_NAME", tmp_buff));
		snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%s%s%s", pfnode->dir.c_str(),
		         uri_path + tmp_len, pfnode->index.c_str());
		QRF(mod_fastcgi_push_name_value(&ndr_push, "SCRIPT_FILENAME", tmp_buff));
	} else {
		QRF(mod_fastcgi_push_name_value(&ndr_push, "SCRIPT_NAME", uri_path));
		snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%s%s", pfnode->dir.c_str(), uri_path + tmp_len);
		QRF(mod_fastcgi_push_name_value(&ndr_push, "SCRIPT_FILENAME", tmp_buff));
	}
	tmp_len = phttp->request.f_accept.get_total_length();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"accept is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		phttp->request.f_accept.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_accept.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_ACCEPT", tmp_buff));
	tmp_len = phttp->request.f_user_agent.get_total_length();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"user-agent is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		phttp->request.f_user_agent.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_user_agent.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_USER_AGENT", tmp_buff));
	tmp_len = phttp->request.f_accept_language.get_total_length();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"accept-language is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		phttp->request.f_accept_language.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_accept_language.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_ACCEPT_LANGUAGE", tmp_buff));
	tmp_len = phttp->request.f_accept_encoding.get_total_length();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"accept-encoding is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		phttp->request.f_accept_encoding.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_accept_encoding.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_ACCEPT_ENCODING", tmp_buff));
	tmp_len = phttp->request.f_cookie.get_total_length();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"cookie is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 != tmp_len) {
		phttp->request.f_cookie.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_cookie.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
		QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_COOKIE", tmp_buff));
	}
	tmp_len = phttp->request.f_content_type.get_total_length();
	if (tmp_len > 128) {
		phttp->log(LV_DEBUG, "length of "
			"content-type is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		phttp->request.f_content_type.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_content_type.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "CONTENT_TYPE", tmp_buff));
	if (NULL != phttp->connection.ssl) {
		QRF(mod_fastcgi_push_name_value(&ndr_push, "REQUEST_SCHEME", "https"));
		QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTPS", "on"));
	} else {
		QRF(mod_fastcgi_push_name_value(&ndr_push, "REQUEST_SCHEME", "http"));
	}
	if (phttp->b_close)
		QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_CONNECTION", "close"));
	else
		QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_CONNECTION", "keep-alive"));
	if (mod_fastcgi_get_others_field(&phttp->request.f_others, "Referer",
	    tmp_buff, arsizeof(tmp_buff)))
		QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_REFERER", tmp_buff));
	if (mod_fastcgi_get_others_field(&phttp->request.f_others, "Cache-Control",
	    tmp_buff, arsizeof(tmp_buff)))
		QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_CACHE_CONTROL", tmp_buff));
	for (const auto &hdr : pfnode->header_list)
		if (mod_fastcgi_get_others_field(&phttp->request.f_others,
		    hdr.c_str(), tmp_buff, GX_ARRAY_SIZE(tmp_buff)))
			QRF(mod_fastcgi_push_name_value(&ndr_push,
			    hdr.c_str(), tmp_buff));
	if (!phttp->pfast_context->b_chunked) {
		snprintf(tmp_buff, sizeof(tmp_buff), "%llu",
		         static_cast<unsigned long long>(phttp->pfast_context->content_length));
		QRF(mod_fastcgi_push_name_value(&ndr_push, "CONTENT_LENGTH", tmp_buff));
	} else {
		if (fstat(phttp->pfast_context->cache_fd, &node_stat) != 0)
			return FALSE;
		snprintf(tmp_buff, sizeof(tmp_buff), "%llu",
		         static_cast<unsigned long long>(node_stat.st_size));
		QRF(mod_fastcgi_push_name_value(&ndr_push, "CONTENT_LENGTH", tmp_buff));
	}
	QRF(mod_fastcgi_push_params_end(&ndr_push));
	*plength = ndr_push.offset;
	return TRUE;
}

BOOL mod_fastcgi_relay_content(HTTP_CONTEXT *phttp)
{
	void *pbuff;
	int cli_sockd;
	int ndr_length;
	NDR_PUSH ndr_push;
	char tmp_buff[65535];
	uint8_t ndr_buff[65800];
	
	ndr_push.init(tmp_buff, 16, NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
	if (mod_fastcgi_push_begin_request(&ndr_push) != NDR_ERR_SUCCESS ||
	    ndr_push.offset != 16)
		return FALSE;
	ndr_length = sizeof(ndr_buff);
	if (!mod_fastcgi_build_params(phttp, ndr_buff, &ndr_length))
		return FALSE;	
	cli_sockd = mod_fastcgi_connect_backend(phttp->pfast_context->pfnode->sock_path.c_str());
	if (cli_sockd < 0) {
		phttp->log(LV_DEBUG, "failed to "
				"connect to fastcgi back-end %s",
				phttp->pfast_context->pfnode->sock_path.c_str());
		return FALSE;
	}
	if (16 != write(cli_sockd, tmp_buff, 16) ||
		ndr_length != write(cli_sockd, ndr_buff,
		ndr_length)) {
		close(cli_sockd);
		phttp->log(LV_DEBUG, "failed to "
			"write record to fastcgi back-end %s",
			phttp->pfast_context->pfnode->sock_path.c_str());
		return FALSE;
	}
	ndr_push.init(tmp_buff, 8, NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
	if (NDR_ERR_SUCCESS != mod_fastcgi_push_params_begin(&ndr_push) ||
		NDR_ERR_SUCCESS != mod_fastcgi_push_params_end(&ndr_push) ||
		8 != ndr_push.offset || 8 != write(cli_sockd, tmp_buff, 8)) {
		close(cli_sockd);
		phttp->log(LV_DEBUG, "failed to "
			"write record to fastcgi back-end %s",
			phttp->pfast_context->pfnode->sock_path.c_str());
		return FALSE;
	}
	if (phttp->pfast_context->cache_fd < 0) {
		if (phttp->pfast_context->content_length == 0)
			goto END_OF_STDIN;
		unsigned int tmp_len = sizeof(tmp_buff);
		while ((pbuff = phttp->stream_in.get_read_buf(&tmp_len)) != nullptr) {
			if (tmp_len > phttp->pfast_context->content_length) {
				phttp->stream_in.rewind_read_ptr(tmp_len - phttp->pfast_context->content_length);
				tmp_len = phttp->pfast_context->content_length;
				phttp->pfast_context->content_length = 0;
			} else{
				phttp->pfast_context->content_length -= tmp_len;
			}
			ndr_push.init(ndr_buff, sizeof(ndr_buff), NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
			if (NDR_ERR_SUCCESS != mod_fastcgi_push_stdin(
				&ndr_push, pbuff, tmp_len)) {
				close(cli_sockd);
				phttp->log(LV_DEBUG, "failed to "
					"push stdin record for mod_fastcgi");
				return FALSE;
			}
			auto ret = write(cli_sockd, ndr_buff, ndr_push.offset);
			if (ret < 0 || static_cast<size_t>(ret) != ndr_push.offset) {
				close(cli_sockd);
				phttp->log(LV_DEBUG, "failed to "
					"write record to fastcgi back-end %s (ret=%zd, %s)",
					phttp->pfast_context->pfnode->sock_path.c_str(),
					ret, strerror(errno));
				return FALSE;
			}
			if (phttp->pfast_context->content_length == 0)
				break;
			tmp_len = sizeof(tmp_buff);
		}
	} else {
		lseek(phttp->pfast_context->cache_fd, 0, SEEK_SET);
		while (true) {
			auto tmp_len = read(phttp->pfast_context->cache_fd,
				tmp_buff, sizeof(tmp_buff));
			if (tmp_len < 0) {
				close(cli_sockd);
				phttp->log(LV_DEBUG, "failed to"
					" read cache file for mod_fastcgi");
				return FALSE;
			} else if (0 == tmp_len) {
				close(phttp->pfast_context->cache_fd);
				phttp->pfast_context->cache_fd = -1;
				if (!phttp->pfast_context->tmpfile.empty() &&
				    unlink(phttp->pfast_context->tmpfile.c_str()) < 0 &&
				    errno != ENOENT)
					mlog(LV_WARN, "W-1362: unlink %s: %s",
					        phttp->pfast_context->tmpfile.c_str(),
					        strerror(errno));
				break;
			}
			ndr_push.init(ndr_buff, sizeof(ndr_buff), NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
			if (NDR_ERR_SUCCESS != mod_fastcgi_push_stdin(
				&ndr_push, tmp_buff, tmp_len)) {
				close(cli_sockd);
				phttp->log(LV_DEBUG, "failed to "
					"push stdin record for mod_fastcgi");
				return FALSE;
			}
			auto ret = write(cli_sockd, ndr_buff, ndr_push.offset);
			if (ret < 0 || static_cast<size_t>(ret) != ndr_push.offset) {
				close(cli_sockd);
				phttp->log(LV_DEBUG, "failed to "
					"write record to fastcgi back-end %s (ret=%zd, %s)",
					phttp->pfast_context->pfnode->sock_path.c_str(),
					ret, strerror(errno));
				return FALSE;
			}
		}
	}
 END_OF_STDIN:
	ndr_push.init(ndr_buff, sizeof(ndr_buff), NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
	if (NDR_ERR_SUCCESS != mod_fastcgi_push_stdin(
		&ndr_push, NULL, 0)) {
		close(cli_sockd);
		phttp->log(LV_DEBUG, "failed to push "
			"last empty stdin record for mod_fastcgi");
		return FALSE;
	}
	auto ret = write(cli_sockd, ndr_buff, ndr_push.offset);
	if (ret < 0 || static_cast<size_t>(ret) != ndr_push.offset) {
		close(cli_sockd);
		phttp->log(LV_DEBUG, "failed to write"
			" last empty stdin to fastcgi back-end %s (ret=%zd, %s)",
			phttp->pfast_context->pfnode->sock_path.c_str(),
			ret, strerror(errno));
		return FALSE;
	}
	phttp->pfast_context->cli_sockd = cli_sockd;
	return TRUE;
}

void mod_fastcgi_put_context(HTTP_CONTEXT *phttp)
{
	auto &fc = *phttp->pfast_context;
	if (fc.cache_fd >= 0) {
		close(phttp->pfast_context->cache_fd);
		phttp->pfast_context->cache_fd = -1;
		if (!fc.tmpfile.empty() && unlink(fc.tmpfile.c_str()) < 0 &&
		    errno != ENOENT)
			mlog(LV_WARN, "W-1362: unlink %s: %s",
				fc.tmpfile.c_str(), strerror(errno));
	}
	if (phttp->pfast_context->cli_sockd != -1) {
		close(phttp->pfast_context->cli_sockd);
		phttp->pfast_context->cli_sockd = -1;
	}
	phttp->pfast_context = NULL;
}

BOOL mod_fastcgi_write_request(HTTP_CONTEXT *phttp)
{
	int size;
	int tmp_len;
	void *pbuff;
	char *ptoken;
	char tmp_buff[1024];
	
	if (phttp->pfast_context->b_end)
		return TRUE;
	if (phttp->pfast_context->cache_fd < 0) {
		if (phttp->pfast_context->content_length <= phttp->stream_in.get_total_length())
			phttp->pfast_context->b_end = TRUE;	
		return TRUE;
	}
	if (!phttp->pfast_context->b_chunked) {
		if (phttp->pfast_context->cache_size + phttp->stream_in.get_total_length() < phttp->pfast_context->content_length &&
		    phttp->stream_in.get_total_length() < g_cache_size)
			return TRUE;	
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = phttp->stream_in.get_read_buf(reinterpret_cast<unsigned int *>(&size))) != nullptr) {
			if (phttp->pfast_context->cache_size + size >
				phttp->pfast_context->content_length) {
				tmp_len = phttp->pfast_context->content_length
							- phttp->pfast_context->cache_size;
				phttp->stream_in.rewind_read_ptr(size - tmp_len);
				phttp->pfast_context->cache_size =
					phttp->pfast_context->content_length;
			} else {
				phttp->pfast_context->cache_size += size;
				tmp_len = size;
			}
			if (tmp_len != write(phttp->pfast_context->cache_fd,
				pbuff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to"
					" write cache file for mod_fastcgi");
				return FALSE;
			}
			if (phttp->pfast_context->cache_size ==
				phttp->pfast_context->content_length) {
				phttp->pfast_context->b_end = TRUE;
				return TRUE;
			}
			size = STREAM_BLOCK_SIZE;
		}
	} else {
 CHUNK_BEGIN:
		if (phttp->pfast_context->chunk_size ==
			phttp->pfast_context->chunk_offset) {
			size = phttp->stream_in.peek_buffer(tmp_buff, 1024);
			if (size < 5)
				return TRUE;
			if (0 == strncmp("0\r\n\r\n", tmp_buff, 5)) {
				phttp->stream_in.fwd_read_ptr(5);
				phttp->pfast_context->b_end = TRUE;
				return TRUE;
			}
			ptoken = static_cast<char *>(memmem(tmp_buff, size, "\r\n", 2));
			if (NULL == ptoken) {
				if (1024 == size) {
					phttp->log(LV_DEBUG, "failed to "
						"parse chunked block for mod_fastcgi");
					return FALSE;
				}
				return TRUE;
			}
			*ptoken = '\0';
			phttp->pfast_context->chunk_size =
					strtol(tmp_buff, NULL, 16);
			if (0 == phttp->pfast_context->chunk_size) {
				phttp->log(LV_DEBUG, "failed to "
					"parse chunked block for mod_fastcgi");
				return FALSE;
			}
			phttp->pfast_context->chunk_offset = 0;
			tmp_len = ptoken + 2 - tmp_buff;
			phttp->stream_in.fwd_read_ptr(tmp_len);
		}
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = phttp->stream_in.get_read_buf(reinterpret_cast<unsigned int *>(&size))) != nullptr) {
			if (phttp->pfast_context->chunk_size >=
				size + phttp->pfast_context->chunk_offset) {
				if (size != write(phttp->pfast_context->cache_fd,
					pbuff, size)) {
					phttp->log(LV_DEBUG, "failed to"
						" write cache file for mod_fastcgi");
					return FALSE;
				}
				phttp->pfast_context->chunk_offset += size;
				phttp->pfast_context->cache_size += size;
			} else {
				tmp_len = phttp->pfast_context->chunk_size
					- phttp->pfast_context->chunk_offset;
				if (tmp_len != write(phttp->pfast_context->cache_fd,
					pbuff, tmp_len)) {
					phttp->log(LV_DEBUG, "failed to"
						" write cache file for mod_fastcgi");
					return FALSE;
				}
				phttp->stream_in.rewind_read_ptr(size - tmp_len);
				phttp->pfast_context->cache_size += tmp_len;
				phttp->pfast_context->chunk_offset =
					phttp->pfast_context->chunk_size;
			}
			if (phttp->pfast_context->cache_size > g_max_size) {
				phttp->log(LV_DEBUG, "chunked content"
						" length is too long for mod_fastcgi");
				return FALSE;
			}
			if (phttp->pfast_context->chunk_offset ==
			    phttp->pfast_context->chunk_size)
				goto CHUNK_BEGIN;	
		}
	}
	phttp->stream_in.clear();
	return TRUE;
}

static BOOL mod_fastcgi_safe_read(FASTCGI_CONTEXT *pfast_context,
    void *pbuff, int length)
{
	int offset;
	int tv_msec;
	int read_len;
	struct pollfd pfd_read;
	
	offset = 0;
	while (true) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pfast_context->cli_sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (poll(&pfd_read, 1, tv_msec) != 1)
			return FALSE;
		read_len = read(pfast_context->cli_sockd,
		           static_cast<char *>(pbuff) + offset,
		           length - offset);
		if (read_len <= 0)
			return FALSE;
		offset += read_len;
		if (length == offset) {
			pfast_context->last_time = tp_now();
			return TRUE;
		}
	}
}

int mod_fastcgi_check_response(HTTP_CONTEXT *phttp)
{
	int tv_msec;
	int context_num;
	struct pollfd pfd_read;
	
	context_num = contexts_pool_get_param(CUR_SCHEDULING_CONTEXTS)
				+ threads_pool_get_param(THREADS_POOL_CUR_THR_NUM);
	tv_msec = POLL_MILLISECONDS_FOR_CHECK *
			(g_unavailable_times / context_num);
	if (tv_msec > 999)
		tv_msec = 999;
	pfd_read.fd = phttp->pfast_context->cli_sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (1 == poll(&pfd_read, 1, tv_msec)) {
		g_unavailable_times = 0;
		return RESPONSE_AVAILABLE;
	}
	g_unavailable_times ++;
	if (tp_now() - phttp->pfast_context->last_time > g_exec_timeout)
		return RESPONSE_TIMEOUT;
	return RESPONSE_WAITING;
}

BOOL mod_fastcgi_read_response(HTTP_CONTEXT *phttp)
{
	unsigned int tmp_len;
	time_t cur_time;
	struct tm tmp_tm;
	NDR_PULL ndr_pull;
	char dstring[128], tmp_buff[80000], response_buff[65536];
	char status_line[1024], *pbody, *ptoken, *ptoken1;
	RECORD_HEADER header;
	uint8_t header_buff[8];
	uint32_t response_offset;
	FCGI_STDSTREAM std_stream;
	FCGI_ENDREQUESTBODY end_request;
	
	if (phttp->pfast_context->b_header &&
		0 == strcasecmp(phttp->request.method, "HEAD")) {
		mod_fastcgi_put_context(phttp);
		return FALSE;	
	}
	response_offset = 0;
	while (true) {
		if (!mod_fastcgi_safe_read(phttp->pfast_context,
		    header_buff, arsizeof(header_buff))) {
			phttp->log(LV_DEBUG, "failed to read"
				" record header from fastcgi back-end %s",
				phttp->pfast_context->pfnode->sock_path.c_str());
			mod_fastcgi_put_context(phttp);
			return FALSE;	
		}
		ndr_pull_init(&ndr_pull, header_buff, 8,
			NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
		if (NDR_ERR_SUCCESS != mod_fastcgi_pull_record_header(
			&ndr_pull, &header)) {
			phttp->log(LV_DEBUG, "failed to "
				"pull record header in mod_fastcgi");
			mod_fastcgi_put_context(phttp);
			return FALSE;
		}
		switch (header.type) {
		case RECORD_TYPE_END_REQUEST:
			if (8 != header.content_len) {
				phttp->log(LV_DEBUG, "record header"
					" format error from fastcgi back-end %s",
					phttp->pfast_context->pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			tmp_len = header.padding_len + 8;
			if (!mod_fastcgi_safe_read(phttp->pfast_context,
			    tmp_buff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to read"
				" record header from fastcgi back-end %s",
				phttp->pfast_context->pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			ndr_pull_init(&ndr_pull, tmp_buff, tmp_len,
				NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
			if (mod_fastcgi_pull_end_request(&ndr_pull,
			    header.padding_len, &end_request) != NDR_ERR_SUCCESS)
				phttp->log(LV_DEBUG, "failed to"
					" pull record body in mod_fastcgi");
			else
				phttp->log(LV_DEBUG, "app_status %u, "
						"protocol_status %d from fastcgi back-end"
						" %s", end_request.app_status,
						(int)end_request.protocol_status,
						phttp->pfast_context->pfnode->sock_path.c_str());
			if (phttp->pfast_context->b_header &&
			    phttp->pfast_context->b_chunked)
				phttp->stream_out.write("0\r\n\r\n", 5);
			mod_fastcgi_put_context(phttp);
			return FALSE;
		case RECORD_TYPE_STDOUT:
		case RECORD_TYPE_STDERR:
			tmp_len = header.content_len + header.padding_len;
			if (!mod_fastcgi_safe_read(phttp->pfast_context,
			    tmp_buff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to read"
					" record header from fastcgi back-end %s",
					phttp->pfast_context->pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			ndr_pull_init(&ndr_pull, tmp_buff, tmp_len,
					NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
			std_stream.length = header.content_len;
			if (NDR_ERR_SUCCESS != mod_fastcgi_pull_stdstream(
				&ndr_pull, header.padding_len, &std_stream)) {
				phttp->log(LV_DEBUG, "failed to"
					" pull record body in mod_fastcgi");
				mod_fastcgi_put_context(phttp);
				return FALSE;	
			}
			if (RECORD_TYPE_STDERR == header.type) {
				memcpy(tmp_buff, std_stream.buffer, std_stream.length);
				tmp_buff[std_stream.length] = '\0';
				phttp->log(LV_DEBUG, "stderr message "
					"\"%s\" from fastcgi back-end %s", tmp_buff,
					phttp->pfast_context->pfnode->sock_path.c_str());
				continue;
			}
			if (phttp->pfast_context->b_header) {
				if (0 == std_stream.length) {
					phttp->log(LV_DEBUG, "empty stdout "
						"record is not supported by mod_fastcgi");
					mod_fastcgi_put_context(phttp);
					return FALSE;
				}
				if (phttp->pfast_context->b_chunked) {
					tmp_len = snprintf(tmp_buff, arsizeof(tmp_buff), "%x\r\n", std_stream.length);
					if (phttp->stream_out.write(tmp_buff, tmp_len) != STREAM_WRITE_OK ||
					    phttp->stream_out.write(std_stream.buffer, std_stream.length) != STREAM_WRITE_OK ||
					    phttp->stream_out.write("\r\n", 2) != STREAM_WRITE_OK) {
						phttp->log(LV_DEBUG, "failed to write"
								" stdin into stream in mod_fastcgi");
						mod_fastcgi_put_context(phttp);
						return FALSE;
					}
				} else {
					if (phttp->stream_out.write(std_stream.buffer,
					    std_stream.length) != STREAM_WRITE_OK) {
						phttp->log(LV_DEBUG, "failed to write"
								" stdin into stream in mod_fastcgi");
						mod_fastcgi_put_context(phttp);
						return FALSE;
					}
				}
				return TRUE;
			}
			if (response_offset + std_stream.length > sizeof(response_buff)) {
				phttp->log(LV_DEBUG, "response "
					"header too long from fastcgi back-end %s",
					phttp->pfast_context->pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			memcpy(response_buff + response_offset,
				std_stream.buffer, std_stream.length);
			response_offset += std_stream.length;
			pbody = static_cast<char *>(memmem(response_buff,
			        response_offset, "\r\n\r\n", 4));
			if (pbody == nullptr)
				continue;
			if (0 == strncasecmp(response_buff, "Status:", 7)) {
				ptoken = response_buff + 7;
			} else {
				ptoken = search_string(response_buff,
					"\r\nStatus:", response_offset);
				if (ptoken != NULL)
					ptoken += 9;
			}
			if (NULL == ptoken) {
				strcpy(status_line, "200 Success");
			} else {
				tmp_len = response_offset - (ptoken - response_buff);
				ptoken1 = static_cast<char *>(memmem(ptoken, tmp_len, "\r\n", 2));
				if (NULL == ptoken1 || (tmp_len = ptoken1
					- ptoken) >= sizeof(status_line)) {
					phttp->log(LV_DEBUG, "response header"
						"format error from fastcgi back-end %s",
						phttp->pfast_context->pfnode->sock_path.c_str());
					mod_fastcgi_put_context(phttp);
					return FALSE;
				}
				memcpy(status_line, ptoken, tmp_len);
				status_line[tmp_len] = '\0';
				HX_strltrim(status_line);
			}
			pbody[2] = '\0';
			pbody += 4;
			/* Content-Length */
			phttp->pfast_context->b_chunked =
				strncasecmp(response_buff, "Content-Length:", 15) != 0 &&
				strcasestr(response_buff, "\r\nContent-Length:") == nullptr ?
				TRUE : false;
			time(&cur_time);
			gmtime_r(&cur_time, &tmp_tm);
			strftime(dstring, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
			if (strcasecmp(phttp->request.method, "HEAD") == 0)
				tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
								"HTTP/1.1 %s\r\n"
								"Date: %s\r\n"
								"%s\r\n", status_line,
								dstring, response_buff);
			else if (phttp->pfast_context->b_chunked)
				tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
				          "HTTP/1.1 %s\r\n"
				          "Date: %s\r\n"
				          "Transfer-Encoding: chunked\r\n"
				          "%s\r\n", status_line,
				          dstring, response_buff);
			else
				tmp_len = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff),
				          "HTTP/1.1 %s\r\n"
				          "Date: %s\r\n"
				          "%s\r\n", status_line,
				          dstring, response_buff);
			if (phttp->stream_out.write(tmp_buff, tmp_len) != STREAM_WRITE_OK) {
				phttp->log(LV_DEBUG, "failed to write "
					"response header into stream in mod_fastcgi");
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			phttp->pfast_context->b_header = TRUE;
			if (strcasecmp(phttp->request.method, "HEAD") == 0)
				return TRUE;
			response_offset = response_buff + response_offset - pbody;
			if (response_offset > 0) {
				if (phttp->pfast_context->b_chunked) {
					tmp_len = snprintf(tmp_buff, arsizeof(tmp_buff), "%x\r\n", response_offset);
					if (phttp->stream_out.write(tmp_buff, tmp_len) != STREAM_WRITE_OK ||
					    phttp->stream_out.write(pbody, response_offset) != STREAM_WRITE_OK ||
					    phttp->stream_out.write("\r\n", 2) != STREAM_WRITE_OK) {
						phttp->log(LV_DEBUG, "failed to write"
								" stdin into stream in mod_fastcgi");
						mod_fastcgi_put_context(phttp);
						return FALSE;
					}
				} else {
					if (phttp->stream_out.write(pbody, response_offset) != STREAM_WRITE_OK) {
						phttp->log(LV_DEBUG, "failed to write"
								" stdin into stream in mod_fastcgi");
						mod_fastcgi_put_context(phttp);
						return FALSE;	
					}
				}
			}
			return TRUE;
		default:
			tmp_len = header.content_len + header.padding_len;
			if (!mod_fastcgi_safe_read(phttp->pfast_context,
			    tmp_buff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to read"
				" record header from fastcgi back-end %s",
				phttp->pfast_context->pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			phttp->log(LV_DEBUG, "ignore record %d"
				" from fastcgi back-end %s", (int)header.type,
				phttp->pfast_context->pfnode->sock_path.c_str());
			continue;
		}
	}
}
