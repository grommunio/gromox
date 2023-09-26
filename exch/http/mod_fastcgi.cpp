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
#include <libHX/io.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/http.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/ndr.hpp>
#include <gromox/paths.h>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "http_parser.h"
#include "mod_fastcgi.h"
#include "resource.h"
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)
#define QRF(expr) do { if (pack_result{expr} != EXT_ERR_SUCCESS) return false; } while (false)

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

struct fastcgi_context {
	BOOL b_index = false;
	BOOL b_header = false; /* is response header met */
	const FASTCGI_NODE *pfnode = nullptr;
	gromox::time_point last_time{};
	int cli_sockd = -1;
	bool b_active = false;
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

void mod_fastcgi_init(int context_num, time_duration exec_timeout)
{
	g_context_num = context_num;
	g_unavailable_times = 0;
	g_exec_timeout = exec_timeout;
}

static int mod_fastcgi_defaults()
{
	mlog(LV_NOTICE, "mod_fastcgi: defaulting to built-in list of handled paths");
	FASTCGI_NODE node;
	node.domain = "*";
	node.path = "/sync";
	node.dir = DATADIR "/grommunio-sync";
	node.suffix = "php";
	node.index = "index.php";
	node.sock_path = FPMSOCKDIR "/php-grommunio-sync-fpm.sock";
	g_fastcgi_list.push_back(node);
	node.path = "/web";
	node.dir = DATADIR "/grommunio-web";
	node.sock_path = FPMSOCKDIR "/php-grommunio-web-fpm.sock";
	g_fastcgi_list.push_back(node);
	if (!g_http_php)
		return 0;
	/* Only if http_old_php_handler: */
	node.path = "/EWS";
	node.dir = PKGDATADIR "/http/php/ews";
	node.header_list = {"X-MAPIHttpCapability", "X-AnchorMailbox", "X-ClientCanHandle"};
	node.sock_path = FPMSOCKDIR "/php-gromox-fpm.sock";
	g_fastcgi_list.push_back(node);
	node.path = "/ews";
	g_fastcgi_list.push_back(node);
	return 0;
}

static int mod_fastcgi_read_txt() try
{
	struct srcitem {
		char domain[256], path[256], dir[256], suffix[16], index[256];
		char extra_headers[304], sock_path[256];
	};
	auto pfile = list_file_initd("fastcgi.txt", g_config_file->get_value("config_file_path"),
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

static pack_result mod_fastcgi_push_name_value(NDR_PUSH *pndr,
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

static pack_result mod_fastcgi_push_begin_request(NDR_PUSH *pndr)
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

static pack_result mod_fastcgi_push_params_begin(NDR_PUSH *pndr)
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

static pack_result mod_fastcgi_push_align_record(NDR_PUSH *pndr)
{
	uint8_t padding_len;
	
	if (!(pndr->offset & 7))
		return NDR_ERR_SUCCESS;
	padding_len = 8 - (pndr->offset & 7);
	pndr->data[6] = padding_len;
	return pndr->p_zero(padding_len);
}

static pack_result mod_fastcgi_push_params_end(NDR_PUSH *pndr)
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

static pack_result mod_fastcgi_push_stdin(NDR_PUSH *pndr,
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

static pack_result mod_fastcgi_pull_end_request(NDR_PULL *pndr,
	uint8_t padding_len, FCGI_ENDREQUESTBODY *pend_request)
{
	TRY(pndr->g_uint32(&pend_request->app_status));
	TRY(pndr->g_uint8(&pend_request->protocol_status));
	TRY(pndr->g_uint8_a(pend_request->reserved, 3));
	return pndr->advance(padding_len);
}

static pack_result mod_fastcgi_pull_stdstream(NDR_PULL *pndr,
	uint8_t padding_len, FCGI_STDSTREAM *pstd_stream)
{
	TRY(pndr->g_uint8_a(pstd_stream->buffer, pstd_stream->length));
	return pndr->advance(padding_len);
}

static pack_result mod_fastcgi_pull_record_header(
	NDR_PULL *pndr, RECORD_HEADER *pheader)
{
	TRY(pndr->g_uint8(&pheader->version));
	TRY(pndr->g_uint8(&pheader->type));
	TRY(pndr->g_uint16(&pheader->request_id));
	TRY(pndr->g_uint16(&pheader->content_len));
	TRY(pndr->g_uint8(&pheader->padding_len));
	return pndr->g_uint8(&pheader->reserved);
}

static const char *
mod_fastcgi_get_others_field(const http_request::other_map &m, const char *k)
{
	auto i = m.find(k);
	return i != m.end() ? i->second.c_str() : nullptr;
}

static int mod_fastcgi_connect_backend(const char *path)
{
	int sockd, len;
	struct sockaddr_un un;

	/* create a UNIX domain stream socket */
	sockd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockd < 0)
		return -errno;
	/* fill socket address structure with server's address */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	gx_strlcpy(un.sun_path, path, std::size(un.sun_path));
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
	if (connect(sockd, (struct sockaddr *)&un, len) < 0) {
		auto se = errno;
		close(sockd);
		return -(errno = se);
	}
	return sockd;
}

http_status mod_fastcgi_take_request(http_context *phttp)
{
	auto &rq = phttp->request;
	BOOL b_index;
	char *ptoken;
	char *ptoken1;
	char suffix[16];
	char file_name[256];
	char request_uri[http_request::uri_limit];
	
	if (!parse_uri(phttp->request.f_request_uri.c_str(), request_uri)) {
		phttp->log(LV_DEBUG, "request"
			" uri format error for mod_fastcgi");
		return http_status::bad_request;
	}
	ptoken = strrchr(request_uri, '?');
	if (ptoken != nullptr)
		*ptoken = '\0';
	ptoken = strrchr(request_uri, '.');
	if (ptoken != nullptr) {
		*ptoken++ = '\0';
		ptoken1 = strchr(ptoken, '/');
		if (ptoken1 != nullptr)
			*ptoken1 = '\0';
		auto tmp_len = strlen(ptoken);
		if (tmp_len >= 16) {
			phttp->log(LV_DEBUG, "suffix in"
				" request uri error for mod_fastcgi");
			return http_status::none;
		}
		strcpy(suffix, ptoken);
	} else {
		suffix[0] = '\0';
	}
	ptoken = strrchr(request_uri, '/');
	if (NULL != ptoken) {
		*ptoken = '\0';
		gx_strlcpy(file_name, &ptoken[1], std::size(file_name));
	} else {
		phttp->log(LV_DEBUG, "request uri format "
					"error, missing slash for mod_fastcgi");
		return http_status::bad_request;
	}
	auto pfnode = mod_fastcgi_find_backend(phttp->request.f_host.c_str(),
	              request_uri, file_name, suffix, &b_index);
	if (pfnode == nullptr)
		return http_status::none;
	phttp->log(LV_DEBUG, "http request \"%s\" "
		"to \"%s\" will be relayed to fastcgi back-end %s",
		phttp->request.f_request_uri.c_str(),
		phttp->request.f_host.c_str(), pfnode->sock_path.c_str());
	if (rq.content_len > g_rqbody_max_size) {
		phttp->log(LV_DEBUG, "content-length"
			" is too long for mod_fastcgi");
		return http_status::bad_request;
	}
	auto pcontext = &g_context_list[phttp->context_id];
	pcontext->last_time = tp_now();
	pcontext->pfnode = pfnode;
	if (rq.b_chunked || rq.content_len > g_rqbody_flush_size) {
		auto path = LOCAL_DISK_TMPDIR;
		if (mkdir(path, 0777) < 0 && errno != EEXIST) {
			mlog(LV_ERR, "E-2077: mkdir %s: %s", path, strerror(errno));
			return http_status::server_error;
		}
		auto ret = rq.body_fd.open_anon(path, O_RDWR | O_TRUNC);
		if (ret < 0) {
			mlog(LV_ERR, "E-2078: open_anon(%s)[%s]: %s",
			        path, rq.body_fd.m_path.c_str(),
			        strerror(-ret));
			return http_status::server_error;
		}
		rq.posted_size = 0;
	} else {
		rq.body_fd.close();
	}
	pcontext->b_index = b_index;
	if (rq.b_chunked) {
		rq.chunk_size = 0;
		rq.chunk_offset = 0;
	}
	rq.b_end = false;
	pcontext->cli_sockd = -1;
	pcontext->b_header = FALSE;
	pcontext->b_active = true;
	return http_status::ok;
}

BOOL mod_fastcgi_check_responded(HTTP_CONTEXT *phttp)
{
	return g_context_list[phttp->context_id].b_header;
}

static BOOL mod_fastcgi_build_params(HTTP_CONTEXT *phttp,
	uint8_t *pbuff, int *plength)
{
	auto &rq = phttp->request;
	char *ptoken;
	char *ptoken1;
	char *path_info;
	NDR_PUSH ndr_push;
	char uri_path[8192];
	char tmp_buff[8192];
	struct stat node_stat;
	
	ndr_push.init(pbuff, *plength, NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
	QRF(mod_fastcgi_push_params_begin(&ndr_push));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "GATEWAY_INTERFACE", "CGI/1.1"));
	if (phttp->auth_status == http_status::ok) {
		QRF(mod_fastcgi_push_name_value(&ndr_push, "REMOTE_USER", phttp->username));
		QRF(mod_fastcgi_push_name_value(&ndr_push, "USER_HOME", phttp->maildir));
		QRF(mod_fastcgi_push_name_value(&ndr_push, "USER_LANG", phttp->lang));
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_HOST", phttp->request.f_host.c_str()));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_NAME", phttp->request.f_host.c_str()));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_ADDR", phttp->connection.server_ip));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_PORT", std::to_string(phttp->connection.server_port).c_str()));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "REMOTE_ADDR", phttp->connection.client_ip));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "REMOTE_PORT", std::to_string(phttp->connection.client_port).c_str()));
	snprintf(tmp_buff, std::size(tmp_buff), "HTTP/%s", phttp->request.version);
	QRF(mod_fastcgi_push_name_value(&ndr_push, "SERVER_PROTOCOL", tmp_buff));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "REQUEST_METHOD", phttp->request.method));
	auto furi = phttp->request.f_request_uri.c_str();
	QRF(mod_fastcgi_push_name_value(&ndr_push, "REQUEST_URI", furi));
	auto qmark = strchr(furi, '?');
	QRF(mod_fastcgi_push_name_value(&ndr_push, "QUERY_STRING", qmark == nullptr ? "" : ++qmark));
	if (!parse_uri(furi, uri_path)) {
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
	auto &fctx = g_context_list[phttp->context_id];
	auto pfnode = fctx.pfnode;
	QRF(mod_fastcgi_push_name_value(&ndr_push, "DOCUMENT_ROOT", pfnode->dir.c_str()));
	if (NULL != path_info) {
		snprintf(tmp_buff, std::size(tmp_buff), "%s/%s", pfnode->dir.c_str(), path_info);
		QRF(mod_fastcgi_push_name_value(&ndr_push, "PATH_TRANSLATED", tmp_buff));
	}
	auto tmp_len = pfnode->path.size();
	if (fctx.b_index) {
		snprintf(tmp_buff, std::size(tmp_buff), "%s%s", uri_path, pfnode->index.c_str());
		QRF(mod_fastcgi_push_name_value(&ndr_push, "SCRIPT_NAME", tmp_buff));
		snprintf(tmp_buff, std::size(tmp_buff), "%s%s%s", pfnode->dir.c_str(),
		         uri_path + tmp_len, pfnode->index.c_str());
		QRF(mod_fastcgi_push_name_value(&ndr_push, "SCRIPT_FILENAME", tmp_buff));
	} else {
		QRF(mod_fastcgi_push_name_value(&ndr_push, "SCRIPT_NAME", uri_path));
		snprintf(tmp_buff, std::size(tmp_buff), "%s%s", pfnode->dir.c_str(), uri_path + tmp_len);
		QRF(mod_fastcgi_push_name_value(&ndr_push, "SCRIPT_FILENAME", tmp_buff));
	}
	tmp_len = phttp->request.f_accept.size();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"accept is too long for mod_fastcgi");
		return FALSE;
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_ACCEPT", phttp->request.f_accept.c_str()));
	tmp_len = phttp->request.f_user_agent.size();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"user-agent is too long for mod_fastcgi");
		return FALSE;
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_USER_AGENT", phttp->request.f_user_agent.c_str()));
	tmp_len = phttp->request.f_accept_language.size();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"accept-language is too long for mod_fastcgi");
		return FALSE;
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_ACCEPT_LANGUAGE", phttp->request.f_accept_language.c_str()));
	tmp_len = phttp->request.f_accept_encoding.size();
	if (tmp_len > 1024) {
		phttp->log(LV_DEBUG, "length of "
			"accept-encoding is too long for mod_fastcgi");
		return FALSE;
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_ACCEPT_ENCODING", phttp->request.f_accept_encoding.c_str()));
	QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_COOKIE", phttp->request.f_cookie.c_str()));
	tmp_len = phttp->request.f_content_type.size();
	if (tmp_len > 128) {
		phttp->log(LV_DEBUG, "length of "
			"content-type is too long for mod_fastcgi");
		return FALSE;
	}
	QRF(mod_fastcgi_push_name_value(&ndr_push, "CONTENT_TYPE", phttp->request.f_content_type.c_str()));
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
	auto val = mod_fastcgi_get_others_field(phttp->request.f_others, "Referer");
	if (val != nullptr)
		QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_REFERER", val));
	val = mod_fastcgi_get_others_field(phttp->request.f_others, "Cache-Control");
	if (val != nullptr)
		QRF(mod_fastcgi_push_name_value(&ndr_push, "HTTP_CACHE_CONTROL", val));
	for (const auto &hdr : pfnode->header_list) {
		val = mod_fastcgi_get_others_field(phttp->request.f_others, hdr.c_str());
		if (val != nullptr)
			QRF(mod_fastcgi_push_name_value(&ndr_push,
			    hdr.c_str(), val));
	}
	if (!rq.b_chunked) {
		snprintf(tmp_buff, sizeof(tmp_buff), "%llu",
		         static_cast<unsigned long long>(rq.content_len));
		QRF(mod_fastcgi_push_name_value(&ndr_push, "CONTENT_LENGTH", tmp_buff));
	} else {
		if (fstat(rq.body_fd, &node_stat) != 0)
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
	auto &rq = phttp->request;
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
	auto &fctx = g_context_list[phttp->context_id];
	auto sk_path = fctx.pfnode->sock_path.c_str();
	cli_sockd = mod_fastcgi_connect_backend(sk_path);
	if (cli_sockd < 0) {
		phttp->log(LV_ERR, "Failed to connect to fastcgi back-end %s: %s",
			sk_path, strerror(-cli_sockd));
		return FALSE;
	}
	if (HXio_fullwrite(cli_sockd, tmp_buff, 16) != 16 ||
	    HXio_fullwrite(cli_sockd, ndr_buff, ndr_length) != ndr_length) {
		auto se = errno;
		close(cli_sockd);
		phttp->log(LV_ERR, "Failed to write record to fastcgi back-end %s: %s",
			sk_path, strerror(se));
		return FALSE;
	}
	ndr_push.init(tmp_buff, 8, NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
	if (NDR_ERR_SUCCESS != mod_fastcgi_push_params_begin(&ndr_push) ||
		NDR_ERR_SUCCESS != mod_fastcgi_push_params_end(&ndr_push) ||
		8 != ndr_push.offset || 8 != write(cli_sockd, tmp_buff, 8)) {
		close(cli_sockd);
		phttp->log(LV_ERR, "Failed to write record to fastcgi back-end %s", sk_path);
		return FALSE;
	}
	if (rq.body_fd < 0) {
		if (rq.content_len == 0)
			goto END_OF_STDIN;
		unsigned int tmp_len = sizeof(tmp_buff);
		while ((pbuff = phttp->stream_in.get_read_buf(&tmp_len)) != nullptr) {
			if (tmp_len > rq.content_len) {
				phttp->stream_in.rewind_read_ptr(tmp_len - rq.content_len);
				tmp_len = rq.content_len;
				rq.content_len = 0;
			} else{
				rq.content_len -= tmp_len;
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
					fctx.pfnode->sock_path.c_str(),
					ret, strerror(errno));
				return FALSE;
			}
			if (rq.content_len == 0)
				break;
			tmp_len = sizeof(tmp_buff);
		}
	} else {
		lseek(rq.body_fd, 0, SEEK_SET);
		while (true) {
			auto tmp_len = read(rq.body_fd, tmp_buff, sizeof(tmp_buff));
			if (tmp_len < 0) {
				close(cli_sockd);
				phttp->log(LV_DEBUG, "failed to"
					" read cache file for mod_fastcgi");
				return FALSE;
			} else if (0 == tmp_len) {
				rq.body_fd.close();
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
					fctx.pfnode->sock_path.c_str(),
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
			fctx.pfnode->sock_path.c_str(),
			ret, strerror(errno));
		return FALSE;
	}
	fctx.cli_sockd = cli_sockd;
	return TRUE;
}

void mod_fastcgi_put_context(HTTP_CONTEXT *phttp)
{
	auto &fctx = g_context_list[phttp->context_id];
	phttp->request.body_fd.close();
	if (fctx.cli_sockd != -1) {
		close(fctx.cli_sockd);
		fctx.cli_sockd = -1;
	}
	fctx.b_active = false;
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
	auto &fctx = g_context_list[phttp->context_id];
	pfd_read.fd = fctx.cli_sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (1 == poll(&pfd_read, 1, tv_msec)) {
		g_unavailable_times = 0;
		return RESPONSE_AVAILABLE;
	}
	g_unavailable_times ++;
	if (tp_now() - fctx.last_time > g_exec_timeout)
		return RESPONSE_TIMEOUT;
	return RESPONSE_WAITING;
}

BOOL mod_fastcgi_read_response(HTTP_CONTEXT *phttp)
{
	auto &rq = phttp->request;
	unsigned int tmp_len;
	NDR_PULL ndr_pull;
	char dstring[128], tmp_buff[80000], response_buff[65536];
	char status_line[1024], *pbody, *ptoken, *ptoken1;
	RECORD_HEADER header;
	uint8_t header_buff[8];
	uint32_t response_offset;
	FCGI_STDSTREAM std_stream;
	FCGI_ENDREQUESTBODY end_request;
	auto &fctx = g_context_list[phttp->context_id];
	
	if (fctx.b_header && strcasecmp(phttp->request.method, "HEAD") == 0) {
		mod_fastcgi_put_context(phttp);
		return FALSE;	
	}
	response_offset = 0;
	while (true) {
		if (!mod_fastcgi_safe_read(&fctx, header_buff, std::size(header_buff))) {
			phttp->log(LV_DEBUG, "failed to read"
				" record header from fastcgi back-end %s",
				fctx.pfnode->sock_path.c_str());
			mod_fastcgi_put_context(phttp);
			return FALSE;	
		}
		ndr_pull.init(header_buff, 8, NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
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
					fctx.pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			tmp_len = header.padding_len + 8;
			if (!mod_fastcgi_safe_read(&fctx,
			    tmp_buff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to read"
				" record header from fastcgi back-end %s",
				fctx.pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			ndr_pull.init(tmp_buff, tmp_len, NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
			if (mod_fastcgi_pull_end_request(&ndr_pull,
			    header.padding_len, &end_request) != NDR_ERR_SUCCESS)
				phttp->log(LV_DEBUG, "failed to"
					" pull record body in mod_fastcgi");
			else
				phttp->log(LV_DEBUG, "app_status %u, "
						"protocol_status %d from fastcgi back-end"
						" %s", end_request.app_status,
						(int)end_request.protocol_status,
						fctx.pfnode->sock_path.c_str());
			if (fctx.b_header && rq.b_chunked)
				phttp->stream_out.write("0\r\n\r\n", 5);
			mod_fastcgi_put_context(phttp);
			return FALSE;
		case RECORD_TYPE_STDOUT:
		case RECORD_TYPE_STDERR:
			tmp_len = header.content_len + header.padding_len;
			if (!mod_fastcgi_safe_read(&fctx,
			    tmp_buff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to read"
					" record header from fastcgi back-end %s",
					fctx.pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			ndr_pull.init(tmp_buff, tmp_len, NDR_FLAG_NOALIGN | NDR_FLAG_BIGENDIAN);
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
					fctx.pfnode->sock_path.c_str());
				continue;
			}
			if (fctx.b_header) {
				if (0 == std_stream.length) {
					phttp->log(LV_DEBUG, "empty stdout "
						"record is not supported by mod_fastcgi");
					mod_fastcgi_put_context(phttp);
					return FALSE;
				}
				if (rq.b_chunked) {
					tmp_len = snprintf(tmp_buff, std::size(tmp_buff),
					          "%x\r\n", std_stream.length);
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
					fctx.pfnode->sock_path.c_str());
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
						fctx.pfnode->sock_path.c_str());
					mod_fastcgi_put_context(phttp);
					return FALSE;
				}
				memcpy(status_line, ptoken, tmp_len);
				status_line[tmp_len] = '\0';
				HX_strltrim(status_line);
			}
			pbody[2] = '\0';
			pbody += 4;
			/*
			 * mod_fastcgi first collects the entire request
			 * (function mod_fastcgi_write_request) before passing
			 * it on (function mod_fastcgi_relay_content). This
			 * allows re-assigning b_chunked now for other purposes.
			 */
			/* Content-Length */
			rq.b_chunked =
				strncasecmp(response_buff, "Content-Length:", 15) != 0 &&
				strcasestr(response_buff, "\r\nContent-Length:") == nullptr;
			rfc1123_dstring(dstring, std::size(dstring));
			if (strcasecmp(phttp->request.method, "HEAD") == 0)
				tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
								"HTTP/1.1 %s\r\n"
								"Date: %s\r\n"
								"%s\r\n", status_line,
								dstring, response_buff);
			else if (rq.b_chunked)
				tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
				          "HTTP/1.1 %s\r\n"
				          "Date: %s\r\n"
				          "Transfer-Encoding: chunked\r\n"
				          "%s\r\n", status_line,
				          dstring, response_buff);
			else
				tmp_len = gx_snprintf(tmp_buff, std::size(tmp_buff),
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
			fctx.b_header = TRUE;
			if (strcasecmp(phttp->request.method, "HEAD") == 0)
				return TRUE;
			response_offset = response_buff + response_offset - pbody;
			if (response_offset > 0) {
				if (rq.b_chunked) {
					tmp_len = snprintf(tmp_buff, std::size(tmp_buff),
					          "%x\r\n", response_offset);
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
			if (!mod_fastcgi_safe_read(&fctx,
			    tmp_buff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to read"
				" record header from fastcgi back-end %s",
				fctx.pfnode->sock_path.c_str());
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			phttp->log(LV_DEBUG, "ignore record %d"
				" from fastcgi back-end %s", (int)header.type,
				fctx.pfnode->sock_path.c_str());
			continue;
		}
	}
}

bool mod_fastcgi_is_in_charge(const http_context *hctx)
{
	return g_context_list[hctx->context_id].b_active;
}
