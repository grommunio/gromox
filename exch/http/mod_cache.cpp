// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/paths.h>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "http_parser.h"
#include "mod_cache.hpp"
#include "resource.h"
#include "system_services.hpp"
#define BOUNDARY_STRING				"00000000000000000001"

using namespace gromox;

namespace {
struct cache_item {
	cache_item() = default;
	cache_item(cache_item &&) = delete;
	~cache_item();

	const char *content_type = nullptr;
	void *mblk = nullptr;
	struct stat sb{};
};
using CACHE_ITEM = cache_item;

struct RANGE {
	uint32_t begin;
	uint32_t end;
};

struct cache_context {
	std::shared_ptr<cache_item> pitem;
	BOOL b_header = false;
	uint32_t offset = 0, until = 0;
	ssize_t range_pos = -1;
	std::vector<RANGE> range;
};
using CACHE_CONTEXT = cache_context;

struct DIRECTORY_NODE {
	std::string domain, path, dir;
};

}

static int g_context_num;
static gromox::atomic_bool g_notify_stop;
static pthread_t g_scan_tid;
static std::mutex g_hash_lock;
static std::vector<DIRECTORY_NODE> g_directory_list;
static std::unordered_map<std::string, std::shared_ptr<cache_item>> g_cache_hash;
static std::unique_ptr<CACHE_CONTEXT[]> g_context_list;

cache_item::~cache_item()
{
	if (mblk != nullptr)
		munmap(mblk, static_cast<size_t>(sb.st_size));
}

static bool stat4_eq(const struct stat &a, const struct stat &b)
{
	return a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
	       a.st_mtime == b.st_mtime && a.st_size == b.st_size;
}

static void *mod_cache_scanwork(void *pparam)
{
	int count;
	struct stat node_stat;
	
	count = 0;
	while (!g_notify_stop) {
		count ++;
		if (count < 600) {
			sleep(1);
			continue;
		}
		std::lock_guard hhold(g_hash_lock);
		for (auto iter = g_cache_hash.begin(); iter != g_cache_hash.end(); ) {
			auto &pitem = iter->second;
			if (stat(iter->first.c_str(), &node_stat) == 0 &&
			    S_ISREG(node_stat.st_mode) && stat4_eq(node_stat, pitem->sb)) {
				++iter;
				continue;
			}
			iter = g_cache_hash.erase(iter);
		}
		count = 0;
	}
	return nullptr;
}

void mod_cache_init(int context_num)
{
	g_notify_stop = true;
	g_context_num = context_num;
}

static int mod_cache_defaults()
{
	mlog(LV_NOTICE, "mod_cache: defaulting to built-in list of handled paths");
	DIRECTORY_NODE node;
	node.domain = "*";
	node.path = "/web";
	node.dir = DATADIR "/grommunio-web";
	g_directory_list.push_back(std::move(node));
	return 0;
}

static int mod_cache_read_txt() try
{
	struct srcitem { char domain[256], uri_path[256], dir[256]; };
	
	auto pfile = list_file_initd("cache.txt", resource_get_string("config_file_path"),
	             "%s:256%s:256%s:256", ERROR_ON_ABSENCE);
	if (pfile == nullptr && errno == ENOENT) {
		return mod_cache_defaults();
	} else if (pfile == nullptr) {
		mlog(LV_ERR, "mod_cache: list_file_initd cache.txt: %s", strerror(errno));
		return -1;
	}
	auto item_num = pfile->get_size();
	auto pitem = static_cast<srcitem *>(pfile->get_list());
	for (decltype(item_num) i = 0; i < item_num; ++i) {
		DIRECTORY_NODE node;
		node.domain = pitem[i].domain;
		node.path = pitem[i].uri_path;
		if (node.path.size() > 0 && node.path.back() == '/')
			node.path.pop_back();
		node.dir = pitem[i].dir;
		if (node.dir.size() > 0 && node.dir.back() == '/')
			node.dir.pop_back();
		g_directory_list.push_back(std::move(node));
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1253: ENOMEM");
	return -ENOMEM;
}

int mod_cache_run() try
{
	auto ret = mod_cache_read_txt();
	if (ret < 0)
		return ret;
	g_context_list = std::make_unique<cache_context[]>(g_context_num);
	g_notify_stop = false;
	ret = pthread_create(&g_scan_tid, nullptr, mod_cache_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "mod_cache: failed to create scanning thread: %s", strerror(ret));
		g_notify_stop = true;
		return -4;
	}
	pthread_setname_np(g_scan_tid, "mod_cache");
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "mod_cache: failed to allocate context list");
	return -2;
}

void mod_cache_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (!pthread_equal(g_scan_tid, {})) {
			pthread_kill(g_scan_tid, SIGALRM);
			pthread_join(g_scan_tid, NULL);
		}
	}
	g_directory_list.clear();
	g_context_list.reset();
	g_cache_hash.clear();
}

static CACHE_CONTEXT* mod_cache_get_cache_context(HTTP_CONTEXT *phttp)
{
	return &g_context_list[phttp->context_id];
}

bool mod_cache_is_in_charge(HTTP_CONTEXT *phttp)
{
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	if (NULL != pcontext->pitem) {
		return TRUE;
	}
	return FALSE;
}

static bool mod_cache_retrieve_etag(const char *etag, struct stat &sb)
{
	unsigned int dev, ino;
	unsigned long long size, mtim;
	if (sscanf(etag, "%x-%x-%llx-%llx", &dev, &ino, &size, &mtim) != 4)
		return false;
	sb.st_dev = dev;
	sb.st_ino = ino;
	sb.st_size = size;
	sb.st_mtime = mtim;
	return true;
}

static void mod_cache_serialize_etag(const struct stat &sb, char *etag, size_t len)
{
	snprintf(etag, len, "%x-%llx-%llx-%llx",
	         static_cast<unsigned int>(sb.st_dev),
	         static_cast<unsigned long long>(sb.st_ino),
	         static_cast<unsigned long long>(sb.st_size),
	         static_cast<unsigned long long>(sb.st_mtime));
}

static BOOL mod_cache_get_others_field(MEM_FILE *pf_others,
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

static BOOL mod_cache_parse_rfc1123_dstring(
	const char *dstring, time_t *pmtime)
{
	time_t cur_time;
	struct tm tmp_tm;
	
	time(&cur_time);
	gmtime_r(&cur_time, &tmp_tm);
	if (NULL == strptime(dstring, "%a, %d %b %Y %T GMT", &tmp_tm)) {
		return FALSE;	
	}
	*pmtime = make_gmtime(&tmp_tm);
	return TRUE;
}

static const char *status_text(unsigned int s)
{
	switch (s) {
	case 304: return "304 Not Modified";
	case 400: return "400 Bad Request";
	case 403: return "403 Permission denied";
	case 416: return "416 Range Not Satisfiable";
	case 4162: return "416 Too Many Ranges";
	case 503: return "503 Service Unavailable";
	default: return "500 Internal Server Error";
	}
}

static BOOL mod_cache_exit_response(HTTP_CONTEXT *phttp, unsigned int status)
{
	time_t cur_time;
	struct tm tmp_tm;
	char dstring[128];
	char rb[256];
	
	time(&cur_time);
	gmtime_r(&cur_time, &tmp_tm);
	strftime(dstring, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	auto rl = gx_snprintf(rb, std::size(rb),
	          "HTTP/1.1 %s\r\n"
	          "Date: %s\r\n"
	          "Content-Length: 0\r\n"
	          "Content-Type: text/plain; charset=utf-8\r\n\r\n",
	          status_text(status), dstring);
	return phttp->stream_out.write(rb, rl) == STREAM_WRITE_OK ? TRUE : false;
}

static BOOL mod_cache_response_single_header(HTTP_CONTEXT *phttp)
{
	char etag[128];
	time_t cur_time;
	struct tm tmp_tm;
	int response_len;
	char date_string[128];
	CACHE_CONTEXT *pcontext;
	char response_buff[1024];
	char modified_string[128];
	
	pcontext = mod_cache_get_cache_context(phttp);
	time(&cur_time);
	gmtime_r(&cur_time, &tmp_tm);
	strftime(date_string, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	gmtime_r(&pcontext->pitem->sb.st_mtime, &tmp_tm);
	strftime(modified_string, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	mod_cache_serialize_etag(pcontext->pitem->sb, etag, std::size(etag));
	auto pcontent_type = pcontext->pitem->content_type;
	if (NULL == pcontent_type) {
		pcontent_type = "application/octet-stream";
	}
	bool emit_206 = pcontext->offset != 0 ||
	                pcontext->until != pcontext->pitem->sb.st_size;
	strcpy(response_buff, emit_206 ?
	       "HTTP/1.1 206 Partial Content\r\n" : "HTTP/1.1 200 OK\r\n");
	response_len = strlen(response_buff);
	response_len += gx_snprintf(response_buff + response_len,
	                GX_ARRAY_SIZE(response_buff) - response_len,
					"Date: %s\r\n"
					"Content-Type: %s\r\n"
					"Content-Length: %u\r\n"
					"Accept-Ranges: bytes\r\n"
					"Last-Modified: %s\r\n"
					"ETag: \"%s\"\r\n",
					date_string, pcontent_type,
					pcontext->until - pcontext->offset,
					modified_string, etag);
	if (emit_206) {
		response_len += gx_snprintf(response_buff + response_len,
		                GX_ARRAY_SIZE(response_buff) - response_len,
					"Content-Range: bytes %u-%u/%llu\r\n\r\n",
					pcontext->offset, pcontext->until - 1,
		                static_cast<unsigned long long>(pcontext->pitem->sb.st_size));
	} else {
		gx_strlcpy(&response_buff[response_len], "\r\n",
			arsizeof(response_buff) - response_len);
		response_len += 2;
	}
	return phttp->stream_out.write(response_buff, response_len) == STREAM_WRITE_OK ? TRUE : false;
}

static uint32_t mod_cache_calculate_content_length(CACHE_CONTEXT *pcontext)
{
	int ctype_len;
	char num_buff[64];
	uint32_t content_length;
	
	auto pcontent_type = pcontext->pitem->content_type;
	if (NULL == pcontent_type) {
		pcontent_type = "application/octet-stream";
	}
	ctype_len = strlen(pcontent_type);
	content_length = 0;
	for (size_t i = 0; i < pcontext->range.size(); ++i) {
		/* --boundary_string\r\n */
		content_length += 2 + sizeof(BOUNDARY_STRING) - 1 + 2;
		/* Content-Type: xxx\r\n */
		content_length += 16 + ctype_len;
		/* Content-Range: bytes x-x/xxx\r\n */
		content_length += 25 + sprintf(num_buff, "%u%u%llu",
		                  pcontext->range[i].begin, pcontext->range[i].end,
		                  static_cast<unsigned long long>(pcontext->pitem->sb.st_size));
		content_length += 2; /* \r\n */
		content_length += pcontext->range[i].end - pcontext->range[i].begin + 1;
		content_length += 2; /* \r\n */
	}
	/* --boundary_string--\r\n */
	content_length += 2 + sizeof(BOUNDARY_STRING) - 1 + 2 + 2;
	return content_length;
}

static BOOL mod_cache_response_multiple_header(HTTP_CONTEXT *phttp)
{
	char etag[128];
	time_t cur_time;
	struct tm tmp_tm;
	int response_len;
	char date_string[128];
	uint32_t content_length;
	CACHE_CONTEXT *pcontext;
	char response_buff[1024];
	char modified_string[128];
	
	pcontext = mod_cache_get_cache_context(phttp);
	time(&cur_time);
	gmtime_r(&cur_time, &tmp_tm);
	strftime(date_string, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	gmtime_r(&pcontext->pitem->sb.st_mtime, &tmp_tm);
	strftime(modified_string, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	mod_cache_serialize_etag(pcontext->pitem->sb, etag, std::size(etag));
	content_length =  mod_cache_calculate_content_length(pcontext);	
	response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
					"HTTP/1.1 206 Partial Content\r\n"
					"Date: %s\r\n"
					"Content-Type: multipart/byteranges;"
					" boundary=%s\r\n"
					"Content-Length: %u\r\n"
					"Last-Modified: %s\r\n"
					"ETag: \"%s\"\r\n",
					date_string, BOUNDARY_STRING,
					content_length, modified_string, etag);
	return phttp->stream_out.write(response_buff, response_len) == STREAM_WRITE_OK ? TRUE : false;
}

static int mod_cache_parse_range_value(char *value,
    uint32_t size, cache_context *pcontext) try
{
	int i;
	int val_len;
	char *ptoken;
	char *ptoken1;
	char *plast_token;
	
	HX_strrtrim(value);
	HX_strltrim(value);
	if (0 != strncasecmp(value, "bytes", 5)) {
		return 416;
	}
	value += 5;
	HX_strltrim(value);
	if ('=' != value[0]) {
		return 400;
	}
	value ++;
	HX_strltrim(value);
	val_len = strlen(value);
	if (',' != value[val_len - 1]) {
		value[val_len] = ',';
		val_len ++;
	}
	size_t count = 0;
	for (i=0; i<val_len; i++) {
		if (',' == value[i]) {
			count ++;
		}
	}
	if (count > 1024)
		return 4162;
	plast_token = value;
	pcontext->range.clear();
	for (i=0; i<val_len; i++) {
		if (',' != value[i]) {
			continue;
		}
		ptoken = value + i;
		*ptoken = '\0';
		if (plast_token == ptoken) {
			return 400;
		}
		ptoken1 = strchr(plast_token, '-');
		if (NULL == ptoken1) {
			return 400;
		}
		*ptoken1 = '\0';
		ptoken1 ++;
		auto first_bpos = strtol(plast_token, nullptr, 0);
		if (first_bpos >= 0 && static_cast<unsigned long>(first_bpos) >= size)
			return 416;
		auto last_bpos = strtol(ptoken1, nullptr, 0);
		if (0 == last_bpos) {
			last_bpos = size - 1;
		}
		if (last_bpos < 0 || static_cast<unsigned long>(last_bpos) >= size)
			return 416;
		RANGE r;
		if (first_bpos <= last_bpos) {
			r.begin = first_bpos;
			r.end   = last_bpos;
		} else {
			r.begin = last_bpos;
			r.end   = first_bpos;
		}
		pcontext->range.push_back(std::move(r));
		plast_token = ptoken + 1;
	}
	if (pcontext->range.size() == 0)
		/* RFC 7233 §2.1 specifies at least one range-set is required */
		return 400;
	if (pcontext->range.size() == 1) {
		pcontext->offset = pcontext->range[0].begin;
		pcontext->until = pcontext->range[0].end + 1;
		pcontext->range.clear();
		return 0;
	}
	pcontext->offset = 0;
	pcontext->until = 0;
	pcontext->range_pos = -1;
	return 0;
} catch (const std::bad_alloc &) {
	pcontext->range.clear();
	mlog(LV_ERR, "E-1237: ENOMEM");
	return 503;
}

bool mod_cache_take_request(HTTP_CONTEXT *phttp)
{
	char *ptoken;
	char suffix[16];
	char domain[256];
	char tmp_path[512];
	char tmp_buff[8192];
	struct stat node_stat;
	char request_uri[8192];
	CACHE_CONTEXT *pcontext;
	
	if (0 != strcasecmp(phttp->request.method, "GET") &&
		0 != strcasecmp(phttp->request.method, "HEAD")) {
		return FALSE;
	}
	auto tmp_len = phttp->request.f_content_length.get_total_length();
	if (0 != tmp_len) {
		if (tmp_len >= 32) {
			return FALSE;
		}
		phttp->request.f_content_length.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		phttp->request.f_content_length.read(tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
		if (strtoll(tmp_buff, nullptr, 0) != 0)
			return FALSE;
	}
	tmp_len = phttp->request.f_host.get_total_length();
	if (tmp_len >= sizeof(domain)) {
		phttp->log(LV_DEBUG, "length of "
			"request host is too long for mod_cache");
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
	if (NULL != ptoken) {
		*ptoken = '\0';
	}
	tmp_len = phttp->request.f_request_uri.get_total_length();
	if (0 == tmp_len) {
		phttp->log(LV_DEBUG, "cannot"
			" find request uri for mod_cache");
		return FALSE;
	} else if (tmp_len >= sizeof(tmp_buff)) {
		phttp->log(LV_DEBUG, "length of "
			"request uri is too long for mod_cache");
		return FALSE;
	}
	phttp->request.f_request_uri.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_request_uri.read(tmp_buff, tmp_len);
	tmp_buff[tmp_len] = '\0';
	if (!parse_uri(tmp_buff, request_uri)) {
		phttp->log(LV_DEBUG, "request"
				" uri format error for mod_cache");
		return FALSE;
	}
	suffix[0] = '\0';
	ptoken = strrchr(request_uri, '/');
	if (NULL == ptoken) {
		phttp->log(LV_DEBUG, "request uri "
			"format error, missing slash for mod_cache");
		return FALSE;
	}
	ptoken ++;
	ptoken = strrchr(ptoken, '.');
	if (NULL != ptoken) {
		ptoken ++;
		if (strlen(ptoken) < 16) {
			strcpy(suffix, ptoken);
		}
	}
	auto it = std::find_if(g_directory_list.cbegin(), g_directory_list.cend(),
	          [&](const auto &e) {
	            return wildcard_match(domain, e.domain.c_str(), TRUE) != 0 &&
	                   strncasecmp(request_uri, e.path.c_str(), e.path.size()) == 0;
	          });
	if (it == g_directory_list.cend())
		return FALSE;
	snprintf(tmp_path, GX_ARRAY_SIZE(tmp_path), "%s%s", it->dir.c_str(),
	         request_uri + it->path.size());
	wrapfd fd = open(tmp_path, O_RDONLY);
	if (fd.get() < 0)
		return mod_cache_exit_response(phttp,
			errno == ENOENT || errno == ENOTDIR ? 404 :
			errno == EACCES || errno == EISDIR ? 403 : 503);
	if (fstat(fd.get(), &node_stat) != 0)
		return mod_cache_exit_response(phttp, 503);
	if (static_cast<unsigned long long>(node_stat.st_size) >= UINT32_MAX)
		return mod_cache_exit_response(phttp, 500);
	else if (!S_ISREG(node_stat.st_mode))
		return mod_cache_exit_response(phttp, 403);
	struct stat sb;
	if (mod_cache_get_others_field(&phttp->request.f_others,
	    "If-None-Match", tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
	    mod_cache_retrieve_etag(tmp_buff, sb)) {
		if (stat4_eq(sb, node_stat))
			return mod_cache_exit_response(phttp, 304);
	} else if (mod_cache_get_others_field(&phttp->request.f_others,
	    "If-Modified-Since", tmp_buff, std::size(tmp_buff)) &&
	    mod_cache_parse_rfc1123_dstring(tmp_buff, &sb.st_mtime)) {
		if (sb.st_mtime == node_stat.st_mtime)
			return mod_cache_exit_response(phttp, 304);
	}
	pcontext = mod_cache_get_cache_context(phttp);
	*pcontext = {};
	if (mod_cache_get_others_field(&phttp->request.f_others, "Range",
	    tmp_buff, GX_ARRAY_SIZE(tmp_buff))) {
		auto status = mod_cache_parse_range_value(tmp_buff,
		              node_stat.st_size, pcontext);
		if (status != 0)
			return mod_cache_exit_response(phttp, status);
	} else {
		pcontext->offset = 0;
		pcontext->until = node_stat.st_size;
	}
	std::unique_lock hhold(g_hash_lock);
	auto iter = g_cache_hash.find(tmp_path);
	if (iter != g_cache_hash.end()) {
		auto pitem = iter->second;
		if (!stat4_eq(pitem->sb, node_stat)) {
			g_cache_hash.erase(iter);
		} else {
			pitem->mblk = mmap(nullptr, static_cast<size_t>(node_stat.st_size),
			              PROT_READ, MAP_SHARED, fd.get(), 0);
			if (pitem->mblk == MAP_FAILED) {
				pcontext->range.clear();
				return false;
			}
			posix_madvise(pitem->mblk, static_cast<size_t>(node_stat.st_size), POSIX_MADV_SEQUENTIAL);
			pcontext->pitem = std::move(pitem);
			return TRUE;
		}
	}
	hhold.unlock();

	try {
	auto pitem = std::make_shared<cache_item>();
	pitem->content_type = extension_to_mime(suffix);
	pitem->sb = node_stat;
	hhold.lock();
	iter = g_cache_hash.find(tmp_path);
	if (iter == g_cache_hash.end()) {
		pitem->mblk = mmap(nullptr, static_cast<size_t>(node_stat.st_size),
		              PROT_READ, MAP_SHARED, fd.get(), 0);
		if (pitem->mblk == MAP_FAILED) {
			pcontext->range.clear();
			return false;
		}
		posix_madvise(pitem->mblk, static_cast<size_t>(node_stat.st_size), POSIX_MADV_SEQUENTIAL);
		g_cache_hash.emplace(tmp_path, pitem);
		pcontext->pitem = std::move(pitem);
		return TRUE;
	}
	} catch (const std::bad_alloc &) {
		pcontext->range.clear();
		return mod_cache_exit_response(phttp, 503);
	}
	return TRUE;
}

void mod_cache_put_context(HTTP_CONTEXT *phttp)
{
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	pcontext->pitem.reset();
	pcontext->range.clear();
}

BOOL mod_cache_check_responded(HTTP_CONTEXT *phttp)
{
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	return pcontext->b_header;
}

BOOL mod_cache_read_response(HTTP_CONTEXT *phttp)
{
	int tmp_len;
	char tmp_buff[1024];
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	if (NULL == pcontext->pitem) {
		return FALSE;
	}
	if (!pcontext->b_header) {
		if (pcontext->range.size() < 2) {
			if (!mod_cache_response_single_header(phttp)) {
				mod_cache_put_context(phttp);
				return FALSE;
			}
		} else {
			if (!mod_cache_response_multiple_header(phttp)) {
				mod_cache_put_context(phttp);
				return FALSE;
			}
		}
		pcontext->b_header = TRUE;
		if (0 == strcasecmp(phttp->request.method, "HEAD")) {
			mod_cache_put_context(phttp);
			return FALSE;
		}
	}
	if (pcontext->until - pcontext->offset >=
		STREAM_BLOCK_SIZE - 1) {
		tmp_len = STREAM_BLOCK_SIZE - 1;
	} else {
		tmp_len = pcontext->until - pcontext->offset;
	}
	auto &item = *pcontext->pitem;
	auto rem_to_eof = pcontext->offset < item.sb.st_size ?
	                    item.sb.st_size - pcontext->offset : 0;
	if (tmp_len > rem_to_eof)
		tmp_len = rem_to_eof;
	if (item.mblk == nullptr) {
		mlog(LV_DEBUG, "%s called without active memory mapping", __func__);
		mod_cache_put_context(phttp);
		return FALSE;
	}
	if (phttp->stream_out.write(static_cast<const char *>(item.mblk) +
	    pcontext->offset, tmp_len) != STREAM_WRITE_OK) {
		mod_cache_put_context(phttp);
		return false;
	}
	pcontext->offset += tmp_len;
	if (pcontext->offset == pcontext->until) {
		if (pcontext->range.size() >= 2) {
			pcontext->range_pos ++;
			if (pcontext->range_pos >= 0 &&
			    static_cast<size_t>(pcontext->range_pos) < pcontext->range.size()) {
				pcontext->offset = pcontext->range[pcontext->range_pos].begin;
				pcontext->until = pcontext->range[pcontext->range_pos].end + 1;
				auto pcontent_type = pcontext->pitem->content_type;
				if (NULL == pcontent_type) {
					pcontent_type = "application/octet-stream";
				}
				tmp_len = sprintf(tmp_buff,
					"\r\n--%s\r\n"
					"Content-Type: %s\r\n"
					"Content-Range: bytes %u-%u/%llu\r\n\r\n",
					BOUNDARY_STRING, pcontent_type,
					pcontext->range[pcontext->range_pos].begin,
					pcontext->range[pcontext->range_pos].end,
				          static_cast<unsigned long long>(pcontext->pitem->sb.st_size));
			} else {
				tmp_len = sprintf(tmp_buff,
					"\r\n--%s--\r\n",
					BOUNDARY_STRING);
				pcontext->range.clear();
			}
			if (phttp->stream_out.write(tmp_buff, tmp_len) != STREAM_WRITE_OK) {
				mod_cache_put_context(phttp);
				return FALSE;
			}
			return TRUE;
		}
	}
	if (pcontext->offset == pcontext->until) {
		mod_cache_put_context(phttp);
		return FALSE;
	}
	return TRUE;
}
