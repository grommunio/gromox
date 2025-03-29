// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2023 grommunio GmbH
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
#include <fmt/core.h>
#include <libHX/string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/http.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "http_parser.hpp"
#include "cache.hpp"
#include "resource.hpp"
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
	bool b_header = false;
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
	mlog(LV_INFO, "mod_cache: defaulting to built-in list of handled paths");
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
	
	auto pfile = list_file_initd("cache.txt", g_config_file->get_value("config_file_path"),
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
	ret = pthread_create4(&g_scan_tid, nullptr, mod_cache_scanwork, nullptr);
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
	std::unique_lock lock(g_hash_lock);
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
	return pcontext->pitem != nullptr;
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

static bool mod_cache_serialize_etag(const struct stat &sb, char *etag, size_t len)
{
	if (sb.st_dev == 0)
		return false;
	snprintf(etag, len, "%x-%llx-%llx-%llx",
	         static_cast<unsigned int>(sb.st_dev),
	         static_cast<unsigned long long>(sb.st_ino),
	         static_cast<unsigned long long>(sb.st_size),
	         static_cast<unsigned long long>(sb.st_mtime));
	return true;
}

static const char *
mod_cache_get_others_field(const http_request::other_map &m, const char *k)
{
	auto i = m.find(k);
	return i != m.end() ? i->second.c_str() : nullptr;
}

static BOOL mod_cache_parse_rfc1123_dstring(
	const char *dstring, time_t *pmtime)
{
	struct tm tmp_tm;
	auto cur_time = time(nullptr);
	if (gmtime_r(&cur_time, &tmp_tm) == nullptr)
		tmp_tm = {};
	if (strptime(dstring, "%a, %d %b %Y %T GMT", &tmp_tm) == nullptr)
		return FALSE;	
	*pmtime = timegm(&tmp_tm);
	return TRUE;
}

static BOOL mod_cache_response_single_header(http_context *phttp) try
{
	char etag[128];
	struct tm tmp_tm;
	char date_string[128];
	CACHE_CONTEXT *pcontext;
	char modified_string[128];
	
	pcontext = mod_cache_get_cache_context(phttp);
	rfc1123_dstring(date_string, std::size(date_string));
	if (gmtime_r(&pcontext->pitem->sb.st_mtime, &tmp_tm) == nullptr)
		tmp_tm = {};
	rfc1123_dstring(modified_string, std::size(modified_string), tmp_tm);
	auto pcontent_type = pcontext->pitem->content_type;
	bool emit_206 = pcontext->offset != 0 ||
	                pcontext->until != static_cast<uint64_t>(pcontext->pitem->sb.st_size);
	auto rsp = fmt::format(
		"HTTP/1.1 {}"
		"Date: {}\r\n"
		"Content-Length: {}\r\n"
		"Accept-Ranges: bytes\r\n"
		"Last-Modified: {}\r\n",
		emit_206 ? "206 Partial Content\r\n" : "200 OK\r\n",
		date_string, pcontext->until - pcontext->offset,
		modified_string);
	if (mod_cache_serialize_etag(pcontext->pitem->sb, etag, std::size(etag)))
		rsp += fmt::format("ETag: \"{}\"\r\n", etag);
	if (phttp->request.imethod == http_method::options)
		rsp += fmt::format("Accept: GET,POST,OPTIONS,HEAD\r\n");
	if (pcontent_type != nullptr)
		rsp += fmt::format("Content-Type: {}\r\n", pcontent_type);
	if (emit_206)
		rsp += fmt::format("Content-Range: bytes {}-{}/{}\r\n\r\n",
		       pcontext->offset, pcontext->until - 1,
		       static_cast<unsigned long long>(pcontext->pitem->sb.st_size));
	else
		rsp += "\r\n";
	return phttp->stream_out.write(rsp.c_str(), rsp.size()) == STREAM_WRITE_OK ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1726: ENOMEM");
	return false;
}

static uint32_t mod_cache_calculate_content_length(CACHE_CONTEXT *pcontext)
{
	int ctype_len;
	char num_buff[64];
	uint32_t content_length;
	
	auto pcontent_type = pcontext->pitem->content_type;
	if (pcontent_type == nullptr)
		pcontent_type = "application/octet-stream";
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

static BOOL mod_cache_response_multiple_header(http_context *phttp) try
{
	char etag[128];
	struct tm tmp_tm;
	char date_string[128];
	uint32_t content_length;
	CACHE_CONTEXT *pcontext;
	char modified_string[128];
	
	pcontext = mod_cache_get_cache_context(phttp);
	rfc1123_dstring(date_string, std::size(date_string));
	if (gmtime_r(&pcontext->pitem->sb.st_mtime, &tmp_tm) == nullptr)
		tmp_tm = {};
	rfc1123_dstring(modified_string, std::size(modified_string), tmp_tm);
	content_length =  mod_cache_calculate_content_length(pcontext);	
	auto rsp = fmt::format(
	           "HTTP/1.1 206 Partial Content\r\n"
	           "Date: %s\r\n"
	           "Content-Type: multipart/byteranges; boundary=%s\r\n"
	           "Content-Length: %u\r\n"
	           "Last-Modified: %s\r\n",
	           date_string, BOUNDARY_STRING, content_length, modified_string);
	if (mod_cache_serialize_etag(pcontext->pitem->sb, etag, std::size(etag)))
		rsp += fmt::format("ETag: \"{}\"\r\n", etag);
	return phttp->stream_out.write(rsp.c_str(), rsp.size()) == STREAM_WRITE_OK ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1736: ENOMEM");
	return false;
}

static http_status mod_cache_parse_range_value(char *value,
    uint32_t size, cache_context *pcontext) try
{
	char *ptoken;
	char *ptoken1;
	char *plast_token;
	
	HX_strrtrim(value);
	HX_strltrim(value);
	if (strncasecmp(value, "bytes", 5) != 0)
		return http_status::range_insatisfiable;
	value += 5;
	HX_strltrim(value);
	if (*value != '=')
		return http_status::bad_request_CL;
	value ++;
	HX_strltrim(value);
	auto val_len = strlen(value);
	if (',' != value[val_len - 1]) {
		value[val_len++] = ',';
	}
	size_t count = 0;
	for (size_t i = 0; i < val_len; ++i)
		if (value[i] == ',')
			count ++;
	if (count > 1024)
		return static_cast<http_status>(4162);
	plast_token = value;
	pcontext->range.clear();
	for (size_t i = 0; i < val_len; ++i) {
		if (value[i] != ',')
			continue;
		ptoken = value + i;
		*ptoken = '\0';
		if (plast_token == ptoken)
			return http_status::bad_request;
		ptoken1 = strchr(plast_token, '-');
		if (ptoken1 == nullptr)
			return http_status::bad_request;
		*ptoken1++ = '\0';
		auto first_bpos = strtol(plast_token, nullptr, 0);
		if (first_bpos >= 0 && static_cast<unsigned long>(first_bpos) >= size)
			return http_status::range_insatisfiable;
		auto last_bpos = strtol(ptoken1, nullptr, 0);
		if (last_bpos == 0)
			last_bpos = size - 1;
		if (last_bpos < 0 || static_cast<unsigned long>(last_bpos) >= size)
			return http_status::range_insatisfiable;
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
		return http_status::bad_request;
	if (pcontext->range.size() == 1) {
		pcontext->offset = pcontext->range[0].begin;
		pcontext->until = pcontext->range[0].end + 1;
		pcontext->range.clear();
		return http_status::none;
	}
	pcontext->offset = 0;
	pcontext->until = 0;
	pcontext->range_pos = -1;
	return http_status::none;
} catch (const std::bad_alloc &) {
	pcontext->range.clear();
	mlog(LV_ERR, "E-1237: ENOMEM");
	return http_status::service_unavailable;
}

http_status mod_cache_take_request(http_context *phttp)
{
	char *ptoken;
	char suffix[16];
	char tmp_buff[8192];
	struct stat node_stat{};
	char request_uri[http_request::uri_limit];
	CACHE_CONTEXT *pcontext;
	
	if (!parse_uri(phttp->request.f_request_uri.c_str(), request_uri)) {
		phttp->log(LV_DEBUG, "request"
				" uri format error for mod_cache");
		return http_status::bad_request_CL;
	}
	suffix[0] = '\0';
	wrapfd fd;
	pcontext = mod_cache_get_cache_context(phttp);
	*pcontext = {};
	std::string tmp_path;
	bool opstar = phttp->request.imethod == http_method::options &&
	              strcmp(request_uri, "*") == 0;
	if (opstar) {
		tmp_path = request_uri;
	} else {
		ptoken = strrchr(request_uri, '/');
		if (NULL == ptoken) {
			phttp->log(LV_DEBUG, "request uri "
				"format error, missing slash for mod_cache");
			return http_status::bad_request_CL;
		}
		ptoken ++;
		ptoken = strrchr(ptoken, '.');
		if (NULL != ptoken) {
			ptoken ++;
			if (strlen(ptoken) < 16)
				strcpy(suffix, ptoken);
		}
		auto it = std::find_if(g_directory_list.cbegin(), g_directory_list.cend(),
		          [&](const auto &e) {
		          	return wildcard_match(phttp->request.f_host.c_str(), e.domain.c_str(), TRUE) != 0 &&
		          	       strncasecmp(request_uri, e.path.c_str(), e.path.size()) == 0;
		          });
		if (it == g_directory_list.cend())
			return http_status::none;
		tmp_path = it->dir + &request_uri[it->path.size()];
		fd = wrapfd(open(tmp_path.c_str(), O_RDONLY));
		if (fd.get() < 0)
			return errno == ENOENT || errno == ENOTDIR ? http_status::not_found :
			       errno == EACCES || errno == EISDIR ? http_status::forbidden :
			       http_status::service_unavailable;
		if (fstat(fd.get(), &node_stat) != 0)
			return http_status::server_error;
		else if (!S_ISREG(node_stat.st_mode))
			return http_status::forbidden;
		else if (static_cast<unsigned long long>(node_stat.st_size) >= UINT32_MAX)
			return http_status::server_error;
		static_assert(UINT32_MAX <= SIZE_MAX);
	}
	switch (phttp->request.imethod) {
	case http_method::options:
		/* Never output bodies with OPTIONS */
		fd = wrapfd(open("/dev/null", O_RDONLY));
		if (fd.get() < 0)
			return http_status::service_unavailable;
		break;
	case http_method::head:
	case http_method::get:
	case http_method::post:
		break;
	case http_method::put:
	case http_method::patch:
	case http_method::xdelete:
		return http_status::forbidden;
	default:
		return http_status::not_impl;
	}
	if (!opstar) {
		struct stat sb;
		auto val = mod_cache_get_others_field(phttp->request.f_others, "If-None-Match");
		if (val != nullptr && mod_cache_retrieve_etag(val, sb)) {
			if (stat4_eq(sb, node_stat))
				return http_status::not_modified;
		} else if ((val = mod_cache_get_others_field(phttp->request.f_others, "If-Modified-Since")) != nullptr &&
		    mod_cache_parse_rfc1123_dstring(val, &sb.st_mtime)) {
			if (sb.st_mtime == node_stat.st_mtime)
				return http_status::not_modified;
		}
	}
	phttp->request.posted_size = 0;
	auto val = mod_cache_get_others_field(phttp->request.f_others, "Range");
	if (val != nullptr) {
		gx_strlcpy(tmp_buff, val, std::size(tmp_buff));
		auto status = mod_cache_parse_range_value(tmp_buff,
		              node_stat.st_size, pcontext);
		if (status != http_status::none)
			return status;
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
			pcontext->pitem = std::move(pitem);
			return http_status::ok;
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
		if (node_stat.st_size != 0) {
			pitem->mblk = mmap(nullptr, node_stat.st_size,
				      PROT_READ, MAP_SHARED, fd.get(), 0);
			if (pitem->mblk == MAP_FAILED) {
				pcontext->range.clear();
				return http_status::service_unavailable;
			}
			posix_madvise(pitem->mblk, static_cast<size_t>(node_stat.st_size), POSIX_MADV_SEQUENTIAL);
		}
		g_cache_hash.emplace(std::move(tmp_path), pitem);
		pcontext->pitem = std::move(pitem);
		return http_status::ok;
	}
	} catch (const std::bad_alloc &) {
		pcontext->range.clear();
		return http_status::service_unavailable;
	}
	return http_status::ok;
}

void mod_cache_insert_ctx(HTTP_CONTEXT *phttp)
{
	auto &rq = phttp->request;
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	pcontext->pitem.reset();
	pcontext->range.clear();
	rq.b_end = false;
	rq.chunk_size = rq.chunk_offset = 0;
	rq.content_len = rq.posted_size = 0;
}

BOOL mod_cache_check_responded(HTTP_CONTEXT *phttp)
{
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	return pcontext->b_header ? TRUE : false;
}

BOOL mod_cache_read_response(HTTP_CONTEXT *phttp)
{
	char tmp_buff[1024];
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	if (pcontext->pitem == nullptr)
		return FALSE;
	if (!pcontext->b_header) {
		if (pcontext->range.size() < 2) {
			if (!mod_cache_response_single_header(phttp)) {
				mod_cache_insert_ctx(phttp);
				return FALSE;
			}
		} else {
			if (!mod_cache_response_multiple_header(phttp)) {
				mod_cache_insert_ctx(phttp);
				return FALSE;
			}
		}
		pcontext->b_header = true;
		if (phttp->request.imethod == http_method::head) {
			mod_cache_insert_ctx(phttp);
			return FALSE;
		}
	}
	auto &item = *pcontext->pitem;
	uint32_t writeout_size = std::min(pcontext->until - pcontext->offset, static_cast<uint32_t>(STREAM_BLOCK_SIZE) - 1);
	auto rem_to_eof = pcontext->offset < static_cast<uint64_t>(item.sb.st_size) ?
	                  static_cast<uint64_t>(item.sb.st_size) - pcontext->offset : 0;
	writeout_size = std::min(static_cast<uint64_t>(writeout_size), rem_to_eof);
	if (writeout_size != 0) {
		if (item.mblk == nullptr) {
			mlog(LV_DEBUG, "%s called without active memory mapping", __func__);
			mod_cache_insert_ctx(phttp);
			return FALSE;
		}
		if (phttp->stream_out.write(static_cast<const char *>(item.mblk) +
		    pcontext->offset, writeout_size) != STREAM_WRITE_OK) {
			mod_cache_insert_ctx(phttp);
			return false;
		}
	}
	pcontext->offset += writeout_size;
	if (pcontext->offset == pcontext->until) {
		if (pcontext->range.size() >= 2) {
			pcontext->range_pos ++;
			int tmp_len;
			if (pcontext->range_pos >= 0 &&
			    static_cast<size_t>(pcontext->range_pos) < pcontext->range.size()) {
				pcontext->offset = pcontext->range[pcontext->range_pos].begin;
				pcontext->until = pcontext->range[pcontext->range_pos].end + 1;
				auto pcontent_type = pcontext->pitem->content_type;
				if (pcontent_type == nullptr)
					pcontent_type = "application/octet-stream";
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
			tmp_len = std::max(0, tmp_len);
			if (phttp->stream_out.write(tmp_buff, tmp_len) != STREAM_WRITE_OK) {
				mod_cache_insert_ctx(phttp);
				return FALSE;
			}
			return TRUE;
		}
	}
	if (pcontext->offset == pcontext->until) {
		mod_cache_insert_ctx(phttp);
		return FALSE;
	}
	return TRUE;
}

bool mod_cache_discard_content(http_context *hc)
{
	if (hc->request.body_fd < 0)
		/* write_request made sure to loop until stream_in has enough bytes */
		hc->stream_in.fwd_read_ptr(hc->request.content_len);
	return true;
}
