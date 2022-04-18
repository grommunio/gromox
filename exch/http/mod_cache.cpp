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
#include <mutex>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/paths.h>
#include <gromox/str_hash.hpp>
#include <gromox/util.hpp>
#include "http_parser.h"
#include "mod_cache.h"
#include "resource.h"
#include "system_services.h"
#define HASH_GROWING_NUM			1000

#define BOUNDARY_STRING				"00000000000000000001"

using namespace gromox;

namespace {
struct CACHE_ITEM {
	DOUBLE_LIST_NODE node;
	char extention[16];
	DATA_BLOB blob;
	ino_t ino;
	time_t mtime;
	BOOL b_expired;
	int reference;
};

struct RANGE {
	uint32_t begin;
	uint32_t end;
};

struct CACHE_CONTEXT {
	CACHE_ITEM *pitem;
	BOOL b_header;
	uint32_t offset;
	uint32_t until;
	int range_pos;
	int range_num;
	RANGE *prange;
};

struct DIRECTORY_NODE {
	std::string domain, path, dir;
};

}

static int g_context_num;
static gromox::atomic_bool g_notify_stop;
static pthread_t g_scan_tid;
static DOUBLE_LIST g_item_list;
static std::mutex g_hash_lock;
static std::vector<DIRECTORY_NODE> g_directory_list;
static std::unique_ptr<STR_HASH_TABLE> g_cache_hash;
static CACHE_CONTEXT *g_context_list;


static void *mod_cache_scanwork(void *pparam)
{
	int count;
	char tmp_key[1024];
	CACHE_ITEM *pitem;
	CACHE_ITEM **ppitem;
	struct stat node_stat;
	
	count = 0;
	while (!g_notify_stop) {
		count ++;
		if (count < 600) {
			sleep(1);
			continue;
		}
		std::lock_guard hhold(g_hash_lock);
		auto iter = g_cache_hash->make_iter();
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppitem = static_cast<CACHE_ITEM **>(str_hash_iter_get_value(iter, tmp_key));
			pitem = *ppitem;
			if (0 != pitem->reference) {
				continue;
			}
			if (0 == stat(tmp_key, &node_stat) &&
				0 != S_ISREG(node_stat.st_mode) &&
				node_stat.st_ino == pitem->ino &&
				node_stat.st_size == pitem->blob.length &&
				node_stat.st_mtime == pitem->mtime) {
				continue;
			}
			str_hash_iter_remove(iter);
			free(pitem->blob.data);
			free(pitem);
		}
		str_hash_iter_free(iter);
		count = 0;
	}
	return nullptr;
}

static BOOL mod_cache_enlarge_hash()
{
	void *ptmp_value;
	char tmp_key[1024];
	
	auto phash = STR_HASH_TABLE::create(g_cache_hash->capacity +
		HASH_GROWING_NUM, sizeof(CACHE_ITEM*), NULL);
	if (NULL == phash) {
		return FALSE;
	}
	auto iter = g_cache_hash->make_iter();
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		ptmp_value = str_hash_iter_get_value(iter, tmp_key);
		phash->add(tmp_key, ptmp_value);
	}
	str_hash_iter_free(iter);
	g_cache_hash = std::move(phash);
	return TRUE;
}

void mod_cache_init(int context_num)
{
	g_notify_stop = true;
	g_context_num = context_num;
	double_list_init(&g_item_list);
}

static int mod_cache_defaults()
{
	printf("[mod_cache]: defaulting to built-in list of handled paths\n");
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
		printf("[mod_cache]: list_file_initd cache.txt: %s\n", strerror(errno));
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
	printf("[mod_cache: bad_alloc\n");
	return -ENOMEM;
}

int mod_cache_run()
{
	auto ret = mod_cache_read_txt();
	if (ret < 0)
		return ret;
	g_context_list = me_alloc<CACHE_CONTEXT>(g_context_num);
	if (NULL == g_context_list) {
		printf("[mod_cache]: Failed to allocate context list\n");
		return -2;
	}
	memset(g_context_list, 0, sizeof(CACHE_CONTEXT)*g_context_num);
	g_cache_hash = STR_HASH_TABLE::create(HASH_GROWING_NUM, sizeof(CACHE_ITEM *), nullptr);
	if (NULL == g_cache_hash) {
		printf("[mod_cache]: Failed to init cache hash table\n");
		return -3;
	}
	g_notify_stop = false;
	ret = pthread_create(&g_scan_tid, nullptr, mod_cache_scanwork, nullptr);
	if (ret != 0) {
		printf("[mod_cache]: failed to create scanning thread: %s\n", strerror(ret));
		g_notify_stop = true;
		return -4;
	}
	pthread_setname_np(g_scan_tid, "mod_cache");
	return 0;
}

void mod_cache_stop()
{
	CACHE_ITEM *pitem;
	CACHE_ITEM **ppitem;
	DOUBLE_LIST_NODE *pnode;
	
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (!pthread_equal(g_scan_tid, {})) {
			pthread_kill(g_scan_tid, SIGALRM);
			pthread_join(g_scan_tid, NULL);
		}
	}
	g_directory_list.clear();
	if (NULL != g_context_list) {
		free(g_context_list);
		g_context_list = NULL;
	}
	if (NULL != g_cache_hash) {
		auto iter = g_cache_hash->make_iter();
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppitem = static_cast<CACHE_ITEM **>(str_hash_iter_get_value(iter, nullptr));
			free((*ppitem)->blob.data);
			free(*ppitem);
		}
		str_hash_iter_free(iter);
		g_cache_hash.reset();
	}
	while ((pnode = double_list_pop_front(&g_item_list)) != nullptr) {
		pitem = (CACHE_ITEM*)pnode->pdata;
		free(pitem->blob.data);
		free(pitem);
	}
	double_list_free(&g_item_list);
}

static CACHE_CONTEXT* mod_cache_get_cache_context(HTTP_CONTEXT *phttp)
{
	return &g_context_list[phttp->context_id];
}

BOOL mod_cache_check_caching(HTTP_CONTEXT *phttp)
{
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	if (NULL != pcontext->pitem) {
		return TRUE;
	}
	return FALSE;
}

static BOOL mod_cache_retrieve_etag(const char *etag,
	ino_t *pino, uint32_t *plength, time_t *pmtime)
{
	char *ptoken;
	char *ptoken1;
	char tmp_buff[128];
	
	auto tmp_len = strlen(etag);
	if (tmp_len >= sizeof(tmp_buff)) {
		return FALSE;
	}
	if ('"' == etag[0]) {
		etag ++;
		tmp_len --;
	}
	memcpy(tmp_buff, etag, tmp_len + 1);
	if ('"' == tmp_buff[tmp_len - 1]) {
		tmp_buff[tmp_len - 1] = '\0';
	}
	ptoken = strchr(tmp_buff, '-');
	if (NULL == ptoken) {
		return FALSE;
	}
	*ptoken = '\0';
	ptoken ++;
	if (!decode_hex_binary(tmp_buff, pino, sizeof(ino_t)))
		return FALSE;
	ptoken1 = strchr(ptoken, '-');
	if (NULL == ptoken1) {
		return FALSE;
	}
	*ptoken1 = '\0';
	ptoken1 ++;
	if (!decode_hex_binary(ptoken, plength, sizeof(uint32_t)))
		return FALSE;
	return decode_hex_binary(ptoken1, pmtime, sizeof(time_t));
}

static void mod_cache_serialize_etag(ino_t ino,
	uint32_t length, time_t mtime, char *etag)
{
	int offset;
	
	offset = 0;
	encode_hex_binary(&ino, sizeof(ino_t), etag + offset, 32);
	offset += 2*sizeof(ino_t);
	etag[offset] = '-';
	offset ++;
	encode_hex_binary(&length, sizeof(uint32_t), etag + offset, 32);
	offset += 2*sizeof(uint32_t);
	etag[offset] = '-';
	offset ++;
	encode_hex_binary(&mtime, sizeof(time_t), etag + offset, 32);
	offset += 2*sizeof(time_t);
	etag[offset] = '\0';
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

static BOOL mod_cache_response_unmodified(HTTP_CONTEXT *phttp)
{
	time_t cur_time;
	struct tm tmp_tm;
	int response_len;
	char dstring[128];
	char response_buff[1024];
	
	time(&cur_time);
	gmtime_r(&cur_time, &tmp_tm);
	strftime(dstring, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
					"HTTP/1.1 304 Not Modified\r\n"
					"Date: %s\r\n\r\n",
					dstring);
	return phttp->stream_out.write(response_buff, response_len) == STREAM_WRITE_OK ? TRUE : false;
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
	const char *pcontent_type;
	
	pcontext = mod_cache_get_cache_context(phttp);
	time(&cur_time);
	gmtime_r(&cur_time, &tmp_tm);
	strftime(date_string, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	gmtime_r(&pcontext->pitem->mtime, &tmp_tm);
	strftime(modified_string, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	mod_cache_serialize_etag(pcontext->pitem->ino,
		pcontext->pitem->blob.length, pcontext->pitem->mtime, etag);
	pcontent_type = system_services_extension_to_mime(
							pcontext->pitem->extention);
	if (NULL == pcontent_type) {
		pcontent_type = "application/octet-stream";
	}
	strcpy(response_buff, pcontext->until != pcontext->pitem->blob.length ?
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
	if (pcontext->until != pcontext->pitem->blob.length) {
		response_len += gx_snprintf(response_buff + response_len,
		                GX_ARRAY_SIZE(response_buff) - response_len,
					"Content-Range: bytes %u-%u/%u\r\n\r\n",
					pcontext->offset, pcontext->until - 1,
					pcontext->pitem->blob.length);
	} else {
		memcpy(response_buff + response_len, "\r\n", 2);
		response_len += 2;
	}
	return phttp->stream_out.write(response_buff, response_len) == STREAM_WRITE_OK ? TRUE : false;
}

static uint32_t mod_cache_calculate_content_length(CACHE_CONTEXT *pcontext)
{
	int i;
	int ctype_len;
	char num_buff[64];
	uint32_t content_length;
	const char *pcontent_type;
	
	pcontent_type = system_services_extension_to_mime(
							pcontext->pitem->extention);
	if (NULL == pcontent_type) {
		pcontent_type = "application/octet-stream";
	}
	ctype_len = strlen(pcontent_type);
	content_length = 0;
	for (i=0; i<pcontext->range_num; i++) {
		/* --boundary_string\r\n */
		content_length += 2 + sizeof(BOUNDARY_STRING) - 1 + 2;
		/* Content-Type: xxx\r\n */
		content_length += 16 + ctype_len;
		/* Content-Range: bytes x-x/xxx\r\n */
		content_length += 25 + sprintf(num_buff, "%u%u%u",
								pcontext->prange[i].begin,
								pcontext->prange[i].end,
								pcontext->pitem->blob.length);
		content_length += 2; /* \r\n */
		content_length += pcontext->prange[i].end -
						pcontext->prange[i].begin + 1;
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
	gmtime_r(&pcontext->pitem->mtime, &tmp_tm);
	strftime(modified_string, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
	mod_cache_serialize_etag(pcontext->pitem->ino,
		pcontext->pitem->blob.length, pcontext->pitem->mtime, etag);
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

static BOOL mod_cache_parse_range_value(char *value,
	uint32_t size, CACHE_CONTEXT *pcontext)
{
	int i;
	int val_len;
	char *ptoken;
	char *ptoken1;
	int range_num;
	char *plast_token;
	RANGE ranges[1024];
	
	HX_strrtrim(value);
	HX_strltrim(value);
	if (0 != strncasecmp(value, "bytes", 5)) {
		return FALSE;
	}
	value += 5;
	HX_strltrim(value);
	if ('=' != value[0]) {
		return FALSE;
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
	if (count > GX_ARRAY_SIZE(ranges))
		return FALSE;
	range_num = 0;
	plast_token = value;
	for (i=0; i<val_len; i++) {
		if (',' != value[i]) {
			continue;
		}
		ptoken = value + i;
		*ptoken = '\0';
		if (plast_token == ptoken) {
			return FALSE;
		}
		ptoken1 = strchr(plast_token, '-');
		if (NULL == ptoken1) {
			return FALSE;
		}
		*ptoken1 = '\0';
		ptoken1 ++;
		auto first_bpos = strtol(plast_token, nullptr, 0);
		if (first_bpos >= 0 && static_cast<unsigned long>(first_bpos) >= size)
			return FALSE;
		auto last_bpos = strtol(ptoken1, nullptr, 0);
		if (0 == last_bpos) {
			last_bpos = size - 1;
		}
		if (last_bpos < 0 || static_cast<unsigned long>(last_bpos) >= size)
			return FALSE;
		if (first_bpos <= last_bpos) {
			ranges[range_num].begin = first_bpos;
			ranges[range_num].end = last_bpos;
		} else {
			ranges[range_num].begin = last_bpos;
			ranges[range_num].end = first_bpos;
		}
		range_num ++;
		plast_token = ptoken + 1;
	}
	if (0 == range_num) {
		return FALSE;
	}
	if (1 == range_num) {
		pcontext->offset = ranges[0].begin;
		pcontext->until = ranges[0].end + 1;
		return TRUE;
	}
	pcontext->offset = 0;
	pcontext->until = 0;
	pcontext->range_pos = -1;
	pcontext->range_num = range_num;
	pcontext->prange = me_alloc<RANGE>(range_num);
	if (NULL == pcontext->prange) {
		return FALSE;
	}
	memcpy(pcontext->prange, ranges, sizeof(RANGE)*range_num);
	return TRUE;
}

BOOL mod_cache_get_context(HTTP_CONTEXT *phttp)
{
	ino_t ino;
	char *ptoken;
	time_t mtime;
	uint32_t size;
	char suffix[16];
	char domain[256];
	CACHE_ITEM *pitem;
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
		http_parser_log_info(phttp, LV_DEBUG, "length of "
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
		http_parser_log_info(phttp, LV_DEBUG, "cannot"
			" find request uri for mod_cache");
		return FALSE;
	} else if (tmp_len >= sizeof(tmp_buff)) {
		http_parser_log_info(phttp, LV_DEBUG, "length of "
			"request uri is too long for mod_cache");
		return FALSE;
	}
	phttp->request.f_request_uri.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_request_uri.read(tmp_buff, tmp_len);
	tmp_buff[tmp_len] = '\0';
	if (!parse_uri(tmp_buff, request_uri)) {
		http_parser_log_info(phttp, LV_DEBUG, "request"
				" uri format error for mod_cache");
		return FALSE;
	}
	suffix[0] = '\0';
	ptoken = strrchr(request_uri, '/');
	if (NULL == ptoken) {
		http_parser_log_info(phttp, LV_DEBUG, "request uri "
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
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0 ||
	    !S_ISREG(node_stat.st_mode))
		return FALSE;
	if (node_stat.st_size >= UINT32_MAX)
		return FALSE;
	if (mod_cache_get_others_field(&phttp->request.f_others,
	    "If-None-Match", tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
	    mod_cache_retrieve_etag(tmp_buff, &ino, &size, &mtime)) {
		if (ino == node_stat.st_ino &&
			size == node_stat.st_size &&
			mtime == node_stat.st_mtime) {
			return mod_cache_response_unmodified(phttp);
		}
	} else {
		if (mod_cache_get_others_field(&phttp->request.f_others,
		    "If-Modified-Since", tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
		    mod_cache_parse_rfc1123_dstring(tmp_buff, &mtime)) {
			if (mtime == node_stat.st_mtime) {
				return mod_cache_response_unmodified(phttp);
			}
		}
	}
	pcontext = mod_cache_get_cache_context(phttp);
	memset(pcontext, 0, sizeof(CACHE_CONTEXT));
	if (mod_cache_get_others_field(&phttp->request.f_others, "Range",
	    tmp_buff, GX_ARRAY_SIZE(tmp_buff))) {
		if (!mod_cache_parse_range_value(tmp_buff, node_stat.st_size, pcontext)) {
			http_parser_log_info(phttp, LV_DEBUG, "\"range\""
				" value in http request header format"
				" error for mod_cache");
			return FALSE;
		}
	} else {
		pcontext->offset = 0;
		pcontext->until = node_stat.st_size;
	}
	std::unique_lock hhold(g_hash_lock);
	auto ppitem = g_cache_hash->query<CACHE_ITEM *>(tmp_path);
	if (NULL != ppitem) {
		pitem = *ppitem;
		if (pitem->ino != node_stat.st_ino ||
			pitem->blob.length != node_stat.st_size ||
			pitem->mtime != node_stat.st_mtime) {
			g_cache_hash->remove(tmp_path);
			if (pitem->reference > 0) {
				pitem->b_expired = TRUE;
				pitem->node.pdata = pitem;
				double_list_append_as_tail(
					&g_item_list, &pitem->node);
			} else {
				free(pitem->blob.data);
				free(pitem);
			}
		} else {
			pitem->reference ++;
			pcontext->pitem = pitem;
			return TRUE;
		}
	}
	hhold.unlock();
	pitem = me_alloc<CACHE_ITEM>();
	if (NULL == pitem) {
		if (NULL != pcontext->prange) {
			free(pcontext->prange);
			pcontext->prange = NULL;
		}
		return FALSE;
	}
	strcpy(pitem->extention, suffix);
	pitem->reference = 1;
	pitem->ino = node_stat.st_ino;
	pitem->blob.length = node_stat.st_size;
	pitem->mtime = node_stat.st_mtime;
	pitem->blob.data = me_alloc<uint8_t>(node_stat.st_size);
	if (NULL == pitem->blob.data) {
		free(pitem);
		if (NULL != pcontext->prange) {
			free(pcontext->prange);
			pcontext->prange = NULL;
		}
		return FALSE;
	}
	if (read(fd.get(), pitem->blob.data, node_stat.st_size) != node_stat.st_size) {
		free(pitem->blob.data);
		free(pitem);
		if (NULL != pcontext->prange) {
			free(pcontext->prange);
			pcontext->prange = NULL;
		}
		return FALSE;
	}
	fd.close();
	hhold.lock();
	ppitem = g_cache_hash->query<CACHE_ITEM *>(tmp_path);
	if (NULL == ppitem) {
		if (g_cache_hash->add(tmp_path, &pitem) != 1) {
			if (!mod_cache_enlarge_hash())
				goto INVALIDATE_ITEM;
			g_cache_hash->add(tmp_path, &pitem);
		}
		pitem->b_expired = FALSE;
		pcontext->pitem = pitem;
		return TRUE;
	}
 INVALIDATE_ITEM:
	pitem->b_expired = TRUE;
	pitem->node.pdata = pitem;
	double_list_append_as_tail(&g_item_list, &pitem->node);
	pcontext->pitem = pitem;
	return TRUE;
}

void mod_cache_put_context(HTTP_CONTEXT *phttp)
{
	CACHE_ITEM *pitem;
	CACHE_CONTEXT *pcontext;
	
	pcontext = mod_cache_get_cache_context(phttp);
	if (NULL == pcontext->pitem) {
		return;
	}
	pitem = pcontext->pitem;
	pcontext->pitem = NULL;
	std::unique_lock hhold(g_hash_lock);
	pitem->reference --;
	if (pitem->reference != 0 || !pitem->b_expired)
		return;
	double_list_remove(&g_item_list, &pitem->node);
	hhold.unlock();
	free(pitem->blob.data);
	free(pitem);
	if (NULL != pcontext->prange) {
		free(pcontext->prange);
		pcontext->prange = NULL;
	}
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
	const char *pcontent_type;
	
	pcontext = mod_cache_get_cache_context(phttp);
	if (NULL == pcontext->pitem) {
		return FALSE;
	}
	if (!pcontext->b_header) {
		if (NULL == pcontext->prange) {
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
	if (phttp->stream_out.write(pcontext->pitem->blob.data +
	    pcontext->offset, tmp_len) != STREAM_WRITE_OK) {
		mod_cache_put_context(phttp);
		return FALSE;
	}
	pcontext->offset += tmp_len;
	if (pcontext->offset == pcontext->until) {
		if (NULL != pcontext->prange) {
			pcontext->range_pos ++;
			if (pcontext->range_pos < pcontext->range_num) {
				pcontext->offset = pcontext->prange[
						pcontext->range_pos].begin;
				pcontext->until = pcontext->prange[
						pcontext->range_pos].end + 1;
				pcontent_type = system_services_extension_to_mime(
							pcontext->pitem->extention);
				if (NULL == pcontent_type) {
					pcontent_type = "application/octet-stream";
				}
				tmp_len = sprintf(tmp_buff,
					"\r\n--%s\r\n"
					"Content-Type: %s\r\n"
					"Content-Range: bytes %u-%u/%u\r\n\r\n",
					BOUNDARY_STRING, pcontent_type,
					pcontext->prange[pcontext->range_pos].begin,
					pcontext->prange[pcontext->range_pos].end,
					pcontext->pitem->blob.length);
			} else {
				tmp_len = sprintf(tmp_buff,
					"\r\n--%s--\r\n",
					BOUNDARY_STRING);
				free(pcontext->prange);
				pcontext->prange = NULL;
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
