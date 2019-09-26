#include "util.h"
#include "str_hash.h"
#include "resource.h"
#include "mod_cache.h"
#include "list_file.h"
#include "mail_func.h"
#include "double_list.h"
#include "http_parser.h"
#include "system_services.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>


#define HASH_GROWING_NUM			1000

#define BOUNDARY_STRING				"00000000000000000001"

typedef struct _CAHCE_ITEM {
	DOUBLE_LIST_NODE node;
	char extention[16];
	DATA_BLOB blob;
	ino_t ino;
	time_t mtime;
	BOOL b_expired;
	int reference;
} CACHE_ITEM;

typedef struct _RANGE {
	uint32_t begin;
	uint32_t end;
} RANGE;

typedef struct _CACHE_CONTEXT {
	CACHE_ITEM *pitem;
	BOOL b_header;
	uint32_t offset;
	uint32_t until;
	int range_pos;
	int range_num;
	RANGE *prange;
} CACHE_CONTEXT;

typedef struct _DIRECTORY_NODE {
	DOUBLE_LIST_NODE node;
	char *domain;
	char *path;
	char *directory;
} DIRECTORY_NODE;

static int g_context_num;
static BOOL g_notify_stop;
static pthread_t g_scan_tid;
static char g_list_path[256];
static DOUBLE_LIST g_item_list;
static pthread_mutex_t g_hash_lock;
static DOUBLE_LIST g_directory_list;
static STR_HASH_TABLE *g_cache_hash;
static CACHE_CONTEXT *g_context_list;


static void* scan_work_func(void *pparam)
{
	int count;
	char tmp_key[1024];
	CACHE_ITEM *pitem;
	CACHE_ITEM **ppitem;
	STR_HASH_ITER *iter;
	struct stat node_stat;
	
	count = 0;
	while (FALSE == g_notify_stop) {
		count ++;
		if (count < 600) {
			sleep(1);
			continue;
		}
		pthread_mutex_lock(&g_hash_lock);
		iter = str_hash_iter_init(g_cache_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppitem = str_hash_iter_get_value(iter, tmp_key);
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
		pthread_mutex_unlock(&g_hash_lock);
		count = 0;
	}
	pthread_exit(0);
}

static BOOL mod_cache_enlarge_hash()
{
	void *ptmp_value;
	char tmp_key[1024];
	STR_HASH_ITER *iter;
	STR_HASH_TABLE *phash;
	
	phash = str_hash_init(g_cache_hash->capacity + 
		HASH_GROWING_NUM, sizeof(CACHE_ITEM*), NULL);
	if (NULL == phash) {
		return FALSE;
	}
	iter = str_hash_iter_init(g_cache_hash);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		ptmp_value = str_hash_iter_get_value(iter, tmp_key);
		str_hash_add(phash, tmp_key, ptmp_value);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_cache_hash);
	g_cache_hash = phash;
	return TRUE;
}

void mod_cache_init(int context_num, const char *list_path)
{
	g_notify_stop = TRUE;
	g_context_num = context_num;
	strcpy(g_list_path, list_path);
	pthread_mutex_init(&g_hash_lock, NULL);
	double_list_init(&g_item_list);
	double_list_init(&g_directory_list);
}

int mod_cache_run()
{
	int i;
	int tmp_len;
	char *pitem;
	int item_num;
	LIST_FILE *pfile;
	DIRECTORY_NODE *pdnode;
	
	pfile = list_file_init(g_list_path, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		printf("[mod_cache]: fail to init list file\n");
		return -1;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		pdnode = malloc(sizeof(DIRECTORY_NODE));
		if (NULL == pdnode) {
			continue;
		}
		pdnode->node.pdata = pdnode;
		pdnode->domain = strdup(pitem + 768*i);
		pdnode->path = strdup(pitem + 768*i + 256);
		tmp_len = strlen(pdnode->path);
		if ('/' == pdnode->path[tmp_len - 1]) {
			pdnode->path[tmp_len - 1] = '\0';
		}
		pdnode->directory = strdup(pitem + 768*i + 512);
		tmp_len = strlen(pdnode->directory);
		if ('/' == pdnode->directory[tmp_len - 1]) {
			pdnode->directory[tmp_len - 1] = '\0';
		}
		double_list_append_as_tail(&g_directory_list, &pdnode->node);
	}
	list_file_free(pfile);
	g_context_list = malloc(sizeof(CACHE_CONTEXT)*g_context_num);
	if (NULL == g_context_list) {
		printf("[mod_cache]: fail to allocate context list\n");
		return -2;
	}
	memset(g_context_list, 0, sizeof(CACHE_CONTEXT)*g_context_num);
	g_cache_hash = str_hash_init(HASH_GROWING_NUM,
						sizeof(CACHE_ITEM*), NULL);
	if (NULL == g_cache_hash) {
		printf("[mod_cache]: fail to init cache hash table\n");
		return -3;
	}
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_scan_tid, NULL, scan_work_func, NULL)) {
		printf("[mod_cache]: fail to create scanning thread\n");
		g_notify_stop = TRUE;
		return -4;
	}
	return 0;
}

int mod_cache_stop()
{
	int i;
	CACHE_ITEM *pitem;
	CACHE_ITEM **ppitem;
	STR_HASH_ITER *iter;
	DIRECTORY_NODE *pdnode;
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_tid, NULL);
	}
	while (pnode=double_list_get_from_head(&g_directory_list)) {
		pdnode = (DIRECTORY_NODE*)pnode->pdata;
		free(pdnode->domain);
		free(pdnode->path);
		free(pdnode->directory);
		free(pdnode);
	}
	if (NULL != g_context_list) {
		free(g_context_list);
		g_context_list = NULL;
	}
	if (NULL != g_cache_hash) {
		iter = str_hash_iter_init(g_cache_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppitem = str_hash_iter_get_value(iter, NULL);
			free((*ppitem)->blob.data);
			free(*ppitem);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_cache_hash);
		g_cache_hash = NULL;
	}
	while (pnode=double_list_get_from_head(&g_item_list)) {
		pitem = (CACHE_ITEM*)pnode->pdata;
		free(pitem->blob.data);
		free(pitem);
	}
	return 0;
}

void mod_cache_free()
{
	pthread_mutex_destroy(&g_hash_lock);
	double_list_free(&g_directory_list);
	double_list_free(&g_item_list);
}

static CACHE_CONTEXT* mod_cache_get_cache_context(HTTP_CONTEXT *phttp)
{
	int context_id;
	
	context_id = phttp - http_parser_get_contexts_list();
	return g_context_list + context_id;
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
	int tmp_len;
	char *ptoken;
	char *ptoken1;
	char tmp_buff[128];
	
	tmp_len = strlen(etag);
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
	if (FALSE == decode_hex_binary(tmp_buff, (void*)pino, sizeof(ino_t))) {
		return FALSE;
	}
	ptoken1 = strchr(ptoken, '-');
	if (NULL == ptoken1) {
		return FALSE;
	}
	*ptoken1 = '\0';
	ptoken1 ++;
	if (FALSE == decode_hex_binary(ptoken,
		(void*)plength, sizeof(uint32_t))) {
		return FALSE;
	}
	return decode_hex_binary(ptoken1, (void*)pmtime, sizeof(time_t));
}

static void mod_cache_serialize_etag(ino_t ino,
	uint32_t length, time_t mtime, char *etag)
{
	int offset;
	
	offset = 0;
	encode_hex_binary((void*)&ino, sizeof(ino_t), etag + offset, 32);
	offset += 2*sizeof(ino_t);
	etag[offset] = '-';
	offset ++;
	encode_hex_binary((void*)&length, sizeof(uint32_t), etag + offset, 32);
	offset += 2*sizeof(uint32_t);
	etag[offset] = '-';
	offset ++;
	encode_hex_binary((void*)&mtime, sizeof(time_t), etag + offset, 32);
	offset += 2*sizeof(time_t);
	etag[offset] = '\0';
}

static BOOL mod_cache_get_others_field(MEM_FILE *pf_others,
	const char *tag, char *value, int length)
{
	char tmp_buff[256];
	int tag_len, val_len;
	
	mem_file_seek(pf_others, MEM_FILE_READ_PTR,
		0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_read(pf_others,
		&tag_len, sizeof(int))) {
		if (tag_len > sizeof(tmp_buff)) {
			return FALSE;
		}
		mem_file_read(pf_others, tmp_buff, tag_len);
		tmp_buff[tag_len] = '\0';
		mem_file_read(pf_others, &val_len, sizeof(int));
		if (0 == strcasecmp(tag, tmp_buff)) {
			length = (length > val_len)?val_len:(length - 1);
			mem_file_read(pf_others, value, length);
			value[length] = '\0';
			return TRUE;
		}
		mem_file_seek(pf_others, MEM_FILE_READ_PTR,
			val_len, MEM_FILE_SEEK_CUR);
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
	response_len = snprintf(response_buff, sizeof(response_buff),
					"HTTP/1.1 304 Not Modified\r\n"
					"Server: %s\r\n"
					"Date: %s\r\n\r\n",
					resource_get_string(RES_HOST_ID), dstring);
	if (STREAM_WRITE_OK != stream_write(&phttp->stream_out,
		response_buff, response_len)) {
		return FALSE;	
	}
	return TRUE;
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
	if (pcontext->until != pcontext->pitem->blob.length) {
		response_len = snprintf(response_buff,
					sizeof(response_buff),
					"HTTP/1.1 206 Partial Content\r\n");
	} else {
		response_len = snprintf(response_buff,
					sizeof(response_buff),
					"HTTP/1.1 200 OK\r\n");
	}
	response_len += snprintf(response_buff + response_len,
					sizeof(response_buff) - response_len,
					"Server: %s\r\n"
					"Date: %s\r\n"
					"Content-Type: %s\r\n"
					"Content-Length: %u\r\n"
					"Accept-Ranges: bytes\r\n"
					"Last-Modified: %s\r\n"
					"ETag: \"%s\"\r\n",
					resource_get_string(RES_HOST_ID),
					date_string, pcontent_type,
					pcontext->until - pcontext->offset,
					modified_string, etag);
	if (pcontext->until != pcontext->pitem->blob.length) {
		response_len += snprintf(response_buff + response_len,
					sizeof(response_buff) - response_len,
					"Content-Range: bytes %u-%u/%u\r\n\r\n",
					pcontext->offset, pcontext->until - 1,
					pcontext->pitem->blob.length);
	} else {
		memcpy(response_buff + response_len, "\r\n", 2);
		response_len += 2;
	}
	if (STREAM_WRITE_OK != stream_write(&phttp->stream_out,
		response_buff, response_len)) {
		return FALSE;	
	}
	return TRUE;
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
	response_len = snprintf(response_buff, sizeof(response_buff),
					"HTTP/1.1 206 Partial Content\r\n"
					"Server: %s\r\n"
					"Date: %s\r\n"
					"Content-Type: multipart/byteranges;"
					" boundary=%s\r\n"
					"Content-Length: %u\r\n"
					"Last-Modified: %s\r\n"
					"ETag: \"%s\"\r\n",
					resource_get_string(RES_HOST_ID),
					date_string, BOUNDARY_STRING,
					content_length, modified_string, etag);
	if (STREAM_WRITE_OK != stream_write(&phttp->stream_out,
		response_buff, response_len)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL mod_cache_parse_range_value(char *value,
	uint32_t size, CACHE_CONTEXT *pcontext)
{
	int i;
	int count;
	int val_len;
	char *ptoken;
	char *ptoken1;
	int range_num;
	long last_bpos;
	long first_bpos;
	char *plast_token;
	RANGE ranges[1024];
	
	count = 0;
	ltrim_string(value);
	rtrim_string(value);
	if (0 != strncasecmp(value, "bytes", 5)) {
		return FALSE;
	}
	value += 5;
	ltrim_string(value);
	if ('=' != value[0]) {
		return FALSE;
	}
	value ++;
	ltrim_string(value);
	val_len = strlen(value);
	if (',' != value[val_len - 1]) {
		value[val_len] = ',';
		val_len ++;
	}
	for (i=0; i<val_len; i++) {
		if (',' == value[i]) {
			count ++;
		}
	}
	if (count > sizeof(ranges)/sizeof(RANGE)) {
		return FALSE;
	}
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
		first_bpos = atol(plast_token);
		if (first_bpos >= size) {
			return FALSE;
		}
		last_bpos = atol(ptoken1);
		if (0 == last_bpos) {
			last_bpos = size - 1;
		}
		if (last_bpos < 0 || last_bpos >= size) {
			return FALSE;
		}
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
	pcontext->prange = malloc(sizeof(RANGE)*range_num);
	if (NULL == pcontext->prange) {
		return FALSE;
	}
	memcpy(pcontext->prange, ranges, sizeof(RANGE)*range_num);
	return TRUE;
}

BOOL mod_cache_get_context(HTTP_CONTEXT *phttp)
{
	int fd;
	ino_t ino;
	int tmp_len;
	int path_len;
	char *ptoken;
	time_t mtime;
	uint32_t size;
	char suffix[16];
	char domain[256];
	CACHE_ITEM *pitem;
	char tmp_path[512];
	CACHE_ITEM **ppitem;
	char tmp_buff[8192];
	struct stat node_stat;
	DIRECTORY_NODE *pdnode;
	char request_uri[8192];
	DOUBLE_LIST_NODE *pnode;
	CACHE_CONTEXT *pcontext;
	
	if (0 != strcasecmp(phttp->request.method, "GET") &&
		0 != strcasecmp(phttp->request.method, "HEAD")) {
		return FALSE;
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_content_length);
	if (0 != tmp_len) {
		if (tmp_len >= 32) {
			return FALSE;
		}
		mem_file_seek(&phttp->request.f_content_length,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_content_length, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
		if (0 != atoll(tmp_buff)) {
			return FALSE;
		}
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_host);
	if (tmp_len >= sizeof(domain)) {
		http_parser_log_info(phttp, 8, "length of "
			"request host is too long for mod_cache");
		return FALSE;
	}
	if (0 == tmp_len) {
		strcpy(domain, phttp->connection.server_ip);
	} else {
		mem_file_seek(&phttp->request.f_host,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_host, domain, tmp_len);
		domain[tmp_len] = '\0';
	}
	ptoken = strchr(domain, ':');
	if (NULL != ptoken) {
		*ptoken = '\0';
	}
	tmp_len = mem_file_get_total_length(
		&phttp->request.f_request_uri);
	if (0 == tmp_len) {
		http_parser_log_info(phttp, 8, "cannot"
			" find request uri for mod_cache");
		return FALSE;
	} else if (tmp_len >= sizeof(tmp_buff)) {
		http_parser_log_info(phttp, 8, "length of "
			"request uri is too long for mod_cache");
		return FALSE;
	}
	mem_file_seek(&phttp->request.f_request_uri,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_read(&phttp->request.f_request_uri, tmp_buff, tmp_len);
	tmp_buff[tmp_len] = '\0';
	if (FALSE == parse_uri(tmp_buff, request_uri)) {
		http_parser_log_info(phttp, 8, "request"
				" uri format error for mod_cache");
		return FALSE;
	}
	suffix[0] = '\0';
	ptoken = strrchr(request_uri, '/');
	if (NULL == ptoken) {
		http_parser_log_info(phttp, 8, "request uri "
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
	path_len = strlen(request_uri);
	for (pnode=double_list_get_head(&g_directory_list); NULL!=pnode;
		pnode=double_list_get_after(&g_directory_list, pnode)) {
		pdnode = (DIRECTORY_NODE*)pnode->pdata;	
		if (0 == wildcard_match(domain, pdnode->domain, TRUE)) {
			continue;
		}
		tmp_len = strlen(pdnode->path);
		if (0 == strncasecmp(request_uri, pdnode->path, tmp_len)) {
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	snprintf(tmp_path, sizeof(tmp_path), "%s%s",
		pdnode->directory, request_uri + tmp_len);
	if (0 != stat(tmp_path, &node_stat) ||
		0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	if (node_stat.st_size >= 0xFFFFFFFF) {
		return FALSE;
	}
	if (TRUE == mod_cache_get_others_field(
		&phttp->request.f_others,
		"If-None-Match", tmp_buff, 128) &&
		TRUE == mod_cache_retrieve_etag(
		tmp_buff, &ino, &size, &mtime)) {
		if (ino == node_stat.st_ino &&
			size == node_stat.st_size &&
			mtime == node_stat.st_mtime) {
			return mod_cache_response_unmodified(phttp);
		}
	} else {
		if (TRUE == mod_cache_get_others_field(
			&phttp->request.f_others,
			"If-Modified-Since", tmp_buff, 128) &&
			TRUE == mod_cache_parse_rfc1123_dstring(
			tmp_buff, &mtime)) {
			if (mtime == node_stat.st_mtime) {
				return mod_cache_response_unmodified(phttp);
			}
		}
	}
	pcontext = mod_cache_get_cache_context(phttp);
	memset(pcontext, 0, sizeof(CACHE_CONTEXT));
	if (TRUE == mod_cache_get_others_field(
		&phttp->request.f_others, "Range",
		tmp_buff, sizeof(tmp_buff))) {
		if (FALSE == mod_cache_parse_range_value(
			tmp_buff, node_stat.st_size, pcontext)) {
			http_parser_log_info(phttp, 8, "\"range\""
				" value in http request header format"
				" error for mod_cache");
			return FALSE;
		}
	} else {
		pcontext->offset = 0;
		pcontext->until = node_stat.st_size;
	}
	pthread_mutex_lock(&g_hash_lock);
	ppitem = str_hash_query(g_cache_hash, tmp_path);
	if (NULL != ppitem) {
		pitem = *ppitem;
		if (pitem->ino != node_stat.st_ino ||
			pitem->blob.length != node_stat.st_size ||
			pitem->mtime != node_stat.st_mtime) {
			str_hash_remove(g_cache_hash, tmp_path);
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
			pthread_mutex_unlock(&g_hash_lock);
			pcontext->pitem = pitem;
			return TRUE;
		}
	}
	pthread_mutex_unlock(&g_hash_lock);
	pitem = malloc(sizeof(CACHE_ITEM));
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
	pitem->blob.data = malloc(node_stat.st_size);
	if (NULL == pitem->blob.data) {
		free(pitem);
		if (NULL != pcontext->prange) {
			free(pcontext->prange);
			pcontext->prange = NULL;
		}
		return FALSE;
	}
	fd = open(tmp_path, O_RDONLY);
	if (-1 == fd) {
		free(pitem->blob.data);
		free(pitem);
		if (NULL != pcontext->prange) {
			free(pcontext->prange);
			pcontext->prange = NULL;
		}
		return FALSE;
	}
	if (node_stat.st_size != read(fd,
		pitem->blob.data, node_stat.st_size)) {
		close(fd);
		free(pitem->blob.data);
		free(pitem);
		if (NULL != pcontext->prange) {
			free(pcontext->prange);
			pcontext->prange = NULL;
		}
		return FALSE;
	}
	close(fd);
	pthread_mutex_lock(&g_hash_lock);
	ppitem = str_hash_query(g_cache_hash, tmp_path);
	if (NULL == ppitem) {
		if (1 != str_hash_add(g_cache_hash, tmp_path, &pitem)) {
			if (FALSE == mod_cache_enlarge_hash()) {
				goto INVALIDATE_ITEM;
			}
			str_hash_add(g_cache_hash, tmp_path, &pitem);
		}
		pitem->b_expired = FALSE;
		pthread_mutex_unlock(&g_hash_lock);
		pcontext->pitem = pitem;
		return TRUE;
	}
INVALIDATE_ITEM:
	pitem->b_expired = TRUE;
	pitem->node.pdata = pitem;
	double_list_append_as_tail(&g_item_list, &pitem->node);
	pthread_mutex_unlock(&g_hash_lock);
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
	pthread_mutex_lock(&g_hash_lock);
	pitem->reference --;
	if (0 != pitem->reference || FALSE == pitem->b_expired) {
		pthread_mutex_unlock(&g_hash_lock);
		return;
	}
	double_list_remove(&g_item_list, &pitem->node);
	pthread_mutex_unlock(&g_hash_lock);
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
	if (FALSE == pcontext->b_header) {
		if (NULL == pcontext->prange) {
			if (FALSE == mod_cache_response_single_header(phttp)) {
				mod_cache_put_context(phttp);
				return FALSE;
			}
		} else {
			if (FALSE == mod_cache_response_multiple_header(phttp)) {
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
	if (STREAM_WRITE_OK != stream_write(&phttp->stream_out,
		pcontext->pitem->blob.data + pcontext->offset, tmp_len)) {
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
			if (STREAM_WRITE_OK != stream_write(
				&phttp->stream_out, tmp_buff, tmp_len)) {
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
