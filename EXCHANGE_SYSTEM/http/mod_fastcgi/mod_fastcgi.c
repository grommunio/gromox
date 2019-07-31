#include "contexts_pool.h"
#include "threads_pool.h"
#include "mod_fastcgi.h"
#include "http_parser.h"
#include "list_file.h"
#include "resource.h"
#include "util.h"
#include "ndr.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>


#define SOCKET_TIMEOUT							180

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

typedef struct _FCGI_ENDREQUESTBODY {
	uint32_t app_status;
	uint8_t protocol_status;
	uint8_t reserved[3];
} FCGI_ENDREQUESTBODY;

typedef struct _FCGI_STDSTREAM {
	uint8_t buffer[0xFFFF];
	uint16_t length;
} FCGI_STDSTREAM;

typedef struct _RECORD_HEADER {
	uint8_t version;
	uint8_t type;
	uint16_t request_id;
	uint16_t content_len;
	uint8_t padding_len;
	uint8_t reserved;
} RECORD_HEADER;

static int g_context_num;
static int g_exec_timeout;
static uint64_t g_max_size;
static uint64_t g_cache_size;
static char g_list_path[256];
static DOUBLE_LIST g_fastcgi_list;
static FASTCGI_CONTEXT *g_context_list;
static volatile int g_unavailable_times;

static FASTCGI_NODE* mod_fastcgi_find_backend(
	const char*domain, const char *uri_path,
	const char *file_name, const char *suffix,
	BOOL *pb_index)
{
	int tmp_len;
	int path_len;
	FASTCGI_NODE *pfnode;
	DOUBLE_LIST_NODE *pnode;
	
	path_len = strlen(uri_path);
	for (pnode=double_list_get_head(&g_fastcgi_list); NULL!=pnode;
		pnode=double_list_get_after(&g_fastcgi_list, pnode)) {
		pfnode = (FASTCGI_NODE*)pnode->pdata;
		if (0 == wildcard_match(domain, pfnode->domain, TRUE)) {
			continue;
		}
		tmp_len = strlen(pfnode->path);
		if (0 != strncasecmp(uri_path, pfnode->path, tmp_len)) {
			continue;
		}
		if ('\0' == file_name[0] && '\0' == suffix[0]) {
			*pb_index = TRUE;
			return pfnode;
		}
		if (0 != strcmp(pfnode->suffix, "*") &&
			0 == wildcard_match(suffix, pfnode->suffix, TRUE)) {
			continue;
		}
		*pb_index = FALSE;
		return pfnode;
	}
	return NULL;
}

void mod_fastcgi_init(int context_num, const char *list_path,
	uint64_t cache_size, uint64_t max_size, int exec_timeout)
{
	g_context_num = context_num;
	g_unavailable_times = 0;
	strcpy(g_list_path, list_path);
	g_cache_size = cache_size;
	g_max_size = max_size;
	g_exec_timeout = exec_timeout;
	double_list_init(&g_fastcgi_list);
}

static void mod_fastcgi_load_extra_headers(
	char *extra_headers, DOUBLE_LIST *plist)
{
	int i;
	int tmp_len;
	char *ptoken;
	char *plast_token;
	char tmp_buff[128];
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(plist);
	tmp_len = strlen(extra_headers);
	if ('|' != extra_headers[tmp_len - 1]) {
		extra_headers[tmp_len] = '|';
		tmp_len ++;
	}
	plast_token = extra_headers;
	for (i=0; i<tmp_len; i++) {
		if ('|' != extra_headers[i]) {
			continue;
		}
		ptoken = extra_headers + i;
		if (ptoken == plast_token || ptoken -
			plast_token >= sizeof(tmp_buff)) {
			continue;
		}
		memcpy(tmp_buff, plast_token, ptoken - plast_token);
		tmp_buff[ptoken - plast_token] = '\0';
		ltrim_string(tmp_buff);
		rtrim_string(tmp_buff);
		if ('\0' == tmp_buff[0]) {
			continue;
		}
		upper_string(tmp_buff);
		pnode = malloc(sizeof(DOUBLE_LIST_NODE));
		pnode->pdata = strdup(tmp_buff);
		double_list_append_as_tail(plist, pnode);
	}
}

int mod_fastcgi_run()
{
	int i;
	int tmp_len;
	char *pitem;
	int item_num;
	LIST_FILE *pfile;
	FASTCGI_NODE *pfnode;
	char extra_headers[512];
	
	pfile = list_file_init(g_list_path,
		"%s:256%s:256%s:256%s:16%s:256%s:304%s:256");
	if (NULL == pfile) {
		printf("[mod_fastcgi]: fail to init list file\n");
		return -1;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		pfnode = malloc(sizeof(FASTCGI_NODE));
		if (NULL == pfnode) {
			continue;
		}
		pfnode->node.pdata = pfnode;
		double_list_init(&pfnode->header_list);
		pfnode->domain = strdup(pitem + 1600*i);
		pfnode->path = strdup(pitem + 1600*i + 256);
		tmp_len = strlen(pfnode->path);
		if ('/' == pfnode->path[tmp_len - 1]) {
			pfnode->path[tmp_len - 1] = '\0';
		}
		pfnode->directory = strdup(pitem + 1600*i + 512);
		tmp_len = strlen(pfnode->directory);
		if ('/' == pfnode->directory[tmp_len - 1]) {
			pfnode->directory[tmp_len - 1] = '\0';
		}
		pfnode->suffix = strdup(pitem + 1600*i + 768);
		pfnode->index = strdup(pitem + 1600*i + 784);
		strcpy(extra_headers, pitem + 1600*i + 1040);
		mod_fastcgi_load_extra_headers(
			extra_headers, &pfnode->header_list);
		pfnode->sock_path = strdup(pitem + 1600*i + 1344);
		double_list_append_as_tail(&g_fastcgi_list, &pfnode->node);
	}
	list_file_free(pfile);
	g_context_list = malloc(sizeof(FASTCGI_CONTEXT)*g_context_num);
	if (NULL == g_context_list) {
		printf("[mod_fastcgi]: fail to allocate context list\n");
		return -2;
	}
	return 0;
}

int mod_fastcgi_stop()
{
	FASTCGI_NODE *pfnode;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	while (pnode=double_list_get_from_head(&g_fastcgi_list)) {
		pfnode = (FASTCGI_NODE*)pnode->pdata;
		free(pfnode->domain);
		free(pfnode->path);
		free(pfnode->directory);
		free(pfnode->suffix);
		free(pfnode->index);
		free(pfnode->sock_path);
		while (pnode1=double_list_get_from_head(
			&pfnode->header_list)) {
			free(pnode1->pdata);
			free(pnode1);
		}
		free(pfnode);
	}
	if (NULL != g_context_list) {
		free(g_context_list);
		g_context_list = NULL;
	}
}

void mod_fastcgi_free()
{
	double_list_free(&g_fastcgi_list);
}

static int mod_fastcgi_push_name_value(NDR_PUSH *pndr,
	uint8_t *pname, uint8_t *pvalue)
{
	int status;
	uint32_t tmp_len;
	uint32_t val_len;
	uint32_t name_len;
	
	name_len = strlen(pname);
	if (name_len <= 0x7F) {
		status = ndr_push_uint8(pndr, name_len);
	} else {
		tmp_len = name_len | 0x80000000;
		status = ndr_push_uint32(pndr, tmp_len);
	}
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	val_len = strlen(pvalue);
	if (val_len <= 0x7F) {
		status = ndr_push_uint8(pndr, val_len);
	} else {
		tmp_len = val_len | 0x80000000;
		status = ndr_push_uint32(pndr, tmp_len);
	}
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr, pname, name_len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_array_uint8(pndr, pvalue, val_len);
}

static int mod_fastcgi_push_begin_request(NDR_PUSH *pndr)
{
	int status;
	
	status = ndr_push_uint8(pndr, FCGI_VERSION);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, RECORD_TYPE_BEGIN_REQUEST);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, FCGI_REQUEST_ID);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* push content length */
	status = ndr_push_uint16(pndr, 8);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* push padding length */
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* reserved */
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* begin request role */
	status = ndr_push_uint16(pndr, ROLE_RESPONDER);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* begin request flags */
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* begin request reserved bytes */
	return ndr_push_zero(pndr, 5);
}

static int mod_fastcgi_push_params_begin(NDR_PUSH *pndr)
{
	int status;
	
	status = ndr_push_uint8(pndr, FCGI_VERSION);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, RECORD_TYPE_PARAMS);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, FCGI_REQUEST_ID);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* push fake content length */
	status = ndr_push_uint16(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* push fake padding length */
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* reserved */
	return ndr_push_uint8(pndr, 0);
}

static int mod_fastcgi_push_align_record(NDR_PUSH *pndr)
{
	uint8_t padding_len;
	
	if (0 == (pndr->offset & 7)) {
		return NDR_ERR_SUCCESS;
	}
	padding_len = 8 - (pndr->offset & 7);
	pndr->data[6] = padding_len;
	return ndr_push_zero(pndr, padding_len);
}

static int mod_fastcgi_push_params_end(NDR_PUSH *pndr)
{
	int status;
	uint16_t len;
	uint32_t offset;
	
	offset = pndr->offset;
	len = offset - 8;
	if (len > 0xFFFF) {
		return NDR_ERR_FAILURE;
	}
	pndr->offset = 4;
	status = ndr_push_uint16(pndr, len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->offset = offset;
	return mod_fastcgi_push_align_record(pndr);
}

static int mod_fastcgi_push_stdin(NDR_PUSH *pndr,
	uint8_t *pbuff, uint16_t length)
{
	int status;
	
	status = ndr_push_uint8(pndr, FCGI_VERSION);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, RECORD_TYPE_STDIN);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, FCGI_REQUEST_ID);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* push padding length */
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	/* reserved */
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr, pbuff, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return mod_fastcgi_push_align_record(pndr);
}

static int mod_fastcgi_pull_end_request(NDR_PULL *pndr,
	uint8_t padding_len, FCGI_ENDREQUESTBODY *pend_request)
{
	int status;
	
	status = ndr_pull_uint32(pndr, &pend_request->app_status);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &pend_request->protocol_status);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_array_uint8(pndr, pend_request->reserved, 3);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_advance(pndr, padding_len);
}

static int mod_fastcgi_pull_stdstream(NDR_PULL *pndr,
	uint8_t padding_len, FCGI_STDSTREAM *pstd_stream)
{
	int status;
	
	status = ndr_pull_array_uint8(pndr,
		pstd_stream->buffer, pstd_stream->length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_advance(pndr, padding_len);
}

static int mod_fastcgi_pull_record_header(
	NDR_PULL *pndr, RECORD_HEADER *pheader)
{
	int status;
	uint8_t tmp_byte;
	uint16_t tmp_short;
	
	status = ndr_pull_uint8(pndr, &pheader->version);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &pheader->type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &pheader->request_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &pheader->content_len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &pheader->padding_len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_uint8(pndr, &pheader->reserved);
}

static BOOL mod_fastcgi_get_others_field(MEM_FILE *pf_others,
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

static int mod_fastcgi_connect_backend(const char *path)
{
	int sockd, len;
	struct sockaddr_un un;

	/* create a UNIX domain stream socket */
	sockd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockd < 0) {
		return -1;
	}
	/* fill socket address structure with server's address */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, path);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
	if (connect(sockd, (struct sockaddr *)&un, len) < 0) {
		close(sockd);
		return -2;
	}
	return sockd;
}

BOOL mod_fastcgi_get_context(HTTP_CONTEXT *phttp)
{
	int tmp_len;
	BOOL b_index;
	char *ptoken;
	char *ptoken1;
	BOOL b_chunked;
	int context_id;
	char suffix[16];
	char domain[256];
	char file_name[256];
	char tmp_buff[8192];
	FASTCGI_NODE *pfnode;
	char request_uri[8192];
	uint64_t content_length;
	FASTCGI_CONTEXT *pcontext;
	
	tmp_len = mem_file_get_total_length(&phttp->request.f_host);
	if (tmp_len >= sizeof(domain)) {
		http_parser_log_info(phttp, 8, "length of "
			"request host is too long for mod_fastcgi");
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
		http_parser_log_info(phttp, 8, "cannot "
			"find request uri for mod_fastcgi");
		return FALSE;
	} else if (tmp_len >= sizeof(tmp_buff)) {
		http_parser_log_info(phttp, 8, "length of "
			"request uri is too long for mod_fastcgi");
		return FALSE;
	}
	mem_file_seek(&phttp->request.f_request_uri,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_read(&phttp->request.f_request_uri, tmp_buff, tmp_len);
	tmp_buff[tmp_len] = '\0';
	if (FALSE == http_parser_parse_uri(tmp_buff, request_uri)) {
		http_parser_log_info(phttp, 8, "request"
			" uri format error for mod_fastcgi");
		return FALSE;
	}
	ptoken = strrchr(request_uri, '?');
	if (NULL != ptoken) {
		*ptoken = '\0';
	}
	ptoken = strrchr(request_uri, '.');
	if (NULL != ptoken) {
		*ptoken = '\0';
		ptoken ++;
		ptoken1 = strchr(ptoken, '/');
		if (NULL != ptoken1) {
			*ptoken1 = '\0';
		}
		tmp_len = strlen(ptoken);
		if (tmp_len >= 16) {
			http_parser_log_info(phttp, 8, "suffix in"
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
		strncpy(file_name, ptoken + 1, 256);
	} else {
		http_parser_log_info(phttp, 8, "request uri format "
					"error, missing slash for mod_fastcgi");
		return FALSE;
	}
	pfnode = mod_fastcgi_find_backend(domain,
		request_uri, file_name, suffix, &b_index);
	if (NULL == pfnode) {
		return FALSE;
	}
	http_parser_log_info(phttp, 8, "http request \"%s\" "
		"to \"%s\" will be relayed to fastcgi back-end %s",
		tmp_buff, domain, pfnode->sock_path);
	tmp_len = mem_file_get_total_length(&phttp->request.f_content_length);
	if (0 == tmp_len) {
		content_length = 0;
	} else {
		if (tmp_len >= 32) {
			http_parser_log_info(phttp, 8, "length of "
				"content-length is too long for mod_fastcgi");
			return FALSE;
		}
		mem_file_seek(&phttp->request.f_content_length,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_content_length, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
		content_length = atoll(tmp_buff);
	}
	if (content_length > g_max_size) {
		http_parser_log_info(phttp, 8, "content-length"
			" is too long for mod_fastcgi");
		return FALSE;
	}
	b_chunked = FALSE;
	tmp_len = mem_file_get_total_length(&phttp->request.f_transfer_encoding);
	if (tmp_len > 0 && tmp_len < 64) {
		mem_file_seek(&phttp->request.f_transfer_encoding,
				MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_transfer_encoding, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
		if (0 == strcasecmp(tmp_buff, "chunked")) {
			b_chunked = TRUE;
		}
	}
	context_id = phttp - http_parser_get_contexts_list();
	pcontext = g_context_list + context_id;
	time(&pcontext->last_time);
	pcontext->pfnode = pfnode;
	if (TRUE == b_chunked || content_length > g_cache_size) {
		sprintf(tmp_buff, "/tmp/http-%d", context_id);
		pcontext->cache_fd = open(tmp_buff,
			O_CREAT|O_TRUNC|O_RDWR, 0666);
		if (-1 == pcontext->cache_fd) {
			return FALSE;
		}
		pcontext->cache_size = 0;
	} else {
		pcontext->cache_fd = -1;
	}
	pcontext->b_index = b_index;
	pcontext->b_chunked = b_chunked;
	if (TRUE == b_chunked) {
		pcontext->chunk_size = 0;
		pcontext->chunk_offset = 0;
	}
	pcontext->b_end = FALSE;
	pcontext->content_length = content_length;
	pcontext->cli_sockd = -1;
	pcontext->b_header = FALSE;
	phttp->pfast_context = pcontext;
	return TRUE;
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
	int status;
	int tmp_len;
	char *ptoken;
	char *ptoken1;
	char *path_info;
	char domain[256];
	NDR_PUSH ndr_push;
	char uri_path[8192];
	char tmp_buff[8192];
	FASTCGI_NODE *pfnode;
	struct stat node_stat;
	DOUBLE_LIST_NODE *pnode;
	uint64_t content_length;
	char document_root[1024];
	
	ndr_push_init(&ndr_push, pbuff, *plength,
		NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
	status = mod_fastcgi_push_params_begin(&ndr_push);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	status = mod_fastcgi_push_name_value(&ndr_push,
					"GATEWAY_INTERFACE", "CGI/1.1");
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	status = mod_fastcgi_push_name_value(&ndr_push,
				"SERVER_SOFTWARE", SERVER_SOFTWARE);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	if (TRUE == phttp->b_authed) {
		status = mod_fastcgi_push_name_value(&ndr_push,
					"REMOTE_USER", phttp->username);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
		status = mod_fastcgi_push_name_value(
			&ndr_push, "USER_HOME", phttp->maildir);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
		status = mod_fastcgi_push_name_value(
			&ndr_push, "USER_LANG", phttp->lang);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_host);
	if (tmp_len >= sizeof(domain)) {
		http_parser_log_info(phttp, 8, "length of "
			"request host is too long for mod_fastcgi");
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
	status = mod_fastcgi_push_name_value(
		&ndr_push, "HTTP_HOST", domain);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	ptoken = strchr(domain, ':');
	if (NULL != ptoken) {
		*ptoken = '\0';
	}
	status = mod_fastcgi_push_name_value(
		&ndr_push, "SERVER_NAME", domain);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	status = mod_fastcgi_push_name_value(&ndr_push,
		"SERVER_ADDR", phttp->connection.server_ip);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	sprintf(tmp_buff, "%d", phttp->connection.server_port);
	status = mod_fastcgi_push_name_value(
		&ndr_push, "SERVER_PORT", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	status = mod_fastcgi_push_name_value(&ndr_push,
		"REMOTE_ADDR", phttp->connection.client_ip);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	sprintf(tmp_buff, "%d", phttp->connection.client_port);
	status = mod_fastcgi_push_name_value(
		&ndr_push, "REMOTE_PORT", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	sprintf(tmp_buff, "HTTP/%s", phttp->request.version);
	status = mod_fastcgi_push_name_value(&ndr_push,
					"SERVER_PROTOCOL", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	status = mod_fastcgi_push_name_value(&ndr_push,
		"REQUEST_METHOD", phttp->request.method);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	tmp_len = mem_file_get_total_length(
		&phttp->request.f_request_uri);
	if (0 == tmp_len) {
		http_parser_log_info(phttp, 8, "cannot "
			"find request uri for mod_fastcgi");
		return FALSE;
	} else if (tmp_len >= sizeof(tmp_buff)) {
		http_parser_log_info(phttp, 8, "length of "
			"request uri is too long for mod_fastcgi");
		return FALSE;
	}
	mem_file_seek(&phttp->request.f_request_uri,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_read(&phttp->request.f_request_uri, tmp_buff, tmp_len);
	tmp_buff[tmp_len] = '\0';
	status = mod_fastcgi_push_name_value(
		&ndr_push, "REQUEST_URI", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	ptoken = strchr(tmp_buff, '?');
	if (NULL == ptoken) {
		ptoken = "";
	} else {
		ptoken ++;
	}
	status = mod_fastcgi_push_name_value(
		&ndr_push, "QUERY_STRING", ptoken);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	if (FALSE == http_parser_parse_uri(tmp_buff, uri_path)) {
		http_parser_log_info(phttp, 8, "request"
			" uri format error for mod_fastcgi");
		return FALSE;
	}
	if (strlen(uri_path) >= 1024) {
		http_parser_log_info(phttp, 8, "length of "
			"uri path is too long for mod_fastcgi");
		return FALSE;
	}
	path_info = NULL;
	ptoken = strrchr(uri_path, '.');
	if (NULL != ptoken) {
		ptoken1 = strchr(ptoken + 1, '/');
		if (NULL == ptoken1) {
			ptoken1 = uri_path + tmp_len;
		} else {
			status = mod_fastcgi_push_name_value(
				&ndr_push, "PATH_INFO", ptoken1);
			if (NDR_ERR_SUCCESS != status) {
				return FALSE;
			}
			*ptoken1 = '\0';
			path_info = ptoken1 + 1;
		}
	}
	pfnode = phttp->pfast_context->pfnode;
	status = mod_fastcgi_push_name_value(&ndr_push,
				"DOCUMENT_ROOT", pfnode->directory);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	if (NULL != path_info) {
		sprintf(tmp_buff, "%s/%s", pfnode->directory, path_info);
		status = mod_fastcgi_push_name_value(
			&ndr_push, "PATH_TRANSLATED", tmp_buff);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
	}
	tmp_len = strlen(pfnode->path);
	if (TRUE == phttp->pfast_context->b_index) {
		sprintf(tmp_buff, "%s%s", uri_path, pfnode->index);
		status = mod_fastcgi_push_name_value(
			&ndr_push, "SCRIPT_NAME", tmp_buff);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
		sprintf(tmp_buff, "%s%s%s", pfnode->directory,
			uri_path + tmp_len, pfnode->index);
		status = mod_fastcgi_push_name_value(
			&ndr_push, "SCRIPT_FILENAME", tmp_buff);
	} else {
		status = mod_fastcgi_push_name_value(
			&ndr_push, "SCRIPT_NAME", uri_path);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
		sprintf(tmp_buff, "%s%s", pfnode->directory, uri_path + tmp_len);
		status = mod_fastcgi_push_name_value(
			&ndr_push, "SCRIPT_FILENAME", tmp_buff);
	}
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_accept);
	if (tmp_len > 1024) {
		http_parser_log_info(phttp, 8, "length of "
			"accept is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		mem_file_seek(&phttp->request.f_accept,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_accept, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	status = mod_fastcgi_push_name_value(
		&ndr_push, "HTTP_ACCEPT", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_user_agent);
	if (tmp_len > 1024) {
		http_parser_log_info(phttp, 8, "length of "
			"user-agent is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		mem_file_seek(&phttp->request.f_user_agent,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_user_agent, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	status = mod_fastcgi_push_name_value(
		&ndr_push, "HTTP_USER_AGENT", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_accept_language);
	if (tmp_len > 1024) {
		http_parser_log_info(phttp, 8, "length of "
			"accept-language is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		mem_file_seek(&phttp->request.f_accept_language,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_accept_language, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	status = mod_fastcgi_push_name_value(&ndr_push,
				"HTTP_ACCEPT_LANGUAGE", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_accept_encoding);
	if (tmp_len > 1024) {
		http_parser_log_info(phttp, 8, "length of "
			"accept-encoding is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		mem_file_seek(&phttp->request.f_accept_encoding,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_accept_encoding, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	status = mod_fastcgi_push_name_value(&ndr_push,
				"HTTP_ACCEPT_ENCODING", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_cookie);
	if (tmp_len > 1024) {
		http_parser_log_info(phttp, 8, "length of "
			"cookie is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 != tmp_len) {
		mem_file_seek(&phttp->request.f_cookie,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_cookie, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
		status = mod_fastcgi_push_name_value(
			&ndr_push, "HTTP_COOKIE", tmp_buff);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
	}
	tmp_len = mem_file_get_total_length(&phttp->request.f_content_type);
	if (tmp_len > 128) {
		http_parser_log_info(phttp, 8, "length of "
			"content-type is too long for mod_fastcgi");
		return FALSE;
	}
	if (0 == tmp_len) {
		tmp_buff[0] = '\0';
	} else {
		mem_file_seek(&phttp->request.f_content_type,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&phttp->request.f_content_type, tmp_buff, tmp_len);
		tmp_buff[tmp_len] = '\0';
	}
	status = mod_fastcgi_push_name_value(
		&ndr_push, "CONTENT_TYPE", tmp_buff);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	if (NULL != phttp->connection.ssl) {
		status = mod_fastcgi_push_name_value(
			&ndr_push, "REQUEST_SCHEME", "https");
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
		status = mod_fastcgi_push_name_value(
					&ndr_push, "HTTPS", "on");
	} else {
		status = mod_fastcgi_push_name_value(
			&ndr_push, "REQUEST_SCHEME", "http");
	}
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	if (TRUE == phttp->b_close) {
		status = mod_fastcgi_push_name_value(
			&ndr_push, "HTTP_CONNECTION", "close");
	} else {
		status = mod_fastcgi_push_name_value(
			&ndr_push, "HTTP_CONNECTION", "keep-alive");
	}
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	if (TRUE == mod_fastcgi_get_others_field(
		&phttp->request.f_others, "Referer",
		tmp_buff, sizeof(tmp_buff))) {
		status = mod_fastcgi_push_name_value(
			&ndr_push, "HTTP_REFERER", tmp_buff);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
	}
	if (TRUE == mod_fastcgi_get_others_field(
		&phttp->request.f_others, "Cache-Control",
		tmp_buff, 128)) {
		status = mod_fastcgi_push_name_value(
			&ndr_push, "HTTP_CACHE_CONTROL", tmp_buff);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
	}
	for (pnode=double_list_get_head(&pfnode->header_list); NULL!=pnode;
		pnode=double_list_get_after(&pfnode->header_list, pnode)) {
		if (TRUE == mod_fastcgi_get_others_field(
			&phttp->request.f_others, pnode->pdata,
			tmp_buff, 1024)) {
			status = mod_fastcgi_push_name_value(
			&ndr_push, pnode->pdata, tmp_buff);
			if (NDR_ERR_SUCCESS != status) {
				return FALSE;
			}
		}
	}
	if (FALSE == phttp->pfast_context->b_chunked) {
		sprintf(tmp_buff, "%llu", phttp->pfast_context->content_length);
		status = mod_fastcgi_push_name_value(
			&ndr_push, "CONTENT_LENGTH", tmp_buff);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
	} else {
		if (0 != fstat(phttp->pfast_context->cache_fd, &node_stat)) {
			return FALSE;
		}
		sprintf(tmp_buff, "%llu", (uint64_t)node_stat.st_size);
		status = mod_fastcgi_push_name_value(
			&ndr_push, "CONTENT_LENGTH", tmp_buff);
		if (NDR_ERR_SUCCESS != status) {
			return FALSE;
		}
	}
	status = mod_fastcgi_push_params_end(&ndr_push);
	if (NDR_ERR_SUCCESS != status) {
		return FALSE;
	}
	*plength = ndr_push.offset;
	return TRUE;
}

BOOL mod_fastcgi_relay_content(HTTP_CONTEXT *phttp)
{
	int tmp_len;
	char *pbuff;
	int cli_sockd;
	int ndr_length;
	int context_id;
	NDR_PUSH ndr_push;
	char tmp_path[256];
	char tmp_buff[65535];
	uint8_t ndr_buff[65800];
	
	ndr_push_init(&ndr_push, tmp_buff, 16,
		NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
	if (NDR_ERR_SUCCESS != mod_fastcgi_push_begin_request(
		&ndr_push) || 16 != ndr_push.offset) {
		return FALSE;
	}
	ndr_length = sizeof(ndr_buff);
	if (FALSE == mod_fastcgi_build_params(
		phttp, ndr_buff, &ndr_length)) {
		return FALSE;	
	}
	cli_sockd = mod_fastcgi_connect_backend(
		phttp->pfast_context->pfnode->sock_path);
	if (cli_sockd < 0) {
		http_parser_log_info(phttp, 8, "fail to "
				"connect to fastcgi back-end %s",
				phttp->pfast_context->pfnode->sock_path);
		return FALSE;
	}
	if (16 != write(cli_sockd, tmp_buff, 16) ||
		ndr_length != write(cli_sockd, ndr_buff,
		ndr_length)) {
		close(cli_sockd);
		http_parser_log_info(phttp, 8, "fail to "
			"write record to fastcgi back-end %s",
			phttp->pfast_context->pfnode->sock_path);
		return FALSE;
	}
	ndr_push_init(&ndr_push, tmp_buff, 8,
		NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
	if (NDR_ERR_SUCCESS != mod_fastcgi_push_params_begin(&ndr_push) ||
		NDR_ERR_SUCCESS != mod_fastcgi_push_params_end(&ndr_push) ||
		8 != ndr_push.offset || 8 != write(cli_sockd, tmp_buff, 8)) {
		close(cli_sockd);
		http_parser_log_info(phttp, 8, "fail to "
			"write record to fastcgi back-end %s",
			phttp->pfast_context->pfnode->sock_path);
		return FALSE;
	}
	if (-1 == phttp->pfast_context->cache_fd) {
		if (0 == phttp->pfast_context->content_length) {
			goto END_OF_STDIN;
		}
		tmp_len = sizeof(tmp_buff);
		while (pbuff = stream_getbuffer_for_reading(
			&phttp->stream_in, &tmp_len)) {
			if (tmp_len > phttp->pfast_context->content_length) {
				stream_backward_reading_ptr(&phttp->stream_in,
					tmp_len - phttp->pfast_context->content_length);
				tmp_len = phttp->pfast_context->content_length;
				phttp->pfast_context->content_length = 0;
			} else{
				phttp->pfast_context->content_length -= tmp_len;
			}
			ndr_push_init(&ndr_push, ndr_buff, sizeof(ndr_buff),
						NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
			if (NDR_ERR_SUCCESS != mod_fastcgi_push_stdin(
				&ndr_push, pbuff, tmp_len)) {
				close(cli_sockd);
				http_parser_log_info(phttp, 8, "fail to "
					"push stdin record for mod_fastcgi");
				return FALSE;
			}
			if (ndr_push.offset != write(cli_sockd,
				ndr_buff, ndr_push.offset)) {
				close(cli_sockd);
				http_parser_log_info(phttp, 8, "fail to "
					"write record to fastcgi back-end %s",
					phttp->pfast_context->pfnode->sock_path);
				return FALSE;
			}
			if (0 == phttp->pfast_context->content_length) {
				break;
			}
			tmp_len = sizeof(tmp_buff);
		}
	} else {
		lseek(phttp->pfast_context->cache_fd, 0, SEEK_SET);
		while (TRUE) {
			tmp_len = read(phttp->pfast_context->cache_fd,
				tmp_buff, sizeof(tmp_buff));
			if (tmp_len < 0) {
				close(cli_sockd);
				http_parser_log_info(phttp, 8, "fail to"
					" read cache file for mod_fastcgi");
				return FALSE;
			} else if (0 == tmp_len) {
				close(phttp->pfast_context->cache_fd);
				phttp->pfast_context->cache_fd = -1;
				context_id = phttp - http_parser_get_contexts_list();
				sprintf(tmp_path, "/tmp/http-%d", context_id);
				remove(tmp_path);
				break;
			}
			ndr_push_init(&ndr_push, ndr_buff, sizeof(ndr_buff),
						NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
			if (NDR_ERR_SUCCESS != mod_fastcgi_push_stdin(
				&ndr_push, tmp_buff, tmp_len)) {
				close(cli_sockd);
				http_parser_log_info(phttp, 8, "fail to "
					"push stdin record for mod_fastcgi");
				return FALSE;
			}
			if (ndr_push.offset != write(cli_sockd,
				ndr_buff, ndr_push.offset)) {
				close(cli_sockd);
				http_parser_log_info(phttp, 8, "fail to "
					"write record to fastcgi back-end %s",
					phttp->pfast_context->pfnode->sock_path);
				return FALSE;
			}
		}
	}
END_OF_STDIN:
	ndr_push_init(&ndr_push, ndr_buff, sizeof(ndr_buff),
				NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
	if (NDR_ERR_SUCCESS != mod_fastcgi_push_stdin(
		&ndr_push, NULL, 0)) {
		close(cli_sockd);
		http_parser_log_info(phttp, 8, "fail to push "
			"last empty stdin record for mod_fastcgi");
		return FALSE;
	}
	if (ndr_push.offset != write(cli_sockd,
		ndr_buff, ndr_push.offset)) {
		close(cli_sockd);
		http_parser_log_info(phttp, 8, "fail to write"
			" last empty stdin to fastcgi back-end %s",
			phttp->pfast_context->pfnode->sock_path);
		return FALSE;
	}
	phttp->pfast_context->cli_sockd = cli_sockd;
	return TRUE;
}

void mod_fastcgi_put_context(HTTP_CONTEXT *phttp)
{
	int context_id;
	char tmp_path[256];
	
	if (-1 != phttp->pfast_context->cache_fd) {
		close(phttp->pfast_context->cache_fd);
		context_id = phttp - http_parser_get_contexts_list();
		sprintf(tmp_path, "/tmp/http-%d", context_id);
		remove(tmp_path);
	}
	if (-1 != phttp->pfast_context->cli_sockd) {
		close(phttp->pfast_context->cli_sockd);
	}
	phttp->pfast_context = NULL;
}

BOOL mod_fastcgi_write_request(HTTP_CONTEXT *phttp)
{
	int size;
	int tmp_len;
	char *pbuff;
	char *ptoken;
	char tmp_buff[1024];
	
	if (TRUE == phttp->pfast_context->b_end) {
		return TRUE;
	}
	if (-1 == phttp->pfast_context->cache_fd) {
		if (phttp->pfast_context->content_length <=
			stream_get_total_length(&phttp->stream_in)) {
			phttp->pfast_context->b_end = TRUE;	
		}
		return TRUE;
	}
	if (FALSE == phttp->pfast_context->b_chunked) {
		if (phttp->pfast_context->cache_size +
			stream_get_total_length(&phttp->stream_in) <
			phttp->pfast_context->content_length &&
			stream_get_total_length(&phttp->stream_in) <
			g_cache_size) {
			return TRUE;	
		}
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = stream_getbuffer_for_reading(
			&phttp->stream_in, &size))) {
			if (phttp->pfast_context->cache_size + size >
				phttp->pfast_context->content_length) {
				tmp_len = phttp->pfast_context->content_length
							- phttp->pfast_context->cache_size;
				stream_backward_reading_ptr(
					&phttp->stream_in, size - tmp_len);
				phttp->pfast_context->cache_size =
					phttp->pfast_context->content_length;
			} else {
				phttp->pfast_context->cache_size += size;
				tmp_len = size;
			}
			if (tmp_len != write(phttp->pfast_context->cache_fd,
				pbuff, tmp_len)) {
				http_parser_log_info(phttp, 8, "fail to"
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
			size = stream_peek_buffer(&phttp->stream_in,
										tmp_buff, 1024);
			if (size < 5) {
				return TRUE;
			}
			if (0 == strncmp("0\r\n\r\n", tmp_buff, 5)) {
				stream_forward_reading_ptr(&phttp->stream_in, 5);
				phttp->pfast_context->b_end = TRUE;
				return TRUE;
			}
			ptoken = memmem(tmp_buff, size, "\r\n", 2);
			if (NULL == ptoken) {
				if (1024 == size) {
					http_parser_log_info(phttp, 8, "fail to "
						"parse chunked block for mod_fastcgi");
					return FALSE;
				}
				return TRUE;
			}
			*ptoken = '\0';
			phttp->pfast_context->chunk_size =
					strtol(tmp_buff, NULL, 16);
			if (0 == phttp->pfast_context->chunk_size) {
				http_parser_log_info(phttp, 8, "fail to "
					"parse chunked block for mod_fastcgi");
				return FALSE;
			}
			phttp->pfast_context->chunk_offset = 0;
			tmp_len = ptoken + 2 - tmp_buff;
			stream_forward_reading_ptr(
				&phttp->stream_in, tmp_len);
		}
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = stream_getbuffer_for_reading(
			&phttp->stream_in, &size))) {
			if (phttp->pfast_context->chunk_size >=
				size + phttp->pfast_context->chunk_offset) {
				if (size != write(phttp->pfast_context->cache_fd,
					pbuff, size)) {
					http_parser_log_info(phttp, 8, "fail to"
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
					http_parser_log_info(phttp, 8, "fail to"
						" write cache file for mod_fastcgi");
					return FALSE;
				}
				stream_backward_reading_ptr(
					&phttp->stream_in, size - tmp_len);
				phttp->pfast_context->cache_size += tmp_len;
				phttp->pfast_context->chunk_offset =
					phttp->pfast_context->chunk_size;
			}
			if (phttp->pfast_context->cache_size > g_max_size) {
				http_parser_log_info(phttp, 8, "chunked content"
						" length is too long for mod_fastcgi");
				return FALSE;
			}
			if (phttp->pfast_context->chunk_offset
				== phttp->pfast_context->chunk_size) {
				goto CHUNK_BEGIN;	
			}
		}
	}
	stream_clear(&phttp->stream_in);
	return TRUE;
}

static BOOL mod_fastcgi_safe_read(FASTCGI_CONTEXT *pfast_context,
	uint8_t *pbuff, int length)
{
	int offset;
	int tv_msec;
	int read_len;
	struct pollfd pfd_read;
	
	offset = 0;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pfast_context->cli_sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return FALSE;
		}
		read_len = read(pfast_context->cli_sockd,
				pbuff + offset, length - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (length == offset) {
			time(&pfast_context->last_time);
			return TRUE;
		}
	}
}

int mod_fastcgi_check_response(HTTP_CONTEXT *phttp)
{
	int tv_msec;
	int context_num;
	struct pollfd pfd_read;
	
	context_num = contexts_pool_get_param(CUR_SCHEDUING_CONTEXTS)
				+ threads_pool_get_param(THREADS_POOL_CUR_THR_NUM);
	tv_msec = POLL_MILLISECONDS_FOR_CHECK *
			(g_unavailable_times / context_num);
	if (tv_msec > 999) {
		tv_msec = 999;
	}
	pfd_read.fd = phttp->pfast_context->cli_sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (1 == poll(&pfd_read, 1, tv_msec)) {
		g_unavailable_times = 0;
		return RESPONSE_AVAILABLE;
	}
	g_unavailable_times ++;
	if (time(NULL) - phttp->pfast_context->last_time > g_exec_timeout) {
		return RESPONSE_TIMEOUT;
	}
	return RESPONSE_WAITING;
}

BOOL mod_fastcgi_read_response(HTTP_CONTEXT *phttp)
{
	char *pbuff;
	int tmp_len;
	uint8_t *pbody;
	time_t cur_time;
	uint8_t *ptoken;
	uint8_t *ptoken1;
	struct tm tmp_tm;
	NDR_PULL ndr_pull;
	char dstring[128];
	RECORD_HEADER header;
	uint8_t header_buff[8];
	uint8_t tmp_buff[80000];
	uint32_t response_offset;
	FCGI_STDSTREAM std_stream;
	uint8_t status_line[1024];
	uint8_t response_buff[65536];
	FCGI_ENDREQUESTBODY end_request;
	
	if (TRUE == phttp->pfast_context->b_header &&
		0 == strcasecmp(phttp->request.method, "HEAD")) {
		mod_fastcgi_put_context(phttp);
		return FALSE;	
	}
	response_offset = 0;
	while (TRUE) {
		if (FALSE == mod_fastcgi_safe_read(
			phttp->pfast_context, header_buff, 8)) {
			http_parser_log_info(phttp, 8, "fail to read"
				" record header from fastcgi back-end %s",
				phttp->pfast_context->pfnode->sock_path);
			mod_fastcgi_put_context(phttp);
			return FALSE;	
		}
		ndr_pull_init(&ndr_pull, header_buff, 8,
			NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
		if (NDR_ERR_SUCCESS != mod_fastcgi_pull_record_header(
			&ndr_pull, &header)) {
			http_parser_log_info(phttp, 8, "fail to "
				"pull record header in mod_fastcgi");
			mod_fastcgi_put_context(phttp);
			return FALSE;
		}
		switch (header.type) {
		case RECORD_TYPE_END_REQUEST:
			if (8 != header.content_len) {
				http_parser_log_info(phttp, 8, "record header"
					" format error from fastcgi back-end %s",
					phttp->pfast_context->pfnode->sock_path);
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			tmp_len = header.padding_len + 8;
			if (FALSE == mod_fastcgi_safe_read(
				phttp->pfast_context, tmp_buff,
				tmp_len)) {
				http_parser_log_info(phttp, 8, "fail to read"
				" record header from fastcgi back-end %s",
				phttp->pfast_context->pfnode->sock_path);
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			ndr_pull_init(&ndr_pull, tmp_buff, tmp_len,
				NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
			if (NDR_ERR_SUCCESS != mod_fastcgi_pull_end_request(
				&ndr_pull, header.padding_len, &end_request)) {
				http_parser_log_info(phttp, 8, "fail to"
					" pull record body in mod_fastcgi");
			} else {
				http_parser_log_info(phttp, 8, "app_status %u, "
						"protocol_status %d from fastcgi back-end"
						" %s", end_request.app_status,
						(int)end_request.protocol_status,
						phttp->pfast_context->pfnode->sock_path);
			}
			if (TRUE == phttp->pfast_context->b_header &&
				TRUE == phttp->pfast_context->b_chunked) {
				stream_write(&phttp->stream_out, "0\r\n\r\n", 5);
			}
			mod_fastcgi_put_context(phttp);
			return FALSE;
		case RECORD_TYPE_STDOUT:
		case RECORD_TYPE_STDERR:
			tmp_len = header.content_len + header.padding_len;
			if (FALSE == mod_fastcgi_safe_read(
				phttp->pfast_context, tmp_buff,
				tmp_len)) {
				http_parser_log_info(phttp, 8, "fail to read"
					" record header from fastcgi back-end %s",
					phttp->pfast_context->pfnode->sock_path);
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			ndr_pull_init(&ndr_pull, tmp_buff, tmp_len,
					NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
			std_stream.length = header.content_len;
			if (NDR_ERR_SUCCESS != mod_fastcgi_pull_stdstream(
				&ndr_pull, header.padding_len, &std_stream)) {
				http_parser_log_info(phttp, 8, "fail to"
					" pull record body in mod_fastcgi");
				mod_fastcgi_put_context(phttp);
				return FALSE;	
			}
			if (RECORD_TYPE_STDERR == header.type) {
				memcpy(tmp_buff, std_stream.buffer, std_stream.length);
				tmp_buff[std_stream.length] = '\0';
				http_parser_log_info(phttp, 8, "stderr message "
					"\"%s\" from fastcgi back-end %s", tmp_buff,
					phttp->pfast_context->pfnode->sock_path);
				continue;
			}
			if (TRUE == phttp->pfast_context->b_header) {
				if (0 == std_stream.length) {
					http_parser_log_info(phttp, 8, "empty stdout "
						"record is not supported by mod_fastcgi");
					mod_fastcgi_put_context(phttp);
					return FALSE;
				}
				if (TRUE == phttp->pfast_context->b_chunked) {
					tmp_len = sprintf(tmp_buff, "%x\r\n", std_stream.length);
					if (STREAM_WRITE_OK != stream_write(
						&phttp->stream_out, tmp_buff, tmp_len) ||
						STREAM_WRITE_OK != stream_write(
						&phttp->stream_out, std_stream.buffer,
						std_stream.length) ||
						STREAM_WRITE_OK != stream_write(
						&phttp->stream_out, "\r\n", 2)) {
						http_parser_log_info(phttp, 8, "fail to write"
								" stdin into stream in mod_fastcgi");
						mod_fastcgi_put_context(phttp);
						return FALSE;
					}
				} else {
					if (STREAM_WRITE_OK != stream_write(
						&phttp->stream_out, std_stream.buffer,
						std_stream.length)) {
						http_parser_log_info(phttp, 8, "fail to write"
								" stdin into stream in mod_fastcgi");
						mod_fastcgi_put_context(phttp);
						return FALSE;
					}
				}
				return TRUE;
			}
			if (response_offset + std_stream.length > sizeof(response_buff)) {
				http_parser_log_info(phttp, 8, "response "
					"header too long from fastcgi back-end %s",
					phttp->pfast_context->pfnode->sock_path);
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			memcpy(response_buff + response_offset,
				std_stream.buffer, std_stream.length);
			response_offset += std_stream.length;
			pbody = memmem(response_buff,
				response_offset, "\r\n\r\n", 4);
			if (NULL == pbody) {
				continue;
			}
			if (0 == strncasecmp(response_buff, "Status:", 7)) {
				ptoken = response_buff + 7;
			} else {
				ptoken = search_string(response_buff,
					"\r\nStatus:", response_offset);
				if (NULL != ptoken) {
					ptoken += 9;
				}
			}
			if (NULL == ptoken) {
				strcpy(status_line, "200 Success");
			} else {
				tmp_len = response_offset - (ptoken - response_buff);
				ptoken1 = memmem(ptoken, tmp_len, "\r\n", 2);
				if (NULL == ptoken1 || (tmp_len = ptoken1
					- ptoken) >= sizeof(status_line)) {
					http_parser_log_info(phttp, 8, "response header"
						"format error from fastcgi back-end %s",
						phttp->pfast_context->pfnode->sock_path);
					mod_fastcgi_put_context(phttp);
					return FALSE;
				}
				memcpy(status_line, ptoken, tmp_len);
				status_line[tmp_len] = '\0';
				ltrim_string(status_line);
			}
			pbody[2] = '\0';
			pbody += 4;
			/* Content-Length */
			if (0 == strncasecmp(response_buff, "Content-Length:", 15) ||
				NULL != strcasestr(response_buff, "\r\nContent-Length:")) {
				phttp->pfast_context->b_chunked = FALSE;
			} else {
				phttp->pfast_context->b_chunked = TRUE;
			}
			time(&cur_time);
			gmtime_r(&cur_time, &tmp_tm);
			strftime(dstring, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
			if (0 == strcasecmp(phttp->request.method, "HEAD")) {
				tmp_len = snprintf(tmp_buff, sizeof(tmp_buff),
								"HTTP/1.1 %s\r\n"
								"Server: %s\r\n"
								"Date: %s\r\n"
								"%s\r\n", status_line,
								resource_get_string(RES_HOST_ID),
								dstring, response_buff);
			} else {
				if (TRUE == phttp->pfast_context->b_chunked) {
					tmp_len = snprintf(tmp_buff, sizeof(tmp_buff),
								"HTTP/1.1 %s\r\n"
								"Server: %s\r\n"
								"Date: %s\r\n"
								"Transfer-Encoding: chunked\r\n"
								"%s\r\n", status_line,
								resource_get_string(RES_HOST_ID),
								dstring, response_buff);
				} else {
					tmp_len = snprintf(tmp_buff, sizeof(tmp_buff),
								"HTTP/1.1 %s\r\n"
								"Server: %s\r\n"
								"Date: %s\r\n"
								"%s\r\n", status_line,
								resource_get_string(RES_HOST_ID),
								dstring, response_buff);
				}
			}
			if (STREAM_WRITE_OK != stream_write(
				&phttp->stream_out, tmp_buff, tmp_len)) {
				http_parser_log_info(phttp, 8, "fail to write "
					"response header into stream in mod_fastcgi");
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			phttp->pfast_context->b_header = TRUE;
			if (0 == strcasecmp(phttp->request.method, "HEAD")) {
				return TRUE;
			}
			response_offset = response_buff + response_offset - pbody;
			if (response_offset > 0) {
				if (TRUE == phttp->pfast_context->b_chunked) {
					tmp_len = sprintf(tmp_buff, "%x\r\n", response_offset);
					if (STREAM_WRITE_OK != stream_write(
						&phttp->stream_out, tmp_buff, tmp_len) ||
						STREAM_WRITE_OK != stream_write(
						&phttp->stream_out, pbody, response_offset) ||
						STREAM_WRITE_OK != stream_write(
						&phttp->stream_out, "\r\n", 2)) {
						http_parser_log_info(phttp, 8, "fail to write"
								" stdin into stream in mod_fastcgi");
						mod_fastcgi_put_context(phttp);
						return FALSE;
					}
				} else {
					if (STREAM_WRITE_OK != stream_write(
						&phttp->stream_out, pbody, response_offset)) {
						http_parser_log_info(phttp, 8, "fail to write"
								" stdin into stream in mod_fastcgi");
						mod_fastcgi_put_context(phttp);
						return FALSE;	
					}
				}
			}
			return TRUE;
		default:
			tmp_len = header.content_len + header.padding_len;
			if (FALSE == mod_fastcgi_safe_read(
				phttp->pfast_context, tmp_buff,
				tmp_len)) {
				http_parser_log_info(phttp, 8, "fail to read"
				" record header from fastcgi back-end %s",
				phttp->pfast_context->pfnode->sock_path);
				mod_fastcgi_put_context(phttp);
				return FALSE;
			}
			http_parser_log_info(phttp, 8, "ignore record %d"
				" from fastcgi back-end %s", (int)header.type,
				phttp->pfast_context->pfnode->sock_path);
			continue;
		}
	}
}
