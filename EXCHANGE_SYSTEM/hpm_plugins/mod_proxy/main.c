#include "double_list.h"
#include "hpm_common.h"
#include "list_file.h"
#include "mail_func.h"
#include "util.h"
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <time.h>

#define SOCKET_TIMEOUT							180

typedef struct _PROXY_NODE {
	DOUBLE_LIST_NODE node;
	char *domain;
	char *path;
	BOOL remote_ipaddr;
	char *remote_host;
	int remote_port;
	char *remote_path;
} PROXY_NODE;

typedef struct _PROXY_CONTEXT {
	PROXY_NODE *pxnode;
	int sockd;
	time_t last_time;
} PROXY_CONTEXT;

DECLARE_API;

static DOUBLE_LIST g_proxy_list;
static PROXY_CONTEXT *g_context_list;

static BOOL proxy_preproc(int context_id);

static BOOL proxy_proc(int context_id,
	const void *pcontent, uint64_t length);

static int proxy_retr(int context_id);

static void proxy_term(int context_id);


BOOL HPM_LibMain(int reason, void **ppdata)
{
	int i;
	char *pitem;
	int tmp_len;
	int item_num;
	char *ptoken;
	char *ptoken1;
	char tmp_ip[16];
	int context_num;
	LIST_FILE *pfile;
	PROXY_NODE *pxnode;
	char list_path[256];
	DOUBLE_LIST_NODE *pnode;
	HPM_INTERFACE interface;
	
	switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		double_list_init(&g_proxy_list);
		sprintf(list_path, "%s/proxy.txt", get_data_path());
		pfile = list_file_init(list_path, "%s:256%s:256%s:256");
		if (NULL == pfile) {
			printf("[mod_proxy]: fail to init list file\n");
			return FALSE;
		}
		item_num = list_file_get_item_num(pfile);
		pitem = list_file_get_list(pfile);
		for (i=0; i<item_num; i++) {
			pxnode = malloc(sizeof(PROXY_NODE));
			if (NULL == pxnode) {
				continue;
			}
			memset(pxnode, 0, sizeof(PROXY_NODE));
			pxnode->node.pdata = pxnode;
			pxnode->domain = strdup(pitem + 768*i);
			if (NULL == pxnode->domain) {
				break;
			}
			pxnode->path = strdup(pitem + 768*i + 256);
			if (NULL == pxnode->path) {
				break;
			}
			tmp_len = strlen(pxnode->path);
			if ('/' == pxnode->path[tmp_len - 1]) {
				pxnode->path[tmp_len - 1] = '\0';
			}
			if (0 == strncasecmp(pitem + 768*i + 512, "http://", 7)) {
				ptoken1 = pitem + 768*i + 512 + 7;
			} else {
				print("[mod_proxy]: scheme of destination in '%s' "
					"error, can only be http\n", pitem + 768*i + 512);
				break;
			}
			ptoken = strchr(ptoken1, '/');
			if (NULL == ptoken) {
				ptoken = ptoken1 + strlen(ptoken1);
			}
			tmp_len = ptoken - ptoken1;
			pxnode->remote_host = malloc(tmp_len + 1);
			if (NULL == pxnode->remote_host) {
				break;
			}
			memcpy(pxnode->remote_host, ptoken1, tmp_len);
			pxnode->remote_host[tmp_len] = '\0';
			if ('\0' == ptoken[0] || '\0' == ptoken[1]) {
				pxnode->remote_path = NULL;
			} else {
				ptoken ++;
				tmp_len = strlen(ptoken);
				if ('/' == ptoken[tmp_len - 1]) {
					tmp_len --;
				}
				if (0 == tmp_len) {
					pxnode->remote_path = NULL;
				} else {
					pxnode->remote_path = malloc(tmp_len + 1);
					if (NULL == pxnode->remote_path) {
						break;
					}
					memcpy(pxnode->remote_path, ptoken, tmp_len);
					pxnode->remote_path[tmp_len] = '\0';
				}
			}
			ptoken = strchr(pxnode->remote_host, ':');
			if (NULL == ptoken) {
				pxnode->remote_port = 80;
			} else {
				*ptoken = '\0';
				pxnode->remote_port = atoi(ptoken + 1);
				if (pxnode->remote_port <= 0) {
					print("[mod_proxy]: port number of "
						"destination in '%s' error", ptoken1);
					break;
				}
			}
			if (NULL != extract_ip(pxnode->remote_host, tmp_ip)
				&& 0 == strcmp(tmp_ip, pxnode->remote_host)) {
				pxnode->remote_ipaddr = TRUE;
			} else {
				pxnode->remote_ipaddr = FALSE;
			}
			double_list_append_as_tail(&g_proxy_list, &pxnode->node);
		}
		list_file_free(pfile);
		if (i < item_num) {
			if (NULL != pxnode->domain) {
				free(pxnode->domain);
			}
			if (NULL != pxnode->path) {
				free(pxnode->path);
			}
			if (NULL != pxnode->remote_host) {
				free(pxnode->remote_host);
			}
			if (NULL != pxnode->remote_path) {
				free(pxnode->remote_path);
			}
			free(pxnode);
			return FALSE;
		}
		context_num = get_context_num();
		g_context_list = malloc(sizeof(PROXY_CONTEXT)*context_num);
		if (NULL == g_context_list) {
			return FALSE;
		}
		memset(g_context_list, 0, sizeof(PROXY_CONTEXT)*context_num);
		for (i=0; i<context_num; i++) {
			g_context_list[i].sockd = -1;
		}
		interface.preproc = proxy_preproc;
		interface.proc = proxy_proc;
		interface.retr = proxy_retr;
		interface.term = proxy_term;
		if (FALSE == register_interface(&interface)) {
			return FALSE;
		}
		printf("[mod_proxy]: plugin is loaded into system\n");
		return TRUE;
	case PLUGIN_FREE:
		if (NULL != g_context_list) {
			context_num = get_context_num();
			for (i=0; i<context_num; i++) {
				if (-1 != g_context_list[i].sockd) {
					close(g_context_list[i].sockd);
				}
			}
			free(g_context_list);
			g_context_list = NULL;
		}
		while (pnode=double_list_get_from_head(&g_proxy_list)) {
			pxnode = (PROXY_NODE*)pnode->pdata;
			free(pxnode->domain);
			free(pxnode->path);
			free(pxnode->remote_host);
			if (NULL != pxnode->remote_path) {
				free(pxnode->remote_path);
			}
			free(pxnode);
		}
		double_list_free(&g_proxy_list);
		return TRUE;
	}
}

static PROXY_NODE* find_proxy_node(
	const char *domain, const char *uri_path)
{
	int tmp_len;
	int path_len;
	PROXY_NODE *pxnode;
	DOUBLE_LIST_NODE *pnode;

	path_len = strlen(uri_path);
	for (pnode=double_list_get_head(&g_proxy_list); NULL!=pnode;
		pnode=double_list_get_after(&g_proxy_list, pnode)) {
		pxnode = (PROXY_NODE*)pnode->pdata;
		if (0 == wildcard_match(domain, pxnode->domain, TRUE)) {
			continue;
		}
		tmp_len = strlen(pxnode->path);
		if (0 != strncasecmp(uri_path, pxnode->path,
			tmp_len) || ('/' != uri_path[tmp_len] &&
			'\0' != uri_path[tmp_len])) {
			continue;
		}
		return pxnode;
	}
	return NULL;
}

static BOOL proxy_preproc(int context_id)
{
	int tmp_len;
	char *ptoken;
	char domain[256];
	PROXY_NODE *pxnode;
	char tmp_buff[8192];
	char request_uri[8192];
	HTTP_REQUEST *prequest;
	CONNECTION *pconnection;
	
	prequest = get_request(context_id);
	tmp_len = mem_file_get_total_length(&prequest->f_host);
	if (tmp_len >= sizeof(domain)) {
		return FALSE;
	}
	if (0 == tmp_len) {
		pconnection = get_connection(context_id);
		strcpy(domain, pconnection->server_ip);
	} else {
		mem_file_seek(&prequest->f_host,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&prequest->f_host, domain, tmp_len);
		domain[tmp_len] = '\0';
	}
	ptoken = strchr(domain, ':');
	if (NULL != ptoken) {
		*ptoken = '\0';
	}
	if (MEM_END_OF_FILE == (tmp_len = mem_file_read(
		&prequest->f_request_uri, tmp_buff, sizeof(tmp_buff)))) {
		return FALSE;	
	}
	tmp_buff[tmp_len] = '\0';
	if (FALSE == parse_uri(tmp_buff, request_uri)) {
		return FALSE;
	}
	ptoken = strrchr(request_uri, '/');
	if (NULL != ptoken) {
		*ptoken = '\0';
	}
	pxnode = find_proxy_node(domain, request_uri);
	if (NULL == pxnode) {
		return FALSE;
	}
	mem_file_clear(&prequest->f_request_uri);
	tmp_len = strlen(pxnode->path);
	if (NULL == ptoken) {
		if (NULL == pxnode->remote_path) {
			tmp_buff[0] = '/';
			tmp_len = 1;
		} else {
			tmp_len = sprintf(tmp_buff, "/%s/", pxnode->remote_path);
		}
	} else {
		if ('\0' == request_uri[tmp_len]) {
			if (NULL == pxnode->remote_path) {
				tmp_len = sprintf(tmp_buff, "/%s", ptoken + 1);
			} else {
				tmp_len = sprintf(tmp_buff, "/%s/%s",
					pxnode->remote_path, ptoken + 1);
			}
		} else {
			if (NULL == pxnode->remote_path) {
				tmp_len = sprintf(tmp_buff, "/%s/%s",
					request_uri + tmp_len + 1, ptoken + 1);
			} else {
				tmp_len = sprintf(tmp_buff,
					"/%s/%s/%s", pxnode->remote_path,
					request_uri + tmp_len + 1, ptoken + 1);
			}
		}
	}
	mem_file_write(&prequest->f_request_uri, tmp_buff, tmp_len);
	g_context_list[context_id].pxnode = pxnode;
	return TRUE;
}

static int read_header(PROXY_CONTEXT *pcontext,
	uint8_t *pbuff, int length)
{
	int offset;
	int tv_msec;
	int read_len;
	struct pollfd pfd_read;
	
	offset = 0;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pcontext->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return 0;
		}
		read_len = read(pcontext->sockd,
			pbuff + offset, length - offset);
		if (read_len <= 0) {
			return 0;
		}
		offset += read_len;
		if (NULL != memmem(pbuff, offset, "\r\n\r\n", 4)) {
			time(&pcontext->last_time);
			return offset;
		}
		if (offset == length) {
			return 0;
		}
	}
}

static BOOL proxy_proc(int context_id,
	const void *pcontent, uint64_t length)
{
	int ret;
	int offset;
	int tmp_len;
	char *ptoken;
	char *ptoken1;
	char **p_addr;
	BOOL b_connection;
	char tmp_tag[256];
	char tmp_uri[8192];
	BOOL b_forward_for;
	char tmp_host[256];
	int tag_len, val_len;
	HTTP_REQUEST *prequest;
	char tmp_buff[64*1024];
	struct in_addr ip_addr;
	char destination_ip[16];
	PROXY_CONTEXT *pcontext;
	CONNECTION *pconnection;
	struct sockaddr_in servaddr;
	struct hostent hostinfo, *phost;
	
	pconnection = get_connection(context_id);
	prequest = get_request(context_id);
	pcontext = &g_context_list[context_id];
	if (TRUE == pcontext->pxnode->remote_ipaddr) {
		strcpy(destination_ip, pcontext->pxnode->remote_host);
	} else {
		if (0 != gethostbyname_r(pcontext->pxnode->remote_host,
			&hostinfo, tmp_buff, 4096, &phost, &ret) ||
			NULL == phost) {
            return FALSE;
        }
		p_addr = phost->h_addr_list;
		ip_addr.s_addr = *((unsigned int *)*p_addr);
		strcpy(destination_ip, inet_ntoa(ip_addr));
	}
	pcontext->sockd = socket(AF_INET, SOCK_STREAM, 0);
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(pcontext->pxnode->remote_port);
	inet_pton(AF_INET, destination_ip, &servaddr.sin_addr);
	if (0 != connect(pcontext->sockd,
		(struct sockaddr*)&servaddr,
		sizeof(servaddr))) {
		close(pcontext->sockd);
		pcontext->sockd = -1;
		return FALSE;
	}
	offset = strlen(prequest->method);
	memcpy(tmp_buff, prequest->method, offset);
	tmp_buff[offset] = ' ';
	offset ++;
	offset += mem_file_read(&prequest->f_request_uri,
		tmp_buff + offset, sizeof(tmp_buff) - offset);
	offset += sprintf(tmp_buff + offset,
		" HTTP/%s\r\n", prequest->version);
	if (0 != mem_file_get_total_length(&prequest->f_host)) {
		tmp_len = mem_file_read(&prequest->f_host,
					tmp_host, sizeof(tmp_host) - 1);
		tmp_host[tmp_len] = '\0';
		offset += sprintf(tmp_buff + offset, "Host: %s\r\n", tmp_host);
		if (offset >= sizeof(tmp_buff)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
	}
	offset += sprintf(tmp_buff + offset,
		"Content-Length: %llu\r\n", length);
	if (offset >= sizeof(tmp_buff)) {
		close(pcontext->sockd);
		pcontext->sockd = -1;
		return FALSE;
	}
	offset += sprintf(tmp_buff + offset,
		"X-Real-IP: %s\r\n", pconnection->client_ip);
	if (NULL == pconnection->ssl) {
		offset += sprintf(tmp_buff + offset,
			"X-Forwarded-Proto: http\r\n");
	} else {
		offset += sprintf(tmp_buff + offset,
			"X-Forwarded-Proto: https\r\n");
	}
	if (0 != mem_file_get_total_length(&prequest->f_user_agent)) {
		memcpy(tmp_buff + offset, "User-Agent: ", 12);
		offset += 12;
		offset += mem_file_read(&prequest->f_user_agent,
			tmp_buff + offset, sizeof(tmp_buff) - offset);
		if (offset >= sizeof(tmp_buff)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		memcpy(tmp_buff + offset, "\r\n", 2);
		offset += 2;
	}
	if (0 != mem_file_get_total_length(&prequest->f_accept)) {
		memcpy(tmp_buff + offset, "Accept: ", 8);
		offset += 8;
		offset += mem_file_read(&prequest->f_accept,
			tmp_buff + offset, sizeof(tmp_buff) - offset);
		if (offset >= sizeof(tmp_buff)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		memcpy(tmp_buff + offset, "\r\n", 2);
		offset += 2;
	}
	if (0 != mem_file_get_total_length(&prequest->f_accept_language)) {
		memcpy(tmp_buff + offset, "Accept-Language: ", 17);
		offset += 17;
		offset += mem_file_read(&prequest->f_accept_language,
			tmp_buff + offset, sizeof(tmp_buff) - offset);
		if (offset >= sizeof(tmp_buff)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		memcpy(tmp_buff + offset, "\r\n", 2);
		offset += 2;
	}
	if (0 != mem_file_get_total_length(&prequest->f_accept_encoding)) {
		memcpy(tmp_buff + offset, "Accept-Encoding: ", 17);
		offset += 17;
		offset += mem_file_read(&prequest->f_accept_encoding,
			tmp_buff + offset, sizeof(tmp_buff) - offset);
		if (offset >= sizeof(tmp_buff)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		memcpy(tmp_buff + offset, "\r\n", 2);
		offset += 2;
	}
	if (0 != mem_file_get_total_length(&prequest->f_content_type)) {
		memcpy(tmp_buff + offset, "Content-Type: ", 14);
		offset += 14;
		offset += mem_file_read(&prequest->f_content_type,
			tmp_buff + offset, sizeof(tmp_buff) - offset);
		if (offset >= sizeof(tmp_buff)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		memcpy(tmp_buff + offset, "\r\n", 2);
		offset += 2;
	}
	if (0 != mem_file_get_total_length(&prequest->f_cookie)) {
		memcpy(tmp_buff + offset, "Cookie: ", 8);
		offset += 8;
		offset += mem_file_read(&prequest->f_cookie,
			tmp_buff + offset, sizeof(tmp_buff) - offset);
		if (offset >= sizeof(tmp_buff)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		memcpy(tmp_buff + offset, "\r\n", 2);
		offset += 2;
	}
	b_forward_for = FALSE;
	b_connection = FALSE;
	while (MEM_END_OF_FILE != mem_file_read(
		&prequest->f_others, &tag_len, sizeof(int))) {
		if (tag_len >= sizeof(tmp_tag)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		mem_file_read(&prequest->f_others, tmp_tag, tag_len);
		tmp_tag[tag_len] = '\0';
		if (0 == strcasecmp(tmp_tag, "X-Forwarded-Proto") ||
			0 == strcasecmp(tmp_tag, "X-Real-IP")) {
			mem_file_read(&prequest->f_others, &val_len, sizeof(int));
			mem_file_seek(&prequest->f_others, MEM_FILE_READ_PTR,
									val_len, MEM_FILE_SEEK_CUR);
			continue;
		}
		offset += sprintf(tmp_buff + offset, "%s: ", tmp_tag);
		if (offset >= sizeof(tmp_buff)) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		mem_file_read(&prequest->f_others, &val_len, sizeof(int));
		if (val_len >= sizeof(tmp_buff) - offset) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return FALSE;
		}
		mem_file_read(&prequest->f_others, tmp_buff + offset, val_len);
		if (0 == strcasecmp("Connection", tmp_tag)) {
			b_connection = TRUE;
			if (7 != val_len || 0 != strncasecmp(
				"Upgrade", tmp_buff + offset, 7)) {
				memcpy(tmp_buff + offset, "Close\r\n", 7);
				offset += 7;
				continue;
			}
		}
		offset += val_len;
		if (0 == strcasecmp("X-Forwarded-For", tmp_tag)) {
			offset += sprintf(tmp_buff + offset,
				", %s", pconnection->server_ip);
			b_forward_for = TRUE;
		}
		memcpy(tmp_buff + offset, "\r\n", 2);
		offset += 2;
	}
	if (FALSE == b_connection) {
		offset += sprintf(tmp_buff + offset, "Connection: close\r\n");
	}
	if (FALSE == b_forward_for) {
		offset += sprintf(tmp_buff + offset,
					"X-Forwarded-For: %s\r\n",
					pconnection->server_ip);
	}
	
	memcpy(tmp_buff + offset, "\r\n", 2);
	offset += 2;
	if (offset != write(pcontext->sockd, tmp_buff, offset)
		|| (length > 0 && length != write(pcontext->sockd,
		pcontent, length))) {
		close(pcontext->sockd);
		pcontext->sockd = -1;
		return FALSE;
	}
	time(&pcontext->last_time);
	offset = read_header(pcontext, tmp_buff, sizeof(tmp_buff));
	if (0 == offset) {
		close(pcontext->sockd);
		pcontext->sockd = -1;
		return FALSE;
	}
	ptoken = memchr(tmp_buff, ' ', offset);
	if (NULL == ptoken || ' ' != ptoken[4]) {
		close(pcontext->sockd);
		pcontext->sockd = -1;
		return FALSE;
	}
	ptoken ++;
	if (0 == strncmp(ptoken, "301", 3) ||
		0 == strncmp(ptoken, "302", 3) ||
		0 == strncmp(ptoken, "303", 3) ||
		0 == strncmp(ptoken, "304", 3) ||
		0 == strncmp(ptoken, "305", 3) ||
		0 == strncmp(ptoken, "307", 3)) {
		ptoken = search_string(tmp_buff, "\r\nLocation:", offset);
		if (NULL == ptoken) {
			write_response(context_id, tmp_buff, offset);
			return TRUE;
		}
		do {
			ptoken ++;
		} while (' ' == *ptoken);
		ptoken1 = memmem(ptoken, offset - (ptoken - tmp_buff), "\r\n", 2);
		if (NULL == ptoken1 || ptoken1 - ptoken >= sizeof(tmp_uri)) {
			write_response(context_id, tmp_buff, offset);
			return TRUE;
		}
		memcpy(tmp_uri, ptoken, ptoken1 - ptoken);
		tmp_uri[ptoken1 - ptoken] = '\0';
		//TODO replace redirect location with the revser proxy service
	}
	write_response(context_id, tmp_buff, offset);
	return TRUE;
}

static int proxy_retr(int context_id)
{
	int tv_msec;
	int read_len;
	char buff[64*1024];
	struct pollfd pfd_read;
	PROXY_CONTEXT *pcontext;
	
	pcontext = &g_context_list[context_id];
	if (-1 == pcontext->sockd) {
		return HPM_RETRIEVE_DONE;
	}
	tv_msec = 500;
	pfd_read.fd = pcontext->sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (1 != poll(&pfd_read, 1, tv_msec)) {
		if (time(NULL) - pcontext->last_time > SOCKET_TIMEOUT) {
			close(pcontext->sockd);
			pcontext->sockd = -1;
			return HPM_RETRIEVE_ERROR;
		}
		return HPM_RETRIEVE_NONE;
	}
	read_len = read(pcontext->sockd, buff, sizeof(buff));
	if (read_len <= 0) {
		close(pcontext->sockd);
		pcontext->sockd = -1;
		return HPM_RETRIEVE_DONE;
	}
	write_response(context_id, buff, read_len);
	return HPM_RETRIEVE_WRITE;
}

static void proxy_term(int context_id)
{
	if (-1 != g_context_list[context_id].sockd) {
		close(g_context_list[context_id].sockd);
		g_context_list[context_id].sockd = -1;
	}
}
