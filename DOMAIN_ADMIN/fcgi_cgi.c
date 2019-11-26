#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <sys/wait.h>
#include "double_list.h"
#include "config_file.h"
#include "ndr.h"
#include "util.h"
#include <pwd.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <sys/un.h>
#include <net/if.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#define SOCKET_TIMEOUT							180

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

typedef struct _CONNECTION {
	DOUBLE_LIST_NODE node;
	int sockd;
	int offset;
	int record_len;
	char buff[0x10010];
} CONNECTION;

typedef struct _BEGIN_REQUEST {
	uint16_t role;
	uint8_t flags;
	uint8_t reserved[5];
} BEGIN_REQUEST;

typedef struct _RECORD_PARAMS {
	uint8_t count;
	struct {
		DATA_BLOB name;
		DATA_BLOB value;
	} name_vals[0x100];
} RECORD_PARAMS;

typedef struct _END_REQUEST {
	uint32_t app_status;
	uint8_t protocol_status;
	uint8_t reserved[3];
} END_REQUEST;

typedef struct _FCGI_RECORD {
	uint8_t type;
	uint16_t request_id;
	uint8_t reserved;
	union {
		BEGIN_REQUEST begin;
		RECORD_PARAMS params;
		DATA_BLOB stdin;
	} val;
} FCGI_RECORD;

typedef struct _FCGI_CGI {
	pid_t pid;
	int pipe_in;
	int pipe_out;
	int pipe_err;
} FCGI_CGI;

static void* accept_work_func(void *param);

static void* thread_work_func(void *param);

static int g_notify_stop;
static BOOL g_convert_lf;
static DOUBLE_LIST g_conn_list;
static DOUBLE_LIST g_conn_list1;
static pthread_cond_t g_waken_cond;
static pthread_mutex_t g_conn_lock;
static pthread_mutex_t g_cond_mutex;

static void term_handler(int signo)
{
    g_notify_stop = 1;
}

int main(int argc, char **argv)
{
	int i, len;
	int listenfd;
	int thread_num;
	char *str_value;
	CONNECTION *pconn;
	char cs_path[256];
	char username[256];
	pthread_t accept_id;
	pthread_t *pthr_ids;
	CONFIG_FILE *pconfig;
	DOUBLE_LIST_NODE *pnode;
	struct passwd *puser_pass;
	struct sockaddr_un unix_addr;

	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return 1;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	pconfig = config_file_init(argv[1]);
	if (NULL == pconfig) {
		printf("[system]: fail to open config file %s\n", argv[1]);
		return 1;
	}
	str_value = config_file_get_value(pconfig, "FCGI_UNIX_PATH");
	if (NULL == str_value) {
		printf("[system]: fail to get FCGI_UNIX_PATH in config file");
		config_file_free(pconfig);
		return 2;
	}
	strncpy(cs_path, str_value, sizeof(cs_path));
	str_value = config_file_get_value(pconfig, "FCGI_THREAD_NUM");
	if (NULL == str_value) {
		thread_num = 20;
		config_file_set_value(pconfig, "FCGI_THREAD_NUM", "20");
	} else {
		thread_num = atoi(str_value);
		if (thread_num < 1) {
			thread_num = 20;
			config_file_set_value(pconfig, "FCGI_THREAD_NUM", "20");
		}
	}
	printf("[system]: thread number in pool is %d\n", thread_num);
	str_value = config_file_get_value(pconfig, "FCGI_CONVERT_LF");
	if (NULL == str_value || 0 != strcasecmp(str_value, "TRUE")) {
		g_convert_lf = FALSE;
	} else {
		g_convert_lf = TRUE;
		printf("[system]: lf will be converted to crlf\n");
	}
	str_value = config_file_get_value(pconfig, "FCGI_RUNNING_IDENTITY");
	if (NULL == str_value) {
		username[0] = '\0';
		printf("[system]: running identity will not be changed\n");
	} else {
		strncpy(username, str_value, 256);
		printf("[system]: running identity of process will be %s\n", username);
	}
	config_file_save(pconfig);
	config_file_free(pconfig);
	
	
	signal(SIGPIPE, SIG_IGN);

	/* Create a Unix domain stream socket */
	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (-1 == listenfd) {
		printf("[system]: fail to create listen socket\n");
		return 4;
	}

	unlink(cs_path);

	/* Fill in socket address structure */
	memset(&unix_addr, 0, sizeof(unix_addr));
	unix_addr.sun_family = AF_UNIX;
	strcpy(unix_addr.sun_path, cs_path);
	len = sizeof(unix_addr.sun_family) + strlen(unix_addr.sun_path);

	/* Bind the name to the descriptor */
	if (bind(listenfd, (struct sockaddr*)&unix_addr, len) < 0) {
		close(listenfd);
		printf("[system]: fail to bind listen socket\n");
		return 5;
	}

	if (chmod(cs_path, 0666) < 0) {
		close(listenfd);
		printf("[system]: fail to change access mode of %s\n", cs_path);
		return 6;
	}

	if (listen(listenfd, 5) < 0) {
		printf("[system]: fail to listen!\n");
		close(listenfd);
		return 7;
	}
	
	if ('\0' != username[0]) {
		puser_pass = getpwnam(username);
		if (NULL == puser_pass) {
			printf("[system]: no such user %s\n", username);
			return 3;
		}

		if (0 != setgid(puser_pass->pw_gid)) {
			printf("[system]: can not run group of %s\n", username);
			return 3;
		}
		if (0 != setuid(puser_pass->pw_uid)) {
			printf("[system]: can not run as %s\n", username);
			return 3;
		}
	}

	pthread_mutex_init(&g_conn_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);

	double_list_init(&g_conn_list);
	double_list_init(&g_conn_list1);

	if (0 != pthread_create(&accept_id, NULL,
		accept_work_func, (void*)(long)listenfd)) {
		printf("[system]: fail to create accept thread\n");
		close(listenfd);
		return 8;
	}
	pthr_ids = malloc(sizeof(pthread_t)*thread_num);
	if (NULL == pthr_ids) {
		pthread_cancel(accept_id);
		close(listenfd);
		return 9;
	}
	for (i=0; i<thread_num; i++) {
		if (0 != pthread_create(&pthr_ids[i], NULL, thread_work_func, NULL)) {
            printf("[system]: fail to creat pool thread\n");
            break;
        }
	}
	if (i != thread_num) {
        for (i-=1; i>=0; i--) {
            pthread_cancel(pthr_ids[i]);
        }
		pthread_cancel(accept_id);
        close(listenfd);
		return 10;
    }

	g_notify_stop = 0;
	signal(SIGTERM, term_handler);
	
	printf("[system]: FCGICGI is now running\n");

	while (0 == g_notify_stop) {
		sleep(1);
	}
	close(listenfd);
	
	for (i=0; i<thread_num; i++) {
		pthread_cancel(pthr_ids[i]);
	}
	while ((pnode = double_list_get_from_head(&g_conn_list1)) != NULL) {
		pconn = (CONNECTION*)pnode->pdata;
		close(pconn->sockd);
		free(pconn);
	}
	while ((pnode = double_list_get_from_head(&g_conn_list)) != NULL) {
		pconn = (CONNECTION*)pnode->pdata;
		close(pconn->sockd);
		free(pconn);
	}

	pthread_mutex_destroy(&g_conn_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_cond_destroy(&g_waken_cond);

	return 0;
}


static void* accept_work_func(void *param)
{
	CONNECTION *pconn;
	int len, clifd, listenfd;
    struct sockaddr_un unix_addr;
	
	listenfd = (int)(long)param;
	while (0 == g_notify_stop) {
		len = sizeof(unix_addr);
	    memset(&unix_addr, 0, sizeof(unix_addr));
		clifd = accept(listenfd, (struct sockaddr*)&unix_addr, &len);
		if (-1 == clifd) {
			continue;
		}
        len -= sizeof(unix_addr.sun_family);
        unix_addr.sun_path[len] = '\0';
        unlink(unix_addr.sun_path);
        pconn = (CONNECTION*)malloc(sizeof(CONNECTION));
		if (NULL == pconn) {
			close(clifd);
			continue;
		}
		pthread_mutex_lock(&g_conn_lock);
        pconn->node.pdata = pconn;
        pconn->sockd = clifd;
        pconn->offset = 0;
        double_list_append_as_tail(&g_conn_list1, &pconn->node);
		pthread_mutex_unlock(&g_conn_lock);
		pthread_cond_signal(&g_waken_cond);
    }
	pthread_exit(0);
}

static int fcgi_pull_name_value(NDR_PULL *pndr,
	DATA_BLOB *pname, DATA_BLOB *pvalue)
{
	int status;
	uint8_t tmp_len;
	
	status = ndr_pull_uint8(pndr, &tmp_len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (tmp_len > 0x7F) {
		pndr->offset --;
		status = ndr_pull_uint32(pndr, &pname->length);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		pname->length &= 0x7FFFFFFF;
	} else {
		pname->length = tmp_len;
	}
	status = ndr_pull_uint8(pndr, &tmp_len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (tmp_len > 0x7F) {
		pndr->offset --;
		status = ndr_pull_uint32(pndr, &pvalue->length);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		pvalue->length &= 0x7FFFFFFF;
	} else {
		pvalue->length = tmp_len;
	}
	pname->data = pndr->data + pndr->offset;
	status = ndr_pull_advance(pndr, pname->length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pvalue->data = pndr->data + pndr->offset;
	return ndr_pull_advance(pndr, pvalue->length);
}

static int fcgi_pull_record(NDR_PULL *pndr, FCGI_RECORD *precord)
{
	int status;
	uint32_t offset;
	uint8_t tmp_byte;
	uint16_t content_len;
	
	status = ndr_pull_uint8(pndr, &tmp_byte);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (FCGI_VERSION != tmp_byte) {
		printf("[system]: unsupported fastgi request version\n");
		return NDR_ERR_FAILURE;
	}
	status = ndr_pull_uint8(pndr, &precord->type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	switch (precord->type) {
	case RECORD_TYPE_BEGIN_REQUEST:
	case RECORD_TYPE_PARAMS:
	case RECORD_TYPE_STDIN:
		break;
	default:
		printf("[system]: unsupported fastcgi record type\n");
		return NDR_ERR_FAILURE;
	}
	status = ndr_pull_uint16(pndr, &precord->request_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &content_len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &tmp_byte);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &precord->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	switch (precord->type) {
	case RECORD_TYPE_BEGIN_REQUEST:
		status = ndr_pull_uint16(pndr, &precord->val.begin.role);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint8(pndr, &precord->val.begin.flags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_array_uint8(pndr,
			precord->val.begin.reserved, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RECORD_TYPE_PARAMS:
		precord->val.params.count = 0;
		offset = pndr->offset;
		while (pndr->offset - offset < content_len &&
			precord->val.params.count <= 0xFF) {
			status = fcgi_pull_name_value(pndr,
				&precord->val.params.name_vals[
				precord->val.params.count].name,
				&precord->val.params.name_vals[
				precord->val.params.count].value);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			precord->val.params.count ++;
		}
		break;
	case RECORD_TYPE_STDIN:
		precord->val.stdin.data = pndr->data + pndr->offset;
		precord->val.stdin.length = content_len;
		status = ndr_pull_advance(pndr, content_len);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	}
	return NDR_ERR_SUCCESS;
}

static int fcgi_push_stdout(NDR_PUSH *pndr,
	uint16_t request_id, const DATA_BLOB stdout)
{
	int status;
	uint8_t padding_len;
	
	status = ndr_push_uint8(pndr, FCGI_VERSION);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, RECORD_TYPE_STDOUT);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, request_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, stdout.length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == (stdout.length & 7)) {
		padding_len = 0;
	} else {
		padding_len = 8 - (stdout.length & 7);
	}
	status = ndr_push_uint8(pndr, padding_len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr,
			stdout.data, stdout.length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != padding_len) {
		return ndr_push_zero(pndr, padding_len);
	}
	return NDR_ERR_SUCCESS;
}

static int fcgi_push_stderr(NDR_PUSH *pndr,
	uint16_t request_id, const DATA_BLOB stderr)
{
	int status;
	uint8_t padding_len;
	
	status = ndr_push_uint8(pndr, FCGI_VERSION);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, RECORD_TYPE_STDOUT);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, request_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, stderr.length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == (stderr.length & 7)) {
		padding_len = 0;
	} else {
		padding_len = 8 - (stderr.length & 7);
	}
	status = ndr_push_uint8(pndr, padding_len);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr,
			stderr.data, stderr.length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != padding_len) {
		return ndr_push_zero(pndr, padding_len);
	}
	return NDR_ERR_SUCCESS;
}

static int fcgi_push_end_request(NDR_PUSH *pndr,
	uint16_t request_id, const END_REQUEST *pend)
{
	int status;
	
	status = ndr_push_uint8(pndr, FCGI_VERSION);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, RECORD_TYPE_END_REQUEST);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, request_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, 8);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, pend->app_status);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, pend->protocol_status);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_array_uint8(pndr, pend->reserved, 3);
}

static BOOL read_record(CONNECTION *pconn)
{
	fd_set myset;
	int read_len;
	struct timeval tv;
	
	if (pconn->offset > pconn->record_len) {
		pconn->offset -= pconn->record_len;
		memmove(pconn->buff, pconn->buff +
			pconn->record_len, pconn->offset);
	} else {
		pconn->offset = 0;
	}
	pconn->record_len = -1;
	while (TRUE) {
		if (-1 == pconn->record_len) {
			if (pconn->offset >= 7) {
				pconn->record_len = (uint8_t)pconn->buff[4];
				pconn->record_len <<= 8;
				pconn->record_len |= (uint8_t)pconn->buff[5];
				pconn->record_len += (uint8_t)pconn->buff[6];
				pconn->record_len += 8;
			}
		}
		if (-1 != pconn->record_len &&
			pconn->offset >= pconn->record_len) {
			return TRUE;
		}
		if (sizeof(pconn->buff) == pconn->offset) {
			return FALSE;
		}
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pconn->sockd, &myset);
		if (select(pconn->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(pconn->sockd,
			pconn->buff + pconn->offset,
			sizeof(pconn->buff) - pconn->offset);
		if (read_len <= 0) {
			return FALSE;
		}
		pconn->offset += read_len;
	}
}

static BOOL read_stdstream(FCGI_CGI fcgi_cgi,
	char *buff, uint16_t *plen, uint8_t *ptype)
{
	int i;
	int max_des;
	fd_set myset;
	int read_len;
	char *read_buff;
	struct timeval tv;
	char tmp_buff[0x7FFF];
	
	tv.tv_usec = 0;
	tv.tv_sec = SOCKET_TIMEOUT;
	FD_ZERO(&myset);
	FD_SET(fcgi_cgi.pipe_out, &myset);
	FD_SET(fcgi_cgi.pipe_err, &myset);
	if (fcgi_cgi.pipe_out < fcgi_cgi.pipe_err) {
		max_des = fcgi_cgi.pipe_err;
	}
	if (select(max_des + 1, &myset, NULL, NULL, &tv) <= 0) {
		return FALSE;
	}
	if (TRUE == g_convert_lf) {
		read_len = 0x7FFF;
		read_buff = tmp_buff;
	} else {
		read_len = 0xFFFF;
		read_buff = buff;
	}
	if (FD_ISSET(fcgi_cgi.pipe_out, &myset)) {
		*ptype = RECORD_TYPE_STDOUT;
		read_len = read(fcgi_cgi.pipe_out, read_buff, read_len);
	} else {
		*ptype = RECORD_TYPE_STDERR;
		read_len = read(fcgi_cgi.pipe_err, read_buff, read_len);
	}
	if (read_len < 0) {
		return FALSE;
	}
	if (TRUE == g_convert_lf) {
		for (i=0,*plen=0; i<read_len; i++,(*plen)++) {
			if ('\n' == tmp_buff[i]) {
				buff[*plen] = '\r';
				(*plen) ++;
			}
			buff[*plen] = tmp_buff[i];
		}
	} else {
		*plen = read_len;
	}
	return TRUE;
}

static void move_fd(int srcfd, int dstfd)
{
	if (srcfd == dstfd) {
		return;
	}
	close(dstfd);
	dup2(srcfd, dstfd);
	close(srcfd);
}

static FCGI_CGI start_cgi(RECORD_PARAMS *pparams)
{
	int i;
	pid_t pid;
	char** envp;
	char *ptoken;
	char* args[3];
	char dir[256];
	char path[256];
	FCGI_CGI fcgi_cgi;
	int pipes_in[2] = {-1, -1};
	int pipes_out[2] = {-1, -1};
	int pipes_err[2] = {-1, -1};
	
	if (-1 == pipe(pipes_in)) {
		printf("[system]: couldn't create in pipe\n");
		fcgi_cgi.pid = -1;
		return fcgi_cgi;
	}
	if (-1 == pipe(pipes_out)) {
		printf("[system]: couldn't create out pipe\n");
		close(pipes_in[0]);
		close(pipes_in[1]);
		fcgi_cgi.pid = -1;
		return fcgi_cgi;
	}
	if (-1 == pipe(pipes_err)) {
		printf("[system]: couldn't create out pipe\n");
		close(pipes_in[0]);
		close(pipes_in[1]);
		close(pipes_out[0]);
		close(pipes_out[1]);
		fcgi_cgi.pid = -1;
		return fcgi_cgi;
	}
	pid = fork();
	switch (pid) {
	case 0:
		close(pipes_in[1]);
		close(pipes_out[0]);
		close(pipes_err[0]);
		move_fd(pipes_in[0], 0);
		move_fd(pipes_out[1], 1);
		move_fd(pipes_err[1], 2);
		envp = malloc(sizeof(char*)*(pparams->count + 1));
		if (NULL == envp) {
			exit(-1);
		}
		path[0] = '\0';
		for (i=0; i<pparams->count; i++) {
			if (15 == pparams->name_vals[i].name.length &&
				0 == memcmp(pparams->name_vals[i].name.data,
				"SCRIPT_FILENAME", 15)) {
				memcpy(path, pparams->name_vals[i].value.data,
					pparams->name_vals[i].value.length);
				path[pparams->name_vals[i].value.length] = '\0';
			}
			envp[i] = malloc(pparams->name_vals[i].name.length +
						pparams->name_vals[i].value.length + 2);
			if (NULL == envp[i]) {
				exit(-1);
			}
			memcpy(envp[i], pparams->name_vals[i].name.data,
						pparams->name_vals[i].name.length);
			envp[i][pparams->name_vals[i].name.length] = '=';
			memcpy(envp[i] + pparams->name_vals[i].name.length + 1,
				pparams->name_vals[i].value.data,
				pparams->name_vals[i].value.length);
			envp[i][pparams->name_vals[i].name.length +
				pparams->name_vals[i].value.length + 1] = '\0';
		}
		envp[i] = NULL;
		strcpy(dir, path);
		ptoken = strrchr(dir, '/');
		if (NULL == ptoken) {
			exit(-1);
		}
		*ptoken = '\0';
		chdir(dir);
		args[0] = path;
		args[1] = NULL;
		execve(path, args, envp);
		exit(-1);
	case -1:
		printf("[system]: cannot fork cgi process\n");
		close(pipes_in[0]);
		close(pipes_in[1]);
		close(pipes_out[0]);
		close(pipes_out[1]);
		close(pipes_err[0]);
		close(pipes_err[1]);
		fcgi_cgi.pid = -1;
		return fcgi_cgi;
	default:
		fcgi_cgi.pid = pid;
		close(pipes_in[0]);
		close(pipes_out[1]);
		close(pipes_err[1]);
		fcgi_cgi.pipe_in = pipes_in[1];
		fcgi_cgi.pipe_out = pipes_out[0];
		fcgi_cgi.pipe_err = pipes_err[0];
		return fcgi_cgi;
	}
}

static void *thread_work_func(void *param)
{
	int status;
	uint8_t type;
	uint8_t tmp_byte;
	uint16_t tmp_len;
	BOOL empty_params;
	FCGI_CGI fcgi_cgi;
	NDR_PULL ndr_pull;
	NDR_PUSH ndr_push;
	CONNECTION *pconn;
	FCGI_RECORD record;
	uint16_t request_id;
	DATA_BLOB stdstream;
	char tmp_buff[0xFFFF];
	char ndr_buff[0x10010];
	DOUBLE_LIST_NODE *pnode;
	END_REQUEST end_request;
	
	
NEXT_LOOP:
	pthread_mutex_lock(&g_cond_mutex);
	pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
	pthread_mutex_unlock(&g_cond_mutex);

	pthread_mutex_lock(&g_conn_lock);
	pnode = double_list_get_from_head(&g_conn_list1);
	if (NULL != pnode) {
		double_list_append_as_tail(&g_conn_list, pnode);
	}
	pthread_mutex_unlock(&g_conn_lock);
	if (NULL == pnode) {
		goto NEXT_LOOP;
	}
	pconn = (CONNECTION*)pnode->pdata;
	empty_params = FALSE;
	request_id = 0;
	fcgi_cgi.pid = -1;
	fcgi_cgi.pipe_in = -1;
	fcgi_cgi.pipe_out = -1;
	fcgi_cgi.pipe_err = -1;
	while (TRUE) {
		if (FALSE == read_record(pconn)) {
			goto FREE_CONNECTION;
		}
		ndr_pull_init(&ndr_pull, pconn->buff, pconn->record_len,
							NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
		if (NDR_ERR_SUCCESS != fcgi_pull_record(&ndr_pull, &record)) {
			printf("[system]: fail to pull fastcgi record\n");
			goto FREE_CONNECTION;
		}
		if (0 == request_id) {
			if (RECORD_TYPE_BEGIN_REQUEST != record.type) {
				printf("[system]: need begin request record at the first\n");
				goto FREE_CONNECTION;
			}
			if (0 == record.request_id ||
				ROLE_RESPONDER != record.val.begin.role) {
				printf("[system]: begin request record error\n");
				goto FREE_CONNECTION;
			}
			request_id = record.request_id;
			continue;
		}
		if (-1 == fcgi_cgi.pid) {
			if (RECORD_TYPE_PARAMS != record.type) {
				printf("[system]: need params record\n");
				goto FREE_CONNECTION;
			}
			fcgi_cgi = start_cgi(&record.val.params);
			if (-1 == fcgi_cgi.pid) {
				printf("[system]: fail to excute cgi process\n");
				goto FREE_CONNECTION;
			}
			continue;
		}
		if (FALSE == empty_params) {
			if (RECORD_TYPE_PARAMS != record.type
				|| 0 != record.val.params.count) {
				printf("[system]: need empty params record\n");
				goto FREE_CONNECTION;	
			}
			empty_params = TRUE;
			continue;
		}
		if (RECORD_TYPE_STDIN != record.type) {
			printf("[system]: improper record type\n");
			goto FREE_CONNECTION;
		}
		if (0 == record.val.stdin.length) {
			close(fcgi_cgi.pipe_in);
			fcgi_cgi.pipe_in = -1;
			break;
		}
		if (record.val.stdin.length != write(fcgi_cgi.pipe_in,
			record.val.stdin.data, record.val.stdin.length)) {
			printf("[system]: fail to write data to cgi process\n");
			goto FREE_CONNECTION;
		}
    }
	stdstream.data = tmp_buff;
	while (TRUE == read_stdstream(fcgi_cgi, tmp_buff, &tmp_len, &type)) {
		stdstream.length = tmp_len;
		ndr_push_init(&ndr_push, ndr_buff, sizeof(ndr_buff),
					NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
		if (RECORD_TYPE_STDOUT == type) {
			status = fcgi_push_stdout(&ndr_push, request_id, stdstream);
		} else {
			status = fcgi_push_stderr(&ndr_push, request_id, stdstream);
		}
		if (NDR_ERR_SUCCESS != status) {
			printf("[system]: fail to push stdstream record\n");
			goto FREE_CONNECTION;
		}
		if (0 == tmp_len) {
			close(fcgi_cgi.pipe_out);
			close(fcgi_cgi.pipe_err);
			waitpid(fcgi_cgi.pid, &status, 0);
			end_request.app_status = status;
			end_request.protocol_status = PROTOCOL_STATUS_REQUEST_COMPLETE;
			memset(end_request.reserved, 0, 3);
			ndr_push_init(&ndr_push, ndr_buff, sizeof(ndr_buff),
							NDR_FLAG_NOALIGN|NDR_FLAG_BIGENDIAN);
			fcgi_push_end_request(&ndr_push, request_id, &end_request);
			write(pconn->sockd, ndr_buff, ndr_push.offset);
			shutdown(pconn->sockd, SHUT_WR);
			read(pconn->sockd, &tmp_byte, 1);
			pthread_mutex_lock(&g_conn_lock);
			double_list_remove(&g_conn_list, &pconn->node);
			pthread_mutex_unlock(&g_conn_lock);
			close(pconn->sockd);
			free(pconn);
			goto NEXT_LOOP;
		}
		if (write(pconn->sockd, ndr_buff, ndr_push.offset) <= 0) {
			printf("[system]: fail to write "
				"stdstream record to http server\n");
			goto FREE_CONNECTION;
		}
	}
	printf("[system]: fail to read data from cgi process\n");
FREE_CONNECTION:
	if (-1 != fcgi_cgi.pipe_in) {
		close(fcgi_cgi.pipe_in);
	}
	if (-1 != fcgi_cgi.pipe_out) {
		close(fcgi_cgi.pipe_out);
	}
	if (-1 != fcgi_cgi.pipe_err) {
		close(fcgi_cgi.pipe_err);
	}
	if (-1 != fcgi_cgi.pid) {
		kill(fcgi_cgi.pid, SIGKILL);
		waitpid(fcgi_cgi.pid, &status, 0);
	}
	pthread_mutex_lock(&g_conn_lock);
	double_list_remove(&g_conn_list, &pconn->node);
	pthread_mutex_unlock(&g_conn_lock);
	close(pconn->sockd);
	free(pconn);
	goto NEXT_LOOP;
	return NULL;
}
