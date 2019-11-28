#include <errno.h>
#include <string.h>
#include <libHX/defs.h>
#include <gromox/defs.h>
#include "relay_bridge.h"
#include "relay_agent.h"
#include "double_list.h"
#include "list_file.h"
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <zlib.h>

#define MESSAGE_MESS		                 2

#define TOKEN_MESSAGE_QUEUE                  1

#define BRIDGE_STACK_SIZE					0x100000

typedef struct _CONNECTION_THR {
	DOUBLE_LIST_NODE node;
	int sockd;
	pthread_t tid;
} CONNECTION_THR;

typedef struct _ALLOW_UNIT {
	DOUBLE_LIST_NODE node;
	char ip[16];
} ALLOW_UNIT;

typedef struct _MSG_BUFF {
	long msg_type;
	int msg_content;
} MSG_BUFF;

static BOOL g_notify_stop = TRUE;
static int g_listen_port;
static int g_listen_sockd = -1;
static int g_fake_id;
static int g_msg_id;
static pthread_t g_thr_id;
static char g_list_path[256];
static char g_mess_path[256];
static char g_save_path[256];
static char g_token_path[256];
static DOUBLE_LIST g_allow_list;
static DOUBLE_LIST g_connection_list;
static pthread_rwlock_t g_allow_lock;
static pthread_mutex_t g_id_lock;
static pthread_mutex_t g_connection_lock;

static int relay_bridge_retrieve_min_ID(void);
static void relay_bridge_notify(int mess_id);

static void *accept_work_func(void *param);

static void *connection_work_func(void *param);

void relay_bridge_init(int port, const char *list_path, const char *mess_path,
	const char *save_path, const char *token_path)
{
	g_listen_port = port;
	strcpy(g_list_path, list_path);
	strcpy(g_mess_path, mess_path);
	strcpy(g_save_path, save_path);
	strcpy(g_token_path, token_path);
	double_list_init(&g_allow_list);
	double_list_init(&g_connection_list);
	pthread_rwlock_init(&g_allow_lock, NULL);
	pthread_mutex_init(&g_id_lock, NULL);
	pthread_mutex_init(&g_connection_lock, NULL);
}

int relay_bridge_run()
{
	int optval;
	key_t k_msg;
	int sockd, status;
	struct sockaddr_in my_name;
	
	k_msg = ftok(g_token_path, TOKEN_MESSAGE_QUEUE);
	if (-1 == k_msg) {
		printf("[relay_agent]: cannot open key for message queue\n");
		return -1;
	}
	/* get the message queue */
	g_msg_id = msgget(k_msg, 0);
	if (-1 == g_msg_id) {
		printf("[relay_agent]: fail to get message queue\n");
		return -2;
	}

	g_fake_id = relay_bridge_retrieve_min_ID();
	if (FALSE == relay_bridge_refresh_table()) {
		printf("[relay_agent]: fail to load allow list into system\n");
		return -3;
	}
	/* create a socket */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockd == -1) {
		printf("[relay_agent]: failed to create listen socket: %s\n", strerror(errno));
		return -4;
	}
	optval = -1;
	/* eliminates "Address already in use" error from bind */
	setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
		sizeof(int));

	/* socket binding */
	memset(&my_name, 0, sizeof(my_name));
	my_name.sin_family = AF_INET;
	my_name.sin_addr.s_addr = INADDR_ANY;
	my_name.sin_port = htons(g_listen_port);

	status = bind(sockd, (struct sockaddr*)&my_name, sizeof(my_name));
	if (-1 == status) {
		printf("[relay_agent]: bind *:%u: %s\n", g_listen_port, strerror(errno));
		close(sockd);
		return -5;
	}
	
	/* set server socket to nonblock mode */
	fcntl(sockd, F_SETFL, O_NONBLOCK);
	
	status = listen(sockd, 5);

	if (-1 == status) {
		printf("[relay_agent]: fail to listen socket\n");
		close(sockd);
		return -6;
	}
	g_notify_stop = FALSE;
	int ret = pthread_create(&g_thr_id, nullptr, accept_work_func,
	          reinterpret_cast(void *, static_cast(intptr_t, sockd)));
	if (ret != 0) {
		g_notify_stop = TRUE;
		printf("[relay_agent]: failed to create accept thread: %s\n", strerror(ret));
		close(sockd);
		return -7;
	}
	pthread_setname_np(g_thr_id, "relay_bridge");
	g_listen_sockd = sockd;
	return 0;
}

int relay_bridge_stop()
{
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_THR *pconnection;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thr_id, NULL);
	}
	
	if (-1 != g_listen_sockd) {
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}
	
	while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
		pconnection = (CONNECTION_THR*)pnode->pdata;
		pthread_cancel(pconnection->tid);
		close(pconnection->sockd);
		free(pconnection);
	}
	double_list_free(&g_connection_list);

	while ((pnode = double_list_get_from_head(&g_allow_list)) != NULL)
		free(pnode->pdata);
	return 0;
}

void relay_bridge_free()
{
	g_list_path[0] = '\0';
	g_mess_path[0] = '\0';
	g_save_path[0] = '\0';
	g_token_path[0] = '\0';
	double_list_free(&g_allow_list);
	double_list_free(&g_connection_list);
	pthread_rwlock_destroy(&g_allow_lock);
	pthread_mutex_destroy(&g_id_lock);
	pthread_mutex_destroy(&g_connection_lock);
}

BOOL relay_bridge_refresh_table()
{
	char *pitem;
	int i, list_len;
	LIST_FILE *pfile;
	ALLOW_UNIT *pallow;
	DOUBLE_LIST_NODE *pnode;

	pfile = list_file_init(g_list_path, "%s:16");
	if (NULL == pfile) {
		return FALSE;
	}

	
	list_len = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);

	pthread_rwlock_wrlock(&g_allow_lock);

	while ((pnode = double_list_get_from_head(&g_allow_list)) != NULL)
		free(pnode->pdata);
	
	for (i=0; i<list_len; i++) {
		pallow = (ALLOW_UNIT*)malloc(sizeof(ALLOW_UNIT));
		if (NULL == pallow) {
			continue;
		}
		pallow->node.pdata = pallow;
		strcpy(pallow->ip, pitem + 16*i);
		double_list_append_as_tail(&g_allow_list, &pallow->node);
	}

	pthread_rwlock_unlock(&g_allow_lock);
	
	list_file_free(pfile);
	return TRUE;
}

static void *accept_work_func(void *param)
{
	fd_set myset;
	char response;
	struct timeval tv;
	int sockd, sockd2;
	socklen_t addrlen;
	CONNECTION_THR *pconnection;
	struct sockaddr_in peer_name;
	DOUBLE_LIST_NODE *pnode;
	ALLOW_UNIT *pallow;
	char client_ip[16];
	pthread_attr_t attr;

	sockd = (int)(long)param;
	while (FALSE == g_notify_stop) {
		/* wait for an incoming connection */
		tv.tv_usec = 0;
		tv.tv_sec = 1;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			continue;
		}
		addrlen = sizeof(peer_name);
		sockd2 = accept(sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd2){
			continue;
		}
		strcpy(client_ip, inet_ntoa(peer_name.sin_addr));
		pthread_rwlock_rdlock(&g_allow_lock);
		for (pnode=double_list_get_head(&g_allow_list); NULL!=pnode;
			pnode=double_list_get_after(&g_allow_list, pnode)) {
			pallow = (ALLOW_UNIT*)pnode->pdata;
			if (0 == strcmp(pallow->ip, client_ip)) {
				break;
			}
		}
		pthread_rwlock_unlock(&g_allow_lock);
		
		if (NULL == pnode) {
			response = RESPONSE_CONNECT_REJECT;
			write(sockd2, &response, 1);
			close(sockd2);
			continue;
		}
		
		pconnection = (CONNECTION_THR*)malloc(sizeof(CONNECTION_THR));
		if (NULL == pconnection) {
			response = RESPONSE_CONNECT_REJECT;
			write(sockd2, &response, 1);
			close(sockd2);
			continue;
		}
		pconnection->node.pdata = pconnection;
		pconnection->sockd = sockd2;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, BRIDGE_STACK_SIZE);
		if (0 != pthread_create(&pconnection->tid, &attr, connection_work_func,
			pconnection)) {
			pthread_attr_destroy(&attr);
			response = RESPONSE_CONNECT_REJECT;
			write(sockd2, &response, 1);
			close(sockd2);
			free(pconnection);
			continue;
		}
		pthread_setname_np(pconnection->tid, "relay_bridge_work");
		pthread_attr_destroy(&attr);
	}
	return NULL;
}

static void *connection_work_func(void *param)
{
	fd_set myset;
	int read_len;
	int fd, temp_id;
	gzFile gz_fd;
	size_t offset;
	size_t buff_len;
	struct timeval tv;
	char temp_path[256];
	char dest_path[256];
	char zipped_path[256];
	char buff[BUFFER_SIZE];
	char command, response;
	CONNECTION_THR *pconnection;

	pconnection = (CONNECTION_THR*)param;
	
	response = RESPONSE_CONNECT_ACCEPT;
	if (1 != write(pconnection->sockd, &response, 1)) {
		close(pconnection->sockd);
		free(pconnection);
		pthread_detach(pthread_self());
		pthread_exit(0);
	}
	
	pthread_mutex_lock(&g_connection_lock);
	double_list_append_as_tail(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_connection_lock);
	
	while (TRUE) {
		/* wait the socket data to be available */
		tv.tv_sec = MAX_INTERVAL;
		tv.tv_usec = 0;
		FD_ZERO(&myset);
		FD_SET(pconnection->sockd, &myset);
		if (select(pconnection->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			goto EXIT_THEARD;
		}
		if (1 != read(pconnection->sockd, &command, 1)) {
			goto EXIT_THEARD;
		}
		
		if (COMMAND_CONNECT_PING == command) {
			response = RESPONSE_PING_OK;
			if (1 != write(pconnection->sockd, &response, 1)) {
				goto EXIT_THEARD;
			}
			continue;
		} else if (COMMAND_SEND_BUFFER == command) {	
			pthread_mutex_lock(&g_id_lock);
			if (g_fake_id == 0X7FFFFFFF) {
				g_fake_id = 0;
			}
			temp_id = (++g_fake_id);
			pthread_mutex_unlock(&g_id_lock);
			temp_id *= -1;
			sprintf(zipped_path, "%s/%d.gz", g_save_path, temp_id);
			sprintf(temp_path, "%s/%d", g_save_path, temp_id);
			sprintf(dest_path, "%s/%d", g_mess_path, temp_id);
			
			fd = open(zipped_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
			if (-1 == fd) {
				response = RESPONSE_RECV_ERROR;
				if (1 != write(pconnection->sockd, &response, 1)) {
					goto EXIT_THEARD;
				}
				continue;	
			}
			response = RESPONSE_RECV_READY;
			if (1 != write(pconnection->sockd, &response, 1)) {
				close(fd);
				remove(zipped_path);
				goto EXIT_THEARD;
			}
			tv.tv_sec = SOCKET_TIMEOUT;
			tv.tv_usec = 0;
			FD_ZERO(&myset);
			FD_SET(pconnection->sockd, &myset);
			if (select(pconnection->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
				close(fd);
				remove(zipped_path);
				goto EXIT_THEARD;
			}
			if (sizeof(size_t) != read(pconnection->sockd, &buff_len,
				sizeof(size_t))) {
				close(fd);
				remove(zipped_path);
				goto EXIT_THEARD;
			}
			if (8 != sizeof(size_t)) {
				buff_len = ntohl(buff_len);
			}
			
			offset = 0;
			while (TRUE) {
				tv.tv_sec = SOCKET_TIMEOUT;
				tv.tv_usec = 0;
				FD_ZERO(&myset);
				FD_SET(pconnection->sockd, &myset);
				if (select(pconnection->sockd + 1, &myset, NULL,
					NULL, &tv) <=0) {
					close(fd);
					remove(zipped_path);
					goto EXIT_THEARD;
				}
				read_len = read(pconnection->sockd, buff, BUFFER_SIZE);
				if (read_len <= 0) {
					close(fd);
					remove(zipped_path);
					goto EXIT_THEARD;
				}
				if (read_len != write(fd, buff, read_len)) {
					close(fd);
					remove(zipped_path);
					goto EXIT_THEARD;
				}
				offset += read_len;
				if (offset >= buff_len) {
					break;
				}
			}
			
			close(fd);
			gz_fd = gzopen(zipped_path, "r");
			if (Z_NULL == gz_fd) {
				remove(zipped_path);
				response = RESPONSE_RECV_ERROR;
				if (1 != write(pconnection->sockd, &response, 1)) {
					goto EXIT_THEARD;
				}
				continue;
			}
			
			fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
			if (-1 == fd) {
				gzclose(gz_fd);
				remove(zipped_path);
				response = RESPONSE_RECV_ERROR;
				if (1 != write(pconnection->sockd, &response, 1)) {
					goto EXIT_THEARD;
				}
				continue;
			}
			
			while ((read_len = gzread(gz_fd, buff, BUFFER_SIZE)) > 0) {
				write(fd, buff, read_len);
			}
			gzclose(gz_fd);
			close(fd);
			remove(zipped_path);
			
			link(temp_path, dest_path);
			remove(temp_path);
			relay_bridge_notify(temp_id);
			response = RESPONSE_RECV_OK;
			if (1 != write(pconnection->sockd, &response, 1)) {
				goto EXIT_THEARD;
			}
		} else {
			goto EXIT_THEARD;
		}
	}
		
EXIT_THEARD:
	pthread_mutex_lock(&g_connection_lock);
	double_list_remove(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_connection_lock);
	close(pconnection->sockd);
	free(pconnection);
	pthread_detach(pthread_self());
	pthread_exit(0);
}

static int relay_bridge_retrieve_min_ID()
{
	DIR *dirp;
	struct dirent *direntp;
	char temp_path[256];
	int fd, size, min_ID, temp_ID;

	min_ID = 0;
	/* get minimum ID in mess */
	dirp = opendir(g_mess_path);
	while ((direntp = readdir(dirp)) != NULL) {
		if (strcmp(direntp->d_name, ".") == 0 ||
		    strcmp(direntp->d_name, "..") == 0)
			continue;
		temp_ID = atoi(direntp->d_name);
		if (temp_ID < min_ID) {
			sprintf(temp_path, "%s/%s", g_mess_path, direntp->d_name);
			fd = open(temp_path, O_RDONLY);
			if (-1 == fd) {
				continue;
			}
			if (sizeof(int) != read(fd, &size, sizeof(int))) {
				close(fd);
				continue;
			}
			close(fd);
			if (0 != size) {
				min_ID = temp_ID;
			} else {
				remove(temp_path);
			}
		}
	}
	closedir(dirp);
	return min_ID * (-1);
}

static void relay_bridge_notify(int mess_id)
{
	MSG_BUFF msg;

	msg.msg_type = MESSAGE_MESS;
	msg.msg_content = mess_id;
	msgsnd(g_msg_id, &msg, sizeof(int), IPC_NOWAIT);
}

