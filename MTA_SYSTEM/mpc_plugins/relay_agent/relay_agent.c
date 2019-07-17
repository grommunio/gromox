#include "relay_agent.h"
#include "util.h"
#include "double_list.h"
#include "list_file.h"
#include "mail_func.h"
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <zlib.h>
#include <stdint.h>

#define SMTP_RELAY			3

enum {
	STAT_ALIVE,
	STAT_DEAD,
	STAT_USING
};

enum {
	BIT_MODE_MIX,
	BIT_MODE_64,
	BIT_MODE_32
};

typedef struct _HOST_UNIT {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST list;
	char ip[16];
	int port;
	BOOL b_64bit;
	BOOL alive;
} HOST_UNIT;

typedef struct _CONNECTION_UNIT {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_host;
	HOST_UNIT *phost;
	time_t last_stamp;
	int sockd;
	int stat;
} CONNECTION_UNIT;


static int g_bit_mode;
static int g_channel_num;
static int g_fake_id;
static pthread_t g_thr_id;
static BOOL g_relay_switch;
static char g_list_path[256];
static char g_save_path[256];
static DOUBLE_LIST g_host_list;
static DOUBLE_LIST g_alive_list;
static pthread_mutex_t g_tree_lock;
static pthread_mutex_t g_list_lock;
static pthread_mutex_t g_id_lock;
static BOOL g_notify_stop = TRUE;


static BOOL relay_agent_zip(MESSAGE_CONTEXT *pcontext, BOOL b_64bit,
	char *zipped_path);

static int relay_agent_connect(const char *ip, int port);

static void relay_agent_close(int sockd);

static BOOL relay_agent_ping(int sockd);

static BOOL relay_agent_send(int sockd, BOOL b_64bit, const char *path);

static void relay_agent_log_info(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...);

static void *thread_work_func(void *param);

void relay_agent_init(const char *list_path, const char *save_path,
	int channel_num, BOOL relay_switch)
{
	g_fake_id = 0;
	g_channel_num = channel_num;
	g_relay_switch = relay_switch;
	strcpy(g_list_path, list_path);
	strcpy(g_save_path, save_path);
	double_list_init(&g_host_list);
	double_list_init(&g_alive_list);
	pthread_mutex_init(&g_list_lock, NULL);
	pthread_mutex_init(&g_tree_lock, NULL);
	pthread_mutex_init(&g_id_lock, NULL);
}


int relay_agent_run()
{
	int bit32_num;
	int bit64_num;
	LIST_FILE *pfile;
	HOST_UNIT *punit;
	CONNECTION_UNIT *pconnect;
	int i, j, list_len, temp_port;
	char *pitem, temp_ip[16], *pcolon;

	pfile = list_file_init(g_list_path, "%s:32%d");
	if (NULL == pfile) {
		return 0;
	}
	list_len = list_file_get_item_num(pfile);
	if (0 == list_len) {
		printf("[relay_agent]: warning!!! site list is empty!!!\n");
	}
	pitem = list_file_get_list(pfile);
	bit32_num = 0;
	bit64_num = 0;
	for (i=0; i<list_len; i++) {
		if (NULL == extract_ip(pitem + (32 + sizeof(int))*i, temp_ip)) {
			printf("[relay_agent]: line %d: ip address format error in "
				"site list\n", i);
			continue;
		}
		pcolon = strchr(pitem + (32 + sizeof(int))*i, ':');
		if (NULL == pcolon) {
			temp_port = 25;
		} else {
			temp_port = atoi(pcolon + 1);
			if (0 == temp_port) {
				printf("[relay_agent]: line %d: port error in "
					"site list\n", i);
				continue;
			}
		}		
		punit = (HOST_UNIT*)malloc(sizeof(HOST_UNIT));
		if (NULL == punit) {
			debug_info("[relay_agent]: fail to allocate memory");
			continue;
		}
		punit->node.pdata = punit;
		strcpy(punit->ip, temp_ip);
		punit->port = temp_port;
		if (0 == *(int*)(pitem + (32 + sizeof(int))*i + 32)) {
			punit->b_64bit = FALSE;
			bit32_num ++;
		} else {
			punit->b_64bit = TRUE;
			bit64_num ++;
		}
		punit->alive = TRUE;
		double_list_init(&punit->list);
		double_list_append_as_tail(&g_host_list, &punit->node);
		for (j=0; j<g_channel_num; j++) {
			pconnect = (CONNECTION_UNIT*)malloc(sizeof(CONNECTION_UNIT));
			if (NULL == pconnect) {
				debug_info("[relay_agent]: fail to allocate memory");
				continue;
			}
			pconnect->node.pdata = pconnect;
			pconnect->node_host.pdata = pconnect;
			pconnect->phost = punit;
			pconnect->sockd = -1;
			pconnect->stat = STAT_DEAD;
			double_list_append_as_tail(&punit->list, &pconnect->node_host);
		}
	}
	list_file_free(pfile);
	if (bit32_num != 0 && bit64_num != 0) {
		g_bit_mode = BIT_MODE_MIX;
	} else if (0 == bit32_num && 0 != bit64_num) {
		g_bit_mode = BIT_MODE_64;
	} else if (0 == bit64_num && 0 != bit32_num) {
		g_bit_mode = BIT_MODE_32;
	} else {
		g_bit_mode = BIT_MODE_MIX;
	}
	
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_thr_id, NULL, thread_work_func, NULL)) {
		printf("[relay_agent]: fail to create scanning thread\n");
		g_notify_stop = TRUE;
		return -1;
	}
	
	return 0;
}

int relay_agent_stop()
{
	HOST_UNIT *punit;
	CONNECTION_UNIT *pconnect;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thr_id, NULL);
	}
	
	while (pnode=double_list_get_from_head(&g_host_list)) {
		punit = (HOST_UNIT*)pnode->pdata;
		while (pnode1=double_list_get_from_head(&punit->list)) {
			pconnect = (CONNECTION_UNIT*)pnode1->pdata;
			relay_agent_close(pconnect->sockd);
			free(pconnect);
		}
		double_list_free(&punit->list);
		free(punit);
	}
	return 0;
}

void relay_agent_free()
{
	g_list_path[0] = '\0';
	double_list_free(&g_host_list);
	double_list_free(&g_alive_list);
	pthread_mutex_destroy(&g_tree_lock);
	pthread_mutex_destroy(&g_list_lock);
	pthread_mutex_destroy(&g_id_lock);
}

BOOL relay_agent_refresh_table()
{
	int bit32_num;
	int bit64_num;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST temp_list;
	LIST_FILE *pfile;
	HOST_UNIT *punit;
	HOST_UNIT *punit1;
	int i, list_len, temp_port;
	char *pitem, temp_ip[16], *pcolon;

	pfile = list_file_init(g_list_path, "%s:32%d");
	if (NULL == pfile) {
		return FALSE;
	}
	list_len = list_file_get_item_num(pfile);
	if (0 == list_len) {
		printf("[relay_agent]: warning!!! site list is empty!!!\n");
	}
	pitem = list_file_get_list(pfile);
	double_list_init(&temp_list);
	bit32_num = 0;
	bit64_num = 0;
	for (i=0; i<list_len; i++) {
		if (NULL == extract_ip(pitem + (32 + sizeof(int))*i, temp_ip)) {
			printf("[relay_agent]: line %d: ip address format error in "
				"site list\n", i);
			continue;
		}
		pcolon = strchr(pitem + (32 + sizeof(int))*i, ':');
		if (NULL == pcolon) {
			temp_port = 25;
		} else {
			temp_port = atoi(pcolon + 1);
			if (0 == temp_port) {
				printf("[relay_agent]: line %d: port error in "
					"site list\n", i);
				continue;
			}
		}
		punit = (HOST_UNIT*)malloc(sizeof(HOST_UNIT));
		if (NULL == punit) {
			debug_info("[relay_agent]: fail to allocate memory");
			continue;
		}
		punit->node.pdata = punit;
		strcpy(punit->ip, temp_ip);
		punit->port = temp_port;
		if (0 == *(int*)(pitem + (32 + sizeof(int))*i + 32)) {
			punit->b_64bit = FALSE;
			bit32_num ++;
		} else {
			punit->b_64bit = TRUE;
			bit64_num ++;
		}
		punit->alive = TRUE;
		double_list_init(&punit->list);
		double_list_append_as_tail(&temp_list, &punit->node);
	}
	list_file_free(pfile);
	if (bit32_num != 0 && bit64_num != 0) {
		g_bit_mode = BIT_MODE_MIX;
	} else if (0 == bit32_num && 0 != bit64_num) {
		g_bit_mode = BIT_MODE_64;
	} else if (0 == bit64_num && 0 != bit32_num) {
		g_bit_mode = BIT_MODE_32;
	} else {
		g_bit_mode = BIT_MODE_MIX;
	}

	pthread_mutex_lock(&g_tree_lock);
	for (pnode=double_list_get_head(&g_host_list); NULL!=pnode;
		pnode=double_list_get_after(&g_host_list, pnode)) {
		punit = (HOST_UNIT*)pnode->pdata;
		for (pnode1=double_list_get_head(&temp_list); NULL!=pnode1;
			pnode1=double_list_get_after(&temp_list, pnode1)) {
			punit1 = (HOST_UNIT*)pnode1->pdata;
			if (0 == strcmp(punit->ip, punit1->ip) &&
				punit->port == punit1->port) {
				break;
			}
		}
		if (NULL != pnode1) {
			punit->alive = TRUE;
			punit1->alive = FALSE;
		} else {
			punit->alive = FALSE;
		}
	}
	while (pnode=double_list_get_from_head(&temp_list)) {
		punit = (HOST_UNIT*)pnode->pdata;
		if (TRUE == punit->alive) {
			double_list_append_as_tail(&g_host_list, &punit->node);
		} else {
			free(punit);
		}
	}
	pthread_mutex_unlock(&g_tree_lock);
	double_list_free(&temp_list);
	return TRUE;	
}

static void *thread_work_func(void *param)
{
	int i, j;
	time_t now_time;
	HOST_UNIT *punit;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST_NODE *phead;
	DOUBLE_LIST_NODE *ptail;
	DOUBLE_LIST_NODE *ptail1;
	CONNECTION_UNIT *pconnect;
	
	i = 0;
	while (FALSE == g_notify_stop) {
		if (i < SCAN_INTERVAL) {
			sleep(1);
			i ++;
			continue;
		}

		if (FALSE == g_relay_switch) {
			pthread_mutex_lock(&g_tree_lock);
			phead = double_list_get_head(&g_host_list);
			ptail = double_list_get_tail(&g_host_list);
			pthread_mutex_unlock(&g_tree_lock);
			for (pnode=phead; pnode!=NULL;
				pnode=double_list_get_after(&g_host_list, pnode)) {
				punit = (HOST_UNIT*)pnode->pdata;
				for (pnode1=double_list_get_head(&punit->list); NULL!=pnode1;
					pnode1=double_list_get_after(&punit->list, pnode1)) {
					pconnect = (CONNECTION_UNIT*)pnode1->pdata;
					if (STAT_ALIVE == pconnect->stat) {
						pthread_mutex_lock(&g_list_lock);
						if (STAT_ALIVE == pconnect->stat) {
							pconnect->stat = STAT_DEAD;
							double_list_remove(&g_alive_list, &pconnect->node);
							pthread_mutex_unlock(&g_list_lock);
							relay_agent_close(pconnect->sockd);
							pconnect->sockd = -1;
						} else {
							pthread_mutex_unlock(&g_list_lock);
						}
					}
				}
				if (pnode == ptail) {
					break;
				}
			}
			i = 0;
			continue;
		}
		
		pthread_mutex_lock(&g_tree_lock);
		ptail = double_list_get_tail(&g_host_list);
		while (pnode=double_list_get_from_head(&g_host_list)) {
			punit = (HOST_UNIT*)pnode->pdata;
			if (FALSE == punit->alive &&
				0 == double_list_get_nodes_num(&punit->list)) {
				double_list_free(&punit->list);
				free(punit);
			} else {
				double_list_append_as_tail(&g_host_list, pnode);
			}
			if (pnode == ptail) {
				break;
			}
		}
		phead = double_list_get_head(&g_host_list);
		ptail = double_list_get_tail(&g_host_list);
		pthread_mutex_unlock(&g_tree_lock);
		
		for (pnode=phead; pnode!=NULL;
			pnode=double_list_get_after(&g_host_list, pnode)) {
			punit = (HOST_UNIT*)pnode->pdata;
			if (FALSE == punit->alive) {
				ptail1 = double_list_get_tail(&punit->list);
				while (pnode1=double_list_get_from_head(&punit->list)) {
					pconnect = (CONNECTION_UNIT*)pnode1->pdata;
					switch (pconnect->stat) {
					case STAT_USING:
						double_list_append_as_tail(&punit->list, pnode1);
						break;
					case STAT_ALIVE:
						relay_agent_close(pconnect->sockd);
						pthread_mutex_lock(&g_list_lock);
						if (STAT_ALIVE == pconnect->stat) {
							double_list_remove(&g_alive_list, &pconnect->node);
						}
						pthread_mutex_unlock(&g_list_lock);
					case STAT_DEAD:
						free(pconnect);
						break;
					}
					if (pnode1 == ptail1) {
						break;
					}
				}
			} else {
				if (0 == double_list_get_nodes_num(&punit->list)) {
					for (j=0; j<g_channel_num; j++) {
						pconnect = (CONNECTION_UNIT*)malloc(
									sizeof(CONNECTION_UNIT));
						pconnect->node.pdata = pconnect;
						pconnect->node_host.pdata = pconnect;
						pconnect->phost = punit;
						pconnect->sockd = relay_agent_connect(punit->ip,
											punit->port);
						if (-1 == pconnect->sockd) {
							pconnect->stat = STAT_DEAD;
						} else {
							pconnect->stat = STAT_ALIVE;
							time(&pconnect->last_stamp);
							pthread_mutex_lock(&g_list_lock);
							double_list_append_as_tail(&g_alive_list,
								&pconnect->node);
							pthread_mutex_unlock(&g_list_lock);
						}
						double_list_append_as_tail(&punit->list,
							&pconnect->node_host);
					}
				} else {
					for (pnode1=double_list_get_head(&punit->list);
						NULL!=pnode1;
						pnode1=double_list_get_after(&punit->list, pnode1)) {
						pconnect = (CONNECTION_UNIT*)pnode1->pdata;
						if (STAT_DEAD == pconnect->stat) {
							pconnect->sockd = relay_agent_connect(punit->ip,
												punit->port);
							if (-1 != pconnect->sockd) {
								time(&pconnect->last_stamp);
								pthread_mutex_lock(&g_list_lock);
								pconnect->stat = STAT_ALIVE;
								double_list_append_as_tail(&g_alive_list,
									&pconnect->node);
								pthread_mutex_unlock(&g_list_lock);
							}
						} else {
							time(&now_time);
							if (now_time - pconnect->last_stamp >=
								PING_INTERVAL) {
								pthread_mutex_lock(&g_list_lock);
								if (STAT_ALIVE == pconnect->stat) {
									double_list_remove(&g_alive_list,
										&pconnect->node);
									pthread_mutex_unlock(&g_list_lock);	
									if (TRUE == relay_agent_ping(
										pconnect->sockd)) {
										time(&pconnect->last_stamp);
										pthread_mutex_lock(&g_list_lock);
										double_list_append_as_tail(
											&g_alive_list, &pconnect->node);
										pthread_mutex_unlock(&g_list_lock);
									} else {
										relay_agent_close(pconnect->sockd);
										pconnect->sockd = -1;
										pconnect->stat = STAT_DEAD;
									}
								} else {
									pthread_mutex_unlock(&g_list_lock);	
								}
							}
						}
					}
				}
			}
			if (pnode == ptail) {
				break;
			}
		}
		i = 0;
	}
}

static int relay_agent_connect(const char *ip, int port)
{
	int opt_len;
	int val_opt;
	int sockd, opt;
	char response;
	fd_set myset;
	BOOL b_connected;
	struct timeval tv;
	struct sockaddr_in servaddr;
	
	/* try to connect to the destination MTA */
	b_connected = FALSE;
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	/* set the socket to block mode */
	opt = fcntl(sockd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(sockd, F_SETFL, opt);
	/* end of set mode */
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	if (0 == connect(sockd, (struct sockaddr*)&servaddr,sizeof(servaddr))) {
		b_connected = TRUE;
		/* set socket back to block mode */
		opt = fcntl(sockd, F_GETFL, 0);
		opt &= (~O_NONBLOCK);
		fcntl(sockd, F_SETFL, opt);
		/* end of set mode */
	} else {
		if (EINPROGRESS == errno) {
			tv.tv_sec = SOCKET_TIMEOUT;
			tv.tv_usec = 0;
			FD_ZERO(&myset);
			FD_SET(sockd, &myset);
			if (select(sockd + 1, NULL, &myset, NULL, &tv) > 0) {
				opt_len = sizeof(int);
				if (getsockopt(sockd, SOL_SOCKET, SO_ERROR, &val_opt,
					&opt_len) >= 0) {
					if (0 == val_opt) {
						b_connected = TRUE;
						/* set socket back to block mode */
						opt = fcntl(sockd, F_GETFL, 0);
						opt &= (~O_NONBLOCK);
						fcntl(sockd, F_SETFL, opt);
						/* end of set mode */
					}
				}
			}
		} 
	}
	if (FALSE == b_connected) {
		close(sockd);
        return -1;
	}
	/* wait the socket data to be available */
	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		close(sockd);
		return -1;
	}
	if (1 != read(sockd, &response, 1)) {
		close(sockd);
		return -1;
	}
	if (RESPONSE_CONNECT_ACCEPT == response) {
		return sockd;
	} else {
		close(sockd);
		return -1;
	}
}

static void relay_agent_close(int sockd)
{
	char command;
	
	if (-1 != sockd) {
		command = COMMAND_CONNECT_CLOSE;
		write(sockd, &command, 1);
		close(sockd);
	}
}

static BOOL relay_agent_ping(int sockd)
{
	char command;
	char response;
	fd_set myset;
	struct timeval tv;

	if (-1 == sockd) {
		return FALSE;
	}
	command = COMMAND_CONNECT_PING;
	if (1 != write(sockd, &command, 1)) {
		return FALSE;
	}
	/* wait the socket data to be available */
	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		return FALSE;
	}
	
	if (1 != read(sockd, &response, 1)) {
		return FALSE;
	}
		
	if (RESPONSE_PING_OK != response) {
		return FALSE;
	}
	return TRUE;
}

static BOOL relay_agent_send(int sockd, BOOL b_64bit, const char *path)
{
	void *ptr;
	int ptr_len;
	char command;
	char response;
	int fd, read_len;
	int written_len;
	uint32_t fake32;
	uint64_t fake64;
	struct stat node_stat;
	struct timeval tv;
	fd_set myset;
	char buff[BUFFER_SIZE];
	
	if (-1 == sockd) {
		return FALSE;
	}
	
	if (0 != stat(path, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	if (TRUE == b_64bit) {
		if (8 == sizeof(node_stat.st_size)) {
			ptr = &node_stat.st_size;
		} else {
			fake64 = node_stat.st_size;
			ptr = &fake64;
		}
		ptr_len = 8;
	} else {
		if (8 == sizeof(node_stat.st_size)) {
			fake32 = node_stat.st_size;
			fake32 = htonl(fake32);
		} else {
			fake32 = htonl(node_stat.st_size);
		}
		ptr = &fake32;
		ptr_len = 4;
	}

	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		return FALSE;
	}
	
	command = COMMAND_SEND_BUFFER;
	if (1 != write(sockd, &command, 1)) {
		close(fd);
		return FALSE;
	}
	/* wait the socket data to be available */
	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		close(fd);
		return FALSE;
	}
	
	if (1 != read(sockd, &response, 1)) {
		close(fd);
		return FALSE;
	}

	if (RESPONSE_RECV_READY != response) {
		close(fd);
		return FALSE;
	}

	if (ptr_len != write(sockd, ptr, ptr_len)) {
		close(fd);
		return FALSE;
	}
	
	while ((read_len = read(fd, buff, BUFFER_SIZE)) > 0) {
		written_len = write(sockd, buff, read_len);
		if (written_len != read_len) {
			close(fd);
			return FALSE;
		}
	}
	
	close(fd);

	/* wait the socket data to be available */
	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		return FALSE;
	}
	
	if (1 != read(sockd, &response, 1)) {
		return FALSE;
	}

	if (RESPONSE_RECV_OK != response) {
		return FALSE;
	}
	return TRUE;
}


static BOOL relay_agent_zip(MESSAGE_CONTEXT *pcontext, BOOL b_64bit,
	char *zipped_path)
{
	int fd;
	void *ptr;
	int ptr_len;
	int temp_id;
	uint64_t fake64;
	uint32_t fake32;
	size_t mess_len;
	int temp_len;
	int read_len;
	int bound_type;
	gzFile gz_fd;
	char rcpt_to[256];
	char temp_path[256];
	char buff[BUFFER_SIZE];
	
	pthread_mutex_lock(&g_id_lock);
	if (g_fake_id == 0X7FFFFFFF) {
		g_fake_id = 0;
	}
	temp_id = (++g_fake_id);
	pthread_mutex_unlock(&g_id_lock);
	
	sprintf(temp_path, "%s/%d.agent", g_save_path, temp_id);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_RDWR, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	
	mess_len = mail_get_length(pcontext->pmail);
	if (-1 == mess_len) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
		
	if (TRUE == pcontext->pcontrol->need_bounce) {
		temp_len = 25;
		mess_len += 25;
		strcpy(buff, "X-Penetrate-Bounce: Yes\r\n");
	} else {
		temp_len = 24;
		mess_len += 24;
		strcpy(buff, "X-Penetrate-Bounce: No\r\n");	
	}
	bound_type = SMTP_RELAY;
	if (TRUE == b_64bit) {
		if (8 == sizeof(mess_len)) {
			ptr = &mess_len;
		} else {
			fake64 = (uint64_t)mess_len;
			ptr = &fake64;
		}
		ptr_len = 8;
	} else {
		if (8 == sizeof(mess_len)) {
			fake32 = (uint32_t)mess_len;
			ptr = &fake32;
		} else {
			ptr = &mess_len;
		}
		ptr_len = 4;
	}
	if (ptr_len != write(fd, ptr, ptr_len) ||
		temp_len != write(fd, buff, temp_len) ||
		FALSE == mail_to_file(pcontext->pmail, fd) ||
		sizeof(int) != write(fd, &pcontext->pcontrol->queue_ID,
		sizeof(int)) || sizeof(int) != write(fd, &bound_type, sizeof(int)) ||
		sizeof(int) != write(fd, &pcontext->pcontrol->is_spam, sizeof(BOOL))) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}

	temp_len = strlen(pcontext->pcontrol->from);
	temp_len ++;
	if (temp_len != write(fd, pcontext->pcontrol->from, temp_len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	/* write envelop rcpt */
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != (temp_len = mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, rcpt_to, 256))) {
		rcpt_to[temp_len] = '\0';
		temp_len ++;
		if (temp_len != write(fd, rcpt_to, temp_len)) {
			close(fd);
			remove(temp_path);
			return FALSE;	 
		}
	}
	/* last null character for indicating end of rcpt to array */
	*rcpt_to = 0;
	if (1 != write(fd, rcpt_to, 1)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	

	sprintf(zipped_path, "%s/%d.gz", g_save_path, temp_id);
	gz_fd = gzopen(zipped_path, "wb");
	if (Z_NULL == gz_fd) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}

	lseek(fd, 0, SEEK_SET);
	
	while ((read_len = read(fd, buff, BUFFER_SIZE)) > 0) {
		if (read_len != gzwrite(gz_fd, buff, read_len)) {
			close(fd);
			gzclose(gz_fd);
			remove(temp_path);
			remove(zipped_path);
			return FALSE;
		}
	}
	close(fd);
	gzclose(gz_fd);
	remove(temp_path);
	return TRUE;
}

BOOL relay_agent_process(MESSAGE_CONTEXT *pcontext)
{
	char zipped_path[256];
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_UNIT *pconnect;

	if (0 == double_list_get_nodes_num(&g_alive_list)) {
		return FALSE;
	}

	switch (g_bit_mode) {
	case BIT_MODE_MIX:
		pthread_mutex_lock(&g_list_lock);
		pnode = double_list_get_from_head(&g_alive_list);
		if (NULL == pnode) {
			pthread_mutex_unlock(&g_list_lock);
			return FALSE;
		}
		pconnect = (CONNECTION_UNIT*)pnode->pdata;
		if (TRUE == pconnect->phost->alive) {
			pconnect->stat = STAT_USING;
		} else {
			pconnect->stat = STAT_DEAD;
			pthread_mutex_unlock(&g_list_lock);
			relay_agent_close(pconnect->sockd);
			pconnect->sockd = -1;
			return FALSE;
		}
		pthread_mutex_unlock(&g_list_lock);
		
		if (FALSE == relay_agent_zip(pcontext, pconnect->phost->b_64bit,
			zipped_path)) {
			pthread_mutex_lock(&g_list_lock);
			pconnect->stat = STAT_ALIVE;
			double_list_append_as_tail(&g_alive_list, pnode);
			pthread_mutex_unlock(&g_list_lock);
			return FALSE;
		}
		break;
	case BIT_MODE_32:
		if (FALSE == relay_agent_zip(pcontext, FALSE, zipped_path)) {
			return FALSE;
		}
		pthread_mutex_lock(&g_list_lock);
		pnode = double_list_get_from_head(&g_alive_list);
		if (NULL == pnode) {
			remove(zipped_path);
			pthread_mutex_unlock(&g_list_lock);
			return FALSE;
		}
		pconnect = (CONNECTION_UNIT*)pnode->pdata;
		if (TRUE == pconnect->phost->alive) {
			pconnect->stat = STAT_USING;
		} else {
			pconnect->stat = STAT_DEAD;
			pthread_mutex_unlock(&g_list_lock);
			relay_agent_close(pconnect->sockd);
			pconnect->sockd = -1;
			remove(zipped_path);
			return FALSE;
		}
		pthread_mutex_unlock(&g_list_lock);

		if (FALSE != pconnect->phost->b_64bit) {
			pthread_mutex_lock(&g_list_lock);
			pconnect->stat = STAT_ALIVE;
			double_list_append_as_tail(&g_alive_list, pnode);
			pthread_mutex_unlock(&g_list_lock);
			remove(zipped_path);
			return FALSE;
		}
		break;
	case BIT_MODE_64:
		if (FALSE == relay_agent_zip(pcontext, TRUE, zipped_path)) {
			return FALSE;
		}
		pthread_mutex_lock(&g_list_lock);
		pnode = double_list_get_from_head(&g_alive_list);
		if (NULL == pnode) {
			remove(zipped_path);
			pthread_mutex_unlock(&g_list_lock);
			return FALSE;
		}
		pconnect = (CONNECTION_UNIT*)pnode->pdata;
		if (TRUE == pconnect->phost->alive) {
			pconnect->stat = STAT_USING;
		} else {
			pconnect->stat = STAT_DEAD;
			pthread_mutex_unlock(&g_list_lock);
			relay_agent_close(pconnect->sockd);
			pconnect->sockd = -1;
			remove(zipped_path);
			return FALSE;
		}
		pthread_mutex_unlock(&g_list_lock);

		if (TRUE != pconnect->phost->b_64bit) {
			pthread_mutex_lock(&g_list_lock);
			pconnect->stat = STAT_ALIVE;
			double_list_append_as_tail(&g_alive_list, pnode);
			pthread_mutex_unlock(&g_list_lock);
			remove(zipped_path);
			return FALSE;
		}
		break;
	}
	
	if (TRUE == relay_agent_send(pconnect->sockd,
		pconnect->phost->b_64bit, zipped_path)) {
		time(&pconnect->last_stamp);
		pthread_mutex_lock(&g_list_lock);
		pconnect->stat = STAT_ALIVE;
		double_list_append_as_tail(&g_alive_list, pnode);
		pthread_mutex_unlock(&g_list_lock);
		relay_agent_log_info(pcontext, 8, "transfer message to oversea "
			"site %s:%d OK", pconnect->phost->ip, pconnect->phost->port);		
		remove(zipped_path);
		return TRUE;
	} else {
		relay_agent_close(pconnect->sockd);
		pconnect->sockd = -1;
		pthread_mutex_lock(&g_list_lock);
		pconnect->stat = STAT_DEAD;
		pthread_mutex_unlock(&g_list_lock);
		remove(zipped_path);
		return FALSE;
	}
}

int relay_agent_get_param(int param)
{
	if (RELAY_SWITCH == param) {
		return g_relay_switch;
	} else if (CHANNEL_NUM == param) {
		return g_channel_num;
	}
	return 0;

}

void relay_agent_set_param(int param, int value)
{
	if (RELAY_SWITCH == param) {
		g_relay_switch = value;
	}
}

static void relay_agent_log_info(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...)
{
	char log_buf[2048], rcpt_buff[2048];
	size_t size_read = 0, rcpt_len = 0, i;
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	log_buf[sizeof(log_buf) - 1] = '\0';

	/* maximum record 8 rcpt to address */
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
					MEM_FILE_SEEK_BEGIN);
	for (i=0; i<8; i++) {
		size_read = mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
					                  rcpt_buff + rcpt_len, 256);
		if (size_read == MEM_END_OF_FILE) {
			break;
		}
		rcpt_len += size_read;
		rcpt_buff[rcpt_len] = ' ';
		rcpt_len ++;
	}
	rcpt_buff[rcpt_len] = '\0';
	switch (pcontext->pcontrol->bound_type) {
	case BOUND_IN:
	case BOUND_OUT:
	case BOUND_RELAY:
		log_info(level, "SMTP message queue-ID: %d, FROM: %s, TO: %s %s",
			pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
			rcpt_buff, log_buf);
		break;
	default:
		log_info(level, "APP created message FROM: %s, TO: %s %s",
			pcontext->pcontrol->from, rcpt_buff, log_buf);
		break;
	}
}

