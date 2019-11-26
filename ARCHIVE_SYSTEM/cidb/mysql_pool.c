#include "util.h"
#include "mysql_pool.h"
#include "common_types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>


static int g_conn_num;
static int g_scan_interval;
static int g_port;
static int g_timeout;
static char g_host[256];
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];
static pthread_mutex_t g_list_lock;
static DOUBLE_LIST g_connection_list;
static DOUBLE_LIST g_invalid_list;
static pthread_t g_thread_id;
static BOOL g_notify_stop = TRUE;

static void *thread_work_func(void *param);

void mysql_pool_init(int conn_num, int scan_interval, const char *host,
	int port, const char *user, const char *password, const char *db_name,
	int timeout)
{
	g_notify_stop = TRUE;
	g_conn_num = conn_num;
	g_scan_interval = scan_interval;
	strcpy(g_host, host);
	g_port = port;
	strcpy(g_user, user);
	if (NULL == password || '\0' == password[0]) {
		g_password = NULL;
	} else {
		strcpy(g_password_buff, password);
		g_password = g_password_buff;
	}
	strcpy(g_db_name, db_name);
	g_timeout = timeout;
	double_list_init(&g_connection_list);
	double_list_init(&g_invalid_list);
	pthread_mutex_init(&g_list_lock, NULL);
}

int mysql_pool_run()
{
	int i;
	MYSQL_CONNECTION *pconnection;

	
	for (i=0; i<g_conn_num; i++) {
		pconnection = (MYSQL_CONNECTION*)malloc(sizeof(MYSQL_CONNECTION));
		if (NULL == pconnection) {
			continue;
		}
		pconnection->node.pdata = pconnection;
		pconnection->node_temp.pdata = pconnection;
		pconnection->pmysql = mysql_init(NULL);
		if (NULL != pconnection->pmysql) {
			if (g_timeout > 0) {
				mysql_options(pconnection->pmysql, MYSQL_OPT_READ_TIMEOUT,
					&g_timeout);
				mysql_options(pconnection->pmysql, MYSQL_OPT_WRITE_TIMEOUT,
					&g_timeout);
			}
			if (NULL != mysql_real_connect(pconnection->pmysql, g_host, g_user,
				g_password, g_db_name, g_port, NULL, 0)) {
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
			} else {
				printf("[mysql_pool]: fail to connect to mysql server, "
					"reason: %s\n", mysql_error(pconnection->pmysql));
				mysql_close(pconnection->pmysql);
				pconnection->pmysql = NULL;
				double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			}
		} else {
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
		}
	}

	if (0 == double_list_get_nodes_num(&g_connection_list) &&
		0 == double_list_get_nodes_num(&g_invalid_list)) {
		printf("[mysql_pool]: fail to init connection list\n");
		return -1;
	}
	
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_thread_id, NULL, thread_work_func, NULL)) {
		g_notify_stop = TRUE;
		printf("[mysql_pool]: fail to create scanning thread\n");
		return -2;
	}

	return 0;

}

int mysql_pool_stop()
{
	DOUBLE_LIST_NODE *pnode;
	MYSQL_CONNECTION *pconnection;

	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	
	while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
		pconnection = (MYSQL_CONNECTION*)pnode->pdata;
		if (NULL != pconnection->pmysql) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
		}
		free(pconnection);
	}
	
	while ((pnode = double_list_get_from_head(&g_invalid_list)) != NULL) {
		pconnection = (MYSQL_CONNECTION*)pnode->pdata;
		free(pconnection);
	}
	
	return 0;
}

void mysql_pool_free()
{
	double_list_free(&g_connection_list);
	double_list_free(&g_invalid_list);
	pthread_mutex_destroy(&g_list_lock);
}

MYSQL_CONNECTION* mysql_pool_get_connection()
{
	DOUBLE_LIST_NODE *pnode;


	pthread_mutex_lock(&g_list_lock);
	pnode = double_list_get_from_head(&g_connection_list);
	pthread_mutex_unlock(&g_list_lock);
	
	if (NULL == pnode) {
		return NULL;
	}

	return (MYSQL_CONNECTION*)pnode->pdata;
}


void mysql_pool_put_connection(MYSQL_CONNECTION *pconnection, BOOL b_alive)
{
	if (FALSE == b_alive) {
		/* try to reconnect mysql database */
		mysql_close(pconnection->pmysql);
		pconnection->pmysql = NULL;
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_invalid_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
	} else {	
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
	}
}


static void* thread_work_func(void *arg)
{
	int i;
	MYSQL_CONNECTION *pconnection;
	DOUBLE_LIST_NODE *phead, *ptail, *pnode;
	DOUBLE_LIST temp_list;
	
	i = 0;
	double_list_init(&temp_list);
	while (FALSE == g_notify_stop) {
		if (i < g_scan_interval) {
			sleep(1);
			i ++;
			continue;
		}
		pthread_mutex_lock(&g_list_lock);
		phead = double_list_get_head(&g_invalid_list);
		ptail = double_list_get_tail(&g_invalid_list);
		pthread_mutex_unlock(&g_list_lock);
		for (pnode=phead; NULL!=pnode; pnode=double_list_get_after(
			&g_invalid_list, pnode)) {
			pconnection = (MYSQL_CONNECTION*)pnode->pdata;
			pconnection->pmysql = mysql_init(NULL);
			if (NULL != pconnection->pmysql) {
				if (g_timeout > 0) {
					mysql_options(pconnection->pmysql, MYSQL_OPT_READ_TIMEOUT,
						&g_timeout);
					mysql_options(pconnection->pmysql, MYSQL_OPT_WRITE_TIMEOUT,
						&g_timeout);
				}
				if (NULL != mysql_real_connect(pconnection->pmysql, g_host,
					g_user, g_password, g_db_name, g_port, NULL, 0)) {
					double_list_append_as_tail(&temp_list,
						&pconnection->node_temp);
				} else {
					mysql_close(pconnection->pmysql);
					pconnection->pmysql = NULL;
				}
			}
			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_lock(&g_list_lock);
		ptail = double_list_get_tail(&g_connection_list);
		while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
			pconnection = (MYSQL_CONNECTION*)pnode->pdata;
			if (0 != mysql_ping(pconnection->pmysql)) {
				double_list_append_as_tail(&g_invalid_list, pnode);
			} else {
				double_list_append_as_tail(&g_connection_list, pnode);
			}
			if (pnode == ptail) {
				break;
			}
		}

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pconnection = (MYSQL_CONNECTION*)pnode->pdata;
			double_list_remove(&g_invalid_list, &pconnection->node);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
		}

		pthread_mutex_unlock(&g_list_lock);
		i = 0;
	}
	double_list_free(&temp_list);
	return NULL;
}

int mysql_pool_get_param(int param)
{
	switch(param) {
	case MYSQL_POOL_ALIVE_CONNECTION:
		return double_list_get_nodes_num(&g_connection_list);
	case MYSQL_POOL_DEAD_CONNECTION:
		return double_list_get_nodes_num(&g_invalid_list);
	}
	return -1;
}

