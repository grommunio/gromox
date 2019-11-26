#include <stdbool.h>
#include <libHX/defs.h>
#include "url_downloader.h"
#include "double_list.h"
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

typedef struct _CHILD_NODE {
	DOUBLE_LIST_NODE	node;
	pid_t				pid;
} CHILD_NODE;

static DOUBLE_LIST g_children_list;
static pthread_mutex_t g_list_lock;

void url_downloader_init()
{
	double_list_init(&g_children_list);
	pthread_mutex_init(&g_list_lock, NULL);
}

int url_downloader_run()
{
	/* do nothing */
	return 0;
}

BOOL url_downloader_get(const char *url, const char *save_path)
{
	pid_t pid;
	int status;
	CHILD_NODE temp_node;
	char option_buff[512];
	const char *args[] = {"wget", NULL, NULL, NULL, NULL};

	pid = fork();
	if (0 == pid) {
		snprintf(option_buff, sizeof(option_buff), "-O%s", save_path);
		args[1] = "-q";
		args[2] = url;
		args[3] = option_buff;
		execvp("wget", const_cast(char **, args));
		_exit(-1);
	} else if (pid > 0) {
		temp_node.pid = pid;
		temp_node.node.pdata = &temp_node;
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_children_list, &temp_node.node);
		pthread_mutex_unlock(&g_list_lock);
		waitpid(pid, &status, 0);
		pthread_mutex_lock(&g_list_lock);
		double_list_remove(&g_children_list, &temp_node.node);
		pthread_mutex_unlock(&g_list_lock);
		if (0 == WEXITSTATUS(status)) {
			return TRUE;
		}
	}
	return false;
}

int url_downloader_stop()
{
	DOUBLE_LIST_NODE *pnode;
	CHILD_NODE *pchild;

	pthread_mutex_lock(&g_list_lock);
	while ((pnode = double_list_get_from_head(&g_children_list)) != NULL) {
		pchild = (CHILD_NODE*)pnode->pdata;
		kill(pchild->pid, SIGKILL);
	}
	pthread_mutex_unlock(&g_list_lock);
	return 0;
}

void url_downloader_free()
{
	double_list_free(&g_children_list);
	pthread_mutex_destroy(&g_list_lock);
}

