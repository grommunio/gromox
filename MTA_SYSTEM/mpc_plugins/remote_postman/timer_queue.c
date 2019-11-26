#include "timer_queue.h"
#include "smtp_deliverer.h"
#include "files_allocator.h"
#include "net_failure.h"
#include "bounce_producer.h"
#include "double_list.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define MAX_CIRCLE_NUMBER   0x7FFFFFFF
#define THREAD_STACK_SIZE   0x100000
#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct _TIMER_ITEM {
	DOUBLE_LIST_NODE	node;
	int					fd;
	int					file_size;
	char				file_name[256];
	pthread_t           thr_id;
} TIMER_ITEM;

static char g_path[256];
static int g_mess_id;
static int g_scan_interval;
static int g_max_threads;
static void	*g_list_ptr;
static int g_intervals[TIMER_QUEUE_NUM];
static pthread_t g_thread_id;
static pthread_mutex_t g_id_lock;
static pthread_mutex_t g_scan_lock;
static DOUBLE_LIST g_free_list;
static DOUBLE_LIST g_scan_list;
static BOOL g_notify_stop = TRUE;

static int timer_queue_retrieve_mess_ID();

static int timer_queue_increase_mess_ID();

static void timer_queue_feedback_item(TIMER_ITEM *pitem);

static void* scan_work_func(void* arg);

static void* thread_work_func(void* arg);

/*
 *	timer queue's construct function
 *	@param
 *		path [in]				queue path
 *		scan_interval			interval of queue scanning
 *		fresh_interval			interval of trying to deliver the first time
 *		retrying_interval		interval of trying to deliver the second time
 *		final_interval			interval of trying to deliver the last time
 */
void timer_queue_init(const char *path, int max_thr, int scan_interval,
	int fresh_interval, int retrying_interval, int final_interval)
{
	strcpy(g_path, path);
	g_scan_interval = scan_interval;
	g_max_threads = max_thr;
	g_list_ptr = NULL;
	g_notify_stop = TRUE;
	g_intervals[TIMER_QUEUE_FRESH] = fresh_interval;
	g_intervals[TIMER_QUEUE_RETRYING] = retrying_interval;
	g_intervals[TIMER_QUEUE_FINAL] = final_interval;
	pthread_mutex_init(&g_id_lock, NULL);
	pthread_mutex_init(&g_scan_lock, NULL);
	double_list_init(&g_free_list);
	double_list_init(&g_scan_list);
}

/*
 *	run the timer queue module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int timer_queue_run()
{
	pthread_attr_t  attr;
	struct stat node_stat;
	TIMER_ITEM *pitem;
	int i;

	/* check the directory */
    if (0 != stat(g_path, &node_stat)) {
        printf("[remote_postman]: can not find %s directory\n", g_path);
        return -1;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
        printf("[remote_postman]: %s is not a directory\n", g_path);
        return -2;
    }
	g_mess_id = timer_queue_retrieve_mess_ID();
	g_list_ptr = (TIMER_ITEM*)malloc(g_max_threads*sizeof(TIMER_ITEM));
	if (NULL == g_list_ptr) {
        printf("[remote_postman]: fail to allocate memory for threads list\n");
        return -3;
	}
	memset(g_list_ptr, 0, g_max_threads*sizeof(TIMER_ITEM));
	for (i=0; i<g_max_threads; i++) {
		pitem = (TIMER_ITEM*)g_list_ptr + i;
		pitem->node.pdata = pitem;
		double_list_append_as_tail(&g_free_list, &pitem->node);
	}
	g_notify_stop = FALSE;
	pthread_attr_init(&attr);
	if(0 != pthread_create(&g_thread_id, &attr, scan_work_func, NULL)) {
		pthread_attr_destroy(&attr);
		free(g_list_ptr);
		g_list_ptr = NULL;
		g_notify_stop = TRUE;
		printf("[remote_postman]: fail to create timer thread\n");
		return -6;
	}
	pthread_attr_destroy(&attr);
	return 0;
}

/*
 *	stop the timer queue module
 *	@return
 *		 0					OK
 *		<>0					fail
 */
void timer_queue_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	if (NULL != g_list_ptr) {
		free(g_list_ptr);
		g_list_ptr = NULL;
	}
}

/*
 *	timer queue's destruct function
 */
void timer_queue_free()
{
	g_notify_stop = TRUE;
	g_path[0] = '\0';
	g_scan_interval = 0;
	g_intervals[TIMER_QUEUE_FRESH] = 0;
    g_intervals[TIMER_QUEUE_RETRYING] = 0;
    g_intervals[TIMER_QUEUE_FINAL] = 0;
	pthread_mutex_destroy(&g_id_lock);
	pthread_mutex_destroy(&g_scan_lock);
	double_list_free(&g_free_list);
	double_list_free(&g_scan_list);
}

/*
 *	put message into timer queue
 *	@param
 *		pcontext [in]		message context to be sent
 *		original_time		original time
 *		is_untried			indicate whether the message has never been tried
 *	@return
 *		>=0					timer ID
 *		<0					fail
 */
int timer_queue_put(MESSAGE_CONTEXT *pcontext, time_t original_time,
	BOOL is_untried)
{
	int mess_id, len, temp_len;
	char file_name[256];
	char tmp_buff[256];
	time_t current_time;
	time_t until_time, fake_time;
	int fd, type;

	mess_id = timer_queue_increase_mess_ID();
	sprintf(file_name, "%s/%d", g_path, mess_id);
	fd = open(file_name, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return -1;
	}
	time(&current_time);
	if (TRUE == is_untried) {
		type = TIMER_QUEUE_UNTRIED;
		until_time = current_time + g_scan_interval;
	} else {
		type = TIMER_QUEUE_FRESH;
		until_time = current_time + g_intervals[TIMER_QUEUE_FRESH];
	}
	fake_time = 0;
	/* write 0 to indicate unfinished info file */
	/* write the type of message timer*/
	if (sizeof(time_t) != write(fd, &fake_time, sizeof(time_t)) ||
		sizeof(int) != write(fd, &type, sizeof(int)) ||
		sizeof(time_t) != write(fd, &original_time, sizeof(time_t))) {
		close(fd);
		remove(file_name);
        return -1;
	}
	/* at the begin of file, write the length of message */
	len = mail_get_length(pcontext->pmail);
	if (-1 == len) {
		printf("[remote_postman]: fail to get mail length\n");
		close(fd);
        remove(file_name);
        return -1;
	}
	if (sizeof(int) != write(fd, &len, sizeof(int))) {
		close(fd);
        remove(file_name);
        return -1;
	}
	if (FALSE == mail_to_file(pcontext->pmail, fd) ||
		sizeof(int) != write(fd, &pcontext->pcontrol->queue_ID, sizeof(int)) ||
		sizeof(int) != write(fd, &pcontext->pcontrol->bound_type, sizeof(int))||
		sizeof(BOOL) != write(fd, &pcontext->pcontrol->is_spam, sizeof(BOOL))||
		sizeof(BOOL) != write(fd, &pcontext->pcontrol->need_bounce,
		sizeof(BOOL))) {
        close(fd);
        remove(file_name);
        return -1;
    }
	/* write envelop from */
    temp_len = strlen(pcontext->pcontrol->from);
    temp_len ++;
    if (temp_len != write(fd, pcontext->pcontrol->from, temp_len)) {
        close(fd);
        remove(file_name);
        return -1;
    }
	/* write envelop rcpt */
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
			MEM_FILE_SEEK_BEGIN);
    while (MEM_END_OF_FILE != (temp_len = mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, tmp_buff, 256))) {
		tmp_buff[temp_len] = '\0';
		temp_len ++;
		if (temp_len != write(fd, tmp_buff, temp_len)) {
			close(fd);
			remove(file_name);
			return -1;
		}
    }
    /* last null character for indicating end of rcpt to array */
    *tmp_buff = 0;
    if (1 != write(fd, tmp_buff, 1)) {
		close(fd);
        remove(file_name);
        return -1;
	}
	lseek(fd, 0, SEEK_SET);
	if (sizeof(time_t) != write(fd, &until_time, sizeof(time_t))) {
		close(fd);
        remove(file_name);
        return -1;
	}
	close(fd);
	return mess_id;
}

/*
 *	retrieve the message ID in the queue
 *	@return
 *		message ID
 */
static int timer_queue_retrieve_mess_ID()
{
	DIR *dirp;
    struct dirent *direntp;
    int max_ID = 0, temp_ID;

    /*
    read every file under directory and retrieve the maximum number and
    return it
    */
    dirp = opendir(g_path);
    while ((direntp = readdir(dirp)) != NULL) {
    	temp_ID = atoi(direntp->d_name);
        if (temp_ID > max_ID) {
            max_ID = temp_ID;
        }
    }
    closedir(dirp);
    return max_ID;
}

/*
 *	increase the message ID with 1
 *	@return
 *		message ID before increasement
 */
static int timer_queue_increase_mess_ID()
{
	int current_id;
    pthread_mutex_lock(&g_id_lock);
    if (MAX_CIRCLE_NUMBER == g_mess_id) {
        g_mess_id = 1;
    } else {
        g_mess_id ++;
    }
    current_id  = g_mess_id;
    pthread_mutex_unlock(&g_id_lock);
    return current_id;
}

static void* scan_work_func(void* arg)
{
	DIR *dirp;
	BOOL b_sending;
	int create_result, i;
	int scan_interval, fd;
	time_t scan_begin, scan_end;
	time_t until_time, current_time;
    struct dirent *direntp;
	struct stat node_stat;
    char temp_path[256];
	DOUBLE_LIST_NODE *pnode;
	TIMER_ITEM *pitem;
	pthread_attr_t attr;

	
	dirp = opendir(g_path);
	i = 0;
	scan_interval = g_scan_interval;
	while (FALSE == g_notify_stop) {
		if (i < scan_interval) {
			i ++;
			sleep(1);
			continue;
		}
		seekdir(dirp, 0);
		time(&scan_begin);
    	while ((direntp = readdir(dirp)) != NULL) {
			if (FALSE != g_notify_stop) {
				break;
			}
			sprintf(temp_path, "%s/%s", g_path, direntp->d_name);
			if (0 != stat(temp_path, &node_stat) ||
                0 == S_ISREG(node_stat.st_mode)) {
                continue;
            }
			/* check whether the file is now being sent */
			b_sending = FALSE;
			pthread_mutex_lock(&g_scan_lock);
			for (pnode=double_list_get_head(&g_scan_list); NULL!=pnode;
				pnode=double_list_get_after(&g_scan_list, pnode)) {
				pitem = (TIMER_ITEM*)pnode->pdata;
				if (0 == strcmp(pitem->file_name, direntp->d_name)) {
					b_sending = TRUE;
					break;
				}
			}
			pthread_mutex_unlock(&g_scan_lock);
			if (TRUE == b_sending) {
				continue;
			}
            fd = open(temp_path, O_RDWR);
			if (-1 == fd) {
				continue;
			}
			if (sizeof(time_t) != read(fd, &until_time, sizeof(time_t))) {
				close(fd);
				continue;
			}
			if (0 == until_time) {
				close(fd);
                continue;
			}
			time(&current_time);
			/* wether the message should be tried again */
			if (current_time < until_time) {
				close(fd);
                continue;
			}
			/* get one item node from free list */
			pthread_mutex_lock(&g_scan_lock);
			pnode = double_list_get_from_head(&g_free_list);
			pthread_mutex_unlock(&g_scan_lock);
			/* if there's no free item, it means maximum threads were created */
			if (NULL == pnode) {
				close(fd);
				continue;
			}
			pitem = (TIMER_ITEM*)pnode->pdata;
			pitem->fd = fd;
			pitem->file_size = node_stat.st_size;
			strcpy(pitem->file_name, direntp->d_name);
			
			/* append the node into scan list */
			pthread_mutex_lock(&g_scan_lock);
			double_list_append_as_tail(&g_scan_list, &pitem->node);
			pthread_mutex_unlock(&g_scan_lock);
			
			pthread_attr_init(&attr);
			pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
			create_result = pthread_create(&pitem->thr_id, &attr,
								thread_work_func, pitem);
			pthread_attr_destroy(&attr);
			/*
			 * if fail to create sending thread, move the node from 
			 * scan list to free list
			 */
			if (0 != create_result) {
				close(fd);
				pthread_mutex_lock(&g_scan_lock);
				double_list_remove(&g_scan_list, &pitem->node);
				double_list_append_as_tail(&g_scan_list, &pitem->node);
				pthread_mutex_unlock(&g_scan_lock);

			}
    	}
		time(&scan_end);
		if (scan_end - scan_begin >= g_scan_interval) {
			scan_interval = 0;
		} else {
			scan_interval = g_scan_interval - (scan_end - scan_begin);
		}
		i = 0;
	}
    closedir(dirp);
	pthread_mutex_lock(&g_scan_lock);
	while ((pnode = double_list_get_from_head(&g_scan_list)) != NULL) {
		pitem = (TIMER_ITEM*)pnode->pdata;
		pthread_cancel(pitem->thr_id);
	}
	pthread_mutex_unlock(&g_scan_lock);
	return NULL;
}

static void* thread_work_func(void* arg)
{
	char ip_addr[16];
	TIMER_ITEM *pitem;
	char *pbuff, *ptr;
	time_t current_time;
	int type, size, len;
	char temp_path[256];
	char reason_buff[1024];
	MESSAGE_CONTEXT *pcontext;
	int mess_len, bounce_type;
	time_t until_time, original_time;
	MESSAGE_CONTEXT *pbounce_context;
	BOOL b_giveup, need_bounce, need_remove;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pitem = (TIMER_ITEM*)arg;
	pcontext = get_context();
	if (NULL == pcontext) {
		printf("[remote_postman]: fail to get message context for %s in "
				"timer queue thread\n", pitem->file_name);
		timer_queue_feedback_item(pitem);
		pthread_detach(pthread_self());
		pthread_exit(0);
	}
	if (sizeof(int) != read(pitem->fd, &type, sizeof(int)) ||
		sizeof(time_t) != read(pitem->fd, &original_time, sizeof(time_t)) ||
		sizeof(int) != read(pitem->fd, &mess_len, sizeof(int))) {
		printf("[remote_postman]: fail to read information from %s "
				"in timer queue\n", pitem->file_name);
		timer_queue_feedback_item(pitem);
		put_context(pcontext);
		pthread_detach(pthread_self());
		pthread_exit(0);
    }
	size = pitem->file_size - 2*sizeof(time_t) - 2*sizeof(int);
	pbuff = malloc(((size - 1)/(64 * 1024) + 1) * 64 * 1024);
	if (NULL == pbuff) {
		printf("[remote_postman]: fail to allocate memory for %s in "
				"timer queue thread\n", pitem->file_name);
		timer_queue_feedback_item(pitem);
		put_context(pcontext);
		pthread_detach(pthread_self());
		pthread_exit(0);
	}
	if (size != read(pitem->fd, pbuff, size)) {
		free(pbuff);
		printf("[remote_postman]: fail to read information from %s "
				"in timer queue\n", pitem->file_name);
		timer_queue_feedback_item(pitem);
		put_context(pcontext);
		pthread_detach(pthread_self());
		pthread_exit(0);
	}
	if (FALSE == mail_retrieve(pcontext->pmail, pbuff, mess_len)) {
		free(pbuff);
		printf("[remote_postman]: fail to retrieve message %s in timer"
				"queue into mail object\n", pitem->file_name);
		timer_queue_feedback_item(pitem);
		put_context(pcontext);
		pthread_detach(pthread_self());
		pthread_exit(0);
	}
	ptr = pbuff + mess_len;
	pcontext->pcontrol->queue_ID = *(int*)ptr;
	ptr += sizeof(int);
	pcontext->pcontrol->bound_type = *(int*)ptr;
	ptr += sizeof(int);
	pcontext->pcontrol->is_spam = *(BOOL*)ptr;
	ptr += sizeof(BOOL);
	pcontext->pcontrol->need_bounce = *(BOOL*)ptr;
	ptr += sizeof(BOOL);
	strcpy(pcontext->pcontrol->from, ptr);
	ptr += strlen(pcontext->pcontrol->from) + 1;
	mem_file_clear(&pcontext->pcontrol->f_rcpt_to);
	while ((len = strlen(ptr)) != 0) {
		mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, ptr);
		ptr += len + 1;
	}
	if (TIMER_QUEUE_FINAL == type) {
		need_bounce = TRUE;
		need_remove = TRUE;
	} else {
		need_bounce = FALSE;
		need_remove = FALSE;
	}
	b_giveup = FALSE;
	switch (smtp_deliverer_process(pcontext,
		ip_addr, reason_buff, 1024)) {
	case SMTP_DELIVERER_GIVE_UP:
		b_giveup = TRUE;
		need_bounce = FALSE;
		need_remove = FALSE;
		net_failure_statistic(0, 0, 0, 1);
		break;	
    case SMTP_DELIVERER_DNS_ERROR:
		type ++;
		bounce_type = BOUNCE_DNS_ERROR;
		net_failure_statistic(0, 1, 0, 0);
		break;	
    case SMTP_DELIVERER_CANNOT_CONNECT:
		type ++;
		bounce_type = BOUNCE_CANNOT_CONNECT;
		net_failure_statistic(0, 1, 0, 0);
		break;
    case SMTP_DELIVERER_TIME_OUT:
		type ++;
		bounce_type = BOUNCE_TIME_OUT;
		net_failure_statistic(0, 1, 0, 0);
        break;
    case SMTP_DELIVERER_CONNECTION_REFUSED:
		bounce_type = BOUNCE_CONNECTION_REFUSED;
		net_failure_statistic(0, 0, 1, 0);
		need_bounce = TRUE;
		need_remove = TRUE;
		break;
	case SMTP_DELIVERER_EXCEED_SIZE:
		net_failure_statistic(0, 0, 1, 0);
		bounce_type = BOUNCE_EXCEED_SIZE;
		need_bounce = TRUE;
		need_remove = TRUE;
		break;
	case SMTP_DELIVERER_NO_USER:
		net_failure_statistic(0, 0, 1, 0);
		bounce_type = BOUNCE_NO_USER;
		need_bounce = TRUE;
		need_remove = TRUE;
		break;
    case SMTP_DELIVERER_TEMP_ERROR:
    case SMTP_DELIVERER_UNKOWN_RESPONSE:
		type ++;
		net_failure_statistic(0, 1, 0, 0);
		bounce_type = BOUNCE_RESPONSE_ERROR;
		break;
	case SMTP_DELIVERER_PERMANENT_ERROR:
		net_failure_statistic(0, 0, 1, 0);
		bounce_type = BOUNCE_RESPONSE_ERROR;
		need_bounce = TRUE;
		need_remove = TRUE;
		break;
	case SMTP_DELIVERER_OK:
		need_remove = TRUE;
		need_bounce = FALSE;
		net_failure_statistic(1, 0, 0, 0);
		break;
	default:
		printf("[remote_postman]: fatal error of return value of "
			"smtp_deliverer_process\n");
		bounce_type = BOUNCE_CANNOT_CONNECT;
		break;
	}
	need_bounce &= pcontext->pcontrol->need_bounce;	
	if (FALSE == need_remove) {
		/* rewite type and until time */
		lseek(pitem->fd, 0, SEEK_SET);
		time(&current_time);
		if (FALSE == b_giveup) {
			until_time = current_time + g_intervals[type];
		} else {
			until_time = current_time + g_scan_interval;
		}
		if (sizeof(time_t) != write(pitem->fd, &until_time, sizeof(time_t))) {
			printf("[remote_postman]: fatal error when updating time "
					"stamp!!!\n");
		} else {
			if (sizeof(int) != write(pitem->fd, &type, sizeof(int))) {
				printf("[remote_postman]: fatal error when updating timer "
						"type!!!\n");
			}
		}
	}
	close(pitem->fd);
	pitem->fd = -1;
	if (TRUE == need_bounce) {
		pbounce_context = get_context();
	    if (NULL == pbounce_context) {
			smtp_deliverer_log_info(pcontext, 8, "fail to get one "
					"context for bounce mail");
		} else {
            bounce_producer_make(pcontext, original_time, bounce_type,
				ip_addr, reason_buff, pbounce_context->pmail);
            sprintf(pbounce_context->pcontrol->from,"postmaster@%s",
					get_default_domain());
            mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
                pcontext->pcontrol->from);
			pbounce_context->pcontrol->bound_type = BOUND_REMOTE_BOUNCE;
            enqueue_context(pbounce_context);
		}
    }
	if (TRUE == need_remove) {
		sprintf(temp_path, "%s/%s", g_path, pitem->file_name);
		remove(temp_path);
	}
	put_context(pcontext);
	free(pbuff);
	timer_queue_feedback_item(pitem);
	pthread_detach(pthread_self());
	pthread_exit(0);
}

static void timer_queue_feedback_item(TIMER_ITEM *pitem)
{
	if (-1 != pitem->fd) {
		close(pitem->fd);
	}
	pthread_mutex_lock(&g_scan_lock);
	double_list_remove(&g_scan_list, &pitem->node);
	double_list_append_as_tail(&g_free_list, &pitem->node);
	pthread_mutex_unlock(&g_scan_lock);
}

int timer_queue_get_param(int param)
{
	if (param >= 0 && param < TIMER_QUEUE_NUM) { 
		return g_intervals[param];
	} else if (TIMER_QUEUE_SCAN_INTERVAL == param) {
		return g_scan_interval;
	} else if (TIMER_QUEUE_THREADS_MAX == param) {
		return g_max_threads;
	} else if (TIMER_QUEUE_THREADS_NUM == param) {
		return double_list_get_nodes_num(&g_scan_list);
	}
	return 0;
}

void timer_queue_set_param(int param, int val)
{
	if (param >= 0 && param < TIMER_QUEUE_NUM) { 
		g_intervals[param] = val;
	} else if (TIMER_QUEUE_SCAN_INTERVAL == param) {
		g_scan_interval = val;
	}
}

