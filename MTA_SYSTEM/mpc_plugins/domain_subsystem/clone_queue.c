#include <errno.h>
#include <string.h>
#include <gromox/defs.h>
#include "address_list.h"
#include "clone_queue.h"
#include "smtp_clone.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define MAX_CIRCLE_NUMBER   0x7FFFFFFF
#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static char g_path[256];
static int g_mess_id;
static int g_scan_interval;
static int g_retrying_times;
static pthread_t g_thread_id;
static pthread_mutex_t g_id_lock;
static BOOL g_notify_stop = TRUE;

static int clone_queue_retrieve_mess_ID(void);
static int clone_queue_increase_mess_ID(void);
static void* thread_work_func(void* arg);

/*
 *	timer queue's construct function
 *	@param
 *		path [in]				queue path
 *		scan_interval			interval of queue scanning
 *		retrying_times			retrying times of delivery
 */
void clone_queue_init(const char *path, int scan_interval, int retrying_times)
{
	strcpy(g_path, path);
	g_scan_interval = scan_interval;
	g_retrying_times = retrying_times;
	g_notify_stop = TRUE;
	pthread_mutex_init(&g_id_lock, NULL);
}

/*
 *	run the timer queue module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int clone_queue_run()
{
	pthread_attr_t  attr;
	struct stat node_stat;

	/* check the directory */
    if (0 != stat(g_path, &node_stat)) {
        printf("[domain_subsystem]: can not find %s directory\n", g_path);
        return -1;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
        printf("[domain_subsystem]: %s is not a directory\n", g_path);
        return -2;
    }
	g_mess_id = clone_queue_retrieve_mess_ID();
	g_notify_stop = FALSE;
	pthread_attr_init(&attr);
	int ret = pthread_create(&g_thread_id, &attr, thread_work_func, nullptr);
	if (ret != 0) {
		pthread_attr_destroy(&attr);
		g_notify_stop = TRUE;
		printf("[domain_subsystem]: failed to create timer thread: %s\n", strerror(ret));
		return -3;
	}
	pthread_setname_np(g_thread_id, "clone_queue");
	pthread_attr_destroy(&attr);
	return 0;
}

/*
 *	stop the timer queue module
 *	@return
 *		 0					OK
 *		<>0					fail
 */
int clone_queue_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	return 0;
}

/*
 *	timer queue's destruct function
 */
void clone_queue_free()
{
	g_path[0] = '\0';
	g_scan_interval = 0;
	g_retrying_times = 0;
	pthread_mutex_destroy(&g_id_lock);
}

/*
 *	put message into timer queue
 *	@param
 *		pcontext [in]		message context to be sent
 *		original_time		original time
 *	@return
 *		>=0					timer ID
 *		<0					fail
 */
int clone_queue_put(MESSAGE_CONTEXT *pcontext, time_t original_time)
{
	int mess_id, len, temp_len;
	char file_name[256];
	char tmp_buff[256];
	int fd, times;

	mess_id = clone_queue_increase_mess_ID();
	sprintf(file_name, "%s/%d", g_path, mess_id);
	fd = open(file_name, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return -1;
	}
	/* write 0 at the begin of file to indicate message is now being writing */
	times = 0;
	if (sizeof(int) != write(fd, &times, sizeof(int)) ||
		sizeof(time_t) != write(fd, &original_time, sizeof(time_t))) {
		close(fd);
		remove(file_name);
        return -1;
	}
	/* at the begin of file, write the length of message */
	len = mail_get_length(pcontext->pmail);
	if (-1 == len) {
		printf("[domain_subsystem]: fail to get mail length\n");
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
	times = 1;
	if (sizeof(int) != write(fd, &times, sizeof(int))) {
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
static int clone_queue_retrieve_mess_ID()
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
		if (strcmp(direntp->d_name, ".") == 0 ||
		    strcmp(direntp->d_name, "..") == 0)
			continue;
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
static int clone_queue_increase_mess_ID()
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

static void* thread_work_func(void* arg)
{
	DIR *dirp;
	int i, times, size, len, port;
	int scan_interval, fd, mess_len;
	time_t scan_begin, scan_end, original_time;
    struct dirent *direntp;
	struct stat node_stat;
	char *pdomain;
    char temp_path[256];
	char rcpt_buff[256];
	char *pbuff, *ptr, ip[16];
	MESSAGE_CONTEXT *pcontext;
	BOOL need_remove;

	pcontext = get_context();
	if (NULL == pcontext) {
		printf("[domain_subsystem]: fail to get context in clone queue thread\n");
		pthread_exit(0);
	}
	dirp = opendir(g_path);
	if (NULL == dirp) {
		printf("[domain_subsystem]: failed to open clone directory %s: %s\n",
			g_path, strerror(errno));
		pthread_exit(0);
	}
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
            fd = open(temp_path, O_RDWR);
			if (-1 == fd) {
				continue;
			}
			if (sizeof(int) != read(fd, &times, sizeof(int))) {
				close(fd);
				continue;
			}
			if (0 == times) {
				close(fd);
                continue;
			}
			if (sizeof(time_t) != read(fd, &original_time, sizeof(time_t)) ||
				sizeof(int) != read(fd, &mess_len, sizeof(int))) {
				printf("[domain_subsystem]: fail to read information from %s "
					"in timer queue\n", direntp->d_name);
				close(fd);
				continue;
			}
			size = node_stat.st_size - sizeof(time_t) - 2*sizeof(int);
			pbuff = malloc(((size - 1)/(64 * 1024) + 1) * 64 * 1024);
			if (NULL == pbuff) {
				printf("[domain_subsystem]: Failed to allocate memory for %s "
					"in timer queue thread\n", direntp->d_name);
				close(fd);
				continue;
			}
			if (size != read(fd, pbuff, size)) {
				free(pbuff);
				printf("[domain_subsystem]: fail to read information from %s "
					"in timer queue\n", direntp->d_name);
				close(fd);
				continue;
			}
			if (FALSE == mail_retrieve(pcontext->pmail, pbuff, mess_len)) {
				free(pbuff);
				printf("[domain_subsystem]: fail to retrieve message %s in "
					"clone queue into mail object\n", direntp->d_name);
				close(fd);
				continue;
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
			if (g_retrying_times <= times) {
				need_remove = TRUE;
			} else {
				need_remove = FALSE;
			}
			mem_file_readline(&pcontext->pcontrol->f_rcpt_to, rcpt_buff, 256);
			pdomain = strchr(rcpt_buff, '@');
			if (NULL == pdomain || FALSE == address_list_query(pdomain + 1,
				ip, &port) || SMTP_CLONE_TEMP_ERROR != smtp_clone_process(
				pcontext, ip, port)) {
				need_remove = TRUE;
			}
			if (FALSE == need_remove) {
				/* rewite type and until time */
				lseek(fd, 0, SEEK_SET);
				times ++;
				if (sizeof(int) != write(fd, &times, sizeof(int))) {
					printf("[domain_subsystem]: error while updating "
						"times\n");
				}
			}
			close(fd);
			fd = -1;
			if (TRUE == need_remove) {
				remove(temp_path);
			}
			free(pbuff);
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
	return NULL;
}

int clone_queue_get_param(int param)
{
	if (CLONE_QUEUE_SCAN_INTERVAL == param) {
		return g_scan_interval;
	} else if (CLONE_QUEUE_RETRYING_TIMES == param) {
		return g_retrying_times;
	}
	return 0;
}

void clone_queue_set_param(int param, int val)
{
	if (CLONE_QUEUE_SCAN_INTERVAL == param) {
		g_scan_interval = val;
	} else if (CLONE_QUEUE_RETRYING_TIMES == param) {
		g_retrying_times = val;
	}
}

