// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
/*
 *  mail queue have two parts, mess, message queue.when a mail 
 *	is put into mail queue, and create a file in mess directory and write the
 *  mail into file. after mail is saved, system will send a message to
 *  message queue to indicate there's a new mail arrived!
 */
#define DECLARE_API_STATIC
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/flusher_common.h>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#define TOKEN_MESSAGE_QUEUE     1
#define MAX_LINE_LENGTH			64*1024

enum {
	MESSAGE_MESS = 2,
};

enum {
	SMTP_IN = 1,
	SMTP_OUT,
	SMTP_RELAY
};

struct MSG_BUFF {
    long msg_type;
    int msg_content;
};

static void* thread_work_func(void* arg);
static BOOL message_enqueue_check();
static int message_enqueue_retrieve_max_ID();
static BOOL message_enqueue_try_save_mess(FLUSH_ENTITY *);

static char         g_path[256];
static int			g_msg_id;
static pthread_t    g_flushing_thread;
static BOOL         g_notify_stop;
static int			g_last_flush_ID;
static int			g_enqueued_num;
static int			g_last_pos;

/*
 *    message queue's construct function
 *    @param
 *    	path [in]    	path for saving files
 */
static void message_enqueue_init(const char *path)
{
	HX_strlcpy(g_path, path, GX_ARRAY_SIZE(g_path));
    g_notify_stop = TRUE;
    g_last_flush_ID = 0;
	g_enqueued_num = 0;
	g_last_pos = 0;
}

/*
 *    run the message queue 
 *    @return
 *    	0			success
 *		<>0			fail
 */
static int message_enqueue_run()
{
	key_t k_msg;
    char name[256];
    pthread_attr_t attr;

    if (FALSE == message_enqueue_check()) {
        return -1;
    }
	snprintf(name, GX_ARRAY_SIZE(name), "%s/token.ipc", g_path);
	int fd = open(name, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd >= 0)
		close(fd);
    k_msg = ftok(name, TOKEN_MESSAGE_QUEUE);
    if (-1 == k_msg) {
		printf("[message_enqueue]: ftok %s: %s\n", name, strerror(errno));
        return -2;
    }
    /* create the message queue */
    g_msg_id = msgget(k_msg, 0666|IPC_CREAT);
    if (-1 == g_msg_id) {
		printf("[message_enqueue]: msgget: %s\n", strerror(errno));
        return -6;
    }
    g_last_flush_ID = message_enqueue_retrieve_max_ID();

    g_notify_stop = FALSE;
    pthread_attr_init(&attr);
	int ret = pthread_create(&g_flushing_thread, &attr, thread_work_func, nullptr);
	if (ret != 0) {
		printf("[message_enqueue]: failed to create flushing thread: %s\n", strerror(ret));
        return -7;
    }
	pthread_setname_np(g_flushing_thread, "flusher");
    pthread_attr_destroy(&attr);
    return 0;
}

/*
 *  cancel part of a mail, only mess messages will be canceled
 *  @param
 *      pentity [in]     indicate the mail object for cancelling
 */
static void message_enqueue_cancel(FLUSH_ENTITY *pentity)
{
    char file_name[256];
    
    fclose((FILE*)pentity->pflusher->flush_ptr);
    pentity->pflusher->flush_ptr = NULL;
	snprintf(file_name, GX_ARRAY_SIZE(file_name), "%s/mess/%d",
	         g_path, pentity->pflusher->flush_ID);
	remove(file_name);
    pentity->pflusher->flush_ID = 0;
}

/*
 *  stop the message queue 
 *  @return
 *       0  success
 *      -1  fail
 */
static int message_enqueue_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_flushing_thread, NULL);
	}
    return 0;
}

/*
 *	get last flush ID from queue
 *	@return
 *		flush ID
 */
static int message_enqueue_retrieve_flush_ID()
{
	return g_last_flush_ID;
}

/*
 *  message queue's destruct function
 */
static void message_enqueue_free()
{
    g_path[0] = '\0';
    g_notify_stop = TRUE;
    g_last_flush_ID = 0;
	g_last_pos = 0;
	g_msg_id = -1;
}

/*
 *  check the message queue's parameters is same as the entity in file system
 *  @return
 *      TRUE                OK
 *      FALSE               fail
 */
static BOOL message_enqueue_check()
{
    char    name[256];
    struct  stat node_stat;

    /* check if the directory exists and is a real directory */
    if (0 != stat(g_path, &node_stat)) {
        printf("[message_enqueue]: cannot find directory %s\n", g_path);
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
        printf("[message_enqueue]: %s is not a directory\n", g_path);
        return FALSE;
    }
	snprintf(name, GX_ARRAY_SIZE(name), "%s/mess", g_path);
    if (0 != stat(name, &node_stat)) {
        printf("[message_enqueue]: cannot find directory %s\n", name);
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
        printf("[message_enqueue]: %s is not a directory\n", name);
		return FALSE;
    }
	snprintf(name, GX_ARRAY_SIZE(name), "%s/save", g_path);
    if (0 != stat(name, &node_stat)) {
        printf("[message_enqueue]: cannot find directory %s\n", name);
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
        printf("[message_enqueue]: %s is not a directory\n", name);
		return FALSE;
    }
    return TRUE;
}


/*
*    thread's work function in message queue 
*    @param
*        arg [in]    argument passed by thread creator
*/
static void* thread_work_func(void* arg)
{
    FLUSH_ENTITY *pentity = NULL;
	MSG_BUFF msg;

    while (TRUE != g_notify_stop) {
        if (NULL == (pentity = get_from_queue())) {
            usleep(50000);
            continue;
        }
		if (TRUE == message_enqueue_try_save_mess(pentity)) {
			if (FLUSH_WHOLE_MAIL == pentity->pflusher->flush_action) {
    			msg.msg_type = MESSAGE_MESS;
    			msg.msg_content = pentity->pflusher->flush_ID;
    			msgsnd(g_msg_id, &msg, sizeof(int), IPC_NOWAIT);
				g_enqueued_num ++;
			}
			pentity->pflusher->flush_result = FLUSH_RESULT_OK;
		} else {
			pentity->pflusher->flush_result = FLUSH_TEMP_FAIL;
		}
		feedback_entity(pentity);
	}
	return NULL;
}

BOOL message_enqueue_try_save_mess(FLUSH_ENTITY *pentity)
{
	char name[256];
    char time_buff[128];
	char tmp_buff[MAX_LINE_LENGTH + 2];
    time_t cur_time;
	struct tm tm_buff;
	FILE *fp;
	size_t mess_len;
	int j, write_len, tmp_len, smtp_type, copy_result;
	unsigned int size;

	if (NULL == pentity->pflusher->flush_ptr) {
		snprintf(name, GX_ARRAY_SIZE(name), "%s/mess/%d",
		         g_path, pentity->pflusher->flush_ID);
        fp = fopen(name, "w");
        /* check if the file is created successfully */
        if (NULL == fp) {
            return FALSE;
        }
		pentity->pflusher->flush_ptr = fp;
		/* write first 4(8) bytes in the file to indicate incomplete mess */
		mess_len = 0;
		if (sizeof(size_t) != fwrite(&mess_len, 1, sizeof(size_t), fp)) {
			goto REMOVE_MESS;
		}
        /* construct head information for mess file */
        cur_time = time(NULL);
        strftime(time_buff, 128,"%a, %d %b %Y %H:%M:%S %z",
			localtime_r(&cur_time, &tm_buff));
        tmp_len = sprintf(tmp_buff, "X-Lasthop: %s\r\nReceived: from %s "
			"(helo %s)(%s@%s)\r\n\tby %s with SMTP; %s\r\n",
        	pentity->pconnection->client_ip, pentity->penvelop->parsed_domain,
        	pentity->penvelop->hello_domain, pentity->penvelop->parsed_domain,
            pentity->pconnection->client_ip, get_host_ID(), time_buff);
		write_len = fwrite(tmp_buff, 1, tmp_len, fp);
		if (write_len != tmp_len) {
        	goto REMOVE_MESS;
        }
		for (j=0; j<get_extra_num(pentity->context_ID); j++) {
			tmp_len = sprintf(tmp_buff, "%s: %s\r\n",
					get_extra_tag(pentity->context_ID, j),
					get_extra_value(pentity->context_ID, j));
			write_len = fwrite(tmp_buff, 1, tmp_len, fp);
			if (write_len != tmp_len) {
				goto REMOVE_MESS;
			}
		}
	} else {
		fp = (FILE*)pentity->pflusher->flush_ptr;
	}
	/* write stream into mess file */
	while (TRUE) {
		size = MAX_LINE_LENGTH;
		copy_result = stream_copyline(pentity->pstream, tmp_buff, &size);
		if (STREAM_COPY_OK != copy_result &&
			STREAM_COPY_PART != copy_result) {
			break;
		}
		if (STREAM_COPY_OK == copy_result) {
			tmp_buff[size] = '\r';
			size ++;
			tmp_buff[size] = '\n';
			size ++;
		}
		write_len = fwrite(tmp_buff, 1, size, fp);
		if (write_len != size) {
			goto REMOVE_MESS;
		}
	}
	if (STREAM_COPY_TERM == copy_result) {
		write_len = fwrite(tmp_buff, 1, size, fp);
		if (write_len != size) {
			goto REMOVE_MESS;
		}
	}
	if (FLUSH_WHOLE_MAIL != pentity->pflusher->flush_action) {
		return TRUE;
	}
	mess_len = ftell(fp);
	mess_len -= sizeof(size_t);
   	/* write flush ID */
	if (sizeof(int) != fwrite(&pentity->pflusher->flush_ID,1,sizeof(int),fp)) {
		goto REMOVE_MESS;
	}
	/* write bound type */
	if (TRUE == pentity->penvelop->is_relay) {
		smtp_type = SMTP_RELAY;
	} else {
		if (TRUE == pentity->penvelop->is_outbound) {
			smtp_type = SMTP_OUT;
		} else {
			smtp_type = SMTP_IN;
		}
	}
	if (sizeof(int) != fwrite(&smtp_type, 1, sizeof(int), fp)) {
		goto REMOVE_MESS;
	}
	if (sizeof(int) != fwrite(&pentity->is_spam, 1, sizeof(int), fp)) {
		goto REMOVE_MESS;
	}	
	/* write envelop from */
	tmp_len = strlen(pentity->penvelop->from);
    tmp_len ++;
	if (tmp_len != fwrite(pentity->penvelop->from, 1, tmp_len, fp)) {
		goto REMOVE_MESS;
	}
    /* write envelop rcpts */
    mem_file_seek(&pentity->penvelop->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
    while (MEM_END_OF_FILE != (tmp_len = mem_file_readline(
    	&pentity->penvelop->f_rcpt_to, tmp_buff, 256))) {
		tmp_buff[tmp_len] = 0;
		tmp_len ++;
        if (tmp_len != fwrite(tmp_buff, 1, tmp_len, fp)) {
			goto REMOVE_MESS;
		}
	}
	/* last null character for indicating end of rcpt to array */
	*tmp_buff = 0;
	fwrite(tmp_buff, 1, 1, fp);
	fseek(fp, SEEK_SET, 0);
	if (sizeof(size_t) != fwrite(&mess_len, 1, sizeof(size_t), fp)) {
		goto REMOVE_MESS;
	}
    fclose(fp);
	pentity->pflusher->flush_ptr = NULL;
	return TRUE;

 REMOVE_MESS:
	fclose(fp);
    pentity->pflusher->flush_ptr = NULL;
	snprintf(name, GX_ARRAY_SIZE(name), "%s/mess/%d", g_path,
	         pentity->pflusher->flush_ID);
	remove(name);
	return FALSE;
}

/*
 *    retrieve the maximum ID from queue
 *    @return
 *        >=0        the maximum ID used in queue
 */
static int message_enqueue_retrieve_max_ID()
{
    DIR *dirp;
    struct dirent *direntp;
    char   temp_path[256];
	int fd, size, max_ID, temp_ID;

	max_ID = 0;
	/* get maximum flushID in mess */
	snprintf(temp_path, GX_ARRAY_SIZE(temp_path), "%s/mess", g_path);
    dirp = opendir(temp_path);
    while ((direntp = readdir(dirp)) != NULL) {
		if (strcmp(direntp->d_name, ".") == 0 ||
		    strcmp(direntp->d_name, "..") == 0)
			continue;
    	temp_ID = atoi(direntp->d_name);
        if (temp_ID > max_ID) {
			snprintf(temp_path, GX_ARRAY_SIZE(temp_path), "%s/mess/%s",
			         g_path, direntp->d_name);
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
        		max_ID = temp_ID;
			} else {
				remove(temp_path);
			}
        } 
    }
    closedir(dirp);
    return max_ID;
}

static BOOL flh_message_enqueue(int reason, void** ppdata)
{
	const char *queue_path;
	char *psearch;
	char file_name[256], temp_path[256];

	switch (reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		HX_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (psearch != nullptr)
			*psearch = '\0';
		snprintf(temp_path, GX_ARRAY_SIZE(temp_path), "%s.cfg", file_name);
		auto pfile = config_file_initd(temp_path, get_config_path());
		if (pfile == nullptr) {
			printf("[message_enqueue]: config_file_initd %s: %s\n",
				temp_path, strerror(errno));
			return false;
		}
		queue_path = config_file_get_value(pfile, "ENQUEUE_PATH");
		if (queue_path == nullptr) {
			queue_path = PKGSTATEQUEUEDIR;
			config_file_set_value(pfile, "ENQUEUE_PATH", queue_path);
		}
		printf("[message_enqueue]: enqueue path is %s\n", queue_path);

		message_enqueue_init(queue_path);
		if (message_enqueue_run() != 0) {
			printf("[message_enqueue]: failed to run the module\n");
			return false;
		}
		if (!register_cancel(message_enqueue_cancel)) {
			printf("[message_enqueue]: failed to register cancel flushing\n");
			return false;
		}
		set_flush_ID(message_enqueue_retrieve_flush_ID());
		return TRUE;
	}
	case PLUGIN_FREE:
		if (message_enqueue_stop() != 0)
			return false;
		message_enqueue_free();
		return TRUE;
	}
	return false;
}
FLH_ENTRY(flh_message_enqueue);
