/*
 *  mail queue have three parts, tape, mess, message queue.when a mail
 *  is put into mail queue, first, check whether it is less
 *  than 64K, if it is, get a block (128K) from tape, and write the mail
 *  into this block; or, create a file in mess directory and write the
 *  mail into file. after mail is saved, system will send a message to
 *  message queue to indicate there's a new mail arrived!
 */
#include <errno.h>
#include <string.h>
#include "message_dequeue.h"
#include "system_services.h"
#include "util.h"
#include "int_hash.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>

#define DEF_MODE    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
#define TOKEN_MESSAGE_QUEUE		1
#define TOKEN_SHARE_MEMORY		2
#define BLOCK_SIZE				64*1024*2
#define SLEEP_INTERVAL			50000

typedef struct _MSG_BUFF {
	long msg_type;
	int msg_content;
} MSG_BUFF;

static char				g_path[256];    /* directory name for message queue */
static int				g_shm_id;       /* share memory id */
static int				g_msg_id;	    /* message queue id */
static BOOL         	g_with_tape;    /* with tape to accelerate */
static void				*g_tape_begin;  /* share memory begin address */
static int   			g_tape_units;   /* units in tape file */
static size_t			g_message_units;/* allocated message units number */
static size_t			g_max_memory;   /* maximum allocated memory for mess*/
static size_t			g_current_mem;  /*current allocated memory */
static MESSAGE			*g_message_ptr;
static SINGLE_LIST				g_used_list;
static INT_HASH_TABLE	*g_mess_hash;
static INT_HASH_TABLE	*g_tape_hash;
static SINGLE_LIST				g_free_list;
static pthread_mutex_t	g_hash_mutex;
static pthread_mutex_t	g_used_mutex;
static pthread_mutex_t	g_free_mutex;
static pthread_mutex_t	g_mess_mutex;
static pthread_t		g_thread_id;
static BOOL g_notify_stop;
static int				g_dequeued_num;

extern void transporter_wakeup_one_thread(void);
static BOOL message_dequeue_check(void);
static MESSAGE *message_dequeue_get_from_free(int message_option, size_t size);

static void message_dequeue_put_to_free(MESSAGE *pmessage);

static void message_dequeue_put_to_used(MESSAGE *pmessage);

static void message_dequeue_retrieve_to_message(MESSAGE *pmessage,
	char *in_buff);

static void message_dequeue_load_from_mess(int mess);

static void message_dequeue_load_from_tape(int pos);

static void message_dequeue_collect_resource(void);

static void* thread_work_func(void* arg);

/* 
 * message dequeue's construct function
 *	@param
 *		path [in]	path of directory
 *		tape_units	units in tape file
 *		max_memory	maximum memory system allowed concurrently
 */
void message_dequeue_init(const char *path, int tape_units,
	size_t max_memory)
{	
	strcpy(g_path, path);
	g_tape_units = tape_units;
	if (0 == g_tape_units) {
		g_with_tape = FALSE;
	} else {
		g_with_tape = TRUE;
	}
	g_max_memory = ((max_memory-1)/(BLOCK_SIZE/2) + 1) * (BLOCK_SIZE/2);
	single_list_init(&g_used_list);
	single_list_init(&g_free_list);
	pthread_mutex_init(&g_hash_mutex, NULL);
	pthread_mutex_init(&g_used_mutex, NULL);
	pthread_mutex_init(&g_free_mutex, NULL);
	pthread_mutex_init(&g_mess_mutex, NULL);
	g_current_mem = 0;
	g_msg_id = -1;
	g_shm_id = -1;
	g_tape_begin= NULL;
	g_message_ptr = NULL;
	g_mess_hash = NULL;
	g_tape_hash = NULL;	
	g_notify_stop = FALSE;
	g_dequeued_num = 0;
}


/*
 *	check the message queue's parameters is same as the entity in file system
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
static BOOL message_dequeue_check()
{
	char 	name[256];
	struct	stat node_stat;

	/* check if the directory exists and is a real directory */
	if (0 != stat(g_path, &node_stat)) {
		printf("[message_dequeue]: cannot find directory %s\n", g_path);
		return FALSE;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		printf("[message_dequeue]: %s is not a directory\n", g_path);
		return FALSE;
	}
	/* mess directory is used to save the message larger than BLOCK_SIZE */
	sprintf(name, "%s/mess", g_path);
	if (0 != stat(name, &node_stat)) {
        printf("[message_dequeue]: cannot find directory %s\n", name);
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
        printf("[message_dequeue]: %s is not a directory\n", name);
        return FALSE;
    }
	/* save directory is used to save the message for debugging */
    sprintf(name, "%s/save", g_path);
    if (0 != stat(name, &node_stat)) {
        printf("[message_dequeue]: cannot find directory %s\n", name);
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
        printf("[message_dequeue]: %s is not a directory\n", name);
        return FALSE;
    }
	sprintf(name, "%s/token.ipc", g_path);
	if (0 != stat(name, &node_stat)) {
		printf("[message_dequeue]: can not find ipc token file  %s\n", name);
		return FALSE;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		debug_info("[message_dequeue]: %s should be a regular file\n", name);
		return FALSE;		
	}
	return TRUE;
}

/*
 *	collect the global resources system allocated
 */
static void message_dequeue_collect_resource(void)
{
	if (NULL != g_tape_begin) {
		shmdt(g_tape_begin);
		g_tape_begin = NULL;
	}
	if (NULL != g_message_ptr) {
		free(g_message_ptr);
		g_message_ptr = NULL;	
	}
	if (NULL != g_mess_hash) {
		int_hash_free(g_mess_hash);
		g_mess_hash = NULL;
	}
	if (NULL != g_tape_hash) {
		int_hash_free(g_tape_hash);
		g_tape_hash = NULL;
	}
}

/*
 *	run the message dequeue module
 *	@return
 *		0			OK
 *		<>0			fail
 */
int message_dequeue_run()
{
	size_t size;
	key_t k_msg, k_shm;
	int i;
    char name[256];
	MESSAGE *pmessage;
	pthread_attr_t attr;

	if (FALSE == message_dequeue_check()) {
		return -1;
	}
    sprintf(name, "%s/token.ipc", g_path);
    k_msg = ftok(name, TOKEN_MESSAGE_QUEUE);
    if (-1 == k_msg) {
        printf("[message_dequeue]: cannot open key for message queue\n");
        return -2;
    }
    k_shm = ftok(name, TOKEN_SHARE_MEMORY);
    if (-1 == k_shm) {
        printf("[message_dequeue]: cannot open key for share memory\n");
        return -3;
    }
	if (TRUE == g_with_tape) {
    	size = g_tape_units*BLOCK_SIZE;
		/* open or create share memory for tape */
        g_shm_id = shmget(k_shm, size, 0666|IPC_CREAT);
        if (-1 == g_shm_id) {
            printf("[message_enqueue]: fail to get or create share memory\n");
            return -4;
        }
		g_tape_begin = shmat(g_shm_id, NULL, 0);
        if ((void*)-1 == g_tape_begin) {
            printf("[message_enqueue]: fail to attach share memory\n");
            g_tape_begin = NULL;
            return -5;
        }
	}
	/* create the message queue */
	g_msg_id = msgget(k_msg, 0666|IPC_CREAT);
	if (-1 == g_msg_id) {
		printf("[message_dequeue]: fail to get or create message queue\n");
		message_dequeue_collect_resource();
		return -6;
	}
	g_message_units = g_tape_units + g_max_memory/(BLOCK_SIZE/2);
	size = sizeof(MESSAGE)*g_message_units;
	g_message_ptr = (MESSAGE*)malloc(size);
	if (NULL == g_message_ptr) {
		printf("[message_dequeue]: fail to allcate message nodes\n");
		message_dequeue_collect_resource();
		return -7;
	}
	memset(g_message_ptr, 0, size);
	/* append rest of message node into free list */
	for (i=0; i<g_message_units; i++) {
		pmessage = g_message_ptr + i;
        pmessage->node.pdata = pmessage;
		single_list_append_as_tail(&g_free_list, &pmessage->node);
	}
	g_mess_hash = int_hash_init(2*g_message_units + 1, sizeof(void*), NULL);
	g_tape_hash = int_hash_init(2*g_tape_units + 1, sizeof(void*), NULL);
	if (NULL == g_mess_hash || NULL == g_tape_hash) {
		printf("[message_dequeue]: fail to initialize hash table\n");
		message_dequeue_collect_resource();
		return -8;
	}
	pthread_attr_init(&attr);
	if (0 != pthread_create(&g_thread_id, &attr,
		thread_work_func, NULL)) {
		printf("[message_dequeue]: fail to create message dequeue thread\n");
		message_dequeue_collect_resource();
		return -9;
	}
	pthread_setname_np(g_thread_id, "msg_dequeue");
	return 0;
}

/*
 *	get a mail message from mail queue
 *	@return
 *		pointer to mail message, NULL means none message
 */
MESSAGE* message_dequeue_get()
{
	SINGLE_LIST_NODE *pnode;

	pthread_mutex_lock(&g_used_mutex);
	pnode = single_list_get_from_head(&g_used_list);
	pthread_mutex_unlock(&g_used_mutex);
	if (NULL == pnode) {
		return NULL;
	}
	return (MESSAGE*)pnode->pdata;
}

/*
 *	put message back to mail queue
 *	@param
 *		pmessage [in]		pointer to message struct
 */
void message_dequeue_put(MESSAGE *pmessage)
{
	char name[256];
	int *pstart;

	if (MESSAGE_MESS == pmessage->message_option) {
		free(pmessage->begin_address);
		pmessage->begin_address = NULL;
		sprintf(name, "%s/mess/%d", g_path, pmessage->message_data);
		remove(name);
	} else {
		pstart = (int*)((char*)g_tape_begin + 
				 pmessage->message_data*BLOCK_SIZE);
		*pstart = 0;
	}
	pthread_mutex_lock(&g_hash_mutex);
    if (MESSAGE_MESS == pmessage->message_option) {
        int_hash_remove(g_mess_hash, pmessage->message_data);
    } else {
        int_hash_remove(g_tape_hash, pmessage->message_data);
    }
    pthread_mutex_unlock(&g_hash_mutex);
	message_dequeue_put_to_free(pmessage);
	g_dequeued_num ++;
}

/*
 *	stop the message dequeue module
 *	@return
 *		0			OK
 *		<>0			fail
 */
int message_dequeue_stop()
{
	g_notify_stop = TRUE;
	pthread_join(g_thread_id, NULL);

	message_dequeue_collect_resource();
	return 0;
}

/*
 *	message dequeue's destruct function
 */
void message_dequeue_free()
{
	g_path[0] = '\0';
    g_tape_units = 0;
    g_max_memory = 0;
    single_list_free(&g_used_list);
    single_list_free(&g_free_list);
    pthread_mutex_destroy(&g_hash_mutex);
    pthread_mutex_destroy(&g_used_mutex);
    pthread_mutex_destroy(&g_free_mutex);
    pthread_mutex_destroy(&g_mess_mutex);
	g_current_mem  = 0;
    g_msg_id = -1;
	g_shm_id = -1;
    g_tape_begin= NULL;
	g_message_ptr = NULL;
	g_mess_hash = NULL;
	g_tape_hash = NULL;	
    g_notify_stop = TRUE;
}

/*
 *	retrieve buffer into message struct
 *	@param
 *		pmessage [out]			message struct pointer
 *		in_buff [in]			buffer of mail message
 */
static void message_dequeue_retrieve_to_message(MESSAGE *pmessage,
	char *in_buff)
{
	pmessage->begin_address = in_buff;
	pmessage->mail_begin = in_buff + sizeof(size_t);
	pmessage->mail_length = *((size_t*)in_buff);
	pmessage->flush_ID = *((int*)(in_buff + sizeof(size_t) +
						  pmessage->mail_length));
	pmessage->bound_type = *(int*)(in_buff + sizeof(size_t) + sizeof(int) +
                          pmessage->mail_length);
	pmessage->is_spam = *(int*)(in_buff + +sizeof(size_t) + 2*sizeof(int) +
                          pmessage->mail_length);
	pmessage->envelop_from = in_buff + sizeof(size_t) + 3*sizeof(int) +
                         	 pmessage->mail_length;
	pmessage->envelop_rcpt = pmessage->envelop_from +
							 strlen(pmessage->envelop_from) + 1;
}

/*
 *	get a message node back from free list
 *	@param
 *		message_option			MESSAGE_MESS
 *								MESSAGE_TAPE
 *	@return
 *		message pointer, NULL means fail to get
 */
static MESSAGE *message_dequeue_get_from_free(int message_option, size_t size)
{
	SINGLE_LIST_NODE *pnode;
	MESSAGE *pmessage;

	/* at a certain time, number of mess message node is limited */
	if (MESSAGE_MESS == message_option) {
		pthread_mutex_lock(&g_mess_mutex);
		if (g_current_mem + size > g_max_memory) {
			pthread_mutex_unlock(&g_mess_mutex);
			return NULL;
		} else {
			g_current_mem += size;
		}
		pthread_mutex_unlock(&g_mess_mutex);
	}
	pthread_mutex_lock(&g_free_mutex);
	pnode = single_list_get_from_head(&g_free_list);
	pthread_mutex_unlock(&g_free_mutex);
	if (NULL == pnode) {
		debug_info("[message_dequeue]: fatal error in "
			"message_dequeue_get_from_free\n");
		return NULL;
	}
	pmessage = (MESSAGE*) pnode->pdata;
	pmessage->message_option = message_option;
	if (MESSAGE_MESS == message_option) {
		pmessage->size = size;
	} else {
		pmessage->size = 0;
	}
	pmessage->begin_address = NULL;
	pmessage->mail_begin = NULL;
	pmessage->mail_length = 0;
	pmessage->envelop_from = NULL;
	pmessage->envelop_rcpt = NULL;
	return pmessage;
}

/*
 *	put message node back to free list
 *	@param
 *		pmessage [in]		pointer to message struct
 */
static void message_dequeue_put_to_free(MESSAGE *pmessage)
{
	if (MESSAGE_MESS == pmessage->message_option) {
		pthread_mutex_lock(&g_mess_mutex);
		g_current_mem -= pmessage->size;
		pthread_mutex_unlock(&g_mess_mutex);
	}
	pthread_mutex_lock(&g_free_mutex);
	single_list_append_as_tail(&g_free_list, &pmessage->node);
	pthread_mutex_unlock(&g_free_mutex);
}

/*
 *	add a message struct into used list
 *	@param
 *		pmessage [in]		pointer to message struct
 */
static void message_dequeue_put_to_used(MESSAGE *pmessage)
{
	pthread_mutex_lock(&g_used_mutex);
    single_list_append_as_tail(&g_used_list, &pmessage->node);
    pthread_mutex_unlock(&g_used_mutex);
	/* send a signal to threads pool in transporter */
	transporter_wakeup_one_thread();
}

/*
 *	load a mess file into used list, and so threads of other modules can
 *	get message from used list
 *	@param
 *		mess			mess ID
 */
static void message_dequeue_load_from_mess(int mess)
{
	char name[256];
	struct stat node_stat;
	int fd;
	MESSAGE *pmessage;
	char *ptr;
	size_t size;

	pthread_mutex_lock(&g_hash_mutex);
    pmessage = (MESSAGE*)int_hash_query(g_mess_hash, mess);
    pthread_mutex_unlock(&g_hash_mutex);
	if (NULL != pmessage) {
		return;
	}
	sprintf(name, "%s/mess/%d", g_path, mess);
	if (0 != stat(name, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		return;
	}
	size = ((node_stat.st_size - 1)/(64 * 1024) + 1) * 64 * 1024;
	pmessage = message_dequeue_get_from_free(MESSAGE_MESS, size);
	if (NULL == pmessage) {
		return;
	}
	pmessage->message_data = mess;
	ptr = (char*)malloc(size);
	if (NULL == ptr) {
		message_dequeue_put_to_free(pmessage);
        return;
	}

	fd = open(name, O_RDONLY);
	if (-1 == fd) {
		message_dequeue_put_to_free(pmessage);
		free(ptr);
		return;
	}
	if (node_stat.st_size != read(fd, ptr, node_stat.st_size)) {
		message_dequeue_put_to_free(pmessage);
		free(ptr);
		close(fd);
        return;
	}
	close(fd);
	/* check if it is an incomplete message */
	if (0 == *(int*)ptr) {
		message_dequeue_put_to_free(pmessage);
		free(ptr);
		return;	
	}
	message_dequeue_retrieve_to_message(pmessage, ptr);
	message_dequeue_put_to_used(pmessage);

	pthread_mutex_lock(&g_hash_mutex);
	int_hash_add(g_mess_hash, mess, pmessage);
	pthread_mutex_unlock(&g_hash_mutex);
}

/*
 *	load a tape message into used list
 *	@param
 *		pos			indicate block position in tape
 */
static void message_dequeue_load_from_tape(int pos)
{
	MESSAGE *pmessage;

	pthread_mutex_lock(&g_hash_mutex);
    pmessage = (MESSAGE*)int_hash_query(g_tape_hash, pos);
    pthread_mutex_unlock(&g_hash_mutex);
	if (NULL != pmessage || 0 == *(int*)((char*)g_tape_begin +
		BLOCK_SIZE*((long)pos))) {
		return;
	}
	pmessage = message_dequeue_get_from_free(MESSAGE_TAPE, 0);
    if (NULL == pmessage) {
		debug_info("[message_dequeue]: error while loading message "
			"%d in tape", pos);
        return;
	}
	pmessage->message_data = pos;
	message_dequeue_retrieve_to_message(pmessage, (char*)g_tape_begin +
		((long)pos) * BLOCK_SIZE);
	message_dequeue_put_to_used(pmessage);

	pthread_mutex_lock(&g_hash_mutex);
	int_hash_add(g_tape_hash, pos, pmessage);
	pthread_mutex_unlock(&g_hash_mutex);
}

static void* thread_work_func(void* arg)
{
	MSG_BUFF msg;
	size_t size;
    char dir_name[256];
    char file_name[256];
    DIR *dirp;
    struct dirent *direntp;
    int mess_fd, i, len, mess;

    sprintf(dir_name, "%s/mess", g_path);
    while (NULL == (dirp = opendir(dir_name))) {
		printf("[message_dequeue]: failed to open directory %s: %s\n",
			dir_name, strerror(errno));
        sleep(1);
    }

	while (TRUE != g_notify_stop) {
		if (-1 != msgrcv(g_msg_id, &msg, sizeof(int), 0, IPC_NOWAIT)) {
			switch(msg.msg_type) {
			case MESSAGE_TAPE:
				if (TRUE == g_with_tape) {
					if (msg.msg_content >= g_tape_units) {
						printf("[message_dequeue]: error: enqueue tape"
							" size may be larger than dequeue tape size\n");
					} else {
						message_dequeue_load_from_tape(msg.msg_content);
					}
				} else {
					printf("[message_dequeue]: error: should turn off"
						" tape option in message enqueue flusher plugin\n");
				}
				break;
			case MESSAGE_MESS:
				message_dequeue_load_from_mess(msg.msg_content);
				break;
			default:
				printf("[message_dequeue]: unknown message queue type %d, "
					"should be MESSAGE_TAPE or MESSAGE_MESS\n", msg.msg_type);
			}
			continue;
		}
		usleep(SLEEP_INTERVAL);
		if (single_list_get_nodes_num(&g_free_list) != g_message_units) {
			continue;
		}
		/* clean up tape */
		for (i=0; i<g_tape_units; i++) {
			if (0 != *(int*)((char*)g_tape_begin + BLOCK_SIZE*i)) {
				message_dequeue_load_from_tape(i);
			}
		}
		/* clean up mess */
		seekdir(dirp, 0);
		while ((direntp = readdir(dirp)) != NULL) {
        	if (0 == strcmp(direntp->d_name, ".") ||
				0 == strcmp(direntp->d_name, "..")) {
				continue;
			}
			if (g_current_mem == g_max_memory) {
				break;
			}
            sprintf(file_name, "%s/mess/%s", g_path, direntp->d_name);
			mess_fd = open(file_name, O_RDONLY);
			if (-1 == mess_fd) {
				continue;
			}
			len = read(mess_fd, &size, sizeof(size_t));
			close(mess_fd);
			if (len != sizeof(size_t)) {
				continue;
			}
			if (0 == size) {
				continue;
			}
			mess = atoi(direntp->d_name);
			message_dequeue_load_from_mess(mess);
		}
	}
	closedir(dirp);
	return NULL;
}

/*
 *  message dequeue's console talk function
 *  @param
 *  	param			MESSAGE_DEQUEUE_HOLDING
 *						MESSAGE_DEQUEUE_PROCESSING
 *						MESSAGE_DEQUEUE_DEQUEUED
 *						MESSAGE_DEQUEUE_ALLOCATED
 *	@return
 *		value
 */
int message_dequeue_get_param(int param)
{
	int ret_val;

	switch(param) {
	case MESSAGE_DEQUEUE_HOLDING:
		return single_list_get_nodes_num(&g_used_list);
	case MESSAGE_DEQUEUE_PROCESSING:
		ret_val = g_message_units - single_list_get_nodes_num(&g_used_list) -
				  single_list_get_nodes_num(&g_free_list);
		return ret_val;
	case MESSAGE_DEQUEUE_DEQUEUED:
		ret_val = g_dequeued_num;
		g_dequeued_num = 0;
		return ret_val;
	case MESSAGE_DEQUEUE_ALLOCATED:
		return g_current_mem/(BLOCK_SIZE/2);
	default:
		return 0;
	}
}

/*
 *	for debuging when fail to retrieve message into mail object
 *	@param
 *		pmessage [in]			message object
 */
void message_dequeue_save(MESSAGE *pmessage)
{
	char new_file[256];
	char old_file[256];
	char *ptr;
	int fd, len;
	
	sprintf(new_file, "%s/save/%d", g_path, pmessage->flush_ID);
	if (MESSAGE_MESS == pmessage->message_option) {
		sprintf(old_file, "%s/mess/%d", g_path, pmessage->message_data);
		link(old_file, new_file);		
	} else {
		fd = open(new_file, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);	
		write(fd, pmessage->begin_address, pmessage->mail_length + 4*sizeof(int));
		len = strlen(pmessage->envelop_from);
		write(fd, pmessage->envelop_from, len + 1);
		ptr = pmessage->envelop_rcpt;
		while ((len = strlen(ptr)) != 0) {
			len ++;
			write(fd, ptr, len);
			ptr += len;
		}
		close(fd);
	}
}

