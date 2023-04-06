// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
/*
 *  mail queue have two parts, mess, message queue.when a mail 
 *	is put into mail queue, and create a file in mess directory and write the
 *  mail into file. after mail is saved, system will send a message to
 *  message queue to indicate there's a new mail arrived!
 */
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <list>
#include <pthread.h>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <libHX/string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/fileio.h>
#include <gromox/flusher_common.h>
#include <gromox/paths.h>
#include <gromox/plugin.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>
#define TOKEN_MESSAGE_QUEUE     1
#define MAX_LINE_LENGTH			64*1024

using namespace std::string_literals;
using namespace gromox;

enum {
	MESSAGE_MESS = 2,
};

enum {
	SMTP_IN = 1,
	SMTP_OUT,
	SMTP_RELAY
};

namespace {

struct MSG_BUFF {
    long msg_type;
    int msg_content;
};

}

static void *meq_thrwork(void *);
static BOOL message_enqueue_check();
static int message_enqueue_retrieve_max_ID();
static BOOL message_enqueue_try_save_mess(FLUSH_ENTITY *);

static char         g_path[256];
static int			g_msg_id;
static pthread_t    g_flushing_thread;
static gromox::atomic_bool g_notify_stop;
static int			g_last_flush_ID;
static int			g_enqueued_num;
static int			g_last_pos;

static void *(*query_serviceF)(const char *, const std::type_info &);
static int (*get_queue_length)();
static BOOL (*feedback_entity)(std::list<FLUSH_ENTITY> &&);
static BOOL (*register_cancel)(CANCEL_FUNCTION);
static std::list<FLUSH_ENTITY> (*get_from_queue)();
static const char *(*get_host_ID)();
static const char *(*get_config_path)();
static const char *(*get_data_path)();
static const char *(*get_state_path)();
static int (*get_extra_num)(int);
static const char *(*get_extra_tag)(int, int);
static const char *(*get_extra_value)(int, int);
static BOOL (*set_flush_ID)(int);
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(query_serviceF((n), typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)

/*
 *    @param
 *    	path [in]    	path for saving files
 */
static void message_enqueue_init(const char *path)
{
	gx_strlcpy(g_path, path, GX_ARRAY_SIZE(g_path));
	g_notify_stop = true;
    g_last_flush_ID = 0;
	g_enqueued_num = 0;
	g_last_pos = 0;
}

/*
 *    @return
 *    	0			success
 *		<>0			fail
 */
static int message_enqueue_run()
{
	key_t k_msg;
	char name[266];

	if (!message_enqueue_check())
		return -1;
	snprintf(name, GX_ARRAY_SIZE(name), "%s/token.ipc", g_path);
	int fd = open(name, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd >= 0)
		close(fd);
    k_msg = ftok(name, TOKEN_MESSAGE_QUEUE);
    if (-1 == k_msg) {
		mlog(LV_ERR, "message_enqueue: ftok %s: %s", name, strerror(errno));
        return -2;
    }
    /* create the message queue */
    g_msg_id = msgget(k_msg, 0666|IPC_CREAT);
    if (-1 == g_msg_id) {
		mlog(LV_ERR, "message_enqueue: msgget: %s", strerror(errno));
        return -6;
    }
    g_last_flush_ID = message_enqueue_retrieve_max_ID();
	g_notify_stop = false;
	auto ret = pthread_create4(&g_flushing_thread, nullptr, meq_thrwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "message_enqueue: failed to create flushing thread: %s", strerror(ret));
        return -7;
    }
	pthread_setname_np(g_flushing_thread, "flusher");
    return 0;
}

/*
 *  cancel part of a mail, only mess messages will be canceled
 *  @param
 *      pentity [in]     indicate the mail object for cancelling
 */
static void message_enqueue_cancel(FLUSH_ENTITY *pentity) try
{
	auto file_name = g_path + "/mess/"s + std::to_string(pentity->pflusher->flush_ID);
    fclose((FILE*)pentity->pflusher->flush_ptr);
    pentity->pflusher->flush_ptr = NULL;
	if (remove(file_name.c_str()) < 0 && errno != ENOENT)
		mlog(LV_WARN, "W-1399: remove %s: %s", file_name.c_str(), strerror(errno));
    pentity->pflusher->flush_ID = 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1528: ENOMEM");
}

static int message_enqueue_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (!pthread_equal(g_flushing_thread, {})) {
			pthread_kill(g_flushing_thread, SIGALRM);
			pthread_join(g_flushing_thread, NULL);
		}
	}
    return 0;
}

static void message_enqueue_free()
{
    g_path[0] = '\0';
	g_notify_stop = true;
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
static BOOL message_enqueue_check() try
{
    struct  stat node_stat;

    /* check if the directory exists and is a real directory */
    if (0 != stat(g_path, &node_stat)) {
		mlog(LV_ERR, "message_enqueue: cannot find directory %s", g_path);
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
		mlog(LV_ERR, "message_enqueue: %s is not a directory", g_path);
        return FALSE;
    }
	auto name = g_path + "/mess"s;
	if (stat(name.c_str(), &node_stat) != 0) {
		mlog(LV_ERR, "message_enqueue: cannot find directory %s", name.c_str());
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
		mlog(LV_ERR, "message_enqueue: %s is not a directory", name.c_str());
		return FALSE;
    }
	name = g_path + "/save"s;
	if (stat(name.c_str(), &node_stat) != 0) {
		mlog(LV_ERR, "message_enqueue: cannot find directory %s", name.c_str());
        return FALSE;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
		mlog(LV_ERR, "message_enqueue: %s is not a directory", name.c_str());
		return FALSE;
    }
    return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1530: ENOMEM");
	return false;
}

static void *meq_thrwork(void *arg)
{
	MSG_BUFF msg;

	while (!g_notify_stop) {
		auto entlist = get_from_queue(); /* always size 1 */
		if (entlist.size() == 0) {
            usleep(50000);
            continue;
        }
		auto pentity = &entlist.front();
		if (message_enqueue_try_save_mess(pentity)) {
			if (FLUSH_WHOLE_MAIL == pentity->pflusher->flush_action) {
    			msg.msg_type = MESSAGE_MESS;
    			msg.msg_content = pentity->pflusher->flush_ID;
				msgsnd(g_msg_id, &msg, sizeof(uint32_t), IPC_NOWAIT);
				g_enqueued_num ++;
			}
			pentity->pflusher->flush_result = FLUSH_RESULT_OK;
		} else {
			pentity->pflusher->flush_result = FLUSH_TEMP_FAIL;
		}
		feedback_entity(std::move(entlist));
	}
	return NULL;
}

BOOL message_enqueue_try_save_mess(FLUSH_ENTITY *pentity)
{
	std::string name;
    char time_buff[128];
	char tmp_buff[MAX_LINE_LENGTH + 2];
    time_t cur_time;
	struct tm tm_buff;
	FILE *fp;
	size_t write_len, utmp_len;
	int j, tmp_len, copy_result;
	unsigned int size;
	static constexpr uint32_t smtp_type = SMTP_IN;

	try {
		name = g_path + "/mess/"s + std::to_string(pentity->pflusher->flush_ID);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1529: ENOMEM");
		return false;
	}
	uint64_t mess_len = 0;
	if (NULL == pentity->pflusher->flush_ptr) {
		fp = fopen(name.c_str(), "w");
        /* check if the file is created successfully */
        if (NULL == fp) {
            return FALSE;
        }
		pentity->pflusher->flush_ptr = fp;
		/* write first 4(8) bytes in the file to indicate incomplete mess */
		mess_len = cpu_to_le64(0);
		if (fwrite(&mess_len, 1, sizeof(mess_len), fp) != sizeof(mess_len))
			goto REMOVE_MESS;
        /* construct head information for mess file */
        cur_time = time(NULL);
        strftime(time_buff, 128,"%a, %d %b %Y %H:%M:%S %z",
			localtime_r(&cur_time, &tm_buff));
		int af_type = 0;
		socklen_t af_len = sizeof(af_type);
		if (getsockopt(pentity->pconnection->sockd, SOL_SOCKET,
		    SO_DOMAIN, &af_type, &af_len) != 0 || af_len != sizeof(af_type))
			af_type = 0;
		tmp_len = sprintf(tmp_buff, "X-Lasthop: %s\r\nReceived: from %s "
		          "(%s [%s%s])\r\n\tby %s with %s%s;\r\n\t%s\r\n",
		          pentity->pconnection->client_ip,
		          pentity->penvelope->hello_domain,
		          pentity->penvelope->parsed_domain,
		          af_type == AF_INET6 ? "IPv6:" : "",
		          pentity->pconnection->client_ip, get_host_ID(),
		          pentity->command_protocol == HT_LMTP ? "LMTP" : "SMTP",
		          pentity->pconnection->ssl != nullptr ? "S" : "", /* RFC 3848 */
		          time_buff);
		write_len = fwrite(tmp_buff, 1, tmp_len, fp);
		if (write_len != static_cast<size_t>(tmp_len))
			goto REMOVE_MESS;
		for (j=0; j<get_extra_num(pentity->context_ID); j++) {
			tmp_len = snprintf(tmp_buff, arsizeof(tmp_buff), "%s: %s\r\n",
					get_extra_tag(pentity->context_ID, j),
					get_extra_value(pentity->context_ID, j));
			write_len = fwrite(tmp_buff, 1, tmp_len, fp);
			if (write_len != static_cast<size_t>(tmp_len))
				goto REMOVE_MESS;
		}
	} else {
		fp = (FILE*)pentity->pflusher->flush_ptr;
	}
	/* write stream into mess file */
	while (true) {
		size = MAX_LINE_LENGTH;
		copy_result = pentity->pstream->copyline(tmp_buff, &size);
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
	mess_len -= sizeof(uint64_t); /* length at front of file */
   	/* write flush ID */
	if (fwrite(&pentity->pflusher->flush_ID, 1, sizeof(uint32_t), fp) != sizeof(uint32_t))
		goto REMOVE_MESS;
	/* write bound type */
	if (fwrite(&smtp_type, 1, sizeof(uint32_t), fp) != sizeof(uint32_t) ||
	    fwrite(&pentity->is_spam, 1, sizeof(uint32_t), fp) != sizeof(uint32_t))
		goto REMOVE_MESS;
	/* write envelope from */
	utmp_len = strlen(pentity->penvelope->from) + 1;
	if (fwrite(pentity->penvelope->from, 1, utmp_len, fp) != utmp_len)
		goto REMOVE_MESS;
	/* write envelope rcpts */
	for (const auto &rcpt : pentity->penvelope->rcpt_to)
		if (fwrite(rcpt.c_str(), 1, rcpt.size() + 1, fp) != rcpt.size() + 1)
			goto REMOVE_MESS;
	/* last null character for indicating end of rcpt to array */
	*tmp_buff = 0;
	fwrite(tmp_buff, 1, 1, fp);
	fseek(fp, SEEK_SET, 0);
	if (fwrite(&mess_len, 1, sizeof(uint64_t), fp) != sizeof(uint64_t))
		goto REMOVE_MESS;
    fclose(fp);
	pentity->pflusher->flush_ptr = NULL;
	return TRUE;

 REMOVE_MESS:
	fclose(fp);
    pentity->pflusher->flush_ptr = NULL;
	if (remove(name.c_str()) < 0 && errno != ENOENT)
		mlog(LV_WARN, "W-1424: remove %s: %s", name.c_str(), strerror(errno));
	return FALSE;
}

/*
 *    retrieve the maximum ID from queue
 *    @return
 *        >=0        the maximum ID used in queue
 */
static int message_enqueue_retrieve_max_ID() try
{
    struct dirent *direntp;
	int fd, size, max_ID;

	max_ID = 0;
	/* get maximum flushID in mess */
	auto temp_path = g_path + "/mess"s;
	auto dirp = opendir_sd(temp_path.c_str(), nullptr);
	if (dirp.m_dir != nullptr) while ((direntp = readdir(dirp.m_dir.get())) != nullptr) {
		if (strcmp(direntp->d_name, ".") == 0 ||
		    strcmp(direntp->d_name, "..") == 0)
			continue;
		int temp_ID = strtol(direntp->d_name, nullptr, 0);
        if (temp_ID > max_ID) {
			temp_path = g_path + "/mess/"s + direntp->d_name;
			fd = open(temp_path.c_str(), O_RDONLY);
			if (-1 == fd) {
				continue;
			}
			if (read(fd, &size, sizeof(uint32_t)) != sizeof(uint32_t)) {
				close(fd);
				continue;
			}
			close(fd);
			if (size != 0)
				max_ID = temp_ID;
			else if (remove(temp_path.c_str()) < 0 && errno != ENOENT)
				mlog(LV_WARN, "W-1421: remove %s: %s", temp_path.c_str(), strerror(errno));
        } 
    }
    return max_ID;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1532: ENOMEM");
	return 0;
}

static BOOL flh_message_enqueue(int reason, void** ppdata)
{
	const char *queue_path;

	switch (reason) {
	case PLUGIN_INIT: {
		query_serviceF = reinterpret_cast<decltype(query_serviceF)>(ppdata[0]);
		query_service1(get_queue_length);
		query_service1(feedback_entity);
		query_service1(register_cancel);
		query_service1(get_from_queue);
		query_service1(get_host_ID);
		query_service1(set_flush_ID);
		query_service1(get_config_path);
		query_service1(get_data_path);
		query_service1(get_state_path);
		query_service1(get_extra_num);
		query_service1(get_extra_tag);
		query_service1(get_extra_value);
		auto pfile = config_file_initd("message_enqueue.cfg", get_config_path(), nullptr);
		if (pfile == nullptr) {
			mlog(LV_ERR, "message_enqueue: config_file_initd message_enqueue.cfg: %s",
				strerror(errno));
			return false;
		}
		queue_path = pfile->get_value("ENQUEUE_PATH");
		if (queue_path == nullptr)
			queue_path = PKGSTATEQUEUEDIR;
		mlog(LV_INFO, "message_enqueue: enqueue path is %s", queue_path);

		message_enqueue_init(queue_path);
		if (message_enqueue_run() != 0) {
			mlog(LV_ERR, "message_enqueue: failed to run the module");
			return false;
		}
		if (!register_cancel(message_enqueue_cancel)) {
			mlog(LV_ERR, "message_enqueue: failed to register cancel flushing");
			return false;
		}
		set_flush_ID(g_last_flush_ID);
		return TRUE;
	}
	case PLUGIN_FREE:
		if (message_enqueue_stop() != 0)
			return false;
		message_enqueue_free();
		return TRUE;
	}
	return TRUE;
}
BOOL FLH_LibMain(int r, void **p) { return flh_message_enqueue((r), (p)); }
