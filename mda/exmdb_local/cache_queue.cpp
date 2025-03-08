// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <libHX/endian.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

using namespace std::string_literals;
using namespace gromox;
DECLARE_HOOK_API(exmdb_local, extern);
using namespace exmdb_local;

static char g_path[256];
static std::atomic<unsigned long> g_mess_id;
static int g_scan_interval;
static int g_retrying_times;
static pthread_t g_thread_id;
static std::mutex g_id_lock;
static gromox::atomic_bool g_notify_stop{true};

static unsigned long cache_queue_retrieve_mess_ID();
static void *mdl_thrwork(void *);

/*
 *	@param
 *		path [in]				queue path
 *		scan_interval			interval of queue scanning
 *		retrying_times			retrying times of delivery
 */
void cache_queue_init(const char *path, int scan_interval, int retrying_times)
{
	gx_strlcpy(g_path, path, std::size(g_path));
	g_scan_interval = scan_interval;
	g_retrying_times = retrying_times;
	g_notify_stop = true;
}

/*
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int cache_queue_run()
{
	struct stat node_stat;

	/* check the directory */
    if (0 != stat(g_path, &node_stat)) {
		mlog(LV_ERR, "exmdb_local: can not find %s directory", g_path);
        return -1;
    }
    if (0 == S_ISDIR(node_stat.st_mode)) {
		mlog(LV_ERR, "exmdb_local: %s is not a directory", g_path);
        return -2;
    }
	{ /* silence cov-scan, take locks even in single-thread scenarios */
		std::lock_guard lk(g_id_lock);
		g_mess_id = cache_queue_retrieve_mess_ID();
	}
	g_notify_stop = false;
	auto ret = pthread_create4(&g_thread_id, nullptr, mdl_thrwork, nullptr);
	if (ret != 0) {
		g_notify_stop = true;
		mlog(LV_ERR, "exmdb_local: failed to create timer thread: %s", strerror(ret));
		return -3;
	}
	pthread_setname_np(g_thread_id, "cache_queue");
	return 0;
}

void cache_queue_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (!pthread_equal(g_thread_id, {})) {
			pthread_kill(g_thread_id, SIGALRM);
			pthread_join(g_thread_id, NULL);
		}
	}
}

void cache_queue_free()
{
	g_path[0] = '\0';
	g_scan_interval = 0;
	g_retrying_times = 0;
}

/*
 *	put message into timer queue
 *	@param
 *		pcontext [in]		message context to be sent
 *		rcpt_to [in]        rcpt address
 *		original_time		original time
 *	@return
 *		>=0					timer ID
 *		<0					fail
 */
int cache_queue_put(MESSAGE_CONTEXT *pcontext, const char *rcpt_to,
	time_t original_time)
{
	std::string file_name;

	auto mess_id = ++g_mess_id;
	try {
		file_name = g_path + "/"s + std::to_string(mess_id);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1531: ENOMEM");
		return -1;
	}
	wrapfd fd = open(file_name.c_str(), O_WRONLY | O_CREAT | O_TRUNC, FMODE_PRIVATE);
	if (fd.get() < 0)
		return -1;
	/* write 0 at the begin of file to indicate message is now being written */
	uint32_t enc_times    = cpu_to_le32(0);
	uint64_t enc_origtime = cpu_to_le64(original_time);
	if (write(fd.get(), &enc_times, sizeof(enc_times)) != sizeof(enc_times) ||
	    write(fd.get(), &enc_origtime, sizeof(enc_origtime)) != sizeof(enc_origtime)) {
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1353: remove %s: %s",
			        file_name.c_str(), strerror(errno));
        return -1;
	}
	/* at the begin of file, write the length of message */
	auto maillen = pcontext->mail.get_length();
	if (maillen < 0) {
		mlog(LV_ERR, "exmdb_local: failed to get mail length");
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1354: remove %s: %s",
			        file_name.c_str(), strerror(errno));
        return -1;
	}
	auto len = cpu_to_le32(static_cast<size_t>(maillen));
	if (write(fd.get(), &len, sizeof(len)) != sizeof(len)) {
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1355: remove %s: %s",
			        file_name.c_str(), strerror(errno));
        return -1;
	}
	uint32_t enc_qid    = cpu_to_le32(pcontext->ctrl.queue_ID);
	uint32_t enc_bound  = cpu_to_le32(pcontext->ctrl.bound_type);
	uint32_t enc_spam   = cpu_to_le32(false);
	uint32_t enc_bounce = cpu_to_le32(pcontext->ctrl.need_bounce);
	auto err = pcontext->mail.to_fd(fd.get());
	if (err != 0) {
		mlog(LV_ERR, "E-1765: writeout failed: %s", strerror(err));
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-2106: remove %s: %s",
			        file_name.c_str(), strerror(errno));
		return -1;
	}
	if (write(fd.get(), &enc_qid, sizeof(enc_qid)) != sizeof(enc_qid) ||
	    write(fd.get(), &enc_bound, sizeof(enc_bound)) != sizeof(enc_bound) ||
	    write(fd.get(), &enc_spam, sizeof(enc_spam)) != sizeof(enc_spam) ||
	    write(fd.get(), &enc_bounce, sizeof(enc_bounce)) != sizeof(enc_bounce)) {
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1356: remove %s: %s",
			        file_name.c_str(), strerror(errno));
        return -1;
    }
	/* write envelope from */
	auto temp_len = strlen(pcontext->ctrl.from) + 1;
	auto wrret = write(fd.get(), pcontext->ctrl.from, temp_len);
	if (wrret < 0 || static_cast<size_t>(wrret) != temp_len) {
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1357: remove %s: %s",
			        file_name.c_str(), strerror(errno));
        return -1;
    }
	/* write envelope rcpt */
	temp_len = strlen(rcpt_to) + 1;
	wrret = write(fd.get(), rcpt_to, temp_len);
	if (wrret < 0 || static_cast<size_t>(wrret) != temp_len) {
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1358: remove %s: %s",
			        file_name.c_str(), strerror(errno));
		return -1;
    }
    /* last null character for indicating end of rcpt to array */
	if (write(fd.get(), "", 1) != 1) {
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1359: remove %s: %s",
			        file_name.c_str(), strerror(errno));
        return -1;
	}
	lseek(fd.get(), 0, SEEK_SET);
	enc_times = cpu_to_le32(1);
	if (write(fd.get(), &enc_times, sizeof(enc_times)) != sizeof(enc_times) ||
	    fd.close_wr() != 0) {
		if (remove(file_name.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1360: remove %s: %s",
			        file_name.c_str(), strerror(errno));
        return -1;
	}
	return mess_id;
}

static unsigned long cache_queue_retrieve_mess_ID()
{
	struct dirent *direntp;
	unsigned long max_ID = 0;
	auto dirp = opendir_sd(g_path, nullptr);
	if (dirp.m_dir != nullptr) while ((direntp = readdir(dirp.m_dir.get())) != nullptr) {
		if (strcmp(direntp->d_name, ".") == 0 ||
		    strcmp(direntp->d_name, "..") == 0)
			continue;
		errno = 0;
		auto id = strtoul(direntp->d_name, nullptr, 0);
		if (id != ULONG_MAX || errno != ERANGE)
			max_ID = std::max(max_ID, id);
	}
	return max_ID;
}

static void *mdl_thrwork(void *arg)
{
	const char *bounce_type = nullptr;
	int i, scan_interval;
    struct dirent *direntp;
	char temp_from[UADDR_SIZE], temp_rcpt[UADDR_SIZE];
	char *ptr;
	MESSAGE_CONTEXT *pcontext, *pbounce_context;
	BOOL need_bounce = false, need_remove = false;

	pcontext = get_context();
	if (NULL == pcontext) {
		mlog(LV_ERR, "exmdb_local: failed to get context in cache queue thread");
		return nullptr;
	}
	auto dirp = opendir_sd(g_path, nullptr);
	if (dirp.m_dir == nullptr) {
		mlog(LV_ERR, "exmdb_local: failed to open cache directory %s: %s",
			g_path, strerror(errno));
		return nullptr;
	}
	i = 0;
	scan_interval = g_scan_interval;
	while (!g_notify_stop) {
		if (i < scan_interval) {
			i ++;
			sleep(1);
			continue;
		}
		seekdir(dirp.m_dir.get(), 0);
		auto scan_begin = time(nullptr);
		while ((direntp = readdir(dirp.m_dir.get())) != nullptr) {
			if (g_notify_stop)
				break;
			if (strcmp(direntp->d_name, ".") == 0 ||
			    strcmp(direntp->d_name, "..") == 0)
				continue;
			std::string temp_path;
			try {
				temp_path = std::string(g_path) + "/" + direntp->d_name;
			} catch (const std::bad_alloc &) {
				mlog(LV_ERR, "E-1475: ENOMEM");
			}
			wrapfd fd = open(temp_path.c_str(), O_RDWR);
			if (fd.get() < 0)
				continue;
			struct stat node_stat;
			uint32_t times, mess_len;
			if (fstat(fd.get(), &node_stat) != 0 || !S_ISREG(node_stat.st_mode))
				continue;
			if (read(fd.get(), &times, sizeof(uint32_t)) != sizeof(uint32_t))
				continue;
			times = le32_to_cpu(times);
			if (times == 0)
		                continue;
			uint64_t enc_origtime;
			if (read(fd.get(), &enc_origtime, sizeof(uint64_t)) != sizeof(uint64_t) ||
			    read(fd.get(), &mess_len, sizeof(uint32_t)) != sizeof(uint32_t)) {
				mlog(LV_ERR, "exmdb_local: failed to read information from %s "
					"in timer queue", temp_path.c_str());
				continue;
			}
			time_t original_time = le64_to_cpu(enc_origtime);
			mess_len = le32_to_cpu(mess_len);
			size_t size = node_stat.st_size - sizeof(time_t) - 2 * sizeof(uint32_t);
			if (size < mess_len) {
				mlog(LV_WARN, "W-1554: garbage in %s; review and delete", temp_path.c_str());
				continue;
			}
			auto pbuff = me_alloc<char>(((size - 1) / (64 * 1024) + 1) * 64 * 1024);
			if (NULL == pbuff) {
				mlog(LV_ERR, "exmdb_local: Failed to allocate memory for %s "
					"in timer queue thread", temp_path.c_str());
				continue;
			}
			auto rdret = read(fd.get(), pbuff, size);
			if (rdret < 0 || static_cast<size_t>(rdret) != size) {
				free(pbuff);
				mlog(LV_ERR, "exmdb_local: partial read from %s", temp_path.c_str());
				continue;
			}
			if (!pcontext->mail.load_from_str(pbuff, mess_len)) {
				free(pbuff);
				mlog(LV_ERR, "exmdb_local: failed to retrieve message %s in "
				       "cache queue into mail object", temp_path.c_str());
				continue;
			}
			ptr = pbuff + mess_len; /* to hell with this bullcrap */
			size -= mess_len;
			if (size < sizeof(uint32_t)) {
				mlog(LV_WARN, "W-1555: garbage in %s; review and delete", temp_path.c_str());
				continue;
			}
			pcontext->ctrl.queue_ID = le32p_to_cpu(ptr);
			ptr += sizeof(uint32_t);
			size -= sizeof(uint32_t);
			if (size < sizeof(uint32_t)) {
				mlog(LV_WARN, "W-1556: garbage in %s; review and delete", temp_path.c_str());
				continue;
			}
			pcontext->ctrl.bound_type = le32p_to_cpu(ptr);
			ptr += sizeof(uint32_t);
			size -= sizeof(uint32_t);
			if (size < sizeof(uint32_t)) {
				mlog(LV_WARN, "W-1557: garbage in %s; review and delete", temp_path.c_str());
				continue;
			}
			// pcontext->ctrl.is_spam = le32p_to_cpu(ptr);
			ptr += sizeof(uint32_t);
			size -= sizeof(uint32_t);
			if (size < sizeof(uint32_t)) {
				mlog(LV_WARN, "W-1558: garbage in %s; review and delete", temp_path.c_str());
				continue;
			}
			pcontext->ctrl.need_bounce = le32p_to_cpu(ptr);
			ptr += sizeof(uint32_t);
			size -= sizeof(uint32_t);

			if (size == 0)
				mlog(LV_WARN, "W-1559: garbage in %s; review and delete", temp_path.c_str());
			auto zlen = strnlen(ptr, size);
			if (zlen > INT32_MAX)
				zlen = INT32_MAX;
			snprintf(pcontext->ctrl.from, std::size(pcontext->ctrl.from),
			         "%.*s", static_cast<int>(zlen), ptr);
			snprintf(temp_from, std::size(temp_from),
			         "%.*s", static_cast<int>(zlen), ptr);
			ptr += zlen;
			size -= zlen;
			if (size == 0 || *ptr != '\0')
				mlog(LV_WARN, "W-1570: garbage in %s; review and delete", temp_path.c_str());
			++ptr;
			--size;

			if (size == 0)
				mlog(LV_WARN, "W-1590: garbage in %s; review and delete", temp_path.c_str());
			zlen = strnlen(ptr, size);
			/* Need \0 for going on */
			delivery_status deliv_ret;
			if (zlen == size) {
				mlog(LV_WARN, "W-1591: garbage in %s; review and delete", temp_path.c_str());
				deliv_ret = delivery_status::perm_fail;
			} else {
				pcontext->ctrl.rcpt.clear();
				pcontext->ctrl.rcpt.emplace_back(ptr);
				gx_strlcpy(temp_rcpt, ptr, std::size(temp_rcpt));

				if (static_cast<unsigned int>(g_retrying_times) <= times) {
					need_bounce = TRUE;
					need_remove = TRUE;
					bounce_type = "BOUNCE_OPERATION_ERROR";
				} else {
					need_bounce = FALSE;
					need_remove = FALSE;
				}
				deliv_ret = exmdb_local_deliverquota(pcontext, ptr);
			}
			switch (deliv_ret) {
			case delivery_status::ok:
				need_bounce = FALSE;
				need_remove = TRUE;
				break;
			case delivery_status::bounce_sent:
				bounce_type = "BOUNCE_MAIL_DELIVERED";
				need_bounce = TRUE;
				need_remove = TRUE;
				break;
			case delivery_status::no_user:
				bounce_type = "BOUNCE_NO_USER";
			    need_bounce = TRUE;
				need_remove = TRUE;
				break;
			case delivery_status::mailbox_full:
				bounce_type = "BOUNCE_MAILBOX_FULL";
			    need_bounce = TRUE;
				need_remove = TRUE;
			    break;
			case delivery_status::perm_fail:
				bounce_type = "BOUNCE_OPERATION_ERROR";
				need_bounce = TRUE;
				need_remove = TRUE;
				break;
			case delivery_status::temp_fail:
				break;
			}
			if (!need_remove) {
				/* rewrite type and until time */
				lseek(fd.get(), 0, SEEK_SET);
				times = cpu_to_le32(times + 1);
				if (write(fd.get(), &times, sizeof(uint32_t)) != sizeof(uint32_t) ||
				    fd.close_wr() != 0)
					mlog(LV_ERR, "exmdb_local: error while updating "
						"times");
			}
			fd.close_rd();
			if (need_remove && remove(temp_path.c_str()) < 0 && errno != ENOENT)
				mlog(LV_WARN, "W-1432: remove %s: %s",
				        temp_path.c_str(), strerror(errno));
			need_bounce &= pcontext->ctrl.need_bounce;
			
			if (need_bounce && strcasecmp(pcontext->ctrl.from,
			    ENVELOPE_FROM_NULL) != 0) {
				pbounce_context = get_context();
				if (NULL == pbounce_context) {
					exmdb_local_log_info(pcontext->ctrl, ptr, LV_ERR, "fail to get one "
						"context for bounce mail");
				} else if (!bounce_audit_check(temp_rcpt)) {
					exmdb_local_log_info(pcontext->ctrl, ptr, LV_ERR, "will not "
						"produce bounce message, because of too many "
						"mails to %s", temp_rcpt);
					put_context(pbounce_context);
				} else if (!exml_bouncer_make(temp_from,
				    temp_rcpt, &pcontext->mail, original_time,
				    bounce_type, &pbounce_context->mail)) {
					exmdb_local_log_info(pcontext->ctrl, ptr, LV_ERR,
						"error during exml_bouncer_make for %s",
						temp_rcpt);
					put_context(pbounce_context);
				} else {
					gx_strlcpy(pbounce_context->ctrl.from,
						bounce_gen_postmaster(),
						std::size(pbounce_context->ctrl.from));
					pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
					enqueue_context(pbounce_context);
				}
			}
			free(pbuff);
		}
		auto scan_end = time(nullptr);
		if (scan_end - scan_begin >= g_scan_interval)
			scan_interval = 0;
		else
			scan_interval = g_scan_interval - (scan_end - scan_begin);
		i = 0;
	}
	return NULL;
}
