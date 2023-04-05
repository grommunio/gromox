// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/* imap parser is a module, which first read data from socket, parses the imap 
 * commands and then do the corresponding action. 
 */ 
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <libHX/string.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/mjson.hpp>
#include <gromox/scope.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "imap.hpp"
#include "../midb_agent.hpp"
#if (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2090000fL) || \
    (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x1010000fL)
#	define OLD_SSL 1
#endif
#define SLEEP_BEFORE_CLOSE true
#define FILENUM_PER_MIME		8

#define SCAN_INTERVAL			3600

#define SELECT_INTERVAL			20*60

using namespace std::string_literals;
using namespace gromox;

static void *imps_thrwork(void *);
static void *imps_scanwork(void *);
static void imap_parser_event_proc(char *event);
static void imap_parser_event_touch(const char *user, const char *folder);
static void imap_parser_event_flag(const char *username, const char *folder,
	const char *mid_string);

static int imap_parser_dispatch_cmd(int argc, char **argv, IMAP_CONTEXT *pcontext);

static void imap_parser_context_clear(IMAP_CONTEXT *pcontext);
static int imap_parser_wrdat_retrieve(IMAP_CONTEXT *);

unsigned int g_imapcmd_debug;
int g_max_auth_times, g_block_auth_fail;
bool g_support_tls, g_force_tls;
std::atomic<size_t> g_alloc_xarray;
alloc_limiter<stream_block> g_blocks_allocator{"g_blocks_allocator.d"};
static std::atomic<int> g_sequence_id;
static int g_average_num;
static size_t g_context_num, g_cache_size;
static time_duration g_timeout, g_autologout_time;
static pthread_t g_thr_id;
static pthread_t g_scan_id;
static gromox::atomic_bool g_notify_stop;
static std::unique_ptr<IMAP_CONTEXT[]> g_context_list;
static std::vector<SCHEDULE_CONTEXT *> g_context_list2;
static alloc_limiter<file_block> g_alloc_file{"g_alloc_file.d"};
static alloc_limiter<DIR_NODE> g_alloc_dir{"g_alloc_dir.d"};
static alloc_limiter<MJSON_MIME> g_alloc_mjson{"g_alloc_mjson.d"};
static std::shared_ptr<MIME_POOL> g_mime_pool;
static std::unordered_map<std::string, DOUBLE_LIST> g_select_hash;
static std::mutex g_hash_lock, g_list_lock;
static DOUBLE_LIST g_sleeping_list;
static char g_certificate_path[256];
static char g_private_key_path[256];
static char g_certificate_passwd[1024];
static SSL_CTX *g_ssl_ctx;
static std::unique_ptr<std::mutex[]> g_ssl_mutex_buf;

alloc_limiter<DIR_NODE> *imap_parser_get_dpool()
{
	return &g_alloc_dir;
}

void imap_parser_init(int context_num, int average_num, size_t cache_size,
    time_duration timeout, time_duration autologout_time, int max_auth_times,
    int block_auth_fail, bool support_tls, bool force_tls,
	const char *certificate_path, const char *cb_passwd, const char *key_path)
{
    g_context_num           = context_num;
	g_average_num           = average_num;
	g_cache_size            = cache_size;
    g_timeout               = timeout;
	g_autologout_time       = autologout_time;
	g_max_auth_times        = max_auth_times;
	g_block_auth_fail       = block_auth_fail;
	g_support_tls       = support_tls;
	g_ssl_mutex_buf         = NULL;
	g_notify_stop = true;
	double_list_init(&g_sleeping_list);
	g_sequence_id = 0;
	if (support_tls) {
		g_force_tls = force_tls;
		gx_strlcpy(g_certificate_path, certificate_path, arsizeof(g_certificate_path));
		if (NULL != cb_passwd) {
			gx_strlcpy(g_certificate_passwd, cb_passwd, arsizeof(g_certificate_passwd));
		} else {
			g_certificate_passwd[0] = '\0';
		}
		gx_strlcpy(g_private_key_path, key_path, arsizeof(g_private_key_path));
	}
}

#ifdef OLD_SSL
static void imap_parser_ssl_locking(int mode,
	int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		g_ssl_mutex_buf[n].lock();
	else
		g_ssl_mutex_buf[n].unlock();
}

static void imap_parser_ssl_id(CRYPTO_THREADID* id)
{
	CRYPTO_THREADID_set_numeric(id, static_cast<uintptr_t>(pthread_self()));
}
#endif

/* 
 *    @return
 *         0    success
 *        <>0    fail    
 */
int imap_parser_run()
{
	int num;
	
	if (g_support_tls) {
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		g_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (NULL == g_ssl_ctx) {
			printf("[imap_parser]: Failed to init SSL context\n");
			return -1;
		}
		
		if ('\0' != g_certificate_passwd[0]) {
			SSL_CTX_set_default_passwd_cb_userdata(g_ssl_ctx,
				g_certificate_passwd);
		}
		
		if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx,
			g_certificate_path) <= 0) {
			printf("[imap_parser]: fail to use certificate file:");
			ERR_print_errors_fp(stdout);
			return -2;
		}
		
		if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_private_key_path,
			SSL_FILETYPE_PEM) <= 0) {
			printf("[imap_parser]: fail to use private key file:");
			ERR_print_errors_fp(stdout);
			return -3;
		}
		
		if (1 != SSL_CTX_check_private_key(g_ssl_ctx)) {
			printf("[imap_parser]: private key does not match certificate:");
			ERR_print_errors_fp(stdout);
			return -4;
		}
		auto mp = g_config_file->get_value("tls_min_proto");
		if (mp != nullptr && tls_set_min_proto(g_ssl_ctx, mp) != 0) {
			fprintf(stderr, "[imap_parser]: tls_min_proto value \"%s\" not accepted\n", mp);
			return -4;
		}
		tls_set_renego(g_ssl_ctx);
		try {
			g_ssl_mutex_buf = std::make_unique<std::mutex[]>(CRYPTO_num_locks());
		} catch (const std::bad_alloc &) {
			printf("[imap_parser]: Failed to allocate SSL locking buffer\n");
			return -5;
		}
#ifdef OLD_SSL
		CRYPTO_THREADID_set_callback(imap_parser_ssl_id);
		CRYPTO_set_locking_callback(imap_parser_ssl_locking);
#endif
	}
	num = 1024*g_context_num;
	if (num < 1024*1024) {
		num = 1024*1024;
	}
	g_alloc_file = alloc_limiter<file_block>(num,
	               "imap_alloc_file", "imap.cfg:context_num");
	num = 4*g_context_num;
	if (num < 200) {
		num = 200;
	}

	if (num > 800) {
		num = 800;
	}
	g_mime_pool = MIME_POOL::create(num, FILENUM_PER_MIME, "imap_mime_pool");
	if (NULL == g_mime_pool) {
		printf("[imap_parser]: Failed to init MIME pool\n");
		return -6;
	}
	g_alloc_xarray = g_average_num * g_context_num;
	num = 10*g_context_num;
	if (num < 1000) {
		num = 1000;
	}
	g_alloc_dir = alloc_limiter<DIR_NODE>(num, "imap_alloc_dir",
	              "imap.cfg:g_context_num");
	num = 4*g_context_num;
	if (num < 400) {
		num = 400;
	}
	g_alloc_mjson = mjson_allocator_init(num);
	
	try {
		g_context_list = std::make_unique<IMAP_CONTEXT[]>(g_context_num);
		g_context_list2.resize(g_context_num);
		for (size_t i = 0; i < g_context_num; ++i) {
			g_context_list[i].context_id = i;
			g_context_list2[i] = &g_context_list[i];
		}
	} catch (const std::bad_alloc &) {
		printf("[imap_parser]: Failed to allocate IMAP contexts\n");
        return -10;
    }
	
	g_notify_stop = false;
	auto ret = pthread_create4(&g_thr_id, nullptr, imps_thrwork, nullptr);
	if (ret != 0) {
		printf("[imap_parser]: failed to create sleeping list scanning thread: %s\n", strerror(ret));
		g_notify_stop = true;
		return -11;
	}
	pthread_setname_np(g_thr_id, "parser/worker");
	ret = pthread_create4(&g_scan_id, nullptr, imps_scanwork, nullptr);
	if (ret != 0) {
		printf("[imap_parser]: failed to create select hash scanning thread: %s\n", strerror(ret));
		g_notify_stop = true;
		if (!pthread_equal(g_thr_id, {})) {
			pthread_kill(g_thr_id, SIGALRM);
			pthread_join(g_thr_id, NULL);
		}
		return -12;
	}
	pthread_setname_np(g_scan_id, "parser/scan");
	system_services_install_event_stub(imap_parser_event_proc);
    return 0;
}

void imap_parser_stop()
{
	system_services_install_event_stub(nullptr);
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (!pthread_equal(g_thr_id, {}))
			pthread_kill(g_thr_id, SIGALRM);
		if (!pthread_equal(g_scan_id, {}))
			pthread_kill(g_scan_id, SIGALRM);
		if (!pthread_equal(g_thr_id, {}))
			pthread_join(g_thr_id, NULL);
		if (!pthread_equal(g_scan_id, {}))
			pthread_join(g_scan_id, NULL);
	}
	
	g_context_list2.clear();
	g_context_list.reset();
	g_mime_pool.reset();
	g_select_hash.clear();
	if (g_support_tls && g_ssl_ctx != nullptr) {
		SSL_CTX_free(g_ssl_ctx);
		g_ssl_ctx = NULL;
	}
	if (g_support_tls && g_ssl_mutex_buf != nullptr) {
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		g_ssl_mutex_buf.reset();
	}
	double_list_free(&g_sleeping_list);
    g_context_num		= 0;
	g_cache_size	    = 0;
	g_autologout_time   = std::chrono::seconds(0);
	g_timeout           = std::chrono::seconds(INT32_MAX);
	g_block_auth_fail   = 0;
}

int imap_parser_get_context_socket(const schedule_context *ctx)
{
	return static_cast<const imap_context *>(ctx)->connection.sockd;
}

time_point imap_parser_get_context_timestamp(const schedule_context *ctx)
{
	return static_cast<const imap_context *>(ctx)->connection.last_timestamp;
}

int imap_parser_threads_event_proc(int action)
{
    return 0;
}

enum {
	X_CONTEXT_PROCESSING = -1,
	X_CMD_PROCESSING = -2,
	X_LITERAL_CHECKING = -3,
	X_LITERAL_PROCESSING = -4,
};

static int ps_end_processing(IMAP_CONTEXT *, const char * = nullptr, ssize_t = 0);

static int ps_stat_autologout(IMAP_CONTEXT *pcontext)
{
	imap_parser_log_info(pcontext, LV_DEBUG, "auto logout");
	/* IMAP_CODE_2160004: BYE Disconnected by autologout */
	size_t string_length = 0;
	auto imap_reply_str = resource_get_imap_code(1604, 1, &string_length);
	return ps_end_processing(pcontext, imap_reply_str, string_length);
}

static int ps_stat_disconnected(IMAP_CONTEXT *pcontext)
{
	imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
	return ps_end_processing(pcontext);
}

static int ps_stat_stls(IMAP_CONTEXT *pcontext)
{
	if (NULL == pcontext->connection.ssl) {
		pcontext->connection.ssl = SSL_new(g_ssl_ctx);
		if (NULL == pcontext->connection.ssl) {
			/* IMAP_CODE_2180014: BAD internal error: failed to init SSL object */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1814, 1, &string_length);
			write(pcontext->connection.sockd, imap_reply_str, string_length);
			imap_parser_log_info(pcontext, LV_WARN, "out of memory for TLS object");
			pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
			if (system_services_container_remove_ip != nullptr)
				system_services_container_remove_ip(pcontext->connection.client_ip);
			imap_parser_context_clear(pcontext);
			return PROCESS_CLOSE;
		}
		SSL_set_fd(pcontext->connection.ssl, pcontext->connection.sockd);
	}

	if (SSL_accept(pcontext->connection.ssl) != -1) {
		pcontext->sched_stat = SCHED_STAT_RDCMD;
		if (pcontext->connection.server_port == g_listener_ssl_port) {
			char caps[128];
			capability_list(caps, std::size(caps), pcontext);
			SSL_write(pcontext->connection.ssl, "* OK [CAPABILITY ", 17);
			SSL_write(pcontext->connection.ssl, caps, strlen(caps));
			SSL_write(pcontext->connection.ssl, "] Service ready\r\n", 17);
		}
		return PROCESS_CONTINUE;
	}
	auto ssl_errno = SSL_get_error(pcontext->connection.ssl, -1);
	if (SSL_ERROR_WANT_READ == ssl_errno ||
	    SSL_ERROR_WANT_WRITE == ssl_errno) {
		auto current_time = tp_now();
		if (current_time - pcontext->connection.last_timestamp < g_timeout)
			return PROCESS_POLLING_RDONLY;
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		write(pcontext->connection.sockd, "* ", 2);
		write(pcontext->connection.sockd, imap_reply_str, string_length);
		imap_parser_log_info(pcontext, LV_DEBUG, "timeout");
		pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
	} else {
		pcontext->connection.reset();
	}
	if (system_services_container_remove_ip != nullptr)
		system_services_container_remove_ip(pcontext->connection.client_ip);
	imap_parser_context_clear(pcontext);
	return PROCESS_CLOSE;
}

static int ps_stat_notifying(IMAP_CONTEXT *pcontext)
{
	int exists = 0, recent = 0, err = 0;
	if (MIDB_RESULT_OK == system_services_summary_folder(pcontext->maildir,
	    pcontext->selected_folder, &exists, &recent, NULL, NULL, NULL, NULL, &err)) {
		char temp_buff[64];
		auto len = gx_snprintf(temp_buff, arsizeof(temp_buff),
		           "* %d RECENT\r\n"
		           "* %d EXISTS\r\n",
		           recent, exists);
		pcontext->connection.write(temp_buff, len);
	}
	std::unique_lock ll_hold(g_list_lock);
	double_list_append_as_tail(&g_sleeping_list, &pcontext->sleeping_node);
	pcontext->sched_stat = SCHED_STAT_IDLING;
	return PROCESS_SLEEPING;
}

static int ps_stat_rdcmd(IMAP_CONTEXT *pcontext)
{
	ssize_t read_len;
	if (NULL != pcontext->connection.ssl) {
		read_len = SSL_read(pcontext->connection.ssl, pcontext->read_buffer +
		           pcontext->read_offset, 64*1024 - pcontext->read_offset);
	} else {
		read_len = read(pcontext->connection.sockd, pcontext->read_buffer +
		           pcontext->read_offset, 64*1024 - pcontext->read_offset);
	}
	auto current_time = tp_now();
	if (0 == read_len) {
		imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return ps_end_processing(pcontext);
	} else if (read_len < 0) {
		if (EAGAIN != errno) {
			imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
			return ps_end_processing(pcontext);
		}
		/* check if context is timed out */
		if (current_time - pcontext->connection.last_timestamp < g_timeout)
			return PROCESS_POLLING_RDONLY;
		if (pcontext->is_authed()) {
			std::unique_lock ll_hold(g_list_lock);
			double_list_append_as_tail(&g_sleeping_list, &pcontext->sleeping_node);
			return PROCESS_SLEEPING;
		}
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}

	pcontext->connection.last_timestamp = current_time;
	pcontext->read_offset += read_len;

	if (SCHED_STAT_APPENDED == pcontext->sched_stat ||
	    SCHED_STAT_IDLING == pcontext->sched_stat) {
		return X_CMD_PROCESSING;
	}
	return X_LITERAL_CHECKING;
}

static int ps_literal_checking(IMAP_CONTEXT *pcontext)
{
	if (pcontext->literal_ptr == nullptr) {
		return X_LITERAL_PROCESSING;
	}
	if (pcontext->read_buffer + pcontext->read_offset - pcontext->literal_ptr <
	    pcontext->literal_len) {
		return PROCESS_CONTINUE;
	}
	auto temp_len = pcontext->literal_ptr + pcontext->literal_len - pcontext->read_buffer;
	if (temp_len <= 0 || temp_len >= 64 * 1024 ||
	    pcontext->command_len + temp_len >= 64 * 1024) {
		/* IMAP_CODE_2180017: BAD literal size too large */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	memcpy(pcontext->command_buffer + pcontext->command_len, pcontext->read_buffer,
		temp_len);
	pcontext->command_len += temp_len;
	pcontext->read_offset -= temp_len;
	if (pcontext->read_offset > 0 && pcontext->read_offset < 64*1024) {
		memmove(pcontext->read_buffer, pcontext->literal_ptr + pcontext->literal_len,
			pcontext->read_offset);
	} else {
		pcontext->read_offset = 0;
	}
	pcontext->literal_ptr = NULL;
	pcontext->literal_len = 0;
	return X_LITERAL_PROCESSING;
}

static int ps_literal_processing(IMAP_CONTEXT *pcontext)
{
	auto &ctx = *pcontext;
	/*
	 * Minus 2 is just a mundane microoptimization to short-circuit to the
	 * exit if we don't even have a chance of finding an opening brace and
	 * the mandatory newline (which the line breaker in ps_cmd_processing
	 * has left us with).
	 */
	for (ssize_t i = 0; i < pcontext->read_offset - 2; ++i) {
		if (pcontext->read_buffer[i] != '{' /* } */)
			continue;
		auto ptr = static_cast<char *>(memchr(&pcontext->read_buffer[i],
		           /* { */ '}', pcontext->read_offset - 1 - i));
		if (ptr == nullptr)
			continue;
		auto nl_len = newline_size(&ptr[1], pcontext->read_offset - 1 - i);
		if (nl_len == 0)
			continue;
		if (ptr - pcontext->read_buffer - i > 16) {
			/* IMAP_CODE_2180017: BAD literal size too large */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
			return ps_end_processing(pcontext, imap_reply_str, string_length);
		}

		ctx.literal_ptr = &ptr[1]; /* skip over brace */
		auto temp_len = ptr - &ctx.read_buffer[i+1];
		char temp_buff[4096];
		memcpy(temp_buff, &ctx.read_buffer[i+1], temp_len);
		temp_buff[temp_len] = '\0';
		pcontext->literal_len = strtol(temp_buff, nullptr, 0);
		temp_len = 64 * 1024 - (&ctx.literal_ptr[nl_len] - ctx.read_buffer) -
		           pcontext->command_len - nl_len;
		if (temp_len <= 0 || temp_len >= 64 * 1024) {
			imap_parser_log_info(pcontext, LV_WARN, "error in command buffer length");
			/* IMAP_CODE_2180017: BAD literal size too large */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
			return ps_end_processing(pcontext, imap_reply_str, string_length);
		}
		if (pcontext->literal_len < temp_len) {
			pcontext->read_offset -= nl_len;
			temp_len = ctx.read_offset - (ctx.literal_ptr - ctx.read_buffer);
			if (temp_len > 0 && temp_len < 64 * 1024) {
				memmove(ctx.literal_ptr, &ctx.literal_ptr[nl_len], temp_len);
			}
			/* IMAP_CODE_2160003: + ready for additional command text */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1603, 1, &string_length);
			pcontext->connection.write(imap_reply_str, string_length);
			return X_LITERAL_CHECKING;
		}
		memcpy(&ctx.command_buffer[ctx.command_len],
		       pcontext->read_buffer, i);
		pcontext->command_len += i;
		char *argv[128];
		auto argc = parse_imap_args(pcontext->command_buffer, pcontext->command_len,
			    argv, arsizeof(argv));
		if (argc >= 4 && 0 == strcasecmp(argv[1], "APPEND")) {
			switch (imap_cmd_parser_append_begin(argc, argv, pcontext)) {
			case DISPATCH_CONTINUE: {
				ctx.current_len = &ctx.read_buffer[ctx.read_offset] - &ctx.literal_ptr[nl_len];
				if (pcontext->current_len < 0) {
					imap_parser_log_info(pcontext, LV_WARN, "error in read buffer length");
					/* IMAP_CODE_2180017: BAD literal size too large */
					size_t string_length = 0;
					auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
					return ps_end_processing(pcontext, imap_reply_str, string_length);
				}
				if (pcontext->stream.write(&ctx.literal_ptr[nl_len], ctx.current_len) != STREAM_WRITE_OK)
					return 1922;
				pcontext->sched_stat = SCHED_STAT_APPENDING;
				pcontext->read_offset = 0;
				pcontext->command_len = 0;
				/* IMAP_CODE_2160003 + Ready for additional command text */
				size_t string_length = 0;
				auto imap_reply_str = resource_get_imap_code(1603, 1, &string_length);
				pcontext->connection.write(imap_reply_str, string_length);
				return PROCESS_CONTINUE;
			}
			case DISPATCH_SHOULD_CLOSE:
				return ps_end_processing(pcontext);
			case DISPATCH_BREAK:
				ctx.read_offset -= &ctx.literal_ptr[nl_len] - ctx.read_buffer;
				if (pcontext->read_offset > 0 && pcontext->read_offset < 64*1024) {
					memmove(ctx.read_buffer, &ctx.literal_ptr[nl_len], ctx.read_offset);
				} else {
					pcontext->read_offset = 0;
				}
				pcontext->literal_ptr = NULL;
				pcontext->literal_len = 0;
				pcontext->command_len = 0;
				return X_LITERAL_PROCESSING;
			}
		}

		/* IMAP_CODE_2180017: BAD literal size too large */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
		pcontext->connection.write("* ", 2);
		pcontext->connection.write(imap_reply_str, string_length);
		ctx.read_offset -= &ctx.literal_ptr[nl_len] - ctx.read_buffer;
		if (pcontext->read_offset > 0 && pcontext->read_offset < 64*1024) {
			memmove(ctx.read_buffer, &ctx.literal_ptr[nl_len], ctx.read_offset);
		} else {
			pcontext->read_offset = 0;
		}
		pcontext->literal_ptr = NULL;
		pcontext->literal_len = 0;
		pcontext->command_len = 0;
		return X_LITERAL_PROCESSING;
	}
	return X_CMD_PROCESSING;
}

/*
 * This function tries to mark off a whole line (i.e. find the newline). If
 * none is there yet, ps_cmd_processing will soon be invoked again, with a
 * read_buffer that has been _appended_ to -- so we will see the same leading
 * string in pcontext->read_buffer.
 */
static int ps_cmd_processing(IMAP_CONTEXT *pcontext)
{
	for (ssize_t i = 0; i < pcontext->read_offset; ++i) {
		auto nl_len = newline_size(&pcontext->read_buffer[i], pcontext->read_offset - i);
		if (nl_len == 0)
			continue;
		if (i >= 64 * 1024 || pcontext->command_len + i >= 64 * 1024) {
			imap_parser_log_info(pcontext, LV_WARN, "error in command buffer length");
			/* IMAP_CODE_2180017: BAD literal size too large */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
			return ps_end_processing(pcontext, imap_reply_str, string_length);
		}
		memcpy(pcontext->command_buffer + pcontext->command_len,
		       pcontext->read_buffer, i);
		pcontext->command_len += i;
		pcontext->command_buffer[pcontext->command_len] = '\0';
		pcontext->read_offset -= i + nl_len;
		if (pcontext->read_offset > 0 && pcontext->read_offset < 64 * 1024) {
			memmove(pcontext->read_buffer, &pcontext->read_buffer[i+nl_len],
			        pcontext->read_offset);
		} else {
			pcontext->read_offset = 0;
		}

		char *argv[128];
		if (PROTO_STAT_USERNAME == pcontext->proto_stat) {
			argv[0] = pcontext->command_buffer;
			argv[1] = NULL;
			imap_cmd_parser_username(1, argv, pcontext);
			pcontext->command_len = 0;
			return X_LITERAL_PROCESSING;
		} else if (PROTO_STAT_PASSWORD == pcontext->proto_stat) {
			argv[0] = pcontext->command_buffer;
			argv[1] = NULL;
			if (DISPATCH_SHOULD_CLOSE == imap_cmd_parser_password(
			    1, argv, pcontext)) {
				return ps_end_processing(pcontext);
			}
			pcontext->command_len = 0;
			safe_memset(pcontext->command_buffer, 0, std::size(pcontext->command_buffer));
			return X_LITERAL_PROCESSING;
		}

		auto argc = parse_imap_args(pcontext->command_buffer,
			    pcontext->command_len, argv, arsizeof(argv));
		if (SCHED_STAT_APPENDED == pcontext->sched_stat) {
			if (0 != argc) {
				if (-1 != pcontext->message_fd) {
					close(pcontext->message_fd);
					pcontext->message_fd = -1;
				}
				if (!pcontext->file_path.empty()) {
					if (remove(pcontext->file_path.c_str()) != 0 && errno != ENOENT)
						mlog(LV_WARN, "W-1474: remove %s: %s",
						        pcontext->file_path.c_str(), strerror(errno));
					pcontext->file_path.clear();
				}
				size_t string_length = 0;
				auto imap_reply_str = resource_get_imap_code(1800, 1, &string_length);
				pcontext->connection.write(pcontext->tag_string, strlen(pcontext->tag_string));
				pcontext->connection.write(" ", 1);
				pcontext->connection.write(imap_reply_str, string_length);
			} else {
				imap_cmd_parser_append_end(argc, argv, pcontext);
			}
			pcontext->sched_stat = SCHED_STAT_RDCMD;
			pcontext->literal_ptr = NULL;
			pcontext->literal_len = 0;
			pcontext->command_len = 0;
			return X_LITERAL_PROCESSING;
		}

		if (SCHED_STAT_IDLING == pcontext->sched_stat) {
			size_t string_length = 0;
			const char *imap_reply_str = nullptr;
			if (1 != argc || 0 != strcasecmp(argv[0], "DONE")) {
				/* IMAP_CODE_2180018: BAD expected DONE */
				imap_reply_str = resource_get_imap_code(1818, 1,
				                 &string_length);
			} else {
				pcontext->sched_stat = SCHED_STAT_RDCMD;
				/* IMAP_CODE_2170027: OK IDLE completed */
				imap_reply_str = resource_get_imap_code(1727, 1,
				                 &string_length);
			}
			pcontext->connection.write(pcontext->tag_string, strlen(pcontext->tag_string));
			pcontext->connection.write(" ", 1);
			pcontext->connection.write(imap_reply_str, string_length);
			pcontext->command_len = 0;
			return X_LITERAL_PROCESSING;
		}

		if (argc < 2 || strlen(argv[0]) >= 32) {
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1800, 1, &string_length);
			if (argc <= 0 || strlen(argv[0]) >= 32) {
				pcontext->connection.write("* ", 2);
				pcontext->connection.write(imap_reply_str, string_length);
			} else {
				pcontext->connection.write(argv[0], strlen(argv[0]));
				pcontext->connection.write(" ", 1);
				pcontext->connection.write(imap_reply_str, string_length);
			}
			pcontext->command_len = 0;
			return X_LITERAL_CHECKING;
		}

		switch (imap_parser_dispatch_cmd(argc, argv, pcontext)) {
		case DISPATCH_CONTINUE:
			pcontext->command_len = 0;
			return X_LITERAL_PROCESSING;
		case DISPATCH_BREAK:
			pcontext->command_len = 0;
			return X_CONTEXT_PROCESSING;
		case DISPATCH_SHOULD_CLOSE:
			return ps_end_processing(pcontext);
		}
	}

	if (64 * 1024 == pcontext->read_offset) {
		pcontext->read_offset = 0;
		pcontext->literal_ptr = NULL;
		pcontext->literal_len = 0;
		pcontext->command_len = 0;
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1800, 1, &string_length);
		pcontext->connection.write(imap_reply_str, string_length);
	}

	if (pcontext->sched_stat != SCHED_STAT_IDLING) {
		return PROCESS_CONTINUE;
	}
	std::unique_lock ll_hold(g_list_lock);
	double_list_append_as_tail(&g_sleeping_list, &pcontext->sleeping_node);
	return PROCESS_SLEEPING;
}

static int ps_stat_appending(IMAP_CONTEXT *pcontext)
{
	unsigned int len = STREAM_BLOCK_SIZE;
	auto pbuff = static_cast<char *>(pcontext->stream.get_write_buf(&len));
	if (NULL == pbuff) {
		imap_parser_log_info(pcontext, LV_WARN, "out of memory");
		/* IMAP_CODE_2180009: BAD internal error: fail to get stream buffer */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1809, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	ssize_t read_len;
	if (NULL != pcontext->connection.ssl) {
		read_len = SSL_read(pcontext->connection.ssl, pbuff, len);
	} else {
		read_len = read(pcontext->connection.sockd, pbuff, len);
	}
	auto current_time = tp_now();
	if (0 == read_len) {
		imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return ps_end_processing(pcontext);
	} else if (read_len < 0) {
		if (EAGAIN != errno) {
			imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
			return ps_end_processing(pcontext);
		}
		/* check if context is timed out */
		if (current_time - pcontext->connection.last_timestamp < g_timeout)
			return PROCESS_POLLING_RDONLY;
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	pcontext->connection.last_timestamp = current_time;
	if (pcontext->literal_len <= pcontext->current_len + read_len) {
		ssize_t temp_len = pcontext->current_len + read_len - pcontext->literal_len;
		memcpy(pcontext->read_buffer, pbuff + read_len - temp_len, temp_len);
		pcontext->read_offset = temp_len;
		pcontext->stream.fwd_write_ptr(read_len - temp_len);
		pcontext->current_len = pcontext->literal_len;
		pcontext->sched_stat = SCHED_STAT_APPENDED;
	} else {
		pcontext->stream.fwd_write_ptr(read_len);
		pcontext->current_len += read_len;
	}

	auto total_len = pcontext->stream.get_total_length();
	if (total_len >= g_cache_size ||
	    pcontext->literal_len == pcontext->current_len) {
		if (pcontext->stream.dump(pcontext->message_fd) != STREAM_DUMP_OK) {
			imap_parser_log_info(pcontext, LV_WARN, "failed to flush mail from memory into file");
			/* IMAP_CODE_2180010: BAD internal error: fail to dump stream object */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1810, 1, &string_length);
			return ps_end_processing(pcontext, imap_reply_str, string_length);
		}
		pcontext->stream.clear();
	}
	if (pcontext->sched_stat != SCHED_STAT_APPENDED) {
		return PROCESS_CONTINUE;
	}
	pcontext->literal_ptr = NULL;
	pcontext->literal_len = 0;
	return X_CMD_PROCESSING;
}

static int ps_stat_wrdat(IMAP_CONTEXT *pcontext)
{
	if (0 == pcontext->write_length) {
		imap_parser_wrdat_retrieve(pcontext);
	}
	auto written_len = pcontext->connection.write(&pcontext->write_buff[pcontext->write_offset],
	                   pcontext->write_length - pcontext->write_offset);
	auto current_time = tp_now();
	if (0 == written_len) {
		imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return ps_end_processing(pcontext);
	} else if (written_len < 0) {
		if (EAGAIN != errno) {
			imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
			return ps_end_processing(pcontext);
		}
		/* check if context is timed out */
		if (current_time - pcontext->connection.last_timestamp < g_timeout)
			return PROCESS_POLLING_WRONLY;
		imap_parser_log_info(pcontext, LV_DEBUG, "timeout");
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	pcontext->connection.last_timestamp = current_time;
	pcontext->write_offset += written_len;

	if (pcontext->write_offset < pcontext->write_length) {
		return PROCESS_CONTINUE;
	}

	if (pcontext->message_fd == -1) {
		pcontext->write_offset = 0;
		pcontext->write_length = 0;
		switch (imap_parser_wrdat_retrieve(pcontext)) {
		case IMAP_RETRIEVE_TERM:
			pcontext->stream.clear();
			if (0 == pcontext->write_length) {
				pcontext->sched_stat = SCHED_STAT_RDCMD;
				return X_LITERAL_CHECKING;
			}
			break;
		case IMAP_RETRIEVE_OK:
			break;
		case IMAP_RETRIEVE_ERROR:
			/* IMAP_CODE_2180008: internal error, fail to retrieve from stream object */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1808, 1, &string_length);
			return ps_end_processing(pcontext, imap_reply_str, string_length);
		}
		return PROCESS_CONTINUE;
	}
	auto len = pcontext->literal_len - pcontext->current_len;
	if (len > 64 * 1024) {
		len = 64 * 1024;
	}
	auto read_len = read(pcontext->message_fd, pcontext->write_buff, len);
	if (read_len != len) {
		imap_parser_log_info(pcontext, LV_WARN, "failed to read message file");
		/* IMAP_CODE_2180012: * BAD internal error: fail to read file */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1812, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	pcontext->current_len += len;
	pcontext->write_length = len;
	pcontext->write_offset = 0;
	if (pcontext->literal_len != pcontext->current_len) {
		return PROCESS_CONTINUE;
	}
	close(pcontext->message_fd);
	pcontext->message_fd = -1;
	pcontext->literal_len = 0;
	pcontext->current_len = 0;
	if (imap_parser_wrdat_retrieve(pcontext) != IMAP_RETRIEVE_ERROR) {
		return PROCESS_CONTINUE;
	}
	/* IMAP_CODE_2180008: internal error, fail to retrieve from stream object */
	size_t string_length = 0;
	auto imap_reply_str = resource_get_imap_code(1808, 1, &string_length);
	return ps_end_processing(pcontext, imap_reply_str, string_length);
}

static int ps_stat_wrlst(IMAP_CONTEXT *pcontext)
{
	if (0 == pcontext->write_length) {
		unsigned int temp_len = MAX_LINE_LENGTH;
		pcontext->write_buff = static_cast<char *>(pcontext->stream.get_read_buf(&temp_len));
		pcontext->write_length = temp_len;
	}
	auto written_len = pcontext->connection.write(&pcontext->write_buff[pcontext->write_offset],
	                   pcontext->write_length - pcontext->write_offset);
	auto current_time = tp_now();
	if (0 == written_len) {
		imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return ps_end_processing(pcontext);
	} else if (written_len < 0) {
		if (EAGAIN != errno) {
			imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
			return ps_end_processing(pcontext);
		}
		/* check if context is timed out */
		if (current_time - pcontext->connection.last_timestamp < g_timeout)
			return PROCESS_POLLING_WRONLY;
		imap_parser_log_info(pcontext, LV_DEBUG, "time out");
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	pcontext->connection.last_timestamp = current_time;
	pcontext->write_offset += written_len;

	if (pcontext->write_offset < pcontext->write_length) {
		return PROCESS_CONTINUE;
	}

	pcontext->write_offset = 0;
	unsigned int temp_len = MAX_LINE_LENGTH;
	pcontext->write_buff = static_cast<char *>(pcontext->stream.get_read_buf(&temp_len));
	pcontext->write_length = temp_len;
	if (pcontext->write_buff != nullptr) {
		return PROCESS_CONTINUE;
	}
	pcontext->stream.clear();
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_RDCMD;
	return X_LITERAL_CHECKING;
}

int imap_parser_process(IMAP_CONTEXT *ctx)
{
	int ret = X_CONTEXT_PROCESSING;
	while (ret < 0) {
		if (ret == X_CMD_PROCESSING)
			ret = ps_cmd_processing(ctx);
		else if (ret == X_LITERAL_CHECKING)
			ret = ps_literal_checking(ctx);
		else if (ret == X_LITERAL_PROCESSING)
			ret = ps_literal_processing(ctx);
		else if (ctx->sched_stat == SCHED_STAT_AUTOLOGOUT)
			ret = ps_stat_autologout(ctx);
		else if (ctx->sched_stat == SCHED_STAT_DISCONNECTED)
			ret = ps_stat_disconnected(ctx);
		else if (ctx->sched_stat == SCHED_STAT_STLS)
			ret = ps_stat_stls(ctx);
		else if (ctx->sched_stat == SCHED_STAT_NOTIFYING)
			ret = ps_stat_notifying(ctx);
		else if (ctx->sched_stat == SCHED_STAT_RDCMD ||
		    ctx->sched_stat == SCHED_STAT_APPENDED ||
		    ctx->sched_stat == SCHED_STAT_IDLING)
			ret = ps_stat_rdcmd(ctx);
		else if (ctx->sched_stat == SCHED_STAT_APPENDING)
			ret = ps_stat_appending(ctx);
		else if (ctx->sched_stat == SCHED_STAT_WRDAT)
			ret = ps_stat_wrdat(ctx);
		else if (ctx->sched_stat == SCHED_STAT_WRLST)
			ret = ps_stat_wrlst(ctx);
		else
			ret = ps_end_processing(ctx);
	}
	return ret;
}

static int ps_end_processing(IMAP_CONTEXT *pcontext,
    const char *imap_reply_str, ssize_t string_length)
{
	if (NULL != imap_reply_str) {
		pcontext->connection.write("* ", 2);
		pcontext->connection.write(imap_reply_str, string_length);
	}
	pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_remove_select(pcontext);
		pcontext->proto_stat = PROTO_STAT_AUTH;
		pcontext->selected_folder[0] = '\0';
	}
	if (-1 != pcontext->message_fd) {
		close(pcontext->message_fd);
		pcontext->message_fd = -1;
	}
	if (!pcontext->file_path.empty()) {
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1381: remove %s: %s",
				pcontext->file_path.c_str(), strerror(errno));
		pcontext->file_path.clear();
	}
	if (system_services_container_remove_ip != nullptr)
		system_services_container_remove_ip(pcontext->connection.client_ip);
	imap_parser_context_clear(pcontext);
	return PROCESS_CLOSE;
}

static int imap_parser_wrdat_retrieve(IMAP_CONTEXT *pcontext)
{
	int len;
	int read_len;
	int line_length;
	char *last_line;
	char *ptr, *ptr1;
	
	while (true) {
		line_length = MAX_LINE_LENGTH - pcontext->write_length;
		if (line_length < 64) {
			return IMAP_RETRIEVE_OK;
		}
		/* make room for CRLF */
		line_length -= 2;
		auto copy_result = pcontext->stream.copyline(pcontext->write_buff +
		              pcontext->write_length, reinterpret_cast<unsigned int *>(&line_length));
		switch (copy_result) {
		case STREAM_COPY_END:
			return IMAP_RETRIEVE_TERM;
		case STREAM_COPY_TERM:
			return IMAP_RETRIEVE_ERROR;
		case STREAM_COPY_OK:
			last_line = pcontext->write_buff + pcontext->write_length;
			if (line_length > 8 && 0 == strncmp(last_line, "<<{file}", 8)) {
				last_line[line_length] = '\0';
				if (NULL == (ptr = strchr(last_line + 8, '|')) ||
					NULL == (ptr1 = strchr(ptr + 1, '|'))) {
					strcpy(&pcontext->write_buff[pcontext->write_length], "NIL");
					pcontext->write_length += 3;
				} else {
					*ptr = '\0';
					*ptr1 = '\0';
					pcontext->message_fd = -1;
					try {
						auto eml_path = std::string(pcontext->maildir) + "/eml/" + (last_line + 8);
						pcontext->message_fd = open(eml_path.c_str(), O_RDONLY);
					} catch (const std::bad_alloc &) {
						mlog(LV_ERR, "E-1466: ENOMEM");
					}
					if (-1 == pcontext->message_fd) {
						strcpy(&pcontext->write_buff[pcontext->write_length], "NIL");
						pcontext->write_length += 3;
					} else {
						if (lseek(pcontext->message_fd, strtol(ptr + 1, nullptr, 0), SEEK_SET) < 0)
							mlog(LV_ERR, "E-1426: lseek: %s", strerror(errno));
						pcontext->literal_len = strtol(ptr1 + 1, nullptr, 0);
						pcontext->current_len = 0;
						len = MAX_LINE_LENGTH - pcontext->write_length;
						if (len > pcontext->literal_len) {
							len = pcontext->literal_len;
						}
						read_len = read(pcontext->message_fd, pcontext->write_buff +
									pcontext->write_length, len);
						if (read_len != len) {
							imap_parser_log_info(pcontext, LV_WARN, "failed to read message file");
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
							return IMAP_RETRIEVE_ERROR;
						}
						pcontext->current_len += len;
						pcontext->write_length += len;
						if (pcontext->literal_len == len) {
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
							pcontext->literal_len = 0;
							pcontext->current_len = 0;
						}
					}
				}
			} else if (line_length > 10 && 0 == strncmp(last_line, "<<{rfc822}", 10)) {
				last_line[line_length] = '\0';
				if (NULL == (ptr = strchr(last_line + 10, '|')) ||
					NULL == (ptr1 = strchr(ptr + 1, '|'))) {
					strcpy(&pcontext->write_buff[pcontext->write_length], "NIL");
					pcontext->write_length += 3;
				} else {
					*ptr = '\0';
					*ptr1 = '\0';
					pcontext->message_fd = -1;
					try {
						auto rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822/" + (last_line + 10);
						pcontext->message_fd = open(rfc_path.c_str(), O_RDONLY);
					} catch (const std::bad_alloc &) {
						mlog(LV_ERR, "E-1467: ENOMEM");
					}
					if (-1 == pcontext->message_fd) {
						strcpy(&pcontext->write_buff[pcontext->write_length], "NIL");
						pcontext->write_length += 3;
					} else {
						if (lseek(pcontext->message_fd, strtol(ptr + 1, nullptr, 0), SEEK_SET) < 0)
							mlog(LV_ERR, "E-1427: lseek: %s", strerror(errno));
						pcontext->literal_len = strtol(ptr1 + 1, nullptr, 0);
						pcontext->current_len = 0;
						len = MAX_LINE_LENGTH - pcontext->write_length;
						if (len > pcontext->literal_len) {
							len = pcontext->literal_len;
						}
						read_len = read(pcontext->message_fd, pcontext->write_buff +
									pcontext->write_length, len);
						if (read_len != len) {
							imap_parser_log_info(pcontext, LV_WARN, "failed to read message file");
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
							return IMAP_RETRIEVE_ERROR;
						}
						pcontext->current_len += len;
						pcontext->write_length += len;
						if (pcontext->literal_len == len) {
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
							pcontext->literal_len = 0;
							pcontext->current_len = 0;
						}
					}
				}
			} else {
				pcontext->write_length += line_length;
				strcpy(&pcontext->write_buff[pcontext->write_length], "\r\n");
				pcontext->write_length += 2;
			}
			break;
		case STREAM_COPY_PART:
			pcontext->write_length += line_length;
			return IMAP_RETRIEVE_OK;
		}
	}
}

static DOUBLE_LIST *sh_query(const char *x)
{
	auto i = g_select_hash.find(x);
	return i == g_select_hash.end() ? nullptr : &i->second;
}

void imap_parser_touch_modify(IMAP_CONTEXT *pcontext, const char *username,
    const char *folder)
{
	char buff[1024];
	DOUBLE_LIST_NODE *pnode;
	
	gx_strlcpy(buff, username, arsizeof(buff));
	HX_strlower(buff);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(buff);
	if (NULL == plist) {
		return;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pcontext1 = static_cast<IMAP_CONTEXT *>(pnode->pdata);
		if (pcontext != pcontext1 && 0 == strcmp(folder, pcontext1->selected_folder)) {
			pcontext1->b_modify = TRUE;
		}
	}
	hl_hold.unlock();
	snprintf(buff, 1024, "FOLDER-TOUCH %s %s", username, folder);
	system_services_broadcast_event(buff);
}

static void imap_parser_event_touch(const char *username, const char *folder)
{
	char temp_string[UADDR_SIZE];
	DOUBLE_LIST_NODE *pnode;
	
	gx_strlcpy(temp_string, username, arsizeof(temp_string));
	HX_strlower(temp_string);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(temp_string);
	if (NULL == plist) {
		return;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pcontext = static_cast<IMAP_CONTEXT *>(pnode->pdata);
		if (0 == strcmp(folder, pcontext->selected_folder)) {
			pcontext->b_modify = TRUE;
		}
	}
}

void imap_parser_modify_flags(IMAP_CONTEXT *pcontext, const char *mid_string) try
{
	char buff[1024];
	DOUBLE_LIST_NODE *pnode;
	
	gx_strlcpy(buff, pcontext->username, arsizeof(buff));
	HX_strlower(buff);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(buff);
	if (NULL == plist) {
		return;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pcontext1 = static_cast<IMAP_CONTEXT *>(pnode->pdata);
		if (pcontext != pcontext1 && 0 == strcmp(pcontext->selected_folder,
			pcontext1->selected_folder)) {
			pcontext1->f_flags.emplace_back(mid_string);
		}
	}
	hl_hold.unlock();
	auto buf = "MESSAGE-FLAG "s + pcontext->username + " " +
	           pcontext->selected_folder + " " + mid_string;
	system_services_broadcast_event(buf.c_str());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1468: ENOMEM");
}

static void imap_parser_event_flag(const char *username, const char *folder,
    const char *mid_string) try
{
	char temp_string[UADDR_SIZE];
	DOUBLE_LIST_NODE *pnode;
	
	gx_strlcpy(temp_string, username, arsizeof(temp_string));
	HX_strlower(temp_string);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(temp_string);
	if (NULL == plist) {
		return;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pcontext = static_cast<IMAP_CONTEXT *>(pnode->pdata);
		if (0 == strcmp(pcontext->selected_folder, folder)) {
			pcontext->f_flags.emplace_back(mid_string);
		}
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1087: ENOMEM");
}

void imap_parser_echo_modify(IMAP_CONTEXT *pcontext, STREAM *pstream)
{
	int id;
	int err;
	int recent;
	int exists;
	int tmp_len;
	int flag_bits;
	BOOL b_first;
	char buff[1024];
	
	std::unique_lock hl_hold(g_hash_lock);
	pcontext->b_modify = FALSE;
	auto temp_file = std::move(pcontext->f_flags);
	hl_hold.unlock();
	
	if (system_services_summary_folder(pcontext->maildir,
	    pcontext->selected_folder, &exists, &recent, nullptr, nullptr,
	    nullptr, nullptr, &err) == MIDB_RESULT_OK) {
		tmp_len = gx_snprintf(buff, arsizeof(buff), "* %d RECENT\r\n"
									   "* %d EXISTS\r\n",
									   recent, exists);
		if (NULL == pstream) {
			pcontext->connection.write(buff, tmp_len);
		} else if (pstream->write(buff, tmp_len) != STREAM_WRITE_OK) {
			return;
		}
	}
	
	if (temp_file.empty())
		return;
	for (const auto &mid : temp_file) {
		auto mid_string = mid.c_str();
		if (system_services_get_id(pcontext->maildir,
		    pcontext->selected_folder, mid_string,
		    reinterpret_cast<unsigned int *>(&id)) != MIDB_RESULT_OK ||
		    system_services_get_flags(pcontext->maildir,
		    pcontext->selected_folder, mid_string, &flag_bits,
		    &err) != MIDB_RESULT_OK)
			continue;
		tmp_len = gx_snprintf(buff, arsizeof(buff), "* %d FETCH (FLAGS (", id);
		b_first = FALSE;
		if (flag_bits & FLAG_RECENT) {
			tmp_len += gx_snprintf(buff + tmp_len, arsizeof(buff) - tmp_len, "\\Recent");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_ANSWERED) {
			if (b_first) {
				buff[tmp_len] = ' ';
				tmp_len++;
			}
			tmp_len += gx_snprintf(buff + tmp_len, arsizeof(buff) - tmp_len, "\\Answered");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_FLAGGED) {
			if (b_first) {
				buff[tmp_len] = ' ';
				tmp_len++;
			}
			tmp_len += gx_snprintf(buff + tmp_len, arsizeof(buff) - tmp_len, "\\Flagged");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_DELETED) {
			if (b_first) {
				buff[tmp_len] = ' ';
				tmp_len++;
			}
			tmp_len += gx_snprintf(buff + tmp_len, arsizeof(buff) - tmp_len, "\\Deleted");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_SEEN) {
			if (b_first) {
				buff[tmp_len] = ' ';
				tmp_len++;
			}
			tmp_len += gx_snprintf(buff + tmp_len, arsizeof(buff) - tmp_len, "\\Seen");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_DRAFT) {
			if (b_first) {
				buff[tmp_len] = ' ';
				tmp_len++;
			}
			tmp_len += gx_snprintf(buff + tmp_len, arsizeof(buff) - tmp_len, "\\Draft");
		}
		tmp_len += gx_snprintf(buff + tmp_len, arsizeof(buff) - tmp_len, "))\r\n");
		if (pstream == nullptr)
			pcontext->connection.write(buff, tmp_len);
		else if (pstream->write(buff, tmp_len) != STREAM_WRITE_OK)
			break;
	}
}

SCHEDULE_CONTEXT **imap_parser_get_contexts_list()
{
	return g_context_list2.data();
}

static int imap_parser_dispatch_cmd2(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	size_t string_length;
	const char *imap_reply_str;
	char reply_buff[1024];
	static constexpr std::pair<const char *, int (*)(int, char **, IMAP_CONTEXT *)> proc[] = {
		{"APPEND", imap_cmd_parser_append},
		{"AUTHENTICATE", imap_cmd_parser_authenticate},
		{"CAPABILITY", imap_cmd_parser_capability},
		{"CHECK", imap_cmd_parser_check},
		{"CLOSE", imap_cmd_parser_close},
		{"COPY", imap_cmd_parser_copy},
		{"CREATE", imap_cmd_parser_create},
		{"DELETE", imap_cmd_parser_delete},
		{"EXAMINE", imap_cmd_parser_examine},
		{"EXPUNGE", imap_cmd_parser_expunge},
		{"FETCH", imap_cmd_parser_fetch},
		{"ID", imap_cmd_parser_id},
		{"IDLE", imap_cmd_parser_idle},
		{"LIST", imap_cmd_parser_list},
		{"LOGIN", imap_cmd_parser_login},
		{"LOGOUT", imap_cmd_parser_logout},
		{"LSUB", imap_cmd_parser_lsub},
		{"NOOP", imap_cmd_parser_noop},
		{"RENAME", imap_cmd_parser_rename},
		{"SEARCH", imap_cmd_parser_search},
		{"SELECT", imap_cmd_parser_select},
		{"STARTTLS", imap_cmd_parser_starttls},
		{"STATUS", imap_cmd_parser_status},
		{"STORE", imap_cmd_parser_store},
		{"SUBSCRIBE", imap_cmd_parser_subscribe},
		{"UNSELECT", imap_cmd_parser_unselect},
		{"UNSUBSCRIBE", imap_cmd_parser_unsubscribe},
		{"XLIST", imap_cmd_parser_xlist},
	}, proc_uid[] = {
		{"COPY", imap_cmd_parser_uid_copy},
		{"EXPUNGE", imap_cmd_parser_uid_expunge},
		{"FETCH", imap_cmd_parser_uid_fetch},
		{"SEARCH", imap_cmd_parser_uid_search},
		{"STORE", imap_cmd_parser_uid_store},
	};

	auto scmp = [](decltype(*proc) &p, const char *cmd) { return strcasecmp(p.first, cmd) < 0; };
	if (strcasecmp(argv[1], "UID") == 0) {
		auto it = std::lower_bound(std::begin(proc_uid), std::end(proc_uid), argv[2], scmp);
		if (it != std::end(proc_uid) && strcasecmp(argv[2], it->first) == 0)
			return it->second(argc, argv, pcontext);
	} else {
		auto it = std::lower_bound(std::begin(proc), std::end(proc), argv[1], scmp);
		if (it != std::end(proc) && strcasecmp(argv[1], it->first) == 0)
			return it->second(argc, argv, pcontext);
	}

	imap_reply_str = resource_get_imap_code(1800, 1, &string_length);
	string_length = gx_snprintf(reply_buff, arsizeof(reply_buff), "%s %s", argv[0], imap_reply_str);
	pcontext->connection.write(reply_buff, string_length);
	return DISPATCH_CONTINUE;
}

static int imap_parser_dispatch_cmd(int argc, char **argv, IMAP_CONTEXT *ctx) try
{
	/* cmd2 can/will further tokenize and thus modify argv */
	std::vector<std::string> argv_copy;
	auto ac_clean = make_scope_exit([&]() {
		for (size_t i = 0; i < argv_copy.size(); ++i)
			safe_memset(argv_copy[i].data(), 0, argv_copy[i].size());
	});
	if (g_imapcmd_debug != 0)
		argv_copy.assign(&argv[0], &argv[argc]);
	auto ret = imap_parser_dispatch_cmd2(argc, argv, ctx);
	auto code = ret & DISPATCH_VALMASK;
	if (g_imapcmd_debug >= 2 || (g_imapcmd_debug >= 1 && code != 0 && code != 1700)) {
		/*
		 * Can't really hide AUTHENTICATE because the prompts
		 * and answers are backend-specific.
		 */
		if (strcasecmp(argv[1], "LOGIN") == 0) {
			fprintf(stderr, "< LOGIN ****: ret=%xh code=%u\n", ret, code);
		} else {
			fprintf(stderr, "<");
			for (int i = 0; i < argc; ++i)
				fprintf(stderr, " %s", argv_copy[i].c_str());
			fprintf(stderr, ": ret=%xh code=%u\n", ret, code);
		}
	}
	return imap_cmd_parser_dval(argc, argv, ctx, ret);
} catch (const std::bad_alloc &) {
	return imap_cmd_parser_dval(argc, argv, ctx, 1915);
}

imap_context::imap_context() :
	stream(&g_blocks_allocator)
{
	auto pcontext = this;
	pcontext->hash_node.pdata = pcontext;
	pcontext->sleeping_node.pdata = pcontext;
    pcontext->connection.sockd = -1;
}

static void imap_parser_context_clear(IMAP_CONTEXT *pcontext)
{
    if (NULL == pcontext) {
        return;
    }
	pcontext->connection.reset();
	pcontext->proto_stat = 0;
	pcontext->sched_stat = 0;
	pcontext->mid[0] = '\0';
	pcontext->file_path[0] = '\0';
	pcontext->message_fd = -1;
	pcontext->write_buff = NULL;
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	pcontext->selected_time = 0;
	pcontext->selected_folder[0] = '\0';
	pcontext->b_readonly = FALSE;
	pcontext->tag_string[0] = '\0';
	pcontext->command_len = 0;
	pcontext->command_buffer[0] = '\0';
	pcontext->read_offset = 0;
	pcontext->read_buffer[0] = '\0';
	pcontext->literal_ptr = NULL;
	pcontext->literal_len = 0;
	pcontext->current_len = 0;
	pcontext->stream.clear();
	pcontext->f_flags.clear();
	pcontext->auth_times = 0;
	pcontext->username[0] = '\0';
	pcontext->maildir[0] = '\0';
}

imap_context::~imap_context()
{
	auto pcontext = this;
	if (-1 != pcontext->message_fd) {
		close(pcontext->message_fd);
	}
	if (!pcontext->file_path.empty())
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1351: chmod %s: %s",
				pcontext->file_path.c_str(), strerror(errno));
}

static void *imps_thrwork(void *argp)
{
	int peek_len;
	char tmp_buff;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	
	while (!g_notify_stop) {
		std::unique_lock ll_hold(g_list_lock);
		ptail = double_list_get_tail(&g_sleeping_list);
		ll_hold.unlock();
		if (NULL == ptail) {
			usleep(100000);
			continue;
		}
		
		do {
			ll_hold.lock();
			pnode = double_list_pop_front(&g_sleeping_list);
			ll_hold.unlock();
			if (pnode == nullptr)
				break;
			auto pcontext = static_cast<IMAP_CONTEXT *>(pnode->pdata);
			if (SCHED_STAT_IDLING == pcontext->sched_stat) {
				std::unique_lock hl_hold(g_hash_lock);
				if (pcontext->b_modify) {
					pcontext->b_modify = FALSE;
					hl_hold.unlock();
					pcontext->sched_stat = SCHED_STAT_NOTIFYING;
					contexts_pool_wakeup_context(pcontext, CONTEXT_TURNING);
					if (pnode == ptail) {
						break;
					} else {
						continue;
					}
				}
			}
			peek_len = recv(pcontext->connection.sockd, &tmp_buff, 1, MSG_PEEK);
			if (1 == peek_len) {
				contexts_pool_wakeup_context(pcontext, CONTEXT_TURNING);
			} else if (peek_len < 0) {
				auto current_time = tp_now();
				if (current_time - pcontext->connection.last_timestamp >= g_autologout_time) {
					pcontext->sched_stat = SCHED_STAT_AUTOLOGOUT;
					contexts_pool_wakeup_context(pcontext, CONTEXT_TURNING);
				} else {
					ll_hold.lock();
					double_list_append_as_tail(&g_sleeping_list, pnode);
					ll_hold.unlock();
				}
			} else {
				pcontext->sched_stat = SCHED_STAT_DISCONNECTED;
				contexts_pool_wakeup_context(pcontext, CONTEXT_TURNING);
			}
		} while (pnode != ptail);
		usleep(100000);
	}
	return nullptr;
}

void imap_parser_log_info(IMAP_CONTEXT *pcontext, int level, const char *format, ...)
{
	char log_buf[2048];
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	mlog(level, "user=%s, host=[%s]  %s",
		pcontext->username, pcontext->connection.client_ip, log_buf);

}

static void imap_parser_event_proc(char *event)
{
	char *pspace, *pspace1;
	
	if (0 == strncasecmp(event, "FOLDER-TOUCH ", 13)) {
		pspace = strchr(event + 13, ' ');
		if (NULL != pspace) {
			*pspace = '\0';
			imap_parser_event_touch(event + 13, pspace + 1);
		}
	} else if (0 == strncasecmp(event, "MESSAGE-FLAG ", 13)) {
		pspace = strchr(event + 13, ' ');
		if (NULL != pspace) {
			*pspace = '\0';
			pspace1 = strchr(pspace + 1, ' ');
			if (NULL != pspace1) {
				*pspace1 = '\0';
				imap_parser_event_flag(event + 13, pspace + 1, pspace1 + 1);
			}
		}
	}
}


void imap_parser_add_select(IMAP_CONTEXT *pcontext)
{
	char temp_string[UADDR_SIZE];
	DOUBLE_LIST temp_list;
	
	gx_strlcpy(temp_string, pcontext->username, arsizeof(temp_string));
	HX_strlower(temp_string);
	time(&pcontext->selected_time);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(temp_string);
	if (NULL == plist) {
		double_list_init(&temp_list);
		if (g_select_hash.size() <= g_context_num) {
			g_select_hash.emplace(std::string(temp_string), temp_list);
			plist = sh_query(temp_string);
			if (NULL != plist) {
				double_list_append_as_tail(plist, &pcontext->hash_node);
			}
		}
	} else {
		double_list_append_as_tail(plist, &pcontext->hash_node);
	}
	hl_hold.unlock();
	system_services_broadcast_select(pcontext->username, pcontext->selected_folder);
}

void imap_parser_remove_select(IMAP_CONTEXT *pcontext)
{
	BOOL should_remove;
	char temp_string[UADDR_SIZE];
	DOUBLE_LIST_NODE *pnode;
	
	should_remove = TRUE;
	pcontext->selected_time = 0;
	gx_strlcpy(temp_string, pcontext->username, arsizeof(temp_string));
	HX_strlower(temp_string);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(temp_string);
	if (NULL != plist) {
		double_list_remove(plist, &pcontext->hash_node);
		if (double_list_get_nodes_num(plist) == 0) {
			g_select_hash.erase(temp_string);
		} else {
			pcontext->b_modify = FALSE;
			pcontext->f_flags.clear();
			for (pnode=double_list_get_head(plist); NULL!=pnode;
				pnode=double_list_get_after(plist, pnode)) {
				auto pcontext1 = static_cast<IMAP_CONTEXT *>(pnode->pdata);
				if (0 == strcmp(pcontext->selected_folder, pcontext1->selected_folder)) {
					should_remove = FALSE;
					break;
				}
			}
		}
	}
	hl_hold.unlock();
	if (should_remove)
		system_services_broadcast_unselect(pcontext->username, pcontext->selected_folder);
}

static void *imps_scanwork(void *argp)
{
	struct bk {
		std::string user, dir, folder;
	};
	int i = 0;
	int err_num;
	time_t cur_time;
	
	while (!g_notify_stop) {
		i ++;
		sleep(1);
		if (i < SCAN_INTERVAL) {
			continue;
		}
		
		i = 0;
		std::vector<bk> temp_file;
		std::unique_lock hl_hold(g_hash_lock);
		time(&cur_time);
		for (const auto &xpair : g_select_hash) {
			auto plist = &xpair.second;
			for (auto pnode = double_list_get_head(plist); pnode != nullptr;
				pnode=double_list_get_after(plist, pnode)) {
				auto pcontext = static_cast<IMAP_CONTEXT *>(pnode->pdata);
				if (cur_time - pcontext->selected_time > SELECT_INTERVAL) {
					try {
						temp_file.emplace_back(bk{pcontext->username,
							pcontext->maildir, pcontext->selected_folder});
					} catch (const std::bad_alloc &) {
						mlog(LV_ERR, "E-1816: ENOMEM");
					}
					pcontext->selected_time = cur_time;
				}
			}
		}
		hl_hold.unlock();
		for (const auto &e : temp_file) {
			system_services_broadcast_select(e.user.c_str(), e.folder.c_str());
			system_services_ping_mailbox(e.dir.c_str(), &err_num);
		}
	}
	return nullptr;
}

alloc_limiter<file_block> *imap_parser_get_allocator()
{
	return &g_alloc_file;
}

std::shared_ptr<MIME_POOL> imap_parser_get_mpool()
{
	return g_mime_pool;
}

alloc_limiter<MJSON_MIME> *imap_parser_get_jpool()
{
	return &g_alloc_mjson;
}

int imap_parser_get_sequence_ID()
{
	int old = 0, nu = 0;
	do {
		old = g_sequence_id.load(std::memory_order_relaxed);
		nu  = old != INT_MAX ? old + 1 : 1;
	} while (!g_sequence_id.compare_exchange_weak(old, nu));
	return nu;
}

void imap_parser_safe_write(IMAP_CONTEXT *pcontext, const void *pbuff, size_t count)
{
	int opt;
	
	/* set socket to block mode */
	opt = fcntl(pcontext->connection.sockd, F_GETFL, 0);
	opt &= (~O_NONBLOCK);
	if (fcntl(pcontext->connection.sockd, F_SETFL, opt) < 0)
		mlog(LV_WARN, "W-1365: fcntl: %s", strerror(errno));
	/* end of set mode */
	pcontext->connection.write(pbuff, count);
	/* set the socket back to non-block mode */
	opt |= O_NONBLOCK;
	if (fcntl(pcontext->connection.sockd, F_SETFL, opt) < 0)
		mlog(LV_WARN, "W-1366: fcntl: %s", strerror(errno));
	/* end of set mode */
}
