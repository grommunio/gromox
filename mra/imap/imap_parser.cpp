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
#include <libHX/io.h>
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
#include <gromox/mjson.hpp>
#include <gromox/safeint.hpp>
#include <gromox/scope.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include <gromox/xarray2.hpp>
#include "imap.hpp"
#include "../midb_agent.hpp"
#if (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2090000fL) || \
    (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x1010000fL)
#	define OLD_SSL 1
#endif
#define SLEEP_BEFORE_CLOSE true
#define SCAN_INTERVAL			3600

#define SELECT_INTERVAL			20*60

using namespace std::string_literals;
using namespace gromox;

static void *imps_thrwork(void *);
static void *imps_scanwork(void *);
static void imap_parser_event_proc(char *event);
static void imap_parser_event_touch(const char *user, const char *folder);
static void imap_parser_event_flag(const char *username, const char *folder, uint32_t uid);

static int imap_parser_dispatch_cmd(int argc, char **argv, IMAP_CONTEXT *pcontext);

static void imap_parser_context_clear(IMAP_CONTEXT *pcontext);
static int imap_parser_wrdat_retrieve(IMAP_CONTEXT *);

unsigned int g_imapcmd_debug;
int g_max_auth_times, g_block_auth_fail;
bool g_support_tls, g_force_tls;
static std::atomic<int> g_sequence_id;
static int g_average_num;
static size_t g_context_num, g_cache_size;
static time_duration g_timeout, g_autologout_time;
static pthread_t g_thr_id;
static pthread_t g_scan_id;
static gromox::atomic_bool g_notify_stop;
static std::unique_ptr<IMAP_CONTEXT[]> g_context_list;
static std::vector<SCHEDULE_CONTEXT *> g_context_list2;
static std::unordered_map<std::string, std::vector<imap_context *>> g_select_hash; /* username=>context */
static std::mutex g_hash_lock, g_list_lock;
static std::vector<imap_context *> g_sleeping_list;
static char g_certificate_path[256];
static char g_private_key_path[256];
static char g_certificate_passwd[1024];
static SSL_CTX *g_ssl_ctx;
static std::unique_ptr<std::mutex[]> g_ssl_mutex_buf;

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
	g_sequence_id = 0;
	if (support_tls) {
		g_force_tls = force_tls;
		gx_strlcpy(g_certificate_path, certificate_path, std::size(g_certificate_path));
		if (cb_passwd != nullptr)
			gx_strlcpy(g_certificate_passwd, cb_passwd, std::size(g_certificate_passwd));
		else
			g_certificate_passwd[0] = '\0';
		gx_strlcpy(g_private_key_path, key_path, std::size(g_private_key_path));
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
	if (g_support_tls) {
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		g_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (NULL == g_ssl_ctx) {
			printf("[imap_parser]: Failed to init SSL context\n");
			return -1;
		}
		if (*g_certificate_passwd != '\0')
			SSL_CTX_set_default_passwd_cb_userdata(g_ssl_ctx,
				g_certificate_passwd);
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
	g_sleeping_list.clear();
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

static tproc_status ps_end_processing(imap_context *, const char * = nullptr, ssize_t = 0);

static tproc_status ps_stat_autologout(imap_context *pcontext)
{
	imap_parser_log_info(pcontext, LV_DEBUG, "auto logout");
	/* IMAP_CODE_2160004: BYE Disconnected by autologout */
	size_t string_length = 0;
	auto imap_reply_str = resource_get_imap_code(1604, 1, &string_length);
	return ps_end_processing(pcontext, imap_reply_str, string_length);
}

static tproc_status ps_stat_disconnected(imap_context *pcontext)
{
	imap_parser_log_info(pcontext, LV_DEBUG, "connection lost");
	return ps_end_processing(pcontext);
}

static tproc_status ps_stat_stls(imap_context *pcontext)
{
	if (NULL == pcontext->connection.ssl) {
		pcontext->connection.ssl = SSL_new(g_ssl_ctx);
		if (NULL == pcontext->connection.ssl) {
			/* IMAP_CODE_2180014: BAD internal error: failed to init SSL object */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1814, 1, &string_length);
			if (HXio_fullwrite(pcontext->connection.sockd,
			    imap_reply_str, string_length) < 0)
				/* ignore */;
			imap_parser_log_info(pcontext, LV_WARN, "out of memory for TLS object");
			pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
			imap_parser_context_clear(pcontext);
			return tproc_status::close;
		}
		SSL_set_fd(pcontext->connection.ssl, pcontext->connection.sockd);
	}

	if (SSL_accept(pcontext->connection.ssl) != -1) {
		pcontext->sched_stat = isched_stat::rdcmd;
		if (pcontext->connection.server_port == g_listener_ssl_port) {
			char caps[128];
			capability_list(caps, std::size(caps), pcontext);
			SSL_write(pcontext->connection.ssl, "* OK [CAPABILITY ", 17);
			SSL_write(pcontext->connection.ssl, caps, strlen(caps));
			SSL_write(pcontext->connection.ssl, "] Service ready\r\n", 17);
		}
		return tproc_status::cont;
	}
	auto ssl_errno = SSL_get_error(pcontext->connection.ssl, -1);
	if (SSL_ERROR_WANT_READ == ssl_errno ||
	    SSL_ERROR_WANT_WRITE == ssl_errno) {
		auto current_time = tp_now();
		if (current_time - pcontext->connection.last_timestamp < g_timeout)
			return tproc_status::polling_rdonly;
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		if (HXio_fullwrite(pcontext->connection.sockd, "* ", 2) < 0 ||
		    HXio_fullwrite(pcontext->connection.sockd, imap_reply_str, string_length) < 0)
			/* ignore */;
		imap_parser_log_info(pcontext, LV_DEBUG, "timeout");
		pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
	} else {
		unsigned long e;
		char buf[256];
		while ((e = ERR_get_error()) != 0) {
			ERR_error_string_n(e, buf, std::size(buf));
			mlog(LV_DEBUG, "SSL_accept [%s]: %s", pcontext->connection.client_ip, buf);
		}
		pcontext->connection.reset();
		pcontext->connection.reset();
	}
	imap_parser_context_clear(pcontext);
	return tproc_status::close;
}

static tproc_status ps_stat_notifying(imap_context *pcontext)
{
	imap_parser_echo_modify(pcontext, nullptr);
	std::unique_lock ll_hold(g_list_lock);
	g_sleeping_list.push_back(pcontext);
	pcontext->sched_stat = isched_stat::idling;
	return tproc_status::sleeping;
}

/**
 * Read something from the network and add it to read_buffer. Other functions
 * will trim the read buffer and make room again if(!) and when there is a
 * newline. As a result, ps_stat_rdcmd may be unable to append the network data
 * into read_context and if so, terminates the request.
 */
static tproc_status ps_stat_rdcmd(imap_context *pcontext)
{
	ssize_t read_len;
	if (pcontext->connection.ssl != nullptr)
		read_len = SSL_read(pcontext->connection.ssl, pcontext->read_buffer +
		           pcontext->read_offset, 64*1024 - pcontext->read_offset);
	else
		read_len = read(pcontext->connection.sockd, pcontext->read_buffer +
		           pcontext->read_offset, 64*1024 - pcontext->read_offset);
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
			return tproc_status::polling_rdonly;
		if (pcontext->is_authed()) {
			std::unique_lock ll_hold(g_list_lock);
			g_sleeping_list.push_back(pcontext);
			return tproc_status::sleeping;
		}
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}

	pcontext->connection.last_timestamp = current_time;
	pcontext->read_offset += read_len;
	return pcontext->sched_stat == isched_stat::appended ||
	       pcontext->sched_stat == isched_stat::idling ?
	       tproc_status::cmd_processing : tproc_status::literal_checking;
}

static tproc_status ps_literal_checking(imap_context *pcontext)
{
	auto &ctx = *pcontext;
	if (ctx.literal_ptr == nullptr)
		return tproc_status::literal_processing;
	if (&ctx.read_buffer[ctx.read_offset] - ctx.literal_ptr < ctx.literal_len)
		return tproc_status::cont;
	auto temp_len = &ctx.literal_ptr[ctx.literal_len] - ctx.read_buffer;
	if (temp_len <= 0 || temp_len >= 64 * 1024 ||
	    pcontext->command_len + temp_len >= 64 * 1024) {
		/* IMAP_CODE_2180017: BAD literal size too large */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	memcpy(&ctx.command_buffer[ctx.command_len], ctx.read_buffer, temp_len);
	pcontext->command_len += temp_len;
	pcontext->read_offset -= temp_len;
	if (ctx.read_offset > 0 && ctx.read_offset < 64 * 1024)
		memmove(ctx.read_buffer, &ctx.literal_ptr[ctx.literal_len], ctx.read_offset);
	else
		pcontext->read_offset = 0;
	pcontext->literal_ptr = NULL;
	pcontext->literal_len = 0;
	return tproc_status::literal_processing;
}

/**
 * This function analyzes ctx.read_buffer (and always does so from the start).
 *
 * If ctx.read_buffer does not contain a "complete command" (in the sense of
 * RFC 9051 §2.1.1), for example because a newline is missing or because a
 * literal is incomplete, the function returns early, so that e.g.
 * ps_stat_rdcmd() can append more bytes to read_buffer.
 *
 * The loop looks for, and validates, "{octet}" substrings. It is possible
 * there is more than one literal in read_buffer.
 */
static tproc_status ps_literal_processing(imap_context *pcontext)
{
	auto &ctx = *pcontext;
	auto tail = &ctx.read_buffer[ctx.read_offset];
	for (ssize_t i = 0; i < pcontext->read_offset - 1; ++i) {
		auto openbr = &ctx.read_buffer[i];
		if (*openbr != '{' /* } */)
			continue;
		auto endbr = static_cast<char *>(memchr(&openbr[1], /* { */ '}', tail - &openbr[1]));
		if (endbr == nullptr)
			break;
		auto nl_len = newline_size(&endbr[1], tail - &endbr[1]);
		if (nl_len == 0)
			continue;
		if (endbr - openbr <= 1 || endbr - openbr > 16) {
			/* IMAP_CODE_2180017: BAD literal size too large */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
			return ps_end_processing(pcontext, imap_reply_str, string_length);
		}

		ctx.literal_ptr = &endbr[1]; /* skip over brace */
		char *end = nullptr;
		pcontext->literal_len = strtoul(&openbr[1], &end, 10);
		pcontext->synchronizing_literal = true;
		if (*end == '+' || (*end == '-' && pcontext->literal_len <= 4096)) {
			pcontext->synchronizing_literal = false;
			++end;
		}
		if (end != endbr) {
			size_t len = 0;
			auto msg = resource_get_imap_code(1817, 1, &len);
			return ps_end_processing(pcontext, msg, len);
		}
		auto temp_len = 64 * 1024 - (&ctx.literal_ptr[nl_len] - ctx.read_buffer) -
		           pcontext->command_len - nl_len;
		if (temp_len <= 0 || temp_len >= 64 * 1024) {
			imap_parser_log_info(pcontext, LV_WARN, "error in command buffer length");
			/* IMAP_CODE_2180017: BAD literal size too large */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
			return ps_end_processing(pcontext, imap_reply_str, string_length);
		}
		if (cmp_less(pcontext->literal_len, temp_len)) {
			pcontext->read_offset -= nl_len;
			auto chunk_len = tail - ctx.literal_ptr;
			if (chunk_len > 0 && chunk_len < 64 * 1024)
				/*
				 * Remove the newline between "{n}" and the
				 * literal data, we don't need it for
				 * processing.
				 */
				memmove(ctx.literal_ptr, &ctx.literal_ptr[nl_len], chunk_len);

			/* IMAP_CODE_2160003: + ready for additional command text */
			size_t string_length = 0;
			if (!pcontext->synchronizing_literal)
				return tproc_status::literal_checking;
			auto imap_reply_str = resource_get_imap_code(1603, 1, &string_length);
			pcontext->connection.write(imap_reply_str, string_length);
			return tproc_status::literal_checking;
		}
		memcpy(&ctx.command_buffer[ctx.command_len],
		       pcontext->read_buffer, i);
		pcontext->command_len += i;
		char *argv[128];
		auto argc = parse_imap_args(pcontext->command_buffer, pcontext->command_len,
			    argv, std::size(argv));
		if (argc >= 3 && 0 == strcasecmp(argv[1], "APPEND")) {
			/* Special handling for APPEND with potentially huge literals */
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
				if (pcontext->stream.write(&ctx.literal_ptr[nl_len], ctx.current_len) != STREAM_WRITE_OK) {
					size_t sl = 0;
					auto str = resource_get_imap_code(1922, 1, &sl);
					return ps_end_processing(pcontext, str, sl);
				}
				pcontext->sched_stat = isched_stat::appending;
				pcontext->read_offset = 0;
				pcontext->command_len = 0;
				if (!pcontext->synchronizing_literal)
					return tproc_status::cont;
				/* IMAP_CODE_2160003 + Ready for additional command text */
				size_t string_length = 0;
				auto imap_reply_str = resource_get_imap_code(1603, 1, &string_length);
				pcontext->connection.write(imap_reply_str, string_length);
				return tproc_status::cont;
			}
			case DISPATCH_SHOULD_CLOSE:
				return ps_end_processing(pcontext);
			case DISPATCH_BREAK:
				ctx.read_offset -= &ctx.literal_ptr[nl_len] - ctx.read_buffer;
				if (pcontext->read_offset > 0 && pcontext->read_offset < 64 * 1024)
					memmove(ctx.read_buffer, &ctx.literal_ptr[nl_len], ctx.read_offset);
				else
					pcontext->read_offset = 0;
				pcontext->literal_ptr = NULL;
				pcontext->literal_len = 0;
				pcontext->command_len = 0;
				return tproc_status::literal_processing;
			}
		}

		/* IMAP_CODE_2180017: BAD literal size too large */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1817, 1, &string_length);
		pcontext->connection.write("* ", 2);
		pcontext->connection.write(imap_reply_str, string_length);
		ctx.read_offset -= &ctx.literal_ptr[nl_len] - ctx.read_buffer;
		if (pcontext->read_offset > 0 && pcontext->read_offset < 64  *1024)
			memmove(ctx.read_buffer, &ctx.literal_ptr[nl_len], ctx.read_offset);
		else
			pcontext->read_offset = 0;
		pcontext->literal_ptr = NULL;
		pcontext->literal_len = 0;
		pcontext->command_len = 0;
		return tproc_status::literal_processing;
	}
	return tproc_status::cmd_processing;
}

/**
 * This function tries to mark off a whole line (i.e. find the newline). If
 * none is there yet, ps_cmd_processing will soon be invoked again, with a
 * read_buffer that has been _appended_ to -- so we will see the same leading
 * string in pcontext->read_buffer.
 *
 * The maximum line length is sizeof(read_buffer), i.e. 64K.
 * The octet counts for synchronizing literals "{256}" must fit in there.
 */
static tproc_status ps_cmd_processing(imap_context *pcontext)
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
		if (pcontext->read_offset > 0 && pcontext->read_offset < 64 * 1024)
			memmove(pcontext->read_buffer, &pcontext->read_buffer[i+nl_len],
			        pcontext->read_offset);
		else
			pcontext->read_offset = 0;

		char *argv[128];
		if (iproto_stat::username == pcontext->proto_stat) {
			argv[0] = pcontext->command_buffer;
			argv[1] = NULL;
			imap_cmd_parser_username(1, argv, pcontext);
			pcontext->command_len = 0;
			return tproc_status::literal_processing;
		} else if (iproto_stat::password == pcontext->proto_stat) {
			argv[0] = pcontext->command_buffer;
			argv[1] = NULL;
			if (imap_cmd_parser_password(1, argv, pcontext) == DISPATCH_SHOULD_CLOSE)
				return ps_end_processing(pcontext);
			pcontext->command_len = 0;
			safe_memset(pcontext->command_buffer, 0, std::size(pcontext->command_buffer));
			return tproc_status::literal_processing;
		}

		auto argc = parse_imap_args(pcontext->command_buffer,
			    pcontext->command_len, argv, std::size(argv));
		if (pcontext->sched_stat == isched_stat::appended) {
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
			pcontext->sched_stat = isched_stat::rdcmd;
			pcontext->literal_ptr = NULL;
			pcontext->literal_len = 0;
			pcontext->command_len = 0;
			return tproc_status::literal_processing;
		}

		if (pcontext->sched_stat == isched_stat::idling) {
			size_t string_length = 0;
			const char *imap_reply_str = nullptr;
			if (1 != argc || 0 != strcasecmp(argv[0], "DONE")) {
				/* IMAP_CODE_2180018: BAD expected DONE */
				imap_reply_str = resource_get_imap_code(1818, 1,
				                 &string_length);
			} else {
				pcontext->sched_stat = isched_stat::rdcmd;
				/* IMAP_CODE_2170027: OK IDLE completed */
				imap_reply_str = resource_get_imap_code(1727, 1,
				                 &string_length);
			}
			pcontext->connection.write(pcontext->tag_string, strlen(pcontext->tag_string));
			pcontext->connection.write(" ", 1);
			pcontext->connection.write(imap_reply_str, string_length);
			pcontext->command_len = 0;
			return tproc_status::literal_processing;
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
			return tproc_status::literal_checking;
		}

		switch (imap_parser_dispatch_cmd(argc, argv, pcontext)) {
		case DISPATCH_CONTINUE:
			pcontext->command_len = 0;
			return tproc_status::literal_processing;
		case DISPATCH_BREAK:
			pcontext->command_len = 0;
			return tproc_status::context_processing;
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

	if (pcontext->sched_stat != isched_stat::idling)
		return tproc_status::cont;
	std::unique_lock ll_hold(g_list_lock);
	g_sleeping_list.push_back(pcontext);
	return tproc_status::sleeping;
}

static tproc_status ps_stat_appending(imap_context *pcontext)
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
	if (pcontext->connection.ssl != nullptr)
		read_len = SSL_read(pcontext->connection.ssl, pbuff, len);
	else
		read_len = read(pcontext->connection.sockd, pbuff, len);
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
			return tproc_status::polling_rdonly;
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
		pcontext->sched_stat = isched_stat::appended;
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
	if (pcontext->sched_stat != isched_stat::appended)
		return tproc_status::cont;
	pcontext->literal_ptr = NULL;
	pcontext->literal_len = 0;
	return tproc_status::cmd_processing;
}

static tproc_status ps_stat_wrdat(imap_context *pcontext)
{
	if (pcontext->write_length == 0)
		imap_parser_wrdat_retrieve(pcontext);
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
			return tproc_status::polling_wronly;
		imap_parser_log_info(pcontext, LV_DEBUG, "timeout");
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	pcontext->connection.last_timestamp = current_time;
	pcontext->write_offset += written_len;
	if (pcontext->write_offset < pcontext->write_length)
		return tproc_status::cont;

	if (pcontext->message_fd == -1) {
		pcontext->write_offset = 0;
		pcontext->write_length = 0;
		switch (imap_parser_wrdat_retrieve(pcontext)) {
		case IMAP_RETRIEVE_TERM:
			pcontext->stream.clear();
			if (0 == pcontext->write_length) {
				pcontext->sched_stat = isched_stat::rdcmd;
				return tproc_status::literal_checking;
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
		return tproc_status::cont;
	}
	auto len = pcontext->literal_len - pcontext->current_len;
	if (len > 64 * 1024)
		len = 64 * 1024;
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
	if (pcontext->literal_len != pcontext->current_len)
		return tproc_status::cont;
	close(pcontext->message_fd);
	pcontext->message_fd = -1;
	pcontext->literal_len = 0;
	pcontext->current_len = 0;
	if (imap_parser_wrdat_retrieve(pcontext) != IMAP_RETRIEVE_ERROR)
		return tproc_status::cont;
	/* IMAP_CODE_2180008: internal error, fail to retrieve from stream object */
	size_t string_length = 0;
	auto imap_reply_str = resource_get_imap_code(1808, 1, &string_length);
	return ps_end_processing(pcontext, imap_reply_str, string_length);
}

static tproc_status ps_stat_wrlst(imap_context *pcontext)
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
			return tproc_status::polling_wronly;
		imap_parser_log_info(pcontext, LV_DEBUG, "time out");
		/* IMAP_CODE_2180011: BAD timeout */
		size_t string_length = 0;
		auto imap_reply_str = resource_get_imap_code(1811, 1, &string_length);
		return ps_end_processing(pcontext, imap_reply_str, string_length);
	}
	pcontext->connection.last_timestamp = current_time;
	pcontext->write_offset += written_len;

	if (pcontext->write_offset < pcontext->write_length)
		return tproc_status::cont;
	pcontext->write_offset = 0;
	unsigned int temp_len = MAX_LINE_LENGTH;
	pcontext->write_buff = static_cast<char *>(pcontext->stream.get_read_buf(&temp_len));
	pcontext->write_length = temp_len;
	if (pcontext->write_buff != nullptr)
		return tproc_status::cont;
	pcontext->stream.clear();
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::rdcmd;
	return tproc_status::literal_checking;
}

tproc_status imap_parser_process(schedule_context *vctx)
{
	auto ctx = static_cast<imap_context *>(vctx);
	auto ret = tproc_status::context_processing;
	while (ret >= tproc_status::app_specific_codes) {
		if (ret == tproc_status::cmd_processing)
			ret = ps_cmd_processing(ctx);
		else if (ret == tproc_status::literal_checking)
			ret = ps_literal_checking(ctx);
		else if (ret == tproc_status::literal_processing)
			ret = ps_literal_processing(ctx);
		else if (ctx->sched_stat == isched_stat::autologout)
			ret = ps_stat_autologout(ctx);
		else if (ctx->sched_stat == isched_stat::disconnected)
			ret = ps_stat_disconnected(ctx);
		else if (ctx->sched_stat == isched_stat::stls)
			ret = ps_stat_stls(ctx);
		else if (ctx->sched_stat == isched_stat::notifying)
			ret = ps_stat_notifying(ctx);
		else if (ctx->sched_stat == isched_stat::rdcmd ||
		    ctx->sched_stat == isched_stat::appended ||
		    ctx->sched_stat == isched_stat::idling)
			ret = ps_stat_rdcmd(ctx);
		else if (ctx->sched_stat == isched_stat::appending)
			ret = ps_stat_appending(ctx);
		else if (ctx->sched_stat == isched_stat::wrdat)
			ret = ps_stat_wrdat(ctx);
		else if (ctx->sched_stat == isched_stat::wrlst)
			ret = ps_stat_wrlst(ctx);
		else
			ret = ps_end_processing(ctx);
	}
	return ret;
}

static tproc_status ps_end_processing(imap_context *pcontext,
    const char *imap_reply_str, ssize_t string_length)
{
	if (NULL != imap_reply_str) {
		pcontext->connection.write("* ", 2);
		pcontext->connection.write(imap_reply_str, string_length);
	}
	pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
	if (iproto_stat::select == pcontext->proto_stat) {
		imap_parser_remove_select(pcontext);
		pcontext->proto_stat = iproto_stat::auth;
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
	imap_parser_context_clear(pcontext);
	return tproc_status::close;
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
		if (line_length < 64)
			return IMAP_RETRIEVE_OK;
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
						if (len > pcontext->literal_len)
							len = pcontext->literal_len;
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
						if (len > pcontext->literal_len)
							len = pcontext->literal_len;
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

static std::vector<imap_context *> *sh_query(const char *x)
{
	auto i = g_select_hash.find(x);
	return i == g_select_hash.end() ? nullptr : &i->second;
}

void imap_parser_bcast_touch(const imap_context *current, const char *username,
    const char *folder)
{
	char buff[1024];
	
	gx_strlcpy(buff, username, std::size(buff));
	HX_strlower(buff);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(buff);
	if (plist == nullptr)
		return;
	for (auto other : *plist)
		if (current != other &&
		    strcmp(folder, other->selected_folder) == 0)
			other->async_change_mask |= REPORT_NEWMAIL;
	hl_hold.unlock();
	snprintf(buff, 1024, "FOLDER-TOUCH %s %s", username, folder);
	system_services_broadcast_event(buff);
}

static void imap_parser_event_touch(const char *username, const char *folder)
{
	char temp_string[UADDR_SIZE];
	
	gx_strlcpy(temp_string, username, std::size(temp_string));
	HX_strlower(temp_string);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(temp_string);
	if (plist == nullptr)
		return;
	for (auto other : *plist)
		if (strcmp(folder, other->selected_folder) == 0)
			other->async_change_mask |= REPORT_NEWMAIL;
}

void imap_parser_bcast_flags(const imap_context &current, uint32_t uid) try
{
	char buff[1024];
	
	gx_strlcpy(buff, current.username, std::size(buff));
	HX_strlower(buff);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(buff);
	if (plist == nullptr)
		return;
	for (auto other : *plist) {
		if (&current == other ||
		    strcmp(current.selected_folder, other->selected_folder) != 0)
			continue;
		other->f_flags.emplace(uid);
		other->async_change_mask |= REPORT_FLAGS;
	}
	hl_hold.unlock();
	auto buf = "MESSAGE-UFLAG "s + current.username + " " +
	           current.selected_folder + " " + std::to_string(uid);
	system_services_broadcast_event(buf.c_str());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1468: ENOMEM");
}

static void imap_parser_event_flag(const char *username, const char *folder,
    uint32_t uid) try
{
	char temp_string[UADDR_SIZE];
	gx_strlcpy(temp_string, username, std::size(temp_string));
	HX_strlower(temp_string);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(temp_string);
	if (plist == nullptr)
		return;
	for (auto other : *plist) {
		if (strcmp(folder, other->selected_folder) != 0)
			continue;
		other->f_flags.emplace(uid);
		other->async_change_mask |= REPORT_FLAGS;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1087: ENOMEM");
}

void imap_parser_bcast_expunge(const imap_context &current,
    const std::vector<MITEM *> &exp_list) try
{
	char user_lo[UADDR_SIZE];
	gx_strlcpy(user_lo, current.username, std::size(user_lo));
	HX_strlower(user_lo);
	/*
	 * gromox-event does not send back events to our own process.
	 * (So, we have to edit the data structures for our other threads
	 * from this function.)
	 * Benefit: no IPC roundtrip to notify other threads.
	 * Downside: Some code duplication between imap_parser_event_expunge
	 * and imap_parser_bcast_expunge.
	 */
	std::unique_lock hl_hold(g_hash_lock);
	auto ctx_list = sh_query(user_lo);
	if (ctx_list == nullptr)
		return;
	for (auto &other : *ctx_list) {
		if (&current == other ||
		    strcmp(current.selected_folder, other->selected_folder) != 0)
			continue;
		for (auto p : exp_list)
			other->f_expunged_uids.emplace_back(p->uid);
		other->async_change_mask |= REPORT_EXPUNGE;
	}
	hl_hold.unlock();
	/* Bcast to other entities */
	auto cmd = "MESSAGE-EXPUNGE "s + user_lo + " " + current.selected_folder + " ";
	auto csize = cmd.size();
	for (auto p : exp_list) {
		cmd.resize(csize);
		cmd += std::to_string(p->uid);
		system_services_broadcast_event(cmd.c_str());
	}
} catch (const std::bad_alloc &) {
}

void imap_parser_event_expunge(const char *user, const char *folder, unsigned int uid)
{
	/* This function is only called for events generated by non-imapd.. which is just pop3 */
	char user_lo[UADDR_SIZE];
	gx_strlcpy(user_lo, user, std::size(user_lo));
	HX_strlower(user_lo);

	std::unique_lock hl_hold(g_hash_lock);
	auto ctx_list = sh_query(user_lo);
	if (ctx_list == nullptr)
		return;
	for (auto other : *ctx_list) {
		if (strcmp(folder, other->selected_folder) != 0)
			continue;
		other->f_expunged_uids.emplace_back(uid);
		other->async_change_mask |= REPORT_EXPUNGE;
	}
}

static void imap_parser_echo_expunges(imap_context &ctx, STREAM *stream,
    const std::vector<unsigned int> &exp_list) try
{
	std::vector<unsigned int> seqid_list;
	for (auto uid : exp_list) {
		auto item = ctx.contents.get_itemx(uid);
		if (item == nullptr)
			continue;
		seqid_list.push_back(item->id);
	}
	std::sort(seqid_list.begin(), seqid_list.end());
	seqid_list.erase(std::unique(seqid_list.begin(), seqid_list.end()), seqid_list.end());
	size_t elem = seqid_list.size();
	/* Use a higher-to-lower approach (cf. RFC 3501 §7.4.1) */
	while (elem-- > 0) {
		char buf[80];
		auto len = gx_snprintf(buf, std::size(buf), "* %u EXPUNGE\r\n", seqid_list[elem]);
		if (stream == nullptr)
			ctx.connection.write(buf, len);
		else if (stream->write(buf, len) != STREAM_WRITE_OK)
			break;
	}
} catch (const std::bad_alloc &) {
}

void imap_parser_echo_modify(imap_context *pcontext, STREAM *pstream)
{
	if (pcontext->async_change_mask == 0)
		return;
	int err;
	int flag_bits;
	BOOL b_first;
	char buff[1024];
	decltype(pcontext->f_expunged_uids) f_expunged;
	
	std::unique_lock hl_hold(g_hash_lock);
	f_expunged = std::move(pcontext->f_expunged_uids);
	pcontext->async_change_mask &= ~REPORT_EXPUNGE;
	auto f_flags = std::move(pcontext->f_flags);
	pcontext->async_change_mask &= ~(REPORT_FLAGS | REPORT_NEWMAIL);
	hl_hold.unlock();

	imap_parser_echo_expunges(*pcontext, pstream, f_expunged);
	if (pcontext->contents.refresh(*pcontext, pcontext->selected_folder,
	    f_expunged.size() > 0) == 0) {
		auto outlen = gx_snprintf(buff, std::size(buff),
		          "* %zu EXISTS\r\n"
		          "* %u RECENT\r\n",
		          pcontext->contents.n_exists(),
		          pcontext->contents.n_recent);
		if (pstream == nullptr)
			pcontext->connection.write(buff, outlen);
		else if (pstream->write(buff, outlen) != STREAM_WRITE_OK)
			return;
	}
	
	for (auto uid : f_flags) {
		auto item = pcontext->contents.get_itemx(uid);
		if (item == nullptr)
			continue;
		if (system_services_get_flags(pcontext->maildir,
		    pcontext->selected_folder, item->mid, &flag_bits,
		    &err) != MIDB_RESULT_OK)
			continue;
		auto outlen = gx_snprintf(buff, std::size(buff), "* %d FETCH (FLAGS (", item->id);
		b_first = FALSE;
		if (flag_bits & FLAG_RECENT) {
			outlen += gx_snprintf(&buff[outlen], std::size(buff) - outlen, "\\Recent");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_ANSWERED) {
			if (b_first)
				buff[outlen++] = ' ';
			outlen += gx_snprintf(&buff[outlen], std::size(buff) - outlen, "\\Answered");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_FLAGGED) {
			if (b_first)
				buff[outlen++] = ' ';
			outlen += gx_snprintf(&buff[outlen], std::size(buff) - outlen, "\\Flagged");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_DELETED) {
			if (b_first)
				buff[outlen++] = ' ';
			outlen += gx_snprintf(&buff[outlen], std::size(buff) - outlen, "\\Deleted");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_SEEN) {
			if (b_first)
				buff[outlen++] = ' ';
			outlen += gx_snprintf(&buff[outlen], std::size(buff) - outlen, "\\Seen");
			b_first = TRUE;
		}
		if (flag_bits & FLAG_DRAFT) {
			if (b_first)
				buff[outlen++] = ' ';
			outlen += gx_snprintf(&buff[outlen], std::size(buff) - outlen, "\\Draft");
		}
		outlen += gx_snprintf(&buff[outlen], std::size(buff) - outlen, "))\r\n");
		if (pstream == nullptr)
			pcontext->connection.write(buff, outlen);
		else if (pstream->write(buff, outlen) != STREAM_WRITE_OK)
			return;
	}
}

SCHEDULE_CONTEXT **imap_parser_get_contexts_list()
{
	return g_context_list2.data();
}

static int imap_parser_dispatch_cmd2(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
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

	auto imap_reply_str = resource_get_imap_code(1800, 1);
	auto string_length = gx_snprintf(reply_buff, std::size(reply_buff), "%s %s", argv[0], imap_reply_str);
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

imap_context::imap_context()
{
	auto pcontext = this;
    pcontext->connection.sockd = -1;
}

static void imap_parser_context_clear(IMAP_CONTEXT *pcontext)
{
    if (NULL == pcontext) {
        return;
    }
	pcontext->connection.reset();
	pcontext->proto_stat = iproto_stat::none;
	pcontext->sched_stat = isched_stat::none;
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
	pcontext->f_expunged_uids.clear();
	pcontext->auth_times = 0;
	pcontext->username[0] = '\0';
	pcontext->maildir[0] = '\0';
}

imap_context::~imap_context()
{
	auto pcontext = this;
	if (pcontext->message_fd >= 0)
		close(pcontext->message_fd);
	if (!pcontext->file_path.empty())
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1351: chmod %s: %s",
				pcontext->file_path.c_str(), strerror(errno));
}

static void *imps_thrwork(void *argp)
{
	int peek_len;
	char tmp_buff;
	
	while (!g_notify_stop) {
		std::unique_lock ll_hold(g_list_lock);
		imap_context *ptail = nullptr, *pcontext = nullptr;
		if (g_sleeping_list.size() > 0)
			ptail = g_sleeping_list.back();
		ll_hold.unlock();
		if (NULL == ptail) {
			usleep(100000);
			continue;
		}
		
		do {
			ll_hold.lock();
			if (g_sleeping_list.size() > 0) {
				pcontext = g_sleeping_list.front();
				g_sleeping_list.erase(g_sleeping_list.begin());
			} else {
				pcontext = nullptr;
			}
			ll_hold.unlock();
			if (pcontext == nullptr)
				break;
			if (pcontext->sched_stat == isched_stat::idling) {
				if (pcontext->async_change_mask != 0) {
					pcontext->sched_stat = isched_stat::notifying;
					contexts_pool_wakeup_context(pcontext, CONTEXT_TURNING);
					if (pcontext == ptail)
						break;
					continue;
				}
			}
			peek_len = recv(pcontext->connection.sockd, &tmp_buff, 1, MSG_PEEK);
			if (1 == peek_len) {
				contexts_pool_wakeup_context(pcontext, CONTEXT_TURNING);
			} else if (peek_len < 0) {
				auto current_time = tp_now();
				if (current_time - pcontext->connection.last_timestamp >= g_autologout_time) {
					pcontext->sched_stat = isched_stat::autologout;
					contexts_pool_wakeup_context(pcontext, CONTEXT_TURNING);
				} else {
					ll_hold.lock();
					g_sleeping_list.push_back(pcontext);
					ll_hold.unlock();
				}
			} else {
				pcontext->sched_stat = isched_stat::disconnected;
				contexts_pool_wakeup_context(pcontext, CONTEXT_TURNING);
			}
		} while (pcontext != ptail);
		usleep(100000);
	}
	return nullptr;
}

void imap_parser_log_info(imap_context *ctx, int level, const char *format, ...)
{
	char log_buf[2048];
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	const auto &co = ctx->connection;
	mlog(level, "rhost=[%s]:%hu user=%s %s", co.client_ip, co.client_port,
		ctx->username, log_buf);

}

static void imap_parser_event_proc(char *line)
{
	char *argv[4]{};
	auto argc = HX_split_fixed(line, " ", std::size(argv), argv);
	if (argc < 1)
		return;
	if (strcasecmp(argv[0], "FOLDER-TOUCH") == 0) {
		if (argc < 3)
			return;
		imap_parser_event_touch(argv[1], argv[2]);
	} else if (strcasecmp(argv[0], "MESSAGE-UFLAG") == 0) {
		if (argc < 4)
			return;
		imap_parser_event_flag(argv[1], argv[2], strtoul(argv[3], nullptr, 0));
	} else if (strcasecmp(argv[0], "MESSAGE-EXPUNGE") == 0) {
		if (argc < 4)
			return;
		imap_parser_event_expunge(argv[1], argv[2], strtoul(argv[3], nullptr, 0));
	}
}


void imap_parser_add_select(IMAP_CONTEXT *pcontext)
{
	char temp_string[UADDR_SIZE];
	
	gx_strlcpy(temp_string, pcontext->username, std::size(temp_string));
	HX_strlower(temp_string);
	time(&pcontext->selected_time);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(temp_string);
	if (NULL == plist) {
		if (g_select_hash.size() <= g_context_num) {
			auto xpair = g_select_hash.emplace(temp_string, std::vector<imap_context *>());
			auto &list = xpair.first->second;
			list.push_back(pcontext);
		}
	} else {
		/* Ensure the memory block pointed to by pcontext is not going by accidents */
		static_assert(!std::is_move_constructible_v<imap_context>);
		static_assert(!std::is_move_assignable_v<imap_context>);
		plist->push_back(pcontext);
	}
	hl_hold.unlock();
	system_services_broadcast_select(pcontext->username, pcontext->selected_folder);
}

void imap_parser_remove_select(IMAP_CONTEXT *pcontext)
{
	BOOL should_remove;
	char temp_string[UADDR_SIZE];
	
	should_remove = TRUE;
	pcontext->selected_time = 0;
	gx_strlcpy(temp_string, pcontext->username, std::size(temp_string));
	HX_strlower(temp_string);
	std::unique_lock hl_hold(g_hash_lock);
	auto plist = sh_query(temp_string);
	if (NULL != plist) {
		plist->erase(std::remove(plist->begin(), plist->end(), pcontext), plist->end());
		if (plist->size() == 0) {
			g_select_hash.erase(temp_string);
		} else {
			pcontext->async_change_mask = 0;
			pcontext->f_flags.clear();
			pcontext->f_expunged_uids.clear();
			for (auto pcontext1 : *plist) {
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
		if (i < SCAN_INTERVAL)
			continue;
		
		i = 0;
		std::vector<bk> temp_file;
		std::unique_lock hl_hold(g_hash_lock);
		time(&cur_time);
		for (const auto &xpair : g_select_hash) {
			auto plist = &xpair.second;
			for (auto pcontext : *plist) {
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
