// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/* smtp parser is a module, which first read data from socket, parses the smtp 
 * commands and then do the corresponding action. 
 */ 
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <openssl/err.h>
#include <gromox/config_file.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/mail_func.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "smtp_aux.hpp"
#include "smtp_cmd_handler.h"
#include "smtp_parser.h"
#if (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2090000fL) || \
    (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x1010000fL)
#	define OLD_SSL 1
#endif
#define READ_BUFFER_SIZE    4096
#define MAX_LINE_LENGTH     64*1024

/* the ratio must larger than 2 */
#define TLS_BUFFER_RATIO    3
#define TLS_BUFFER_BUS_ALLIN(size)                  \
		(sizeof(void*)*((int)((size)/sizeof(void*))+1))
#define SLEEP_BEFORE_CLOSE true

using namespace gromox;

/* return value for smtp_parser_parse_and_save_blkmime */
enum{
	ERROR_FOUND,
	TYPE_FOUND,
	BOUNDARY_FOUND
};

static int smtp_parser_dispatch_cmd(const char *cmd_line, int line_length, 
	SMTP_CONTEXT *pcontext);

static void smtp_parser_context_clear(SMTP_CONTEXT *pcontext);

static void smtp_parser_reset_context_session(SMTP_CONTEXT *pcontext);

static int smtp_parser_try_flush_mail(SMTP_CONTEXT *pcontext, BOOL is_whole);
static void smtp_parser_reset_stream_reading(SMTP_CONTEXT *pcontext);

static std::unique_ptr<SMTP_CONTEXT[]> g_context_list;
static std::vector<SCHEDULE_CONTEXT *> g_context_list2;
static int g_block_ID;
static SSL_CTX *g_ssl_ctx;
static std::unique_ptr<std::mutex[]> g_ssl_mutex_buf;
smtp_param g_param;
alloc_limiter<stream_block> g_blocks_allocator{"g_blocks_allocator.d"};

/* 
 * construct a smtp parser object
 * @param
 *        context_num        number of contexts
 *        threads_num        number of threads in the pool
 *        dm_valid           is domain list valid
 *        max_mail_length    maximum mail size
 *        max_mail_sessions  maximum mail sessions per connection
 *        blktime_sessions   block interval if max sessions is exceeded
 *        flushing_size      maximum size the stream can hold
 *        timeout            seconds if there's no data comes from connection
 *        auth_times         maximum authentication times, session permit
 *        blktime_auths      block interval if max auths is exceeded
 */
void smtp_parser_init(const smtp_param &param)
{
	g_param = std::move(param);
	g_block_ID              = 0;
	g_ssl_mutex_buf         = NULL;
}

#ifdef OLD_SSL
static void smtp_parser_ssl_locking(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		g_ssl_mutex_buf[n].lock();
	else
		g_ssl_mutex_buf[n].unlock();
}

static void smtp_parser_ssl_id(CRYPTO_THREADID* id)
{
	CRYPTO_THREADID_set_numeric(id, (uintptr_t)pthread_self());
}
#endif

/* 
 *    @return
 *         0    success
 *        <>0    fail    
 */
int smtp_parser_run()
{
	if (g_param.support_starttls) {
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		g_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (NULL == g_ssl_ctx) {
			printf("[smtp_parser]: Failed to init SSL context\n");
			return -1;
		}
		if (g_param.cert_passwd.size() > 0)
			SSL_CTX_set_default_passwd_cb_userdata(g_ssl_ctx, deconst(g_param.cert_passwd.c_str()));
		if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx, g_param.cert_path.c_str()) <= 0) {
			printf("[smtp_parser]: fail to use certificate file:");
			ERR_print_errors_fp(stdout);
			return -2;
		}
		if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_param.key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
			printf("[smtp_parser]: fail to use private key file:");
			ERR_print_errors_fp(stdout);
			return -3;
		}

		if (1 != SSL_CTX_check_private_key(g_ssl_ctx)) {
			printf("[smtp_parser]: private key does not match certificate:");
			ERR_print_errors_fp(stdout);
			return -4;
		}
		auto mp = g_config_file->get_value("tls_min_proto");
		if (mp != nullptr && tls_set_min_proto(g_ssl_ctx, mp) != 0) {
			fprintf(stderr, "[smtp_parser]: tls_min_proto value \"%s\" not accepted\n", mp);
			return -4;
		}
		try {
			g_ssl_mutex_buf = std::make_unique<std::mutex[]>(CRYPTO_num_locks());
		} catch (const std::bad_alloc &) {
			printf("[smtp_parser]: Failed to allocate SSL locking buffer\n");
			return -5;
		}
#ifdef OLD_SSL
		CRYPTO_THREADID_set_callback(smtp_parser_ssl_id);
		CRYPTO_set_locking_callback(smtp_parser_ssl_locking);
#endif
	}
	try {
		g_context_list = std::make_unique<SMTP_CONTEXT[]>(g_param.context_num);
		g_context_list2.resize(g_param.context_num);
		for (size_t i = 0; i < g_param.context_num; ++i) {
			g_context_list[i].context_id = i;
			g_context_list2[i] = &g_context_list[i];
		}
	} catch (const std::bad_alloc &) {
		printf("[smtp_parser]: Failed to allocate SMTP contexts\n");
		return -7;
	}
	return 0;
}

void smtp_parser_stop()
{
	g_context_list2.clear();
	g_context_list.reset();
	if (g_param.support_starttls && g_ssl_ctx != nullptr) {
		SSL_CTX_free(g_ssl_ctx);
		g_ssl_ctx = NULL;
	}
	if (g_param.support_starttls && g_ssl_mutex_buf != nullptr) {
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		g_ssl_mutex_buf.reset();
	}
	g_param = {};
}

int smtp_parser_get_context_socket(SCHEDULE_CONTEXT *ctx)
{
	return static_cast<SMTP_CONTEXT *>(ctx)->connection.sockd;
}

time_point smtp_parser_get_context_timestamp(SCHEDULE_CONTEXT *ctx)
{
	return static_cast<SMTP_CONTEXT *>(ctx)->connection.last_timestamp;
}

/*
 *    threads event procedure for smtp parser
 *    @param
 *        action    indicate the event of thread
 *    @return
 *         0    success
 *        <>0    fail
 */
int smtp_parser_threads_event_proc(int action)
{
	switch (action) {
	case THREAD_CREATE:
		break;
	case THREAD_DESTROY:
		break;
	}
	return 0;
}

static int smtp_parser_size_check(SMTP_CONTEXT &ctx)
{
	if (ctx.total_length < g_param.max_mail_length)
		return PROCESS_CONTINUE;
	/* 552 message exceeds fixed maximum message size */
	size_t len = 0;
	auto reply = resource_get_smtp_code(521, 1, &len);
	ctx.connection.write(reply, len);
	smtp_parser_log_info(&ctx, LV_NOTICE, "closing session because maximum message size exceeded");
	if (ctx.flusher.flush_ID != 0)
		flusher_cancel(&ctx);
	ctx.connection.reset(SLEEP_BEFORE_CLOSE);
	smtp_parser_context_clear(&ctx);
	return PROCESS_CLOSE;
}

int smtp_parser_process(SMTP_CONTEXT *pcontext)
{
	char *line, reply_buf[1024];
	int actual_read, ssl_errno;
	int size = READ_BUFFER_SIZE, len;
	time_point current_time;
	const char *host_ID;
	char *pbuff = nullptr;
	BOOL b_should_flush = FALSE;
	size_t string_length = 0;

	/* first check the context is flushed last time */
	if (FLUSH_RESULT_OK == pcontext->flusher.flush_result) {
		if (FLUSH_WHOLE_MAIL == pcontext->flusher.flush_action) {
			pcontext->session_num ++;
			/* 250 Ok <flush ID> */
			auto smtp_reply_str = resource_get_smtp_code(205, 1, &string_length);
			if (string_length >= 2 && smtp_reply_str[string_length-2] == '\r' &&
			    smtp_reply_str[string_length-1] == '\n')
				string_length -= 2;

			memcpy(reply_buf, smtp_reply_str, string_length);
			string_length += sprintf(reply_buf + string_length, 
							" queue-id: %d\r\n", pcontext->flusher.flush_ID);
			pcontext->connection.write(reply_buf, string_length);
			smtp_parser_log_info(pcontext, LV_NOTICE, "return OK, queue-id:%d",
							pcontext->flusher.flush_ID);
			smtp_parser_reset_context_session(pcontext);
			if (pcontext->stream_second.has_value()) {
				pcontext->stream = std::move(*pcontext->stream_second);
				pcontext->stream_second.reset();
				goto CMD_PROCESS;
			}
			return PROCESS_CONTINUE;
		} else {
			pcontext->stream.clear();
			size = STREAM_BLOCK_SIZE;
			pbuff = static_cast<char *>(pcontext->stream.get_write_buf(reinterpret_cast<unsigned int *>(&size)));
			/* 
			 * do not need to check the pbuff pointer because it will never
			 * be NULL because of stream's characteristic
			 */
			
			/* 
			 when state is parsing block content, check if need to rewrite
			 the part of boundary string into the clear stream
			 */
				memcpy(pbuff, pcontext->last_bytes, 4);
				pcontext->stream.fwd_write_ptr(4);
				pcontext->pre_rstlen = 4;
			pcontext->flusher.flush_result = FLUSH_NONE;
			/* let the context continue to be processed */
		}
	} else if (FLUSH_TEMP_FAIL == pcontext->flusher.flush_result) {
		/* 451 Temporary internal failure - queue message failed */
		auto smtp_reply_str = resource_get_smtp_code(414, 1, &string_length);
		pcontext->connection.write(smtp_reply_str, string_length);
		smtp_parser_log_info(pcontext, LV_ERR, "flushing queue temporary fail");
		smtp_parser_reset_context_session(pcontext);
		return PROCESS_CONTINUE;
	} else if (FLUSH_PERMANENT_FAIL == pcontext->flusher.flush_result) {
		/* 554 Message is infected by virus */
		auto smtp_reply_str = resource_get_smtp_code(536, 1, &string_length);
		pcontext->connection.write(smtp_reply_str, string_length);
		smtp_parser_log_info(pcontext, LV_ERR, "flushing queue permanent failure");
		pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
		smtp_parser_context_clear(pcontext);
		return PROCESS_CLOSE;
	}
	
	if (T_STARTTLS_CMD == pcontext->last_cmd) {
		if (NULL == pcontext->connection.ssl) {
			pcontext->connection.ssl = SSL_new(g_ssl_ctx);
			if (NULL == pcontext->connection.ssl) {
				/* 452 Temporary internal failure - failed to initialize TLS */
				auto smtp_reply_str = resource_get_smtp_code(418, 1, &string_length);
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
				smtp_parser_log_info(pcontext, LV_ERR, "out of SSL object");
				pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
		        smtp_parser_context_clear(pcontext);
			    return PROCESS_CLOSE;        
			}
			SSL_set_fd(pcontext->connection.ssl, pcontext->connection.sockd);
		}

		
		if (-1 == SSL_accept(pcontext->connection.ssl)) {
			ssl_errno = SSL_get_error(pcontext->connection.ssl, -1);
			if (SSL_ERROR_WANT_READ == ssl_errno ||
				SSL_ERROR_WANT_WRITE == ssl_errno) {
				current_time = tp_now();
				if (CALCULATE_INTERVAL(current_time,
				    pcontext->connection.last_timestamp) < g_param.timeout)
					return PROCESS_POLLING_RDONLY;
				/* 451 Timeout */
				auto smtp_reply_str = resource_get_smtp_code(412, 1, &string_length);
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
				smtp_parser_log_info(pcontext, LV_DEBUG, "timeout");
				pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
			} else {
				pcontext->connection.reset();
			}
			smtp_parser_context_clear(pcontext);
			return PROCESS_CLOSE;
		} else {
			pcontext->last_cmd = T_NONE_CMD;
			if (pcontext->connection.server_port == g_listener_ssl_port) {
				/* 220 <domain> Service ready */
				auto smtp_reply_str = resource_get_smtp_code(202, 1, &string_length);
				auto smtp_reply_str2 = resource_get_smtp_code(202, 2, &string_length);
				host_ID = resource_get_string("HOST_ID");
				len = sprintf(reply_buf, "%s%s%s", smtp_reply_str, host_ID,
						      smtp_reply_str2);
				SSL_write(pcontext->connection.ssl, reply_buf, len);
			}
		}
	}

	/* read buffer from socket into stream */
	pbuff = static_cast<char *>(pcontext->stream.get_write_buf(reinterpret_cast<unsigned int *>(&size)));
	if (NULL == pbuff) {
		auto smtp_reply_str = resource_get_smtp_code(416, 1, &string_length);
		pcontext->connection.write(smtp_reply_str, string_length);
		smtp_parser_log_info(pcontext, LV_ERR, "out of memory");
		if (0 != pcontext->flusher.flush_ID) {
			flusher_cancel(pcontext);
		}
		pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
		smtp_parser_context_clear(pcontext);
		return PROCESS_CLOSE;
	}
	if (NULL != pcontext->connection.ssl) {
		actual_read = SSL_read(pcontext->connection.ssl, pbuff, size);
	} else {
		actual_read = read(pcontext->connection.sockd, pbuff, size);
	}
	current_time = tp_now();
	if (0 == actual_read) {
 LOST_READ:
		if (0 != pcontext->flusher.flush_ID) {
			flusher_cancel(pcontext);
		}
		smtp_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		pcontext->connection.reset();
		smtp_parser_context_clear(pcontext);
		return PROCESS_CLOSE;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		pcontext->stream.fwd_write_ptr(actual_read);
	} else {
		if (EAGAIN != errno) {
			goto LOST_READ;
		}
		/* check if context is timed out */
		if (CALCULATE_INTERVAL(current_time,
		    pcontext->connection.last_timestamp) >= g_param.timeout) {
			/* 451 Timeout */
			auto smtp_reply_str = resource_get_smtp_code(412, 1, &string_length);
			pcontext->connection.write(smtp_reply_str, string_length);
			smtp_parser_log_info(pcontext, LV_DEBUG, "timeout");
			if (0 != pcontext->flusher.flush_ID) {
				flusher_cancel(pcontext);
			}
			pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
			smtp_parser_context_clear(pcontext);
			return PROCESS_CLOSE;
		} else {
			return PROCESS_POLLING_RDONLY;
		}
	}
	/* envelope command is met */
 CMD_PROCESS:
	if (T_DATA_CMD != pcontext->last_cmd) {    
		pcontext->stream.try_mark_line();
		switch (pcontext->stream.has_newline()) {
		case STREAM_LINE_FAIL: {
			auto smtp_reply_str = resource_get_smtp_code(525, 1, &string_length);
			pcontext->connection.write(smtp_reply_str, string_length);
			smtp_parser_log_info(pcontext, LV_DEBUG, "envelope line too long");
			pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
			smtp_parser_context_clear(pcontext);
			return PROCESS_CLOSE;        
		}
		case STREAM_LINE_UNAVAILABLE:
			return PROCESS_CONTINUE;
		case STREAM_LINE_AVAILABLE:
			do{
				auto line_length = pcontext->stream.readline(&line);
				if (0 != line_length) {
					switch (smtp_parser_dispatch_cmd(line, line_length, 
							pcontext)) {
					case DISPATCH_SHOULD_CLOSE:
						pcontext->connection.reset(SLEEP_BEFORE_CLOSE);
						smtp_parser_context_clear(pcontext);
						return PROCESS_CLOSE;
					case DISPATCH_CONTINUE:
						break;
					case DISPATCH_BREAK:
						/*
						 * Caution: The stream object is different, so we
						 should get the pbuff from the new stream object and 
						 backward the read ptr to zero as if the steam has 
						 * never been changed.
						 */
						actual_read = STREAM_BLOCK_SIZE;
						pbuff = static_cast<char *>(pcontext->stream.get_read_buf(reinterpret_cast<unsigned int *>(&actual_read)));
						pcontext->stream.rewind_read_ptr(actual_read);
						goto DATA_PROCESS;
					default:
						debug_info("[smtp_parser] :error occurs in "
									"smtp_dispatch_cmd\n");
						pcontext->connection.reset();
						smtp_parser_context_clear(pcontext);
						return PROCESS_CLOSE;
					}
				}
				pcontext->stream.try_mark_line();
			} while (pcontext->stream.has_newline() == STREAM_LINE_AVAILABLE);
			return PROCESS_CONTINUE;
		}
	} else {
	/* data command is met */
 DATA_PROCESS:
		if (pcontext->stream.get_total_length() >= g_param.flushing_size)
			b_should_flush = TRUE;
		if (actual_read >= 4) {
			memcpy(pcontext->last_bytes, pbuff + actual_read - 4, 4);
		} else {
			memmove(pcontext->last_bytes, pcontext->last_bytes + actual_read, 4 - actual_read);
			memcpy(pcontext->last_bytes + 4 - actual_read, pbuff, actual_read);
		}
		pcontext->stream.try_mark_eom();
		
		switch (pcontext->stream.has_eom()) {
		case STREAM_EOM_NET:
			pcontext->stream.split_eom(nullptr);
			pcontext->last_cmd = T_END_MAIL;
			return smtp_parser_try_flush_mail(pcontext, TRUE);
		case STREAM_EOM_DIRTY:
			pcontext->stream_second.emplace(&g_blocks_allocator);
			pcontext->stream.split_eom(&*pcontext->stream_second);
			pcontext->last_cmd = T_END_MAIL;
			return smtp_parser_try_flush_mail(pcontext, TRUE);
		default:
			return !b_should_flush ? smtp_parser_size_check(*pcontext) :
			       smtp_parser_try_flush_mail(pcontext, false);
		}
	}
	pcontext->connection.reset();
	smtp_parser_context_clear(pcontext);
	return PROCESS_CLOSE;
}

static int smtp_parser_try_flush_mail(SMTP_CONTEXT *pcontext, BOOL is_whole)
{
	pcontext->total_length += pcontext->stream.get_total_length() - pcontext->pre_rstlen;
	auto ret = smtp_parser_size_check(*pcontext);
	if (ret != PROCESS_CONTINUE)
		return ret;
	smtp_parser_reset_stream_reading(pcontext);
	pcontext->flusher.flush_action = is_whole ? FLUSH_WHOLE_MAIL : FLUSH_PART_MAIL;
	pcontext->stream.reset_reading();
	/* 
	 when block_info state is parsing block content and the possible boundary
	 string appears in the last of stream, copy the unfinished line into 
	 block_info's block_mime. after the context is flushed, rewrite the 
	 unfinished line into the clear stream. under the other conditions, always 
	 ignore the last 4 bytes.
	 */
	if (!is_whole) {
			pcontext->stream.rewind_write_ptr(4);
	}    
	flusher_put_to_queue(pcontext);
	return PROCESS_SLEEPING;
}

/* 
 *    get contexts list for contexts pool
 *    @return
 *        contexts array's address
 */
SCHEDULE_CONTEXT **smtp_parser_get_contexts_list()
{
	return g_context_list2.data();
}

/* 
 *    dispatch the smtp command to the corresponding procedure
 *    @param
 *        cmd_line [in]        command string
 *        line_length            length of command line
 *        pcontext [in, out]    context object
 *     @return
 *         DISPATCH_CONTINUE        continue to dispatch command
 *         DISPATCH_SHOULD_CLOSE    quit command is read
 *         DISPATCH_BREAK            data command is met
 */
static int smtp_parser_dispatch_cmd2(const char *cmd_line, int line_length,
	SMTP_CONTEXT *pcontext)
{
	size_t string_length = 0;
	const char* smtp_reply_str;
	
	/* check the line length */
	if (line_length > 1000) {
		/* 500 syntax error - line too long */
		return 502;
	}
	if (pcontext->session_num == static_cast<unsigned int>(g_param.max_mail_sessions) &&
		(4 != line_length || 0 != strncasecmp(cmd_line, "QUIT", 4))) {
		/* reach the maximum of mail transactions */
		smtp_reply_str = resource_get_smtp_code(529, 1, &string_length);
		pcontext->connection.write(smtp_reply_str, string_length);
		smtp_parser_log_info(pcontext, LV_NOTICE, "added %s into temporary list because"
							" it exceeds the maximum mail number on session",
							pcontext->connection.client_ip);
		return DISPATCH_SHOULD_CLOSE; 
	}
	if (g_param.cmd_prot & HT_LMTP) {
		if (strncasecmp(cmd_line, "LHLO", 4) == 0)
			return smtp_cmd_handler_lhlo(cmd_line, line_length, pcontext);
	}
	if (g_param.cmd_prot & HT_SMTP) {
		if (strncasecmp(cmd_line, "HELO", 4) == 0)
			return smtp_cmd_handler_helo(cmd_line, line_length, pcontext);
		if (strncasecmp(cmd_line, "EHLO", 4) == 0)
			return smtp_cmd_handler_ehlo(cmd_line, line_length, pcontext);
	}
	if (strncasecmp(cmd_line, "STARTTLS", 8) == 0) {
		return smtp_cmd_handler_starttls(cmd_line, line_length, pcontext);
	} else if (0 == strncasecmp(cmd_line, "AUTH", 4)) {
		return smtp_cmd_handler_auth(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "MAIL", 4)) {
		return smtp_cmd_handler_mail(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "RCPT", 4)) {
		return smtp_cmd_handler_rcpt(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "DATA", 4)) {
		return smtp_cmd_handler_data(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "RSET", 4)) {
		return smtp_cmd_handler_rset(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "NOOP", 4)) {
		return smtp_cmd_handler_noop(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "HELP", 4)) {
		return smtp_cmd_handler_help(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "VRFY", 4)) {
		return smtp_cmd_handler_vrfy(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "QUIT", 4)) {
		return smtp_cmd_handler_quit(cmd_line, line_length, pcontext);    
	} else if (0 == strncasecmp(cmd_line, "ETRN", 4)) {
		return smtp_cmd_handler_etrn(cmd_line, line_length, pcontext);    
	} else {
		return smtp_cmd_handler_else(cmd_line, line_length, pcontext);    
	}
}

static int smtp_parser_dispatch_cmd(const char *cmd, int len, SMTP_CONTEXT *ctx)
{
	auto ret = smtp_parser_dispatch_cmd2(cmd, len, ctx);
	auto code = ret & DISPATCH_VALMASK;
	if (code == 0)
		return ret & DISPATCH_ACTMASK;
	size_t zlen = 0;
	auto str = resource_get_smtp_code(code, 1, &zlen);
	ctx->connection.write(str, zlen);
	return ret & DISPATCH_ACTMASK;
}

envelope_info::envelope_info(alloc_limiter<file_block> *b)
{
	strcpy(parsed_domain, "unknown");
	mem_file_init(&f_rcpt_to, b);
}

envelope_info::~envelope_info()
{
	mem_file_free(&f_rcpt_to);
}

void envelope_info::clear()
{
	from[0] = '\0';
	strcpy(parsed_domain, "unknown");
	f_rcpt_to.clear();
}

smtp_context::smtp_context() :
	stream(&g_blocks_allocator), menv(&g_files_allocator)
{}

static void smtp_parser_context_clear(SMTP_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		return;
	}
	pcontext->connection.reset();
	pcontext->session_num           = 0;
	pcontext->stream_second.reset();
	smtp_parser_reset_context_session(pcontext);    
}

/*
 *    reset the session when /r/n./r/n is met
 */
static void smtp_parser_reset_context_session(SMTP_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		return;
	}
	memset(&pcontext->ext_data, 0, sizeof(EXT_DATA));
	memset(&pcontext->last_bytes, 0, arsizeof(pcontext->last_bytes));
	pcontext->last_cmd                     = 0;
	pcontext->is_spam                      = FALSE;
	pcontext->total_length                 = 0;
	pcontext->pre_rstlen                   = 0;
	pcontext->stream.clear();
	pcontext->menv.clear();
	memset(&pcontext->menv.hello_domain, 0, arsizeof(pcontext->menv.hello_domain));
	memset(&pcontext->flusher, 0, sizeof(FLUSH_INFO));
}

/*
 *    reset the stream only for smtp parser
 */
static void smtp_parser_reset_stream_reading(SMTP_CONTEXT *pcontext)
{
	pcontext->stream.reset_reading();
	pcontext->stream.fwd_read_ptr(pcontext->pre_rstlen);
}

void smtp_parser_log_info(SMTP_CONTEXT *pcontext, int level,
    const char *format, ...) try
{
	std::unique_ptr<char[], stdlib_delete> line_buf;
	size_t i;
	va_list ap;

	va_start(ap, format);
	vasprintf(&unique_tie(line_buf), format, ap);
	va_end(ap);
	
	pcontext->menv.f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	char rcpt[UADDR_SIZE];
	std::string all_rcpts;
	static constexpr size_t limit = 3;
	for (i = 0; i < limit; ++i) {
		auto size_read = pcontext->menv.f_rcpt_to.readline(rcpt, arsizeof(rcpt));
		if (size_read == MEM_END_OF_FILE) {
			break;
		}
		if (all_rcpts.size() > 0)
			all_rcpts += ' ';
		all_rcpts += rcpt;
	}
	while (pcontext->menv.f_rcpt_to.readline(rcpt, arsizeof(rcpt)) != MEM_END_OF_FILE)
		++i;
	if (i > limit)
		all_rcpts += " + " + std::to_string(i - limit) + " others";
	system_services_log_info(level, "remote=[%s] from=<%s> to={%s} %s",
		pcontext->connection.client_ip,
		pcontext->menv.from, all_rcpts.c_str(), line_buf.get());
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1609: ENOMEM\n");
}

int smtp_parser_get_extra_num(SMTP_CONTEXT *pcontext)
{
	return pcontext->ext_data.cur_pos;
}

const char* smtp_parser_get_extra_tag(SMTP_CONTEXT *pcontext, int pos)
{
	if (pos >= MAX_EXTRA_DATA_INDEX || pos < 0) {
		return NULL;
	}
	return pcontext->ext_data.ext_tag[pos];
}

const char* smtp_parser_get_extra_value(SMTP_CONTEXT *pcontext, int pos)
{
	if (pos >= MAX_EXTRA_DATA_INDEX || pos < 0) {
		return NULL;
	}
	return pcontext->ext_data.ext_data[pos];
}
