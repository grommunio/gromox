// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/* collection of functions for handling the smtp command
 */ 
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <utility>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/util.hpp>
#include "smtp_aux.hpp"
#include "smtp_cmd_handler.h"
#include "smtp_parser.h"

using namespace gromox;

static BOOL smtp_cmd_handler_check_onlycmd(const char *cmd_line,
    int line_length, SMTP_CONTEXT *pcontext);

int smtp_cmd_handler_helo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	pcontext->command_protocol = HT_SMTP;
    if (line_length >= 5 && line_length <= 255 + 1 + 4 ) {
        /* command error, cannot be recognized by system */
        if (cmd_line[4] != ' ') {
            /* 502 Command not implemented */
			return 506;
        } else {
            /* copy parameter to hello_domain */
			memcpy(pcontext->menv.hello_domain, cmd_line + 5, line_length - 5);
			pcontext->menv.hello_domain[line_length-5] = '\0';
        }
    } else if(line_length > 255 + 1 + 4) {
        /* domain name too long */
		return 502;
    }
    /* 250 OK */
	pcontext->menv.clear();
    pcontext->last_cmd = T_HELO_CMD;
	return 205;
}    

static int smtp_cmd_handler_xhlo(const char *cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	size_t string_length = 0;
    char buff[1024];
            
	/* SAME AS HELO [begin] */
    if (line_length >= 5 && line_length <= 255 + 1 + 4 ) {
        /* command error, cannot be recognized by system */
        if (cmd_line[4] != ' ') {
			return 506;
        } else {
            /* copy parameter to hello_domain */
			memcpy(pcontext->menv.hello_domain, cmd_line + 5, line_length - 5);
			pcontext->menv.hello_domain[line_length-5] = '\0';
        }
    } else if(line_length > 255 + 1 + 4) {
        /* domain name too long */
		return 202;
    }
	pcontext->menv.clear();
	/* SAME AS HELO [end] */

    /* inform client side the esmtp type*/
    pcontext->last_cmd = T_EHLO_CMD;
	string_length = sprintf(buff, "250-%s\r\n", resource_get_string("HOST_ID"));
	if (g_param.support_pipeline)
		string_length += sprintf(buff + string_length,
                             "250-PIPELINING\r\n");
	if (g_param.support_starttls)
		string_length += sprintf(buff + string_length,
							"250-STARTTLS\r\n");
    
    string_length += sprintf(buff + string_length, 
        "250-HELP\r\n"
		"250-SIZE %zu\r\n"
        "250 8BITMIME\r\n",
        /* send the size of "SIZE" command */
		g_param.max_mail_length);

	pcontext->connection.write(buff, string_length);
    return DISPATCH_CONTINUE;
}

int smtp_cmd_handler_lhlo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	pcontext->command_protocol = HT_LMTP;
	return smtp_cmd_handler_xhlo(cmd_line, line_length, pcontext);
}

int smtp_cmd_handler_ehlo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	pcontext->command_protocol = HT_SMTP;
	return smtp_cmd_handler_xhlo(cmd_line, line_length, pcontext);
}

int smtp_cmd_handler_starttls(const char *cmd_line, int line_length,
	SMTP_CONTEXT *pcontext)
{
	if (NULL != pcontext->connection.ssl) {
		return 506;
	}
	if (!g_param.support_starttls)
		return 506;
	pcontext->last_cmd = T_STARTTLS_CMD;
	memset(pcontext->menv.hello_domain, 0, arsizeof(pcontext->menv.hello_domain));
	pcontext->menv.clear();
	return 210;
}

int smtp_cmd_handler_auth(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	if (g_param.support_starttls && g_param.force_starttls &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}
        /* 502 Command not implemented */
	return 506;
}

int smtp_cmd_handler_mail(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	size_t string_length = 0;
    const char *smtp_reply_str, *smtp_reply_str2;
    char buff[1024], buff2[1024];
    EMAIL_ADDR email_addr;    
    
    if (line_length <= 10 || 0 != strncasecmp(cmd_line + 4, " FROM:", 6)) {
        /* syntax error or arguments error*/
		return 505;
    }
    memcpy(buff, cmd_line + 10    , line_length - 10);
    buff[line_length - 10] = '\0';
	HX_strltrim(buff);
	/* rfc require MTA support empty from address */
	if (0 == strncmp(buff, "<>", 2)) {
		strcpy(buff, "<none@none>");
	}
	if (g_param.support_starttls && g_param.force_starttls &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

    parse_email_addr(&email_addr, buff);
	if (!email_addr.has_addr()) {
        /* 550 invalid user - <email_addr> */
		smtp_reply_str = resource_get_smtp_code(516, 1, &string_length);
		smtp_reply_str2 = resource_get_smtp_code(516, 2, &string_length);
        string_length = sprintf(buff2, "%s%s%s", smtp_reply_str, buff,
                        smtp_reply_str2);
		pcontext->connection.write(buff2, string_length);
        return DISPATCH_CONTINUE;
    }
    /* check the running mode */
        if (T_NONE_CMD == pcontext->last_cmd ||
            T_HELO_CMD == pcontext->last_cmd ||
            T_EHLO_CMD == pcontext->last_cmd ||
            T_STARTTLS_CMD == pcontext->last_cmd ||
            T_RSET_CMD == pcontext->last_cmd ||
            T_MAIL_CMD == pcontext->last_cmd ||
            T_END_MAIL == pcontext->last_cmd) {
            pcontext->last_cmd = T_MAIL_CMD;
			snprintf(pcontext->menv.from, arsizeof(pcontext->menv.from), "%s@%s",
                email_addr.local_part, email_addr.domain);
            /* 250 OK */
			return 205;
        } else {
            /* bad sequence */
			return 507;
        }
}

int smtp_cmd_handler_rcpt(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	size_t string_length = 0;
    const char*smtp_reply_str, *smtp_reply_str2;
    char buff[1024], reason[1024], path[256];
    EMAIL_ADDR email_addr;
    
    if (line_length <= 8 || 0 != strncasecmp(cmd_line + 4, " TO:", 4)) {
        /* syntax error or arguments error*/
		return 505;
    }
	if (g_param.support_starttls && g_param.force_starttls &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

    memcpy(buff, cmd_line + 8, line_length - 8);
    buff[line_length - 8] = '\0';
    parse_email_addr(&email_addr, buff);
	if (!email_addr.has_addr()) {
        /* 550 invalid user - <email_addr> */
		smtp_reply_str = resource_get_smtp_code(516, 1, &string_length);
		smtp_reply_str2 = resource_get_smtp_code(516, 2, &string_length);
        string_length = sprintf(reason, "%s%s%s", smtp_reply_str, buff,
                        smtp_reply_str2);
		pcontext->connection.write(reason, string_length);
        return DISPATCH_CONTINUE;
    }
    if (T_MAIL_CMD == pcontext->last_cmd || T_RCPT_CMD == pcontext->last_cmd) {
		if (system_services_check_user != nullptr) {
			snprintf(buff, arsizeof(buff), "%s@%s", email_addr.local_part,
                    email_addr.domain);
			if (!system_services_check_user(buff, path, arsizeof(path))) {
                /* 550 invalid user - <email_addr> */
				smtp_reply_str = resource_get_smtp_code(516, 1, &string_length);
				smtp_reply_str2 = resource_get_smtp_code(516, 2, &string_length);
                string_length = gx_snprintf(reason, GX_ARRAY_SIZE(reason),
                                "%s<%s>%s", smtp_reply_str, buff,
                                smtp_reply_str2);
				pcontext->connection.write(reason, string_length);
				mlog(LV_NOTICE, "remote=%s from=%s to=%s  RCPT address is invalid",
					pcontext->connection.client_ip,
					pcontext->menv.from, buff);
                return DISPATCH_CONTINUE;		
            }
            if ('\0' != path[0] && NULL != system_services_check_full &&
			    !system_services_check_full(path)) {
				/* 550 Mailbox <email_addr> is full */
				smtp_reply_str = resource_get_smtp_code(517, 1, &string_length);
				smtp_reply_str2 = resource_get_smtp_code(517, 2, &string_length);
                string_length = gx_snprintf(reason, GX_ARRAY_SIZE(reason),
                                "%s<%s>%s", smtp_reply_str, buff,
                                smtp_reply_str2);
				pcontext->connection.write(reason, string_length);
				mlog(LV_NOTICE, "remote=%s from=%s to=%s  Mailbox is full",
					pcontext->connection.client_ip,
					pcontext->menv.from, buff);
				return DISPATCH_CONTINUE;		
            }
		}
        pcontext->last_cmd = T_RCPT_CMD;
        /* everything is OK */
		snprintf(buff, arsizeof(buff), "%s@%s", email_addr.local_part,
            email_addr.domain);
		pcontext->menv.f_rcpt_to.writeline(buff);
        /* 250 OK */
		return 205;
    } else {
        /* bad sequence */
		return 507;
    }
}

int smtp_cmd_handler_data(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	size_t string_length = 0;
    const char* smtp_reply_str;

    if (T_RCPT_CMD != pcontext->last_cmd) {
        /* 503 bad sequence of command, RCPT first */
		return 509;
    }    
	if (!smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext))
		return DISPATCH_CONTINUE;
	if (g_param.support_starttls && g_param.force_starttls &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

    /* 354 Start mail input; end with <CRLF>.<CRLF> */
	smtp_reply_str = resource_get_smtp_code(303, 1, &string_length);
    pcontext->last_cmd = T_DATA_CMD;
	unsigned int size = STREAM_BLOCK_SIZE;
	void *pbuff = pcontext->stream.get_read_buf(&size);
    if (NULL == pbuff) {
		/* clear stream, all envelope imformation is recorded in menv */
		pcontext->stream.clear();
		pcontext->connection.write(smtp_reply_str, string_length);
        return DISPATCH_CONTINUE;
    }
	/* fill the new stream the data after "data" command */
	STREAM stream(&g_blocks_allocator);
	unsigned int size2 = STREAM_BLOCK_SIZE;
	void *pbuff2 = stream.get_write_buf(&size2);
	/*
	 * do not need to check the pbuff pointer because it will never
	 * be NULL because of stream's characteristic
	 */
	unsigned int size2_used = 0;
	do{
		if (size <= size2 - size2_used) {
			memcpy(pbuff2, pbuff, size);
			size2_used += size;
		} else {
			auto size_copied = size2 - size2_used;
			memcpy(static_cast<char *>(pbuff2) + size2_used, pbuff, size_copied);
			size2 = STREAM_BLOCK_SIZE;
			stream.fwd_write_ptr(STREAM_BLOCK_SIZE);
			pbuff2 = stream.get_write_buf(&size2);
			if (NULL == pbuff2) {
				smtp_parser_log_info(pcontext, LV_NOTICE, "out of memory");
				return 416 | DISPATCH_SHOULD_CLOSE;
			}
			size2_used = size - size_copied;
			memcpy(pbuff2, static_cast<char *>(pbuff) + size_copied, size2_used);
		}
		size = STREAM_BLOCK_SIZE;
		pbuff = pcontext->stream.get_read_buf(&size);
	} while (NULL != pbuff);
	stream.fwd_write_ptr(size2_used);
	pcontext->stream = std::move(stream);
	pcontext->connection.write(smtp_reply_str, string_length);
	return DISPATCH_BREAK;
}    

int smtp_cmd_handler_quit(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	size_t string_length = 0;
    char buff[1024];
    
	if (!smtp_cmd_handler_check_onlycmd(cmd_line, line_length, pcontext))
		return DISPATCH_CONTINUE;
    /* 221 <domain> Good-bye */
	sprintf(buff, "%s%s%s",
		resource_get_smtp_code(203, 1, &string_length),
		resource_get_string("HOST_ID"),
		resource_get_smtp_code(203, 2, &string_length));
	pcontext->connection.write(buff, strlen(buff));
    return DISPATCH_SHOULD_CLOSE;
}

int smtp_cmd_handler_rset(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	if (!smtp_cmd_handler_check_onlycmd(cmd_line, line_length, pcontext))
		return DISPATCH_CONTINUE;
    pcontext->last_cmd = T_RSET_CMD;
	pcontext->menv.clear();
    /* 250 OK */
	return 205;
}    

int smtp_cmd_handler_noop(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	if (!smtp_cmd_handler_check_onlycmd(cmd_line, line_length, pcontext))
		return DISPATCH_CONTINUE;
	/* Caution: no need to mark the last_cmd */
    /* 250 OK */
	return 205;
}

int smtp_cmd_handler_help(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	if (!smtp_cmd_handler_check_onlycmd(cmd_line, line_length, pcontext))
		return DISPATCH_CONTINUE;
	if (g_param.support_starttls && g_param.force_starttls &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

    /* 214 Help available on http:// ... */
	return 201;
}        

int smtp_cmd_handler_vrfy(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	if (!smtp_cmd_handler_check_onlycmd(cmd_line, line_length, pcontext))
		return DISPATCH_CONTINUE;
	if (g_param.support_starttls && g_param.force_starttls &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

        /* 252 Cannot VRFY user, but will accept message and attempt */       
		return 209;
}    

int smtp_cmd_handler_etrn(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	/* command not implement*/
	return 506;
}

int smtp_cmd_handler_else(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    /* command not implement*/
	return 506;
}

static BOOL smtp_cmd_handler_check_onlycmd(const char *cmd_line,
    int line_length, SMTP_CONTEXT *pcontext)
{
	for (ssize_t i = 4; i < line_length; ++i) {
		if (cmd_line[i] == ' ')
			continue;
		/* 501 Syntax error in parameters or arguments */
		size_t string_length = 0;
		auto smtp_reply_str = resource_get_smtp_code(505, 1, &string_length);
		pcontext->connection.write(smtp_reply_str, string_length);
		return FALSE;
    }
    return TRUE;
}
