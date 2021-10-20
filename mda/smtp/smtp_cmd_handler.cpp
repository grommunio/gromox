// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/* collection of functions for handling the smtp command
 */ 
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include "smtp_cmd_handler.h"
#include "system_services.h"
#include "resource.h"
#include "blocks_allocator.h"
#include <gromox/util.hpp>
#include <gromox/mail_func.hpp>
#include <cstring>
#include <cstdio>

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
			memcpy(pcontext->mail.envelope.hello_domain, cmd_line + 5, line_length - 5);
			pcontext->mail.envelope.hello_domain[line_length - 5] = '\0';
        }
    } else if(line_length > 255 + 1 + 4) {
        /* domain name too long */
		return 502;
    }
    /* 250 OK */
	smtp_parser_reset_context_envelope(pcontext);
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
			memcpy(pcontext->mail.envelope.hello_domain, cmd_line + 5, line_length - 5);
			pcontext->mail.envelope.hello_domain[line_length - 5] = '\0';
        }
    } else if(line_length > 255 + 1 + 4) {
        /* domain name too long */
		return 202;
    }
	smtp_parser_reset_context_envelope(pcontext);
	/* SAME AS HELO [end] */

    /* inform client side the esmtp type*/
    pcontext->last_cmd = T_EHLO_CMD;
	string_length = sprintf(buff, "250-%s\r\n", resource_get_string("HOST_ID"));
    if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_PIPELINE)) {
        string_length += sprintf(buff + string_length, 
                             "250-PIPELINING\r\n");
    }
	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS)) {
		string_length += sprintf(buff + string_length,
							"250-STARTTLS\r\n");
	}
    
    string_length += sprintf(buff + string_length, 
        "250-HELP\r\n"
        "250-SIZE %ld\r\n"
        "250 8BITMIME\r\n",
        /* send the size of "SIZE" command */
        smtp_parser_get_param(MAX_MAIL_LENGTH));

	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, buff, string_length);
	} else {
		write(pcontext->connection.sockd, buff, string_length);
	}
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

	if (FALSE == smtp_parser_get_param(SMTP_SUPPORT_STARTTLS)) {
		return 506;
	}
	pcontext->last_cmd = T_STARTTLS_CMD;
	memset(pcontext->mail.envelope.hello_domain, 0, arsizeof(pcontext->mail.envelope.hello_domain));
	smtp_parser_reset_context_envelope(pcontext);
	return 210;
}

int smtp_cmd_handler_auth(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
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
        /* sytax error or arguments error*/
		return 505;
    }
    memcpy(buff, cmd_line + 10    , line_length - 10);
    buff[line_length - 10] = '\0';
	HX_strltrim(buff);
	/* rfc require MTA support empty from address */
	if (0 == strncmp(buff, "<>", 2)) {
		strcpy(buff, "<none@none>");
	}

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

    parse_email_addr(&email_addr, buff);
    if (0 == strlen(email_addr.local_part) || 0 == strlen(email_addr.domain)) {
        /* 550 invalid user - <email_addr> */
		smtp_reply_str = resource_get_smtp_code(516, 1, &string_length);
		smtp_reply_str2 = resource_get_smtp_code(516, 2, &string_length);
        string_length = sprintf(buff2, "%s%s%s", smtp_reply_str, buff,
                        smtp_reply_str2);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, buff2, string_length);
		} else {
			write(pcontext->connection.sockd, buff2, string_length);
		}
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
		    pcontext->mail.envelope.is_outbound = FALSE;
			snprintf(pcontext->mail.envelope.from, arsizeof(pcontext->mail.envelope.from), "%s@%s",
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
        /* sytax error or arguments error*/
		return 505;
    }

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

    memcpy(buff, cmd_line + 8, line_length - 8);
    buff[line_length - 8] = '\0';
    parse_email_addr(&email_addr, buff);
    if (0 == strlen(email_addr.local_part) || 0 == strlen(email_addr.domain)) {
        /* 550 invalid user - <email_addr> */
		smtp_reply_str = resource_get_smtp_code(516, 1, &string_length);
		smtp_reply_str2 = resource_get_smtp_code(516, 2, &string_length);
        string_length = sprintf(reason, "%s%s%s", smtp_reply_str, buff,
                        smtp_reply_str2);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, reason,string_length);
		} else {
			write(pcontext->connection.sockd, reason, string_length);
		}
        return DISPATCH_CONTINUE;
    }
    if (T_MAIL_CMD == pcontext->last_cmd || T_RCPT_CMD == pcontext->last_cmd) {
		if (!pcontext->mail.envelope.is_outbound &&
		    !pcontext->mail.envelope.is_relay &&
			TRUE == smtp_parser_domainlist_valid()) {
            /* 
             check whether the mail address's domain is in system domain, 
             if it is, pass it. else, check it in relay list.
            */
            if (FALSE == system_services_check_domain(email_addr.domain)) {
                /* 554 Relay from your addr <revserse_address> is denied */
				smtp_reply_str = resource_get_smtp_code(532, 1, &string_length);
				smtp_reply_str2 = resource_get_smtp_code(532, 2, &string_length);
                string_length = sprintf(reason, "%s <%s@%s> %s",
                                    smtp_reply_str, email_addr.local_part,
                                    email_addr.domain, smtp_reply_str2);
                if (NULL != pcontext->connection.ssl) {
					SSL_write(pcontext->connection.ssl, reason, string_length);
				} else {
					write(pcontext->connection.sockd, reason, string_length);
				}
                smtp_parser_log_info(pcontext, LV_DEBUG, "Closed session because"
                             " RCPT address is not in our system and ipaddr is not"
                             " in our relay list either");
                return DISPATCH_SHOULD_CLOSE;
            }
        }
		if (!pcontext->mail.envelope.is_outbound &&
		    !pcontext->mail.envelope.is_relay &&
            NULL != system_services_check_user) {
			snprintf(buff, arsizeof(buff), "%s@%s", email_addr.local_part,
                    email_addr.domain);
			if (FALSE == system_services_check_user(buff, path)) {
                /* 550 invalid user - <email_addr> */
				smtp_reply_str = resource_get_smtp_code(516, 1, &string_length);
				smtp_reply_str2 = resource_get_smtp_code(516, 2, &string_length);
                string_length = gx_snprintf(reason, GX_ARRAY_SIZE(reason),
                                "%s<%s>%s", smtp_reply_str, buff,
                                smtp_reply_str2);
				if (NULL != pcontext->connection.ssl) {
					SSL_write(pcontext->connection.ssl, reason, string_length);
				} else {
					write(pcontext->connection.sockd, reason, string_length);
				}
				system_services_log_info(LV_NOTICE, "remote=%s from=%s to=%s  RCPT address is invalid",
					pcontext->connection.client_ip,
					pcontext->mail.envelope.from, buff);
                return DISPATCH_CONTINUE;		
            }
            if ('\0' != path[0] && NULL != system_services_check_full &&
				FALSE == system_services_check_full(path)) {
				/* 550 Mailbox <email_addr> is full */
				smtp_reply_str = resource_get_smtp_code(517, 1, &string_length);
				smtp_reply_str2 = resource_get_smtp_code(517, 2, &string_length);
                string_length = gx_snprintf(reason, GX_ARRAY_SIZE(reason),
                                "%s<%s>%s", smtp_reply_str, buff,
                                smtp_reply_str2);
				if (NULL != pcontext->connection.ssl) {
					SSL_write(pcontext->connection.ssl, reason, string_length);
				} else {
					write(pcontext->connection.sockd, reason, string_length);
				}
				system_services_log_info(LV_NOTICE, "remote=%s from=%s to=%s  Mailbox is full",
					pcontext->connection.client_ip,
					pcontext->mail.envelope.from, buff);
				return DISPATCH_CONTINUE;		
            }
		}
        pcontext->last_cmd = T_RCPT_CMD;
        /* everything is OK */
		snprintf(buff, arsizeof(buff), "%s@%s", email_addr.local_part,
            email_addr.domain);
		mem_file_writeline(&pcontext->mail.envelope.f_rcpt_to, buff);
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
    STREAM stream;

    if (T_RCPT_CMD != pcontext->last_cmd) {
        /* 503 bad sequence of command, RCPT first */
		return 509;
    }    
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

    /* 354 Start mail input; end with <CRLF>.<CRLF> */
	smtp_reply_str = resource_get_smtp_code(303, 1, &string_length);
    pcontext->last_cmd = T_DATA_CMD;
	unsigned int size = STREAM_BLOCK_SIZE;
	void *pbuff = stream_getbuffer_for_reading(&pcontext->stream, &size);
    if (NULL == pbuff) {
		/* clear stream, all envelope imformation is recorded in mail.envelope */
        stream_clear(&pcontext->stream);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;
    }
	/* fill the new stream the data after "data" command */
	stream_init(&stream, blocks_allocator_get_allocator());
	unsigned int size2 = STREAM_BLOCK_SIZE;
	void *pbuff2 = stream_getbuffer_for_writing(&stream, &size2);
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
			stream_forward_writing_ptr(&stream, STREAM_BLOCK_SIZE);
			pbuff2 = stream_getbuffer_for_writing(&stream, &size2);
			if (NULL == pbuff2) {
				stream_free(&stream);
				smtp_parser_log_info(pcontext, LV_NOTICE, "out of memory");
				return 416 | DISPATCH_SHOULD_CLOSE;
			}
			size2_used = size - size_copied;
			memcpy(pbuff2, static_cast<char *>(pbuff) + size_copied, size2_used);
		}
		size = STREAM_BLOCK_SIZE;
		pbuff = stream_getbuffer_for_reading(&pcontext->stream, &size);
	} while (NULL != pbuff);
	stream_forward_writing_ptr(&stream, size2_used);
	stream_free(&pcontext->stream);
	pcontext->stream = stream;
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
	} else {
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
	}
	return DISPATCH_BREAK;
}    

int smtp_cmd_handler_quit(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
	size_t string_length = 0;
    char buff[1024];
    
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }
    /* 221 <domain> Good-bye */
	sprintf(buff, "%s%s%s",
		resource_get_smtp_code(203, 1, &string_length),
		resource_get_string("HOST_ID"),
		resource_get_smtp_code(203, 2, &string_length));
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, buff, strlen(buff));
	} else {
		write(pcontext->connection.sockd, buff, strlen(buff));
	}
    return DISPATCH_SHOULD_CLOSE;
}

int smtp_cmd_handler_rset(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }
    pcontext->last_cmd = T_RSET_CMD;
	smtp_parser_reset_context_envelope(pcontext);
    /* 250 OK */
	return 205;
}    

int smtp_cmd_handler_noop(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }
	/* Caution: no need to mark the last_cmd */
    /* 250 OK */
	return 205;
}

int smtp_cmd_handler_help(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		return 520;
	}

    /* 214 Help availble on http:// ... */
	return 201;
}        

int smtp_cmd_handler_vrfy(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
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
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
		return FALSE;
    }
    return TRUE;
}
