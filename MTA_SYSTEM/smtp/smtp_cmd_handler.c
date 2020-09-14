/* collection of functions for handling the smtp command
 */ 
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "smtp_cmd_handler.h"
#include "system_services.h"
#include "resource.h"
#include "blocks_allocator.h"
#include "util.h"
#include "mail_func.h"
#include <string.h>
#include <stdio.h>

static BOOL smtp_cmd_handler_check_onlycmd(const char *cmd_line,
    int line_length, SMTP_CONTEXT *pcontext);

static int smtp_cmd_handler_auth_service_interact(const char *cmd_line,
	int line_length, SMTP_CONTEXT *pcontext);

int smtp_cmd_handler_helo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char* smtp_reply_str;
    
    if (line_length >= 5 && line_length <= 255 + 1 + 4 ) {
        /* command error, cannot be recognized by system */
        if (cmd_line[4] != ' ') {
            /* 502 Command not implemented */
            smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1,
                             &string_length);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
			} else {
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
			}
            return DISPATCH_CONTINUE;
        } else {
            /* copy parameter to hello_domain */
            memcpy(pcontext->mail.envelop.hello_domain, cmd_line + 5,
                   line_length - 5);
            pcontext->mail.envelop.hello_domain[line_length - 5] = '\0';
        }
    } else if(line_length > 255 + 1 + 4) {
        /* domain name too long */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175002, 1,
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;
    }
    /* 250 OK */
    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 1, 
                     &string_length);
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
	} else {
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
	}
    smtp_parser_reset_context_envelop(pcontext);    
    pcontext->last_cmd = T_HELO_CMD;
    return DISPATCH_CONTINUE;    
}    

int smtp_cmd_handler_ehlo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char* smtp_reply_str;
    char buff[1024];
            
    /* SAME AS HELO ------------------------ begin */
    if (line_length >= 5 && line_length <= 255 + 1 + 4 ) {
        /* command error, cannot be recognized by system */
        if (cmd_line[4] != ' ') {
            smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1,
                             &string_length);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, smtp_reply_str,
					string_length);
			} else {
				write(pcontext->connection.sockd, smtp_reply_str,
					string_length);
			}
            return DISPATCH_CONTINUE;
        } else {
            /* copy parameter to hello_domain */
            memcpy(pcontext->mail.envelop.hello_domain, cmd_line + 5,
                    line_length - 5);
            pcontext->mail.envelop.hello_domain[line_length - 5] = '\0';
        }
    } else if(line_length > 255 + 1 + 4) {
        /* domain name too long */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172002, 1,
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;
    }
    smtp_parser_reset_context_envelop(pcontext);    
    /* SAME AS HELO ------------------------ end */

    /* inform client side the esmtp type*/
    pcontext->last_cmd = T_EHLO_CMD;
	string_length = sprintf(buff, "250-%s\r\n", resource_get_string("HOST_ID"));
    if (SMTP_MODE_INBOUND != smtp_parser_get_param(SMTP_RUNNING_MODE) &&
		NULL != system_services_auth_ehlo) {
        string_length += sprintf(buff + string_length, "250-AUTH %s\r\n",
				system_services_auth_ehlo());
        string_length += sprintf(buff + string_length, "250-AUTH=%s\r\n",
				system_services_auth_ehlo());
    }
    if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_PIPELINE)) {
        string_length += sprintf(buff + string_length, 
                             "250-PIPELINING\r\n");
    }
	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS)) {
		string_length += sprintf(buff + string_length,
							"250-STARTTLS\r\n");
	}
    if (NULL != system_services_etrn_process) {
        string_length += sprintf(buff + string_length,
                             "250-ETRN\r\n");
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

int smtp_cmd_handler_starttls(const char *cmd_line, int line_length,
	SMTP_CONTEXT *pcontext)
{
	int string_length;
	const char*smtp_reply_str;

	if (NULL != pcontext->connection.ssl) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1,
							&string_length);
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

	if (FALSE == smtp_parser_get_param(SMTP_SUPPORT_STARTTLS)) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1,
							&string_length);
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

	smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172010, 1,
						&string_length);
	write(pcontext->connection.sockd, smtp_reply_str, string_length);

	pcontext->last_cmd = T_STARTTLS_CMD;
	memset(pcontext->mail.envelop.hello_domain, 0, 256);
	smtp_parser_reset_context_envelop(pcontext);

	return DISPATCH_CONTINUE;
}

int smtp_cmd_handler_auth(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char* smtp_reply_str;
    
	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175020, 1,
							&string_length);
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

    /* 
	 * if the running mode is "inbound" or there's no "auth" service
	 * tell the client no this command 
	 */ 
    if (SMTP_MODE_INBOUND == smtp_parser_get_param(SMTP_RUNNING_MODE) ||
		NULL == system_services_auth_ehlo) {
        /* 502 Command not implemented */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1,
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str,
				string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str,
				string_length);
		}
        return DISPATCH_CONTINUE;
    }

    if (cmd_line[4] != ' ') {
        /* command not implemented */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1, 
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;    
    }
    /* check whether the user has already logged in */
    if (TRUE == pcontext->mail.envelop.is_login && 0 == pcontext->session_num) {
		/* bad sequence of command */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175007, 1,
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;    
    }
	return smtp_cmd_handler_auth_service_interact(cmd_line, line_length,
			pcontext);
}

int smtp_cmd_handler_mail(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char *smtp_reply_str, *smtp_reply_str2;
    char buff[1024], buff2[1024];
    EMAIL_ADDR email_addr;    
    
    if (line_length <= 10 || 0 != strncasecmp(cmd_line + 4, " FROM:", 6)) {
        /* sytax error or arguments error*/
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175005, 1, 
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;
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
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175020, 1,
							&string_length);
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

    parse_email_addr(&email_addr, buff);
    if (0 == strlen(email_addr.local_part) || 0 == strlen(email_addr.domain)) {
        /* 550 invalid user - <email_addr> */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175016, 1,
                         &string_length);
        smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2175016, 2,
                         &string_length);
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
    switch (smtp_parser_get_param(SMTP_RUNNING_MODE)) {
    case SMTP_MODE_INBOUND:
        if (T_NONE_CMD == pcontext->last_cmd ||
            T_HELO_CMD == pcontext->last_cmd ||
            T_EHLO_CMD == pcontext->last_cmd ||
            T_STARTTLS_CMD == pcontext->last_cmd ||
            T_RSET_CMD == pcontext->last_cmd ||
            T_MAIL_CMD == pcontext->last_cmd ||
            T_END_MAIL == pcontext->last_cmd) {
            pcontext->last_cmd = T_MAIL_CMD;
            pcontext->mail.envelop.is_outbound = FALSE;
            snprintf(pcontext->mail.envelop.from, 256, "%s@%s",
                email_addr.local_part, email_addr.domain);
            /* 250 OK */
            smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 1,
                             &string_length);
        } else {
            /* bad sequence */
            smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175007, 1,
                             &string_length);    
        }
        break;
    case SMTP_MODE_OUTBOUND:
        if (FALSE != smtp_parser_get_param(SMTP_NEED_AUTH)) {
            if (TRUE == pcontext->mail.envelop.is_relay ||
				TRUE == pcontext->mail.envelop.is_login) {
                pcontext->last_cmd = T_MAIL_CMD;
                pcontext->mail.envelop.is_outbound = TRUE;
                snprintf(pcontext->mail.envelop.from, 256, "%s@%s",
                    email_addr.local_part, email_addr.domain);
                /* 250 OK */
                smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 1,
                                 &string_length);
            } else {
                /* 530 Authentication required */
                smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175013, 1,
                                 &string_length);
            }
        } else {
            pcontext->last_cmd = T_MAIL_CMD;
            pcontext->mail.envelop.is_outbound = TRUE;
            snprintf(pcontext->mail.envelop.from, 256, "%s@%s",
                email_addr.local_part, email_addr.domain);
            /* 250 OK */
            smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 1,
                             &string_length);
        }
        break;
    case SMTP_MODE_MIXTURE:
        /* 
         under mixture mode, check whether the domain is system domain, if
         it is, check whether user has logged in. else, it is a mail comes
         from other mta
         */
        if (FALSE == system_services_check_domain(email_addr.domain)) {
            if (T_NONE_CMD == pcontext->last_cmd ||
                T_HELO_CMD == pcontext->last_cmd ||
                T_EHLO_CMD == pcontext->last_cmd ||
				T_STARTTLS_CMD == pcontext->last_cmd ||
                T_MAIL_CMD == pcontext->last_cmd ||
                T_RSET_CMD == pcontext->last_cmd ||
                T_END_MAIL == pcontext->last_cmd) {
                
                    pcontext->last_cmd = T_MAIL_CMD;
                    snprintf(pcontext->mail.envelop.from, 256, "%s@%s",
                        email_addr.local_part, email_addr.domain);
                    /* 250 OK */
                    pcontext->mail.envelop.is_outbound = FALSE;
                    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005,
                                    1, &string_length);
            } else {
                /* bad sequence */
                smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175007, 1,
                                 &string_length);    
            }
        } else {
            if (FALSE != smtp_parser_get_param(SMTP_NEED_AUTH)) {
                if (TRUE == pcontext->mail.envelop.is_relay ||
					TRUE == pcontext->mail.envelop.is_login) {
                    pcontext->last_cmd = T_MAIL_CMD;
                    pcontext->mail.envelop.is_outbound = TRUE;
                    snprintf(pcontext->mail.envelop.from, 256, "%s@%s",
                        email_addr.local_part, email_addr.domain);
                    /* 250 OK */
                    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 
                                     1, &string_length);
                } else {
                    /* 530 Authentication required */
                    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175013,
                                     1, &string_length);
                }
            } else {
                pcontext->last_cmd = T_MAIL_CMD;
                pcontext->mail.envelop.is_outbound = TRUE;
                snprintf(pcontext->mail.envelop.from, 256, "%s@%s",
                    email_addr.local_part, email_addr.domain);
                /* 250 OK */
                smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 
                                 1, &string_length);
            }
        }
        break;
    }
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
	} else {
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
	}
    return DISPATCH_CONTINUE;
}

int smtp_cmd_handler_rcpt(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char*smtp_reply_str, *smtp_reply_str2;
    char buff[1024], reason[1024], path[256];
    EMAIL_ADDR email_addr;
    
    if (line_length <= 8 || 0 != strncasecmp(cmd_line + 4, " TO:", 4)) {
        /* sytax error or arguments error*/
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175005, 1, 
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;
    }

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175020, 1,
							&string_length);
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

    memcpy(buff, cmd_line + 8, line_length - 8);
    buff[line_length - 8] = '\0';
    parse_email_addr(&email_addr, buff);
    if (0 == strlen(email_addr.local_part) || 0 == strlen(email_addr.domain)) {
        /* 550 invalid user - <email_addr> */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175016, 1,
                         &string_length);
        smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2175016, 2,
                         &string_length);
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
        if (FALSE == pcontext->mail.envelop.is_outbound &&
			FALSE == pcontext->mail.envelop.is_relay &&
			TRUE == smtp_parser_domainlist_valid()) {
            /* 
             check whether the mail address's domain is in system domain, 
             if it is, pass it. else, check it in relay list.
            */
            if (FALSE == system_services_check_domain(email_addr.domain)) {
                /* 554 Relay from your addr <revserse_address> is denied */
                smtp_reply_str = resource_get_smtp_code(
									SMTP_CODE_2175032, 1, &string_length);
                smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2175032,
                        2, &string_length);
                string_length = sprintf(reason, "%s <%s@%s> %s",
                                    smtp_reply_str, email_addr.local_part,
                                    email_addr.domain, smtp_reply_str2);
                if (NULL != pcontext->connection.ssl) {
					SSL_write(pcontext->connection.ssl, reason, string_length);
				} else {
					write(pcontext->connection.sockd, reason, string_length);
				}
                smtp_parser_log_info(pcontext, 8, "close session because"
                             " rcpt address is not in our system and ipaddr is not"
                             " in our relay list, too");
                return DISPATCH_SHOULD_CLOSE;
            }
        }
        if (FALSE == pcontext->mail.envelop.is_outbound &&
            FALSE == pcontext->mail.envelop.is_relay &&
            NULL != system_services_check_user) {
            snprintf(buff, 256, "%s@%s", email_addr.local_part,
                    email_addr.domain);
			if (FALSE == system_services_check_user(buff, path)) {
                /* 550 invalid user - <email_addr> */
                smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175016, 1,
                                 &string_length);
                smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2175016, 2,
                                 &string_length);
                string_length = sprintf(reason, "%s<%s>%s", smtp_reply_str, buff,
                                smtp_reply_str2);
				if (NULL != pcontext->connection.ssl) {
					SSL_write(pcontext->connection.ssl, reason, string_length);
				} else {
					write(pcontext->connection.sockd, reason, string_length);
				}
	            system_services_log_info(8, "remote MTA IP: %s, FROM: %s, "
						"TO: %s  rcpt address is invalid",
						pcontext->connection.client_ip,
						pcontext->mail.envelop.from, buff);
                return DISPATCH_CONTINUE;		
            }
            if ('\0' != path[0] && NULL != system_services_check_full &&
				FALSE == system_services_check_full(path)) {
				/* 550 Mailbox <email_addr> is full */
                smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175017, 1,
                                 &string_length);
                smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2175017, 2,
                                 &string_length);
                string_length = sprintf(reason, "%s<%s>%s", smtp_reply_str, buff,
                                smtp_reply_str2);
				if (NULL != pcontext->connection.ssl) {
					SSL_write(pcontext->connection.ssl, reason, string_length);
				} else {
					write(pcontext->connection.sockd, reason, string_length);
				}
				system_services_log_info(8, "remote MTA IP: %s, FROM: %s, "
						"TO: %s  mailbox is full",
						pcontext->connection.client_ip,
						pcontext->mail.envelop.from, buff);
				return DISPATCH_CONTINUE;		
            }
		}
        pcontext->last_cmd = T_RCPT_CMD;
        /* everything is OK */
        snprintf(buff, 256, "%s@%s", email_addr.local_part,
            email_addr.domain);
        mem_file_writeline(&pcontext->mail.envelop.f_rcpt_to, buff);
        /* 250 OK */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 1,
                         &string_length);
    } else {
        /* bad sequence */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175007, 1,
                         &string_length);    
    }
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
	} else {
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
	}
    return DISPATCH_CONTINUE;
}

int smtp_cmd_handler_data(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char* smtp_reply_str;
    STREAM stream;
    int size, size_copied;
	int size2, size2_used;

    if (T_RCPT_CMD != pcontext->last_cmd) {
        /* 503 bad sequence of command, RCPT first */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175009, 1,
            &string_length);    
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;
    }    
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175020, 1,
							&string_length);
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

    /* 354 Start mail input; end with <CRLF>.<CRLF> */
    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2173003,1,&string_length);
    pcontext->last_cmd = T_DATA_CMD;
    size = STREAM_BLOCK_SIZE;
	void *pbuff = stream_getbuffer_for_reading(&pcontext->stream, &size);
    if (NULL == pbuff) {
        /* clear stream, all envelop imformation is recorded in mail.envelop */
        stream_clear(&pcontext->stream);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;
    } else {
        /* fill the new stream the data after "data" command */
        stream_init(&stream, blocks_allocator_get_allocator());
        size2 = STREAM_BLOCK_SIZE;
		void *pbuff2 = stream_getbuffer_for_writing(&stream, &size2);
        /*
         * do not need to check the pbuff pointer because it will never
         * be NULL because of stream's characteristic
         */
        size_copied = 0;
        size2_used = 0;
        do{
            if (size <= size2 - size2_used) {
                memcpy(pbuff2, pbuff, size);
                size2_used += size;
            } else {
                size_copied = size2 - size2_used;
                memcpy(pbuff2 + size2_used, pbuff, size_copied);
                size2 = STREAM_BLOCK_SIZE;
                size2_used = 0;
                stream_forward_writing_ptr(&stream, STREAM_BLOCK_SIZE);
                pbuff2 = stream_getbuffer_for_writing(&stream, &size2);
                if (NULL == pbuff2) {
                    stream_free(&stream);
                    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174016,
                                     1, &string_length);
					if (NULL != pcontext->connection.ssl) {
						SSL_write(pcontext->connection.ssl, smtp_reply_str,
							string_length);
					} else {
						write(pcontext->connection.sockd, smtp_reply_str,
							string_length);
					}
		            smtp_parser_log_info(pcontext, 8, "out of memory");
                    return DISPATCH_SHOULD_CLOSE;
                }
                size2_used = size - size_copied;
                memcpy(pbuff2, pbuff + size_copied, size2_used);
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
}    

int smtp_cmd_handler_quit(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    char buff[1024];
    
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }
    /* 221 <domain> Good-bye */
    sprintf(buff, "%s%s%s", resource_get_smtp_code(SMTP_CODE_2172003, 1, 
		&string_length), resource_get_string("HOST_ID"),
            resource_get_smtp_code(SMTP_CODE_2172003, 2, &string_length));
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
    int string_length;
    const char* smtp_reply_str;
            
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }
    pcontext->last_cmd = T_RSET_CMD;
    smtp_parser_reset_context_envelop(pcontext);
    /* 250 OK */
    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 1,
                     &string_length);
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
	} else {
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
	}
    return DISPATCH_CONTINUE;
}    

int smtp_cmd_handler_noop(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char* smtp_reply_str;
    
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }
	/* Caution: no need to mark the last_cmd */
    /* 250 OK */
    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 1,
                     &string_length);
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
	} else {
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
	}
    return DISPATCH_CONTINUE;
}

int smtp_cmd_handler_help(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char* smtp_reply_str;
    
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175020, 1,
							&string_length);
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

    /* 214 Help availble on http:// ... */
    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172001, 1,
                     &string_length);
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
	} else {
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
	}
    return DISPATCH_CONTINUE;
}        

int smtp_cmd_handler_vrfy(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
	const char *smtp_reply_str = nullptr;
	char reply_string[1024];
    
    if (FALSE == smtp_cmd_handler_check_onlycmd(cmd_line,line_length,pcontext)){
        return DISPATCH_CONTINUE;
    }

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175020, 1,
							&string_length);
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

	if (NULL == system_services_vrfy_process) {
        /* 252 Cannot VRFY user, but will accept message and attempt */       
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172009, 1,
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
	} else {
        system_services_vrfy_process(cmd_line, line_length, reply_string,
            sizeof(reply_string) - 1);
		reply_string[sizeof(reply_string) - 1] = '\0';
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, reply_string, strlen(reply_string));
		}
    }
    return DISPATCH_CONTINUE;
}    

int smtp_cmd_handler_etrn(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char* smtp_reply_str;
	char reply_string[1024];
	
	if (NULL == system_services_etrn_process) {
		/* command not implement*/
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1, 
                     &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
		return DISPATCH_CONTINUE;
	}
	if (cmd_line[4] != ' ') {
        /* 502 Command not implemented */
        smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1,
                         &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
        return DISPATCH_CONTINUE;
	}

	if (FALSE != smtp_parser_get_param(SMTP_SUPPORT_STARTTLS) &&
		FALSE != smtp_parser_get_param(SMTP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175020, 1,
							&string_length);
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
		return DISPATCH_CONTINUE;
	}

	system_services_etrn_process(cmd_line, line_length, reply_string,
		sizeof(reply_string) - 1);
	reply_string[sizeof(reply_string) - 1] = '\0';
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, reply_string, strlen(reply_string));
	} else {
		write(pcontext->connection.sockd, reply_string, strlen(reply_string));
	}
    return DISPATCH_CONTINUE;
}

int smtp_cmd_handler_else(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext)
{
    int string_length;
    const char* smtp_reply_str;
    
    if (T_AUTH_PROCESS == pcontext->last_cmd) {
		return smtp_cmd_handler_auth_service_interact(cmd_line, line_length,
				pcontext);
	} 
    /* command not implement*/
    smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175006, 1, 
                     &string_length);
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
	} else {
		write(pcontext->connection.sockd, smtp_reply_str, string_length);
	}
    return DISPATCH_CONTINUE;
}

static BOOL smtp_cmd_handler_check_onlycmd(const char *cmd_line,
    int line_length, SMTP_CONTEXT *pcontext)
{
    int string_length, i;
    char * smtp_reply_str;

    for (i=4; i<line_length; i++) {
        if (cmd_line[i] != ' ') {
            /* 501 Syntax error in parameters or arguments */
            smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175005, 1,
                             &string_length);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
			} else {
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
			}
            return FALSE;
        }
    }
    return TRUE;
}

static int smtp_cmd_handler_auth_service_interact(const char *cmd_line,
	int line_length, SMTP_CONTEXT *pcontext)
{
	char reply_string[1024];
	const char *smtp_reply_str;
	int interaction_result, string_length;
	BOOL b_has_username;
	
	interaction_result = system_services_auth_process(pcontext - 
		smtp_parser_get_contexts_list(), cmd_line, line_length, 
		reply_string, sizeof(reply_string) - 1);
	reply_string[sizeof(reply_string) - 1] = '\0';
	/* append \r\n at the end of reply string */
	strcat(reply_string, "\r\n");
	string_length = strlen(reply_string);
	b_has_username = system_services_auth_retrieve(pcontext -
			smtp_parser_get_contexts_list(),
			pcontext->mail.envelop.username,
			sizeof(pcontext->mail.envelop.username));
	
	switch (interaction_result) {
	case SERVICE_AUTH_ERROR:
		if (TRUE == b_has_username && (FALSE == system_services_judge_user(
			pcontext->mail.envelop.username))) {
			/* 554 Temporary authentication failure */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175035, 1,
					             &string_length);
			smtp_parser_log_info(pcontext, 8, "user %s is denied by user "
					"filter", pcontext->mail.envelop.username);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
			} else {
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
			}
			return DISPATCH_SHOULD_CLOSE;
		}
		pcontext->mail.envelop.auth_times ++;
		if (pcontext->mail.envelop.auth_times >= 
			smtp_parser_get_param(MAX_AUTH_TIMES)) {
			
			/* 554 Authentication has failed too many times */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175028, 1,
					             &string_length);
			if (TRUE == b_has_username) {
				system_services_add_user_into_temp_list(
					pcontext->mail.envelop.username,
					smtp_parser_get_param(BLOCK_TIME_EXCEED_AUTHS));
				smtp_parser_log_info(pcontext, 8, "auth times is over than "
								"system setting, block the user for a while");	
			}
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
			} else {
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
			}
			return DISPATCH_SHOULD_CLOSE;
		}
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, reply_string, string_length);
		} else {
			write(pcontext->connection.sockd, reply_string, string_length);
		}
		pcontext->last_cmd = T_NONE_CMD;
		return DISPATCH_CONTINUE;
	case SERVICE_AUTH_CONTINUE:
		smtp_reply_str = reply_string;
		string_length = strlen(reply_string);
		pcontext->last_cmd = T_AUTH_PROCESS;
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, reply_string, string_length);
		} else {
			write(pcontext->connection.sockd, reply_string, string_length);
		}
		return DISPATCH_CONTINUE;
	case SERVICE_AUTH_FINISH:
		if (FALSE == system_services_judge_user(
			pcontext->mail.envelop.username)) {
			/* 554 Temporary authentication failure */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175035, 1,
					             &string_length);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
			} else {
				write(pcontext->connection.sockd, smtp_reply_str,string_length);
			}
			smtp_parser_log_info(pcontext, 8, "user %s is denied by user "
					"filter", pcontext->mail.envelop.username);
			return DISPATCH_SHOULD_CLOSE;
		}
		pcontext->mail.envelop.is_login = TRUE;
		pcontext->last_cmd              = T_LOGGED_CMD;
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, reply_string, string_length);
		} else {
			write(pcontext->connection.sockd, reply_string, string_length);
		}
		return DISPATCH_CONTINUE;
	}
	return DISPATCH_SHOULD_CLOSE;
}

