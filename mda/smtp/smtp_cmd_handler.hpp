#pragma once

/* enumeration for the return value of smtp_parser_dispatch_cmd */
enum{
	DISPATCH_CONTINUE = 0,
	DISPATCH_SHOULD_CLOSE = 1U << 24,
	DISPATCH_BREAK = 1U << 25,

	DISPATCH_VALMASK = 0x0000FFFFU,
	DISPATCH_ACTMASK = 0xFF000000U,
};

struct smtp_context;
using SMTP_CONTEXT = smtp_context;

int smtp_cmd_handler_helo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
extern int smtp_cmd_handler_lhlo(const char *line, int len, SMTP_CONTEXT *);
int smtp_cmd_handler_ehlo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_starttls(const char *cmd_line, int line_length,
	SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_auth(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_mail(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_rcpt(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_data(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_quit(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_rset(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_noop(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_help(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_vrfy(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_etrn(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int smtp_cmd_handler_else(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
