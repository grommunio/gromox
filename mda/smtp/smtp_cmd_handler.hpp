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

int cmdh_helo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
extern int cmdh_lhlo(const char *line, int len, SMTP_CONTEXT *);
int cmdh_ehlo(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_starttls(const char *cmd_line, int line_length,
	SMTP_CONTEXT *pcontext);
int cmdh_auth(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_mail(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_rcpt(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_data(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_quit(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_rset(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_noop(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_help(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_vrfy(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_etrn(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
int cmdh_else(const char* cmd_line, int line_length,
    SMTP_CONTEXT *pcontext);
