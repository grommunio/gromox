#pragma once
#include "imap_parser.h"

/* enumeration for the return value of imap_parser_dispatch_cmd */
enum{
	DISPATCH_CONTINUE,
	DISPATCH_SHOULD_CLOSE = 1U << 24,
	DISPATCH_BREAK = 1U << 25,

	DISPATCH_VALMASK = 0x0000FFFFU,
	DISPATCH_TAG     = 0x00800000U,
	DISPATCH_ACTMASK = 0xFF000000U,
};

void imap_cmd_parser_clsfld(IMAP_CONTEXT *pcontext);
int imap_cmd_parser_capability(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_id(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_noop(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_logout(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_starttls(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_authenticate(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_username(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_password(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_login(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_idle(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_select(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_examine(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_create(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_delete(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_rename(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_subscribe(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_unsubscribe(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_list(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_xlist(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_lsub(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_status(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_append(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_append_begin(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_append_end(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_check(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_close(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_expunge(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_unselect(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_search(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_fetch(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_store(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_copy(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_uid_search(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_uid_fetch(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_uid_store(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_uid_copy(int argc, char **argv, IMAP_CONTEXT *pcontext);
int imap_cmd_parser_uid_expunge(int argc, char **argv, IMAP_CONTEXT *pcontext);
extern int imap_cmd_parser_dval(int argc, char **argv, IMAP_CONTEXT *, int res);
