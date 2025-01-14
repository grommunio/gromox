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
extern int cmdh_helo(std::string_view, smtp_context &);
extern int cmdh_lhlo(std::string_view, smtp_context &);
extern int cmdh_ehlo(std::string_view, smtp_context &);
extern int cmdh_starttls(std::string_view, smtp_context &);
extern int cmdh_auth(std::string_view, smtp_context &);
extern int cmdh_mail(std::string_view, smtp_context &);
extern int cmdh_rcpt(std::string_view, smtp_context &);
extern int cmdh_data(std::string_view, smtp_context &);
extern int cmdh_quit(std::string_view, smtp_context &);
extern int cmdh_rset(std::string_view, smtp_context &);
extern int cmdh_noop(std::string_view, smtp_context &);
extern int cmdh_help(std::string_view, smtp_context &);
extern int cmdh_vrfy(std::string_view, smtp_context &);
extern int cmdh_etrn(std::string_view, smtp_context &);
extern int cmdh_else(std::string_view, smtp_context &);
