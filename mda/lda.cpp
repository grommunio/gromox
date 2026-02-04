// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025–2026 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <vmime/mailbox.hpp>
#include <vmime/mailboxList.hpp>
#include <vmime/message.hpp>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

using namespace gromox;

enum class command_protocol {
	lmtp, smtp,
};

/**
 * @rdcmd:     reading LMTP/SMTP commands
 * @data:      reading message lines
 * @data_done: DATA entry phase has concluded
 * @reset:     clear buffers and go back to rdcmd
 * @end:       terminate connection/program
 */
enum class protocol_state {
	rdcmd, data, data_done, reset, end,
};

enum class rcpt_status {
	neg_rcpt,          /* emit negative RCPT line */
	ok_rcpt,           /* emit positive RCPT line */
	group_head,        /* don't deliver anything, emit positive RCPT line */
	member_pending,    /* delivery not attempted, undecided */
	member_ok,         /* deliver, don't emit RCPT line */
	member_failed,     /* delivery failed, emit no RCPT, maybe emit DSN */
};

struct input_recipient {
	std::string addr;
	enum rcpt_status status = rcpt_status::neg_rcpt;
};

/**
 * @cmd_prot:  Chosen command protocol
 * @hello_dom: Originator of LHLO command
 * @have_from: LMTP command phase has seen a FROM command
 * @data_sol:  DATA phase most recently has seen a LF
 * @envl_from: Envelope-From/Return-Path
 * @envl_to:   All recipients given with RCPT, later filtered down
 * @envl_size: Approximate mail size client told us
 * @content:   Accrued message buffer for DATA phase
 * @vmail:     VMIME-parse of @content
 */
struct lmtp_context {
	enum command_protocol cmd_prot = command_protocol::lmtp;
	std::string hello_domain;
	bool have_from = false, data_startofline = false;
	vmime::mailbox envl_from;
	std::vector<input_recipient> envl_to;
	unsigned long envl_size = 0;
	std::string content;
	vmime::message vmail;
};

static char *opt_config_file;
static unsigned long g_max_mail_size = 64U << 30, g_linebuffer_size = 8192;
static std::string g_our_hostname;

static void rsp_data_ok() { printf("354 Go\n"); }
static void rsp_quit_ok() { printf("221 2.0.0 CU\n"); }
static void rsp_noop_ok() { printf("250 2.0.0 Ok\n"); }
static void rsp_mail_ok() { printf("250 2.1.0 Ok\n"); }
static void rsp_mail_size() { printf("552 5.3.4 Too large\n"); }
static void rsp_rcpt_ok() { printf("250 2.1.5 Ok\n"); }
static void rsp_rcpt_unknown() { printf("550 x.x.x User unknown\n"); }
static void rsp_rcpt_order() { printf("503 5.5.1 Command sequence order\n"); }
static void rsp_rcpt_syntax() { printf("501 5.1.3 TO syntax error\n"); }
static void rsp_data_norcpt() { printf("554 5.5.1 No recipients\n"); }
static void rsp_unknown_cmd() { printf("500 5.5.2 Command unknown\n"); }
static void rsp_no_cmd() { printf("500 5.5.2 Syntax error\n"); }
static void rsp_syntax_err() { printf("501 5.5.4 Syntax error\n"); }

static void cmd_xhlo(lmtp_context &ctx, std::vector<std::string> &argv)
{
	if (argv.size() >= 2)
		ctx.hello_domain = std::move(argv[1]);
	printf("250-%s\n", g_our_hostname.c_str());
	printf("250-PIPELINING\n"); /* take all cmds without sync */
	printf("250-SIZE %lu\n", g_max_mail_size); /* convey maxsize, and client can inform us of expected size */
	printf("250-8BITMIME\n");
	printf("250 SMTPUTF8\n");
}

static void cmd_mail(lmtp_context &ctx, std::vector<std::string> &argv)
{
	if (argv.size() < 2 || strncasecmp(argv[1].c_str(), "FROM:", 5) != 0)
		return rsp_syntax_err();
	if (argv[1][6] == '<') {
		if (argv[1].back() != '>')
			return rsp_syntax_err();
	} else {
		ctx.envl_from = vmime::mailbox(&argv[1].c_str()[5]);
	}
	/* FROM:<> is legit */
	ctx.have_from = true;

	for (size_t argc = 2; argc < argv.size(); ++argc) {
		if (strncasecmp(argv[argc].c_str(), "SIZE=", 5) == 0) {
			ctx.envl_size = strtoul(&argv[argc].c_str()[5], nullptr, 0);
			if (g_max_mail_size > 0 && ctx.envl_size > g_max_mail_size)
				return rsp_mail_size();
		}
	}
	return rsp_mail_ok();
}

static void cmd_rcpt(lmtp_context &ctx, std::vector<std::string> &argv)
{
	if (!ctx.have_from)
		return rsp_rcpt_order();
	else if (argv.size() < 2 || strncasecmp(argv[1].c_str(), "TO:", 3) != 0)
		return rsp_syntax_err();

	input_recipient r;
	vmime::mailbox vaddr;
	if (argv[1][3] == '<') {
		if (argv[1].back() != '>')
			return rsp_syntax_err();
		argv[1].pop_back();
		r.addr = argv[1].substr(3);
		vaddr  = vmime::mailbox(r.addr);
	} else {
		r.addr = argv[1].substr(3);
		vaddr  = vmime::mailbox(r.addr);
	}
	if (vaddr.isEmpty())
		return rsp_rcpt_syntax();

	/* ALIAS RESOLUTION */
	if (mysql_adaptor_mda_alias_resolve(r.addr) != 0)
		return rsp_rcpt_unknown();

	/* GROUP EXPANSION */
	std::vector<std::string> exp;
	if (mysql_adaptor_mda_group_expand(r.addr, exp) != 0)
		return rsp_rcpt_unknown();
	if (exp.size() == 1 && exp[1] == r.addr) {
		/* Not a group */
		ctx.envl_to.emplace_back(std::move(r));
	} else {
		/* Expansion complete */
		r.status = rcpt_status::group_head;
		ctx.envl_to.emplace_back(std::move(r));
		for (auto &&member_addr : std::move(exp))
			ctx.envl_to.emplace_back(std::move(member_addr), rcpt_status::member_pending);
	}
	return rsp_rcpt_ok();
}

static protocol_state cmd_data(lmtp_context &ctx, std::vector<std::string> &argv)
{
	if (ctx.envl_to.empty()) {
		rsp_data_norcpt();
		return protocol_state::rdcmd;
	}
	rsp_data_ok();
	return protocol_state::data;
}

static protocol_state read_command(lmtp_context &ctx, FILE *cin)
{
	auto input_buf  = std::make_unique<char[]>(g_linebuffer_size);
	auto input_line = input_buf.get();
	if (fgets(input_line, g_linebuffer_size, cin) == nullptr)
		return protocol_state::end;
	if (strpbrk(input_line, "\n\r") == nullptr) {
		rsp_syntax_err();
		return protocol_state::rdcmd;
	}
	HX_chomp(input_line);
	auto argv = gx_split_ws(input_line);
	if (argv.size() < 1) {
		rsp_no_cmd();
	} else if (strcasecmp(argv[0].c_str(), "QUIT") == 0) {
		rsp_quit_ok();
		return protocol_state::end;
	} else if (strcasecmp(argv[0].c_str(), "NOOP") == 0) {
		rsp_noop_ok();
	} else if (strcasecmp(argv[0].c_str(), "LHLO") == 0) {
		ctx.cmd_prot = command_protocol::lmtp;
		cmd_xhlo(ctx, argv);
	} else if (strcasecmp(argv[0].c_str(), "EHLO") == 0 ||
	    strcasecmp(argv[0].c_str(), "HELO") == 0) {
		ctx.cmd_prot = command_protocol::smtp;
		cmd_xhlo(ctx, argv);
	} else if (strcasecmp(argv[0].c_str(), "MAIL") == 0) {
		cmd_mail(ctx, argv);
	} else if (strcasecmp(argv[0].c_str(), "RCPT") == 0) {
		cmd_rcpt(ctx, argv);
	} else if (strcasecmp(argv[0].c_str(), "DATA") == 0) {
		return cmd_data(ctx, argv);
	} else {
		rsp_unknown_cmd();
	}
	return protocol_state::rdcmd;
}

static protocol_state read_data(lmtp_context &ctx, FILE *cin)
{
	auto input_buf  = std::make_unique<char[]>(g_linebuffer_size);
	auto input_line = input_buf.get();
	if (fgets(input_line, g_linebuffer_size, stdin) == nullptr)
		return protocol_state::end;
	auto line_len = strlen(input_line);

	if (ctx.content.size() >= ULONG_MAX - line_len /*content+input>=MAX*/ ||
	    ctx.content.size() + line_len >= g_max_mail_size) {
		rsp_mail_size();
		return protocol_state::end;
	}
	if (ctx.data_startofline && *input_line == '.') {
		++input_line;
		--line_len;
	}
	ctx.content += std::string_view(input_line, line_len);
	ctx.data_startofline = line_len > 0 && input_line[line_len-1] != '\n';
	return protocol_state::data;
}

static protocol_state finalize_data(lmtp_context &ctx)
{
	auto vpctx = vmail_default_parsectx();
	ctx.vmail.parse(vpctx, ctx.content);
	ctx.content = {};

	//local processing
	//printf("250 2.0.0 Ok\n"); SMTP
	return protocol_state::reset;
}

static int process()
{
	printf("220 %s LMTP\n", g_our_hostname.c_str());

	lmtp_context ctx;
	protocol_state state = protocol_state::rdcmd;

	while (state != protocol_state::end) {
		if (state == protocol_state::rdcmd) {
			state = read_command(ctx, stdin);
		} else if (state == protocol_state::data) {
			state = read_data(ctx, stdin);
		} else if (state == protocol_state::data_done) {
			finalize_data(ctx);
		} else if (state == protocol_state::reset) {
			ctx = {};
			state = protocol_state::rdcmd;
		}
	}
	return 0;
}

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"lda_max_mail_size", "64M", CFG_SIZE},
	CFG_TABLE_END,
};

static constexpr HXoption g_options_table[] = {
	{{}, 'c', HXTYPE_STRP, &opt_config_file, {}, {}, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr generic_module g_dfl_svc_plugins[] = {
	{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor},
};

int main(int argc, char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt6(g_options_table, argc, argv, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cfg = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && cfg == nullptr) {
		mlog(LV_ERR, "%s: %s", opt_config_file, strerror(errno));
		return EXIT_FAILURE;
	}
	if (cfg == nullptr)
		return EXIT_FAILURE; /* permission error */

	auto str = cfg->get_value("host_id");
	if (str != nullptr) {
		g_our_hostname = str;
	} else {
		auto ret = canonical_hostname(g_our_hostname);
		if (ret != 0)
			return EXIT_FAILURE;
	}
	g_max_mail_size = cfg->get_ll("lda_max_mail_size");
	service_init({cfg, g_dfl_svc_plugins, 0, "lda"});
	auto cl_0 = HX::make_scope_exit(service_stop);
	if (switch_user_exec(*cfg, argv) != 0)
		return EXIT_FAILURE;
	if (service_run() != 0) {
		mlog(LV_ERR, "system: failed to run services");
		return EXIT_FAILURE;
	}
	setup_utf8_locale();
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init();
	auto ret = process();
	if (ret != 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
