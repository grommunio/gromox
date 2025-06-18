#pragma once

/*
 * Override HX_getopt_help_cb because it calls exit(0), which is really bad for
 * a library to do. The more so when you have a static deinitialization order
 * fiasco going on.
 */
#define MBOP_AUTOHELP \
	{"help", '?', HXTYPE_XHELP, {}, {}, mbop_help_cb, 0, "Show this help message"}, \
	{"usage", 0, HXTYPE_NONE, {}, {}, mbop_usage_cb, 0, "Display brief usage message"}

using LLU = unsigned long long;

static constexpr int EXIT_PARAM = 2;

namespace cgkreset { extern int main(int, char **); }
namespace delmsg { extern int main(int, char **); }
namespace emptyfld { extern int main(int, char **); }
namespace foreach_wrap { extern int main(int, char **); }
namespace getfreebusy { extern int main(int, char **); }
namespace purgesoftdel { extern int main(int, char **); }
namespace set_locale { extern int main(int, char **); }

namespace global {

extern void command_overview();
extern int cmd_parser(int, char **);

extern char *g_arg_username, *g_arg_userdir;
extern unsigned int g_continuous_mode;

}

extern void mbop_help_cb(const struct HXoptcb *);
extern void mbop_usage_cb(const struct HXoptcb *);
extern void delcount(eid_t fid, uint32_t *delc, uint32_t *fldc);

extern bool g_exit_after_optparse;
extern const struct HXoption empty_options_table[];
