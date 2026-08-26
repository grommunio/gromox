#pragma once
#include <cstdio>
#include "genimport.hpp"

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
namespace movemsg { extern int main(int, char **); }
namespace emptyfld { extern int main(int, char **); }
namespace foreach_wrap { extern int main(int, char **); }
namespace getfreebusy { extern int main(int, char **); }
namespace msgcopy { extern int main(int, char **); }
namespace purgesoftdel { extern int main(int, char **); }
namespace set_locale { extern int main(int, char **); }
namespace sync_midb { extern int main(int, char **); }
namespace addrxlat { extern int main(int, char **, const char *addrtype); }

namespace global {

extern void command_overview();
extern int cmd_parser(int, char **);

extern const char *g_arg_username, *g_arg_userdir;
extern unsigned int g_continuous_mode, g_verbose_mode, g_command_num;

}

/*
 * Resolve a MNID_STRING named property in the store being operated on.
 * Returns ENOENT when the store does not have the name. With @create set that
 * can only mean its named-property table is full, since get_named_propids
 * downgrades b_create silently in that case and reports propid 0 while still
 * succeeding.
 */
extern gromox::errno_t resolvename(const GUID &, const char *name, bool create, uint16_t *out);

extern ec_error_t select_contents_from_folder(eid_t, unsigned int flags, const RESTRICTION *, std::vector<eid_t> &);
extern ec_error_t select_hierarchy(eid_t, unsigned int flags, std::vector<eid_t> &);

template<typename... Args> int mbop_fprintf(FILE *f, Args &&...args)
{
	if (global::g_verbose_mode)
		fprintf(stderr, "%s [cmd %d]: ", g_storedir, global::g_command_num);
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
#endif
	return fprintf(f, args...);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
}

extern void mbop_help_cb(const struct HXoptcb *);
extern void mbop_usage_cb(const struct HXoptcb *);
extern void delcount(eid_t fid, uint32_t *delc, uint32_t *fldc);

extern bool g_exit_after_optparse;
struct HXoption;
extern const struct HXoption empty_options_table[];
