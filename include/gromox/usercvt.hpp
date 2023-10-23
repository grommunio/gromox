#pragma once
#include <functional>
#include <string>
#include <gromox/defs.h>
#include <gromox/mapierr.hpp>

struct BINARY;

namespace gromox {

using cvt_id2user = std::function<ec_error_t(int, std::string &)>;
extern GX_EXPORT ec_error_t cvt_essdn_to_username(const char *emaddr, const char *org, cvt_id2user, std::string &);
extern GX_EXPORT ec_error_t cvt_essdn_to_username(const char *emaddr, const char *org, cvt_id2user, char *, size_t);
extern GX_EXPORT ec_error_t cvt_genaddr_to_smtpaddr(const char *atype, const char *emaddr, const char *org, cvt_id2user, std::string &);
extern GX_EXPORT ec_error_t cvt_genaddr_to_smtpaddr(const char *atype, const char *emaddr, const char *org, cvt_id2user, char *, size_t);
extern GX_EXPORT bool emsab_to_email(EXT_PULL &, const char *org, cvt_id2user, char *addr, size_t adsize);

}
