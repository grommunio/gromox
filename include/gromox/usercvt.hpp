#pragma once
#include <string>
#include <gromox/defs.h>
#include <gromox/mapierr.hpp>

struct BINARY;

namespace gromox {

using cvt_id2user = ec_error_t (*)(int, std::string &);
extern GX_EXPORT ec_error_t cvt_essdn_to_username(const char *emaddr, const char *org, cvt_id2user, std::string &);
extern GX_EXPORT ec_error_t cvt_essdn_to_username(const char *emaddr, const char *org, cvt_id2user, char *, size_t);

}
