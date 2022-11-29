#pragma once
#include <string_view>
#include <gromox/defs.h>
namespace gromox {
extern GX_EXPORT std::string abkt_tojson(std::string_view bin, unsigned int cpid);
extern GX_EXPORT std::string abkt_tobinary(std::string_view json, unsigned int cpid, bool dogap = false);
}
