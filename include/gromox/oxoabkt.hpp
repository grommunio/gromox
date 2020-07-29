#pragma once
#include <string>
#include <gromox/defs.h>
namespace gromox {
extern GX_EXPORT std::string abkt_tojson(const std::string &bin, unsigned int cpid);
extern GX_EXPORT std::string abkt_tobinary(const std::string &json, unsigned int cpid, bool dogap = false);
}
