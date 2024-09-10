#pragma once
#include <string>
#include <gromox/mapidefs.h>

namespace oxcmail {

extern gromox::errno_t bodyset_html(TPROPVAL_ARRAY &, std::string &&, const char *);
extern gromox::errno_t bodyset_plain(TPROPVAL_ARRAY &, std::string &&, const char *);
extern gromox::errno_t bodyset_enriched(TPROPVAL_ARRAY &, std::string &&, const char *);

}
