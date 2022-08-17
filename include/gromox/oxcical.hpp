#pragma once
#include <memory>
#include <vector>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>

struct ical;
namespace gromox {
extern bool g_oxcical_allday_ymd;
}
extern GX_EXPORT ec_error_t oxcical_import_multi(const char *zone, const ical &, EXT_BUFFER_ALLOC, GET_PROPIDS, USERNAME_TO_ENTRYID, std::vector<std::unique_ptr<MESSAGE_CONTENT, gromox::mc_delete>> &);
extern GX_EXPORT std::unique_ptr<MESSAGE_CONTENT, gromox::mc_delete> oxcical_import_single(const char *zone, const ical &, EXT_BUFFER_ALLOC, GET_PROPIDS, USERNAME_TO_ENTRYID);
extern GX_EXPORT BOOL oxcical_export(const MESSAGE_CONTENT *, ical &, EXT_BUFFER_ALLOC, GET_PROPIDS, ENTRYID_TO_USERNAME, ESSDN_TO_USERNAME);
