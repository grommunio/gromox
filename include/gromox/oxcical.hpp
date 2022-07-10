#pragma once
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>

struct ical;
extern GX_EXPORT MESSAGE_CONTENT *oxcical_import(const char *zone, const ical *, EXT_BUFFER_ALLOC, GET_PROPIDS, USERNAME_TO_ENTRYID);
extern GX_EXPORT BOOL oxcical_export(const MESSAGE_CONTENT *, ical *, EXT_BUFFER_ALLOC, GET_PROPIDS, ENTRYID_TO_USERNAME, ESSDN_TO_USERNAME, LCID_TO_LTAG);
