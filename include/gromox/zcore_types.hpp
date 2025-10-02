#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>

enum class zs_objtype : uint8_t {
	/* Zend resource type groups */
	root = 0, table, message, attach, abcont, folder, session, addrbook,
	store, mailuser, distlist, profproperty, advisesink, icsdownctx,
	icsupctx, oneoff, invalid = 255,
};

struct GX_EXPORT ZNOTIFICATION {
	uint32_t event_type = 0;
	mapi_object_type object_type{};
	std::optional<std::string> pentryid, pparentid, pold_entryid, pold_parentid;
	std::optional<std::vector<gromox::proptag_t>> pproptags;

	/* if event_type == fnevNewMail, these are used too: */
	std::string message_class;
	uint32_t flags = 0; /* unicode or not */
	uint32_t message_flags = 0;
};

using ZNOTIFICATION_ARRAY = std::vector<ZNOTIFICATION>;

/* reply or OOF action */
struct GX_EXPORT ZREPLY_ACTION {
	BINARY message_eid; /* zarafa specific */
	GUID template_guid;
};

struct GX_EXPORT ZMOVECOPY_ACTION {
	BINARY store_eid; /* zarafa specific */
	BINARY folder_eid; /* zarafa specific */
};
