#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <gromox/mapidefs.h>

enum class zs_objtype : uint8_t {
	/* Zend resource type groups */
	root = 0, table, message, attach, abcont, folder, session, addrbook,
	store, mailuser, distlist, profproperty, advisesink, icsdownctx,
	icsupctx, oneoff, invalid = 255,
};

struct NEWMAIL_ZNOTIFICATION {
	std::string entryid, parentid, message_class;
	uint32_t flags = 0; /* unicode or not */
	uint32_t message_flags = 0;
};

struct OBJECT_ZNOTIFICATION {
	mapi_object_type object_type;
	std::optional<std::string> pentryid, pparentid, pold_entryid, pold_parentid;
	std::optional<std::vector<gromox::proptag_t>> pproptags;
};

struct ZNOTIFICATION {
	ZNOTIFICATION() = default;
	ZNOTIFICATION(ZNOTIFICATION &&);
	~ZNOTIFICATION() { clear(); }
	ZNOTIFICATION &operator=(ZNOTIFICATION &&);
	void clear();

	uint32_t event_type = 0;
	void *pnotification_data = nullptr; /* NEWMAIL_ZNOTIFICATION or OBJECT_ZNOTIFICATION */
};

using ZNOTIFICATION_ARRAY = std::vector<ZNOTIFICATION>;

/* reply or OOF action */
struct ZREPLY_ACTION {
	BINARY message_eid; /* zarafa specific */
	GUID template_guid;
};

struct ZMOVECOPY_ACTION {
	BINARY store_eid; /* zarafa specific */
	BINARY folder_eid; /* zarafa specific */
};
