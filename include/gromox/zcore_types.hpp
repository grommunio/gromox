#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>

enum class zs_objtype : uint8_t {
	/* Zend resource type groups */
	root = 0, table, message, attach, abcont, folder, session, addrbook,
	store, mailuser, distlist, profproperty, advisesink, icsdownctx,
	icsupctx, oneoff, invalid = 255,
};

struct NEWMAIL_ZNOTIFICATION {
	BINARY entryid;
	BINARY parentid;
	uint32_t flags; /* unicode or not */
	char *message_class;
	uint32_t message_flags;
};

struct OBJECT_ZNOTIFICATION {
	mapi_object_type object_type;
	BINARY *pentryid;
	BINARY *pparentid;
	BINARY *pold_entryid;
	BINARY *pold_parentid;
	PROPTAG_ARRAY *pproptags;
};

struct ZNOTIFICATION {
	uint32_t event_type;
	void *pnotification_data; /* NEWMAIL_ZNOTIFICATION or OBJECT_ZNOTIFICATION */
};

struct ZNOTIFICATION_ARRAY {
	uint16_t count;
	ZNOTIFICATION **ppnotification;
	I_BEGIN_END(ppnotification, count);
};

/* reply or OOF action */
struct ZREPLY_ACTION {
	BINARY message_eid; /* zarafa specific */
	GUID template_guid;
};

struct ZMOVECOPY_ACTION {
	BINARY store_eid; /* zarafa specific */
	BINARY folder_eid; /* zarafa specific */
};
