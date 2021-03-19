#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>

struct SVREID {
	BINARY *pbin;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t instance;
};

struct MOVECOPY_ACTION {
	BINARY store_eid; /* zarafa specific */
	BINARY folder_eid; /* zarafa specific */
};

/* reply or OOF action */
struct REPLY_ACTION {
	BINARY message_eid; /* zarafa specific */
	GUID template_guid;
};

struct RECIPIENT_BLOCK {
	uint8_t reserved;
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
};

struct FORWARDDELEGATE_ACTION {
	uint16_t count;
	RECIPIENT_BLOCK *pblock;
};

#define ACTION_TYPE_OP_MOVE							0x1
#define ACTION_TYPE_OP_COPY							0x2
#define ACTION_TYPE_OP_REPLY						0x3
#define ACTION_TYPE_OP_OOF_REPLY					0x4
#define ACTION_TYPE_OP_DEFER_ACTION					0x5
#define ACTION_TYPE_OP_BOUNCE						0x6
#define ACTION_TYPE_OP_FORWARD						0x7
#define ACTION_TYPE_OP_DELEGATE						0x8
#define ACTION_TYPE_OP_TAG							0x9
#define ACTION_TYPE_OP_DELETE						0xA
#define ACTION_TYPE_OP_MARK_AS_READ					0xB

struct ACTION_BLOCK {
	uint16_t length;
	uint8_t type;
	uint32_t flavor;
	uint32_t flags;
	void *pdata;
};

struct RULE_ACTIONS {
	uint16_t count;
	ACTION_BLOCK *pblock;
};

#define CTRL_FLAG_BINHEX							0x0000
#define CTRL_FLAG_UUENCODE							0x0020
#define CTRL_FLAG_APPLESINGLE						0x0040
#define CTRL_FLAG_APPLEDOUBLE						0x0060

#define CTRL_FLAG_TEXTONLY							0x0006
#define CTRL_FLAG_HTMLONLY							0x000E
#define CTRL_FLAG_TEXTANDHTML						0x0016

#define CTRL_FLAG_NORICH							0x0001
#define CTRL_FLAG_UNICODE							0x8000
#define CTRL_FLAG_DONTLOOKUP						0x1000

struct ONEOFF_ENTRYID {
	uint32_t flags;
	 /* 81.2B.1F.A4.BE.A3.10.19.9D.6E.00.DD.01.0F.54.02 */
	uint8_t provider_uid[16];
	uint16_t version; /* should be 0x0000 */
	uint16_t ctrl_flags;
	char *pdisplay_name;
	char *paddress_type;
	char *pmail_address;
};

#define FOLDER_TYPE_GENERIC							1

#define SYNC_DELETES_FLAG_HARDDELETE				0x02

/* ---------------------- defined by zarafa ---------------------- */

#define STREAM_SEEK_SET								0
#define STREAM_SEEK_CUR								1
#define STREAM_SEEK_END								2

#define BOOKMARK_BEGINNING							0
#define BOOKMARK_CURRENT							1
#define BOOKMARK_END								2

#define MODRECIP_ADD								0x00000002
#define MODRECIP_MODIFY								0x00000004
#define MODRECIP_REMOVE								0x00000008

struct NEWMAIL_ZNOTIFICATION {
	BINARY entryid;
	BINARY parentid;
	uint32_t flags;
	char *message_class;
	uint32_t message_flags;
};

#define MAPI_TABLE									1
#define MAPI_MESSAGE								2
#define MAPI_ATTACHMENT								3
#define MAPI_ABCONT									4
#define MAPI_FOLDER									5
#define MAPI_SESSION								6
#define MAPI_ADDRESSBOOK							7
#define MAPI_STORE									8
#define MAPI_MAILUSER								9
#define MAPI_DISTLIST								10
#define MAPI_PROFPROPERTY							11
#define MAPI_ADVISESINK								12
#define MAPI_ICSDOWNCTX								13
#define MAPI_ICSUPCTX								14
#define MAPI_INVALID								255

#define ROOT_HANDLE									0
#define INVALID_HANDLE								0xFFFFFFFF

struct OBJECT_ZNOTIFICATION {
	uint32_t object_type;
	BINARY *pentryid;
	BINARY *pparentid;
	BINARY *pold_entryid;
	BINARY *pold_parentid;
	PROPTAG_ARRAY *pproptags;
};

#define EVENT_TYPE_NEWMAIL							0x00000002
#define EVENT_TYPE_OBJECTCREATED					0x00000004
#define EVENT_TYPE_OBJECTDELETED					0x00000008
#define EVENT_TYPE_OBJECTMODIFIED					0x00000010
#define EVENT_TYPE_OBJECTMOVED						0x00000020
#define EVENT_TYPE_OBJECTCOPIED						0x00000040
#define EVENT_TYPE_SEARCHCOMPLETE					0x00000080

struct ZNOTIFICATION {
	uint32_t event_type;
	void *pnotification_data; /* NEWMAIL_NOTIFICATION or OBJECT_NOTIFICATION */
};

struct ZNOTIFICATION_ARRAY {
	uint16_t count;
	ZNOTIFICATION **ppnotification;
};

struct RULE_LIST {
	uint16_t count;
	RULE_DATA *prule;
};

#define SYNC_NEW_MESSAGE							0x800
#define SYNC_SOFT_DELETE							0x01
#define ICS_TYPE_CONTENTS							1
#define ICS_TYPE_HIERARCHY							2
