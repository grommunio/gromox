#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include "nsp_types.h"
#define HANDLE_EXCHANGE_NSP				1

/* bitmap NspiBind flags */
enum {
	fAnonymousLogin = 0x20U,
};

/* bitmap NspiQueryRows flags */
enum {
	fSkipObjects = 0x1U,
	fEphID = 0x2U,
};

/* bitmap NspiGetSpecialTable flags */
enum {
	NspiAddressCreationTemplates = 0x2U,
	NspiUnicodeStrings = 0x4U,
};

/* bitmap NspiQueryColumns flags */
enum {
	NspiUnicodeProptypes = 0x80000000U,
};

enum {
	CP_WINUNICODE = 1200,
};

/* PR_CONTAINER_FLAGS values */
#define	AB_RECIPIENTS					0x1
#define	AB_SUBCONTAINERS				0x2
#define	AB_UNMODIFIABLE					0x8

/* positioning of MID */
enum {
	MID_BEGINNING_OF_TABLE = STREAM_SEEK_SET,
	MID_CURRENT = STREAM_SEEK_CUR,
	MID_END_OF_TABLE = STREAM_SEEK_END,
};

/* resolve types of names */
#define MID_UNRESOLVED					0x0
#define MID_AMBIGUOUS					0x1
#define MID_RESOLVED					0x2

enum {
	SortTypeDisplayName = 0,
	SortTypePhoneticDisplayName = 0x3,
	SortTypeDisplayName_RO = 0x3e8,
	SortTypeDisplayName_W = 0x3e9,
};

#define EPOCH_DIFF 						11644473600LL

extern GUID common_util_get_server_guid();
void common_util_day_to_filetime(const char *day, FILETIME *pftime);
int common_util_from_utf8(uint32_t codepage,
	const char *src, char *dst, size_t len);
int common_util_to_utf8(uint32_t codepage,
	const char *src, char *dst, size_t len);
void common_util_guid_to_binary(GUID *pguid, BINARY *pbin);
void common_util_set_ephemeralentryid(uint32_t display_type,
	uint32_t minid, EPHEMERAL_ENTRYID *pephid);
BOOL common_util_set_permanententryid(uint32_t display_type,
	const GUID *pobj_guid, const char *pdn, PERMANENT_ENTRYID *ppermeid);
BOOL common_util_permanent_entryid_to_binary(
	const PERMANENT_ENTRYID *ppermeid, BINARY *pbin);
BOOL common_util_ephemeral_entryid_to_binary(
	const EPHEMERAL_ENTRYID *pephid, BINARY *pbin);
extern NSP_ROWSET *common_util_proprowset_init();
NSP_PROPROW* common_util_proprowset_enlarge(NSP_ROWSET *pset);
NSP_PROPROW* common_util_propertyrow_init(NSP_PROPROW *prow);
PROPERTY_VALUE* common_util_propertyrow_enlarge(NSP_PROPROW *prow);
extern LPROPTAG_ARRAY *common_util_proptagarray_init();
uint32_t* common_util_proptagarray_enlarge(LPROPTAG_ARRAY *pproptags);
BOOL common_util_load_file(const char *path, BINARY *pbin);
extern int common_util_run();
