#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include "nsp_types.h"

#define HANDLE_EXCHANGE_NSP				1

/* bitmap NspiBind flags */
#define FLAG_ANONYMOUSLOGIN				0x00000020

/* bitmap NspiQueryRows flags */
#define FLAG_SKIPOBJECTS				0x00000001
#define FLAG_EPHID						0x00000002

/* bitmap NspiGetSpecialTable flags */
#define FLAG_CREATIONTEMPLATES			0x00000002
#define FLAG_UNICODESTRINGS				0x00000004

/* bitmap NspiQueryColumns flags */
#define FLAG_UNICODEPROPTYPES			0x80000000

#define CODEPAGE_UNICODE				0x04B0

/* PROP_TAG_CONTAINERFLAGS values */
#define	AB_RECIPIENTS					0x1
#define	AB_SUBCONTAINERS				0x2
#define	AB_UNMODIFIABLE					0x8

/* positioning of MID */
#define MID_BEGINNING_OF_TABLE			0x0
#define MID_CURRENT						0x1
#define MID_END_OF_TABLE				0x2

/* resolve types of names */
#define MID_UNRESOLVED					0x0
#define MID_AMBIGUOUS					0x1
#define MID_RESOLVED					0x2

#define SORT_TYPE_DISPLAYNAME			0x00000000
#define SORT_TYPE_PHONETICDISPLAYNAME	0x00000003
#define SORT_TYPE_DISPLAYNAME_RO		0x000003E8
#define SORT_TYPE_DISPLAYNAME_W			0x000003E9

#define EPOCH_DIFF 						11644473600LL

extern const uint8_t *common_util_get_nspi_guid();
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
