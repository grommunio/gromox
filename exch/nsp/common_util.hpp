#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/proc_common.h>
#include "nsp_types.hpp"
#define HANDLE_EXCHANGE_NSP				1

DECLARE_PROC_API(nsp, extern);
using namespace nsp;
#define ZZNDR_NS nsp
#include <gromox/zz_ndr_stack.hpp>

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

/* PR_CONTAINER_FLAGS values */
#define	AB_RECIPIENTS					0x1
#define	AB_SUBCONTAINERS				0x2
#define	AB_UNMODIFIABLE					0x8

enum {
	SortTypeDisplayName = 0,
	SortTypePhoneticDisplayName = 0x3,
	SortTypeDisplayName_RO = 0x3e8,
	SortTypeDisplayName_W = 0x3e9,
};

extern GUID common_util_get_server_guid();
void common_util_day_to_filetime(const char *str, FILETIME *pftime);
extern int cu_utf8_to_mb(cpid_t, const char *src, char *dst, size_t len);
extern int cu_mb_to_utf8(cpid_t, const char *src, char *dst, size_t len);
void common_util_set_ephemeralentryid(uint32_t display_type,
	uint32_t minid, EPHEMERAL_ENTRYID *pephid);
BOOL common_util_set_permanententryid(uint32_t display_type, const GUID *in, const char *dn, EMSAB_ENTRYID *out);
BOOL common_util_permanent_entryid_to_binary(const EMSAB_ENTRYID *, BINARY *);
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

extern BOOL (*get_named_propids)(const char *dir, BOOL create, const PROPNAME_ARRAY *, PROPID_ARRAY *);
extern BOOL (*get_store_properties)(const char *dir, cpid_t, const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
