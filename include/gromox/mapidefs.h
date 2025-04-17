#pragma once
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <type_traits>
#include <gromox/defs.h>

namespace gromox {

using propid_t = uint16_t;
using proptype_t = uint16_t;
using proptag_t = uint32_t;
/* N.B.: PidLids are not propids (they are also 32-bit wide) */

/*
 * MS-DTYP §2.3.3 specifies it as unsigned; though, WinAPI functions
 * for FILETIME<>SYSTIME conversions only allow for year <30828 (~63 bits).
 */
#define TIME_FIXUP_CONSTANT_INT 11644473600LL
using mapitime_t = uint64_t;

}

#define PROP_ID(x) static_cast<gromox::propid_t>((x) >> 16)
#define PROP_TYPE(x) static_cast<gromox::proptype_t>((x) & 0xFFFF)
#define CHANGE_PROP_TYPE(tag, newtype) static_cast<gromox::proptag_t>(((tag) & ~0xFFFF) | (newtype))

/*
 * x|y yields an unsigned result if either x or y are unsigned.
 * x<<y yields unsigned only if x is unsigned.
 * All the while | and << only make *sense* in an unsigned _context_ anyway
 * (i.e. the operator should have returned unsigned all the time)
 */
#define PROP_TAG(type, tag) static_cast<gromox::proptag_t>((static_cast<uint32_t>(tag) << 16) | (type))
namespace {
enum {
	/*
	 * MAPI sucks, episode #17: INSIDE MAPI pg.36 and
	 * https://docs.microsoft.com/en-us/office/client-developer/outlook/mapi/property-types
	 * have a contradiction, saying PT_LONG is "signed or unsigned", yet
	 * also "This property type is the same as […] the OLE type VT_I4".
	 *
	 * MS-OAUT clearly distinguishes signed and unsigned types. MAPI shares
	 * the same enum values, and Exchange treats it as signed too during
	 * rop_sorttable.
	 */
	PT_UNSPECIFIED = 0x0000, /* VT_EMPTY, PtypUnspecified */
	PT_NULL = 0x0001, /* VT_NULL, PtypNull */
	PT_SHORT = 0x0002, /* VT_I2, PT_I2, PtypInteger16 */
	PT_LONG = 0x0003, /* VT_I4, PT_I4, PtypInteger32 */
	PT_FLOAT = 0x0004, /* VT_R4, PT_R4, PtypFloating32 */
	PT_DOUBLE = 0x0005, /* VT_R8, PT_R8, PtypFloating64 */
	PT_CURRENCY = 0x0006, /* VT_CY, PtypCurrency */
	PT_APPTIME = 0x0007, /* VT_DATE, PtypFloatingTime */
	PT_ERROR = 0x000A, /* VT_ERROR, PtypErrorCode */
	PT_BOOLEAN = 0x000B, /* VT_BOOL, PtypBoolean */
	PT_OBJECT = 0x000D, /* VT_UNKNOWN, PtypObject, PtypEmbeddedTable */
	// VT_I1 = 0x0010,
	// VT_UI1 = 0x0011,
	// VT_UI2 = 0x0012,
	// VT_UI4 = 0x0013,
	PT_I8 = 0x0014, /* VT_I8, PtypInteger64 */
	// VT_UI8 = 0x0015,
	PT_STRING8 = 0x001E, /* VT_LPSTR, PtypString8 */
	PT_UNICODE = 0x001F, /* VT_LPWSTR, PtypString */
	PT_GXI_STRING = 0x0f1e, /* Gromox-specific, internal */
	PT_SYSTIME = 0x0040, /* VT_FILETIME, PtypTime (signed) */
	PT_CLSID = 0x0048, /* VT_CLSID, PtypGuid */
	PT_SVREID = 0x00FB, /* PtypServerId; MS-OXCDATA extension */
	PT_SRESTRICTION = 0x00FD, /* PtypRestriction; edkmdb.h extension */
	PT_ACTIONS = 0x00FE, /* PtypRuleAction; edkmdb.h extension */
	PT_BINARY = 0x0102, /* PtypBinary */
	// PT_PTR = 0x0103, /* SPropValue docced extension; (SPropValue::Value.lpv has the file handle) */
	// PT_FILE_HANDLE = 0x0103, /* edkmdb.h extension; (SPropValue::Value.lpv has the file handle) */
	// PT_FILE_EA = 0x0104, /* edkmdb.h extension; (SPropValue::Value.bin has extended attribute data for locating the file) */
	// PT_VIRTUAL = 0x0105, /* edkmdb.h extension; (SPropValue::Value.bin has arbitrary data; store-internal; not externally visible) */
	PT_MV_SHORT = 0x1002, /* PT_MV_I2, PtypMultipleInteger16 */
	PT_MV_LONG = 0x1003, /* PT_MV_I4, PtypMultipleInteger32 */
	PT_MV_FLOAT = 0x1004, /* PT_MV_R4, PtypMultipleFloating32 */
	PT_MV_DOUBLE = 0x1005, /* PT_MV_R8, PtypMultipleFloating64 */
	PT_MV_CURRENCY = 0x1006, /* PT_MV_CURRENCY, PtypMultipleCurrency */
	PT_MV_APPTIME = 0x1007, /* PT_MV_APPTIME, PtypMultipleFloatingTime */
	PT_MV_I8 = 0x1014, /* PtypMultipleInteger64 */
	PT_MV_STRING8 = 0x101E, /* PtypMultipleString8 */
	PT_MV_UNICODE = 0x101F, /* PtypMultipleString */
	PT_MV_SYSTIME = 0x1040, /* PtypMultipleTime */
	PT_MV_CLSID = 0x1048, /* PtypMultipleGuid */
	PT_MV_BINARY = 0x1102, /* PtypMultipleBinary */
};
}

#include "mapitags.hpp"

enum {
	MV_FLAG = 0x1000, /* VT_VECTOR */
	MV_INSTANCE = 0x2000,
	MVI_FLAG = MV_FLAG | MV_INSTANCE,
	FXICS_CODEPAGE_FLAG = 0x8000U,
};

enum ACTTYPE {
	OP_MOVE = 0x1U,
	OP_COPY = 0x2U,
	OP_REPLY = 0x3U,
	OP_OOF_REPLY = 0x4U,
	OP_DEFER_ACTION = 0x5U,
	OP_BOUNCE = 0x6U,
	OP_FORWARD = 0x7U,
	OP_DELEGATE = 0x8U,
	OP_TAG = 0x9U,
	OP_DELETE = 0xaU,
	OP_MARK_AS_READ = 0xbU,
};

enum apptrecur_flags {
	ARO_SUBJECT          =   0x1U,
	ARO_MEETINGTYPE      =   0x2U,
	ARO_REMINDERDELTA    =   0x4U,
	ARO_REMINDER         =   0x8U,
	ARO_LOCATION         =  0x10U,
	ARO_BUSYSTATUS       =  0x20U,
	ARO_ATTACHMENT       =  0x40U,
	ARO_SUBTYPE          =  0x80U,
	ARO_APPTCOLOR        = 0x100U,
	ARO_EXCEPTIONAL_BODY = 0x200U,
};

enum attach_method {
	NO_ATTACHMENT = 0, /* afNone */
	ATTACH_BY_VALUE = 1, /* afByValue */
	ATTACH_BY_REFERENCE = 2, /* afByReference */
	ATTACH_BY_REF_RESOLVE = 3,
	ATTACH_BY_REF_ONLY = 4, /* afByReferenceOnly */
	ATTACH_EMBEDDED_MSG = 5, /* afEmbeddedMessage */
	ATTACH_OLE = 6, /* afStorage */
	ATTACH_BY_WEBREFERENCE = 7, /* afByWebReference */
};

enum { /* for PR_ATTACH_FLAGS */
	ATT_INVISIBLE_IN_HTML = 0x1U,
	ATT_INVISIBLE_IN_RTF  = 0x2U,
	ATT_MHTML_REF         = 0x4U,
};

enum { /* for PR_ATTACHMENT_FLAGS */
	afException = 0x2U, /* OXOCAL v20 §2.2.10.1.2 */
};

enum { /* for PR_AUTO_RESPONSE_SUPPRESS */
	AUTO_RESPONSE_SUPPRESS_DR        = 0x1U,
	AUTO_RESPONSE_SUPPRESS_NDR       = 0x2U,
	AUTO_RESPONSE_SUPPRESS_RN        = 0x4U,
	AUTO_RESPONSE_SUPPRESS_NRN       = 0x8U,
	AUTO_RESPONSE_SUPPRESS_OOF       = 0x10U,
	AUTO_RESPONSE_SUPPRESS_AUTOREPLY = 0x20U,
};

enum { /* bits for PidLidChangeHighlight */
	BIT_CH_START        = 0x1U,
	BIT_CH_END          = 0x2U,
	BIT_CH_RECUR        = 0x4U,
	BIT_CH_LOCATION     = 0x8U,
	BIT_CH_SUBJECT      = 0x10U,
	BIT_CH_REQATT       = 0x20U,
	BIT_CH_OPTATT       = 0x40U,
	BIT_CH_BODY         = 0x80U,
	BIT_CH_RESPONSE     = 0x200U,
	BIT_CH_ALLOWPROPOSE = 0x400U,
	BIT_CH_CNF          = 0x800U, /* deprecated since OXOCAL v0.1 */
	BIT_CH_REM          = 0x1000U, /* reserved since OXOCAL v0.1 */
	// 0x8000000 (bit 27) was reserved from OXOCAL v0.1 to v4.1,
	// 0x80000000 (bit 31) is reversed since OXOCAL v5.0.
};

enum class bm_relop : uint8_t {
	eqz = 0, nez,
};
#define BMR_EQZ bm_relop::eqz
#define BMR_NEZ bm_relop::nez

enum calendar_scale {
	/* 0x1..0xC,0x17 from winnls.h, the others from MS-OXOCAL v20 §2.2.1.44.1 pg 37 */
	CAL_DEFAULT = 0,
	CAL_GREGORIAN = 0x1,
	CAL_GREGORIAN_US = 0x2,
	CAL_JAPAN = 0x3,
	CAL_TAIWAN = 0x4,
	CAL_KOREA = 0x5,
	CAL_HIJRI = 0x6,
	CAL_THAI = 0x7,
	CAL_HEBREW = 0x8,
	CAL_GREGORIAN_ME_FRENCH = 0x9,
	CAL_GREGORIAN_ARABIC = 0xA,
	CAL_GREGORIAN_XLIT_ENGLISH = 0xB,
	CAL_GREGORIAN_XLIT_FRENCH = 0xC,
	CAL_LUNAR_JAPANESE = 0xE,
	CAL_CHINESE_LUNAR = 0xF,
	CAL_SAKA = 0x10,
	CAL_LUNAR_ETO_CHN = 0x11,
	CAL_LUNAR_ETO_KOR = 0x12,
	CAL_LUNAR_ETO_ROKUYOU = 0x13,
	CAL_LUNAR_KOREAN = 0x14,
	CAL_UMALQURA = 0x17,
};

enum {
	/* One-off entryid flags, MS-OXCDATA v17 §2.2.5.1 pg 25 */
	/* We have it modeled as 16-bit, EDK as 32-bit. */
	MAPI_ONE_OFF_NO_RICH_INFO = 0x01U, /* Disable TNEF, use MIME instead */
	ENCODING_PREFERENCE = 0x02U,
	ENCODING_MIME = 0x04U,
	BODY_ENCODING_HTML = 0x08U,
	BODY_ENCODING_TEXT_AND_HTML = 0x10U,
	MAC_ATTACH_ENCODING_BINHEX = 0x00U,
	MAC_ATTACH_ENCODING_UUENCODE = 0x20U,
	MAC_ATTACH_ENCODING_APPLESINGLE = 0x40U,
	MAC_ATTACH_ENCODING_APPLEDOUBLE = 0x60U,

	// 0x100, 0x200, 0x400, 0x800 reserved (P)
	OOP_DONTLOOKUP = 0x1000U,
	// 0x2000 and 0x4000 reserved (R part)
	MAPI_ONE_OFF_UNICODE = 0x8000U,

	CTRL_FLAG_TEXTONLY = ENCODING_MIME | ENCODING_PREFERENCE, /* 0x06 */
	CTRL_FLAG_HTMLONLY = BODY_ENCODING_HTML | ENCODING_MIME | ENCODING_PREFERENCE, /* 0x0E */
	CTRL_FLAG_TEXTANDHTML = BODY_ENCODING_TEXT_AND_HTML | ENCODING_MIME | ENCODING_PREFERENCE, /* 0x16 */
};

/*
 * The SQL.user_properties PR_DISPLAY_TYPE_EX value is just a hint,
 * and SQL.user_properties PR_DISPLAY_TYPE is ignored.
 * NSP/zcore decides what is actually emitted to clients as the value for
 * PR_DISPLAY_TYPE(_EX).
 */
enum display_type {
	/* Values for objects in content tables. */
	DT_MAILUSER = 0,
	DT_DISTLIST = 1,
	DT_FORUM = 2,
	DT_AGENT = 3,
	DT_ORGANIZATION = 4,
	DT_PRIVATE_DISTLIST = 5,
	DT_REMOTE_MAILUSER = 6,
	DT_ROOM = 7,
	DT_EQUIPMENT = 8,
	DT_SEC_DISTLIST = 9,

	DT_CONTAINER = 0x100,
	DT_TEMPLATE = 0x101,
	DT_ADDRESS_TEMPLATE = 0x102,
	DT_SEARCH = 0x200,

	/* Values for objects in AB hierarchy tables */
	DT_MODIFIABLE = 0x1 << 16,
	DT_GLOBAL = 0x2 << 16,
	DT_LOCAL = 0x3 << 16,
	DT_WAN = 0x4 << 16,
	DT_NOT_SPECIFIC = 0x5 << 16,

	/* Values for objects in folder hierarchy tables */
	DT_FOLDER = 1 << 24,
	DT_FOLDER_LINK = 1 << 25,
	DT_FOLDER_SPECIAL = 1 << 26,

	/* Flag-related things for PR_DISPLAY_TYPE_EX */
	DTE_FLAG_ACL_CAPABLE  = 0x40000000U,
	DTE_FLAG_REMOTE_VALID = 0x80000000U,
	DTE_MASK_REMOTE       = 0xFF00U,
	DTE_MASK_LOCAL        = 0xFFU,
};

enum {
	/* PR_CONTROL_FLAGS (PidTagControlFlags), MS-OXOABKT v14 §2.2.2.1.2 */
	_DT_NONE         = 0U, /* gromox-only */
	DT_MULTILINE     = 0x1U,
	DT_EDITABLE      = 0x2U,
	DT_REQUIRED      = 0x4U,
	DT_SET_IMMEDIATE = 0x8U,
	DT_PASSWORD_EDIT = 0x10U,
	DT_ACCEPT_DBCS   = 0x20U,
	DT_SET_SELECTION = 0x40U,
};

enum {
	/* PR_CONTROL_TYPE (PidTagControlType) */
	DTCT_LABEL = 0x0,
	DTCT_EDIT = 0x1,
	DTCT_LBX = 0x2, /* listbox */
	DTCT_COMBOBOX = 0x3,
	DTCT_DDLBX = 0x4,
	DTCT_CHECKBOX = 0x5,
	DTCT_GROUPBOX = 0x6,
	DTCT_BUTTON = 0x7,
	DTCT_PAGE = 0x8,
	DTCT_RADIOBUTTON = 0x9,
	DTCT_MVLISTBOX  = 0xb,
	DTCT_MVDDLBX = 0xc, /* multi-value dropdown list box */
	_DTCT_NONE = 0xff, /* (sentinel value for gromox) */
};

enum mapi_folder_type : uint32_t {
	FOLDER_ROOT = 0,
	FOLDER_GENERIC = 1,
	FOLDER_SEARCH = 2,
};

enum { /* for PR_FLAG_STATUS */
	followupComplete = 0x1U,
	followupFlagged = 0x2U,
};

enum { /* for PR_FOLLOWUP_ICON */
	olNoFlagIcon = 0,
	olPurpleFlagIcon,
	olOrangeFlagIcon,
	olGreenFlagIcon,
	olYellowFlagIcon,
	olBlueFlagIcon,
	olRedFlagIcon,
};

enum { /* for PR_ICON_INDEX */
	MAIL_ICON_REPLIED = 0x105,
	MAIL_ICON_FORWARDED = 0x106,
};

enum mapi_importance {
	IMPORTANCE_LOW = 0,
	IMPORTANCE_NORMAL = 1,
	IMPORTANCE_HIGH = 2,
};

enum class mapi_resource_type : uint32_t {
	store_provider = 33,
	ab = 34,
	ab_provider = 35,
	transport_provider = 36,
	spooler = 37,
	profile_provider = 38,
	subsystem = 39,
	hook_provider = 40,
};
#define MAPI_STORE_PROVIDER     mapi_resource_type::store_provider
#define MAPI_AB                 mapi_resource_type::ab
#define MAPI_AB_PROVIDER        mapi_resource_type::ab_provider
#define MAPI_TRANSPORT_PROVIDER mapi_resource_type::transport_provider
#define MAPI_SPOOLER            mapi_resource_type::spooler
#define MAPI_PROFILE_PROVIDER   mapi_resource_type::profile_provider
#define MAPI_SUBSYSTEM          mapi_resource_type::subsystem
#define MAPI_HOOK_PROVIDER      mapi_resource_type::hook_provider

enum class mapi_object_type {
	store = 1,
	addrbook = 2,
	folder = 3,
	abcont = 4,
	message = 5,
	mailuser = 6,
	attach = 7,
	distlist = 8,
	profsect = 9,
	status = 10,
	session = 11,
	forminfo = 12,
};
#define MAPI_STORE    mapi_object_type::store
#define MAPI_ADDRBOOK mapi_object_type::addrbook
#define MAPI_FOLDER   mapi_object_type::folder
#define MAPI_ABCONT   mapi_object_type::abcont
#define MAPI_MESSAGE  mapi_object_type::message
#define MAPI_MAILUSER mapi_object_type::mailuser
#define MAPI_ATTACH   mapi_object_type::attach
#define MAPI_DISTLIST mapi_object_type::distlist
#define MAPI_PROFSECT mapi_object_type::profsect
#define MAPI_STATUS   mapi_object_type::status
#define MAPI_SESSION  mapi_object_type::session
#define MAPI_FORMINFO mapi_object_type::forminfo

enum mapi_recipient_type {
	MAPI_ORIG = 0U,
	MAPI_TO = 1U,
	MAPI_CC = 2U,
	MAPI_BCC = 3U,
	MAPI_P1        = 0x10000000U, /* bit 28: a need to resend */
	MAPI_SUBMITTED = 0x80000000U, /* bit 31: no need to resend */
};

enum mapi_sensitivity {
	SENSITIVITY_NONE = 0,
	SENSITIVITY_PERSONAL = 1,
	SENSITIVITY_PRIVATE = 2,
	SENSITIVITY_COMPANY_CONFIDENTIAL = 3,
};

enum { /* ENTRYID flags byte 0 */
	MAPI_X_EMSAB     = 0x04U,
	MAPI_NOTRESERVED = 0x08U,
	MAPI_NOW         = 0x10U,
	MAPI_THISSESSION = 0x20U,
	MAPI_NOTRECIP    = 0x40U,
	MAPI_SHORTTERM   = 0x80U,
};
enum { /* ENTRYID flags byte 1 */
	MAPI_COMPOUND = 0x80U,
};
#if 0
enum { /* ENTRYID flags byte 3 */
	ZC6_FAVORITE = 0x01U, // provider-specific extension, not exposed to MSMAPI32
};
#endif
enum {
	ENTRYID_TYPE_PERMANENT = 0U,
	ENTRYID_TYPE_EPHEMERAL = MAPI_SHORTTERM | MAPI_X_EMSAB | 0x03U, /* 0x87 */
};

enum {
	MNID_ID = 0,
	MNID_STRING = 1,
	KIND_NONE = 0xff,
};

enum {
	MODRECIP_ADD    = 0x2U,
	MODRECIP_MODIFY = 0x4U,
	MODRECIP_REMOVE = 0x8U,
};

enum {
	MSGFLAG_READ               = 0x1U, /* mfRead */
	MSGFLAG_UNMODIFIED         = 0x2U, /* mfUnmodified */
	MSGFLAG_SUBMITTED          = 0x4U, /* mfSubmitted */
	MSGFLAG_UNSENT             = 0x8U,
	MSGFLAG_HASATTACH          = 0x10U, /* mfHasAttach */
	MSGFLAG_FROMME             = 0x20U, /* mfFromMe */
	MSGFLAG_ASSOCIATED         = 0x40U, /* mfFAI */
	MSGFLAG_RESEND             = 0x80U,
	MSGFLAG_RN_PENDING         = 0x100U, /* mfNotifyRead */
	MSGFLAG_NRN_PENDING        = 0x200U, /* mfNotifyUnread */
	MSGFLAG_EVERREAD           = 0x400U, /* mfEverRead */
	MSGFLAG_ORIGIN_X400        = 0x1000U,
	MSGFLAG_ORIGIN_INTERNET    = 0x2000U, /* mfInternet */
	MSGFLAG_ORIGIN_MISC_EXT    = 0x8000U, /* mfUntrusted */
	MSGFLAG_OUTLOOK_NON_EMS_XP = 0x10000U,
};

enum ndr_diag_code { /* for PR_NDR_DIAG_CODE */
	MAPI_DIAG_NO_DIAGNOSTIC = 0xFFFFFFFFU,
	MAPI_DIAG_OR_NAME_UNRECOGNIZED = 0U,
	MAPI_DIAG_OR_NAME_AMBIGUOUS = 1U,
	MAPI_DIAG_MTS_CONGESTED = 2U,
	MAPI_DIAG_LOOP_DETECTED = 3U,
	MAPI_DIAG_RECIPIENT_UNAVAILABLE = 4U,
	MAPI_DIAG_MAXIMUM_TIME_EXPIRED = 5U,
	MAPI_DIAG_EITS_UNSUPPORTED = 6U,
	MAPI_DIAG_CONTENT_TOO_LONG = 7U,
	MAPI_DIAG_IMPRACTICAL_TO_CONVERT = 8U,
	MAPI_DIAG_PROHIBITED_TO_CONVERT = 9U,
	MAPI_DIAG_CONVERSION_UNSUBSCRIBED = 10U,
	MAPI_DIAG_PARAMETERS_INVALID = 11U,
	MAPI_DIAG_CONTENT_SYNTAX_IN_ERROR = 12U,
	MAPI_DIAG_LENGTH_CONSTRAINT_VIOLATD = 13U,
	MAPI_DIAG_NUMBER_CONSTRAINT_VIOLATD = 14U,
	MAPI_DIAG_CONTENT_TYPE_UNSUPPORTED = 15U,
	MAPI_DIAG_TOO_MANY_RECIPIENTS = 16U,
	MAPI_DIAG_NO_BILATERAL_AGREEMENT = 17U,
	MAPI_DIAG_CRITICAL_FUNC_UNSUPPORTED = 18U,
	MAPI_DIAG_CONVERSION_LOSS_PROHIB = 19U,
	MAPI_DIAG_LINE_TOO_LONG = 20U,
	MAPI_DIAG_PAGE_TOO_LONG = 21U,
	MAPI_DIAG_PICTORIAL_SYMBOL_LOST = 22U,
	MAPI_DIAG_PUNCTUATION_SYMBOL_LOST = 23U,
	MAPI_DIAG_ALPHABETIC_CHARACTER_LOST = 24U,
	MAPI_DIAG_MULTIPLE_INFO_LOSSES = 25U,
	MAPI_DIAG_REASSIGNMENT_PROHIBITED = 26U,
	MAPI_DIAG_REDIRECTION_LOOP_DETECTED = 27U,
	MAPI_DIAG_EXPANSION_PROHIBITED = 28U,
	MAPI_DIAG_SUBMISSION_PROHIBITED = 29U,
	MAPI_DIAG_EXPANSION_FAILED = 30U,
	MAPI_DIAG_RENDITION_UNSUPPORTED = 31U,
	MAPI_DIAG_MAIL_ADDRESS_INCORRECT = 32U,
	MAPI_DIAG_MAIL_OFFICE_INCOR_OR_INVD = 33U,
	MAPI_DIAG_MAIL_ADDRESS_INCOMPLETE = 34U,
	MAPI_DIAG_MAIL_RECIPIENT_UNKNOWN = 35U,
	MAPI_DIAG_MAIL_RECIPIENT_DECEASED = 36U,
	MAPI_DIAG_MAIL_ORGANIZATION_EXPIRED = 37U,
	MAPI_DIAG_MAIL_REFUSED = 38U,
	MAPI_DIAG_MAIL_UNCLAIMED = 39U,
	MAPI_DIAG_MAIL_RECIPIENT_MOVED = 40U,
	MAPI_DIAG_MAIL_RECIPIENT_TRAVELLING = 41U,
	MAPI_DIAG_MAIL_RECIPIENT_DEPARTED = 42U,
	MAPI_DIAG_MAIL_NEW_ADDRESS_UNKNOWN = 43U,
	MAPI_DIAG_MAIL_FORWARDING_UNWANTED = 44U,
	MAPI_DIAG_MAIL_FORWARDING_PROHIB = 45U,
	MAPI_DIAG_SECURE_MESSAGING_ERROR = 46U,
	MAPI_DIAG_DOWNGRADING_IMPOSSIBLE = 47U,
	/* OXCMAIL v22 §2.1.3.6.1.2 and §2.2.3.7.1.3 */
	MAPI_DIAG_48 = 48U,
};

enum { /* for {IMAPIProp, IMAPISupport}::*Copy*. */
	MAPI_MOVE       = 0x1U,
	MAPI_NOREPLACE  = 0x2U,
	MAPI_DECLINE_OK = 0x4U,
};

enum { /* for PR_MESSAGE_STATUS */
	MSGSTATUS_HIGHLIGHTED     = 0x1U,
	MSGSTATUS_TAGGED          = 0x2U,
	MSGSTATUS_HIDDEN          = 0x4U,
	MSGSTATUS_DELMARKED       = 0x8U,
	MSGSTATUS_DRAFT           = 0x100U,
	MSGSTATUS_ANSWERED        = 0x200U,
	MSGSTATUS_IN_CONFLICT     = 0x800U,
	MSGSTATUS_REMOTE_DOWNLOAD = 0x1000U,
	MSGSTATUS_REMOTE_DELETE   = 0x2000U,
	MSGSTATUS_MDNSENT         = 0x4000U,
};

enum { /* for PR_PROFILE_OPEN_FLAGS */
	OPENSTORE_USE_ADMIN_PRIVILEGE              = 0x1U,
	OPENSTORE_PUBLIC                           = 0x2U,
	OPENSTORE_HOME_LOGON                       = 0x4U,
	OPENSTORE_TAKE_OWNERSHIP                   = 0x8U,
	OPENSTORE_OVERRIDE_HOME_MDB                = 0x10U,
	OPENSTORE_TRANSPORT                        = 0x20U,
	OPENSTORE_REMOTE_TRANSPORT                 = 0x40U,
	OPENSTORE_INTERNET_ANONYMOUS               = 0x80U,
	OPENSTORE_ALTERNATE_SERVER                 = 0x100U,
	OPENSTORE_IGNORE_HOME_MDB                  = 0x200U,
	OPENSTORE_NO_MAIL                          = 0x400U,
	OPENSTORE_OVERRIDE_LAST_MODIFIER           = 0x800U,
	OPENSTORE_CALLBACK_LOGON                   = 0x1000U,
	OPENSTORE_LOCAL                            = 0x2000U,
	OPENSTORE_FAIL_IF_NO_MAILBOX               = 0x4000U,
	OPENSTORE_CACHE_EXCHANGE                   = 0x8000U,
	OPENSTORE_CLI_WITH_NAMEDPROP_FIX           = 0x10000U,
	OPENSTORE_ENABLE_LAZY_LOGGING              = 0x20000U,
	OPENSTORE_CLI_WITH_REPLID_GUID_MAPPING_FIX = 0x40000U,
	OPENSTORE_NO_LOCALIZATION                  = 0x80000U,
	OPENSTORE_RESTORE_DATABASE                 = 0x100000U,
	OPENSTORE_XFOREST_MOVE                     = 0x200000U,
};

enum ol_busy_status {
	olFree = 0,
	olTentative = 1,
	olBusy = 2,
	olOutOfOffice = 3,
	olWorkingElsewhere = 4,
	olIndeterminate = 0xffff, /* gromox internal */
};

enum { /* for PR_RECIPIENT_FLAGS */
	recipSendable            = 0x1U,
	recipOrganizer           = 0x2U,
	recipExceptionalResponse = 0x10U,
	recipExceptionalDeleted  = 0x20U,
	/* nonoriginal_firstcontact = 0x40U, OL2019 */
	recipOriginal            = 0x100U,
	/* added_by_organizer    = 0x200U, OL2019 */
};

enum class relop : uint8_t {
	lt = 0, le, gt, ge, eq, ne, re, dl = 0x64,
};
#define RELOP_LT relop::lt
#define RELOP_LE relop::le
#define RELOP_GT relop::gt
#define RELOP_GE relop::ge
#define RELOP_EQ relop::eq
#define RELOP_NE relop::ne
#define RELOP_RE relop::re
#define RELOP_MEMBER_OF_DL relop::dl

enum class mapi_rtype : uint8_t {
	r_and = 0x0U,
	r_or = 0x01,
	r_not = 0x02,
	content = 0x03,
	property = 0x04,
	propcmp = 0x05,
	bitmask = 0x06,
	size = 0x07,
	exist = 0x08,
	sub = 0x09,
	comment = 0x0a,
	count = 0x0b,
	/* https://docs.microsoft.com/en-us/archive/blogs/stephen_griffin/new-restriction-types-seen-in-wrapped-psts */
	annotation = 0x0c,
	null = 0xff,
};
#define RES_AND            mapi_rtype::r_and
#define RES_OR             mapi_rtype::r_or
#define RES_NOT            mapi_rtype::r_not
#define RES_CONTENT        mapi_rtype::content
#define RES_PROPERTY       mapi_rtype::property
#define RES_PROPCOMPARE    mapi_rtype::propcmp
#define RES_BITMASK        mapi_rtype::bitmask
#define RES_SIZE           mapi_rtype::size
#define RES_EXIST          mapi_rtype::exist
#define RES_SUBRESTRICTION mapi_rtype::sub
#define RES_COMMENT        mapi_rtype::comment
#define RES_COUNT          mapi_rtype::count
#define RES_ANNOTATION     mapi_rtype::annotation
#define RES_NULL           mapi_rtype::null /* aka NULL_RESTRICTION */

enum {
	/* right bits */
	frightsReadAny              = 0x1U,
	frightsCreate               = 0x2U,
	frightsGromoxSendAs         = 0x4U,
	frightsEditOwned            = 0x8U,
	frightsDeleteOwned          = 0x10U,
	frightsEditAny              = 0x20U,
	frightsDeleteAny            = 0x40U,
	frightsCreateSubfolder      = 0x80U,
	/*
	 * "All of the above 8". Kinda redundant, but then, Outlook uses it to
	 * determine whether to show the "Permissions" tab for folders within a
	 * public store.
	 */
	frightsOwner                = 0x100U,
	frightsContact              = 0x200U,
	frightsVisible              = 0x400U,
	frightsFreeBusySimple       = 0x800U, /* cf. IExchangeModifyTable */
	frightsFreeBusyDetailed     = 0x1000U, /* cf. IExchangeModifyTable */
	/*
	 * Special bit that can be set on *IPM_SUBTREE* to toggle the OWNER bit
	 * on *store_object/logon_object* (since Outlook only shows
	 * IPM_SUBTREE / and Gromox has no store-level permission bits really).
	 */
	frightsGromoxStoreOwner     = 0x2000U,

	rightsNone = 0U,
	rightsReadOnly = frightsReadAny,
	rightsReadWrite = frightsReadAny | frightsEditAny,
	/* (0x5fb/1531) */
	rightsAll = frightsReadAny | frightsCreate | frightsEditOwned |
	            frightsDeleteOwned | frightsEditAny | frightsDeleteAny |
	            frightsCreateSubfolder | frightsOwner | frightsVisible,

	/* a set that's often used in code (0x5e3/1507) */
	rightsGromox7 = frightsReadAny | frightsCreate | frightsEditAny |
	                frightsDeleteAny | frightsCreateSubfolder |
	                frightsOwner | frightsVisible,

	rightsMaxROP = rightsAll | frightsContact | frightsFreeBusySimple |
	               frightsFreeBusyDetailed,
	/*
	 * Profiles used by Outlook
	 */
	rightsPublishingEditor = frightsReadAny | frightsVisible | frightsCreate | frightsDeleteOwned | frightsEditOwned |
	                         frightsEditAny | frightsDeleteAny | frightsCreateSubfolder,
	rightsEditor = frightsReadAny | frightsVisible | frightsCreate | frightsDeleteOwned | frightsEditOwned | frightsEditAny |
	               frightsDeleteAny,
	rightsPublishingAuthor = frightsReadAny | frightsVisible | frightsCreate | frightsDeleteOwned | frightsEditOwned |
	                         frightsCreateSubfolder,
	rightsAuthor = frightsReadAny | frightsVisible | frightsCreate | frightsDeleteOwned | frightsEditOwned,
	rightsNoneditingAuthor = frightsReadAny | frightsVisible | frightsCreate | frightsDeleteOwned,
	rightsReviewer = frightsReadAny | frightsVisible,
	rightsContributor = frightsVisible | frightsCreate,
};

enum : uint8_t { /* ROWENTRY::ulRowFlags bits */
	ROW_ADD    = 0x1U,
	ROW_MODIFY = 0x2U,
	ROW_REMOVE = 0x4U,
	ROW_EMPTY  = ROW_ADD | ROW_REMOVE,
};

enum sender_status { /* for PR_SENDER_ID_STATUS */
	SENDER_ID_NEUTRAL = 1,
	SENDER_ID_PASS = 2,
	SENDER_ID_FAIL = 3,
	SENDER_ID_SOFT_FAIL = 4,
	SENDER_ID_NONE = 5,
	SENDER_ID_TEMP_ERROR = 6,
	SENDER_ID_PERM_ERROR = 7,
};

enum { /* for PR_RESOURCE_FLAGS */
	SERVICE_DEFAULT_STORE       = 0x1U,
	SERVICE_SINGLE_COPY         = 0x2U,
	SERVICE_CREATE_WITH_STORE   = 0x4U,
	SERVICE_PRIMARY_IDENTITY    = 0x8U,
	SERVICE_NO_PRIMARY_IDENTITY = 0x20U,

	STATUS_DEFAULT_OUTBOUND    = 0x1U,
	STATUS_DEFAULT_STORE       = 0x2U,
	STATUS_PRIMARY_IDENTITY    = 0x4U,
	STATUS_SIMPLE_STORE        = 0x8U,
	STATUS_XP_PREFER_LAST      = 0x10U,
	STATUS_NO_PRIMARY_IDENTITY = 0x20U,
	STATUS_NO_DEFAULT_STORE    = 0x40U,
	STATUS_TEMP_SECTION        = 0x80U,
	STATUS_OWN_STORE           = 0x100U,
	STATUS_NEED_IPM_TREE       = 0x800U,
	STATUS_PRIMARY_STORE       = 0x1000U,
	STATUS_SECONDARY_STORE     = 0x2000U,

	HOOK_INBOUND               = 0x200U,
	HOOK_OUTBOUND              = 0x400U,
};

enum ren_special_folder {
	/* index into PR_ADDITIONAL_REN_ENTRYIDS */
	sfConflicts = 0,
	sfSyncFailures = 1,
	sfLocalFailures = 2,
	sfServerFailures = 3,
	sfJunkEmail = 4,
	sfSpamTagDontUse = 5, /* no entryid at this index, but a 32-bit tag */
};

enum { /* for PR_STORE_SUPPORT_MASK and PR_STORE_STATE */
	STORE_ENTRYID_UNIQUE    = 0x1U,
	STORE_READONLY          = 0x2U,
	STORE_SEARCH_OK         = 0x4U,
	STORE_MODIFY_OK         = 0x8U,
	STORE_CREATE_OK         = 0x10U,
	STORE_ATTACH_OK         = 0x20U,
	STORE_OLE_OK            = 0x40U,
	STORE_SUBMIT_OK         = 0x80U,
	STORE_NOTIFY_OK         = 0x100U,
	STORE_MV_PROPS_OK       = 0x200U,
	STORE_CATEGORIZE_OK     = 0x400U,
	STORE_RTF_OK            = 0x800U,
	STORE_RESTRICTION_OK    = 0x1000U,
	STORE_SORT_OK           = 0x2000U,
	STORE_PUBLIC_FOLDERS    = 0x4000U,
	STORE_UNCOMPRESSED_RTF  = 0x8000U,
	STORE_HTML_OK           = 0x10000U,
	STORE_ANSI_OK           = 0x20000U,
	STORE_UNICODE_OK        = 0x40000U,
	STORE_LOCALSTORE        = 0x80000U,
	STORE_ITEMPROC          = 0x200000U,
	STORE_PUSHER_OK         = 0x800000U,
	STORE_HAS_SEARCHES      = 0x1000000U,
	STORE_FULLTEXT_QUERY_OK = 0x2000000U,
	STORE_FILTER_SEARCH_OK  = 0x4000000U,
	// ??                   = 0x8000000U, /* MSMAPI/EMSMDB32 shows this */
	STORE_RULES_OK          = 0x10000000U,
};

enum { /* for IExchangeImportContentsChanges et al */
	SYNC_UNICODE                        = 0x1U,
	SYNC_NO_DELETIONS                   = 0x2U,
	SYNC_NO_SOFT_DELETIONS              = 0x4U,
	SYNC_READ_STATE                     = 0x8U,
	SYNC_ASSOCIATED                     = 0x10U,
	SYNC_NORMAL                         = 0x20U,
	SYNC_ONLY_SPECIFIED_PROPS           = 0x80U,
	SYNC_NO_FOREIGN_KEYS                = 0x100U,
	SYNC_LIMITED_IMESSAGE               = 0x200U,
	SYNC_CATCHUP                        = 0x400U,
	SYNC_NEW_MESSAGE                    = 0x800U,
	SYNC_MSG_SELECTIVE                  = 0x1000U,
	SYNC_BEST_BODY                      = 0x2000U,
	SYNC_IGNORE_SPECIFIED_ON_ASSOCIATED = 0x4000U,
	SYNC_PROGRESS_MODE                  = 0x8000U,
	SYNC_FXRECOVERMODE                  = 0x10000U,
	SYNC_DEFER_CONFIG                   = 0x20000U,
	SYNC_FORCE_UNICODE                  = 0x40000U,
};

enum mapi_row_type { /* for PR_ROW_TYPE */
	TBL_LEAF_ROW           = 0x1U,
	TBL_EMPTY_CATEGORY     = 0x2U,
	TBL_EXPANDED_CATEGORY  = 0x3U,
	TBL_COLLAPSED_CATEGORY = 0x4U,
};

enum { /* for PR_TODO_ITEM_FLAGS */
	todoTimeFlaggged = 0x1U,
	todoRecipientFlagged = 0x8U,
};

enum { /* for PidLidTaskStatus */
	tsvNotStarted = 0,
	tsvInProgress,
	tsvComplete,
	tsvWaiting,
	tsvDeferred,
};

enum zics_type {
	ICS_TYPE_CONTENTS = 1,
	ICS_TYPE_HIERARCHY = 2,
};

enum STREAM_SEEK {
	STREAM_SEEK_SET = 0,
	STREAM_SEEK_CUR = 1,
	STREAM_SEEK_END = 2,
};

enum BOOKMARK {
	BOOKMARK_BEGINNING = STREAM_SEEK_SET,
	BOOKMARK_CURRENT = STREAM_SEEK_CUR,
	BOOKMARK_END = STREAM_SEEK_END,
	BOOKMARK_CUSTOM = 3,
};

enum { /* for IMAPIFolder::{DeleteFolder, DeleteMessage, EmptyFolder} */
	DEL_MESSAGES            = 0x1U,
	DEL_FOLDERS             = 0x4U,
	DEL_ASSOCIATED          = 0x8U, /* MAPI only, not used in OXCROPS. */
	DELETE_HARD_DELETE      = 0x10U,
	GX_DELMSG_NOTIFY_UNREAD = 0x40000000U, /* Gromox-specific */
};

enum {
	FL_FULLSTRING = 0,
	FL_SUBSTRING,
	FL_PREFIX,

	FL_PREFIX_ON_ANY_WORD = 0x10U, /* split value and attempt match on each word */
	FL_PHRASE_MATCH       = 0x20U, /* match exact words and in order only */
	FL_IGNORECASE         = 0x10000U,
	FL_IGNORENONSPACE     = 0x20000U,
	FL_LOOSE              = 0x40000U,
};

enum mapi_access { /* for PR_ACCESS */
	MAPI_ACCESS_MODIFY            = 0x1U,
	MAPI_ACCESS_READ              = 0x2U,
	MAPI_ACCESS_DELETE            = 0x4U,
	MAPI_ACCESS_CREATE_HIERARCHY  = 0x8U,
	MAPI_ACCESS_CREATE_CONTENTS   = 0x10U,
	MAPI_ACCESS_CREATE_ASSOCIATED = 0x20U,

	MAPI_ACCESS_AllSix = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE |
	                   MAPI_ACCESS_CREATE_HIERARCHY | MAPI_ACCESS_CREATE_CONTENTS |
	                   MAPI_ACCESS_CREATE_ASSOCIATED,
};

enum {
	/* The OL UI only offers 4 categories and 4 sorts, so we just don't need more ATM. */
	MAXIMUM_SORT_COUNT = 8,
};

enum zaccess_type {
	ACCESS_TYPE_DENIED = 1,
	ACCESS_TYPE_GRANT = 2,
	ACCESS_TYPE_BOTH = 3,
};

enum {
	RIGHT_NORMAL = 0,
	RIGHT_NEW               = 0x1U,
	RIGHT_MODIFY            = 0x2U,
	RIGHT_DELETED           = 0x4U,
	RIGHT_AUTOUPDATE_DENIED = 0x8U,
};

/* cf. glossary.rst "Internal Identifier" */
struct GX_EXPORT eid_t {
	static constexpr uint64_t GCV_MASK = 0xFFFFFFFFFFFF;
	eid_t() = default;
	constexpr eid_t(uint64_t v) : m_value(v) {}
	constexpr eid_t(uint16_t r, uint64_t v) : m_value(__builtin_bswap64(v & GCV_MASK) | r) {}
	constexpr operator uint64_t() const { return m_value; }
	constexpr uint64_t gcv() const { return __builtin_bswap64(m_value) & GCV_MASK; }
	constexpr uint16_t replid() const { return m_value & 0xFFFF; }
	constexpr uint64_t raw() const { return m_value; }
	void operator=(uint64_t) = delete;
	uint64_t m_value;
};

struct GX_EXPORT ACTION_BLOCK {
	uint16_t length;
	uint8_t type;
	uint32_t flavor;
	uint32_t flags;
	void *pdata;

	std::string repr() const;
};

struct GX_EXPORT ADVISE_INFO {
	uint32_t hstore;
	uint32_t sub_id;
};

/*
 * @pv:		may legitimately be nullptr (only if cb==0)
 */
struct GX_EXPORT BINARY {
	uint32_t cb;
	union {
		uint8_t *pb;
		char *pc;
		void *pv;
	};

	operator std::string_view() const { return std::string_view(gromox::znul(pc), cb); }
	int compare(const BINARY &) const;
	std::string repr(bool verbose = true) const;
};
using DATA_BLOB = BINARY;

struct GX_EXPORT BINARY_ARRAY {
	uint32_t count;
	BINARY *pbin;
	I_BEGIN_END(pbin, count);
};

struct GX_EXPORT DOUBLE_ARRAY {
	uint32_t count;
	double *mval;
	I_BEGIN_END(mval, count);
};

struct GX_EXPORT freebusy_event {
	freebusy_event() = default;
	freebusy_event(time_t, time_t, uint32_t, const char *, const char *, const char *, bool, bool, bool, bool, bool, bool);
	freebusy_event(const freebusy_event &);
	void operator=(freebusy_event &&) = delete;

	time_t start_time = 0, end_time = 0;
	uint32_t busy_status = 0;
	bool has_details = false, is_meeting = false, is_recurring = false;
	bool is_exception = false, is_reminderset = false, is_private = false;
	std::string m_id, m_subject, m_location;
	/* location is optional, but id/subject normally are not. */
	const char *id = nullptr, *subject = nullptr, *location = nullptr;
};

/**
 * The host-endian view of struct GUID is often not needed, and so a plethora
 * of GUIDs exist as bytearrays/FLATUID, mostly when the consumer does not care
 * about internal layout.
 */
struct GUID;
struct GX_EXPORT FLATUID {
	operator GUID() const;

	uint8_t ab[16];
#if __cplusplus >= 202000L && defined(__GNUG__) >= 13
	/* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=103733 */
	bool operator==(const FLATUID &) const = default;
#else
	inline bool operator==(const FLATUID &o) const { return memcmp(ab, o.ab, sizeof(ab)) == 0; }
	inline bool operator!=(const FLATUID &o) const { return !operator==(o); }
#endif
};

struct GX_EXPORT FLATUID_ARRAY {
	uint32_t cvalues;
	FLATUID **ppguid;
	I_BEGIN_END(ppguid, cvalues);
};

struct GX_EXPORT FLOAT_ARRAY {
	uint32_t count;
	float *mval;
	I_BEGIN_END(mval, count);
};

struct GX_EXPORT GLOBCNT {
	uint8_t ab[6];
};

/**
 * A host-endian view of a GUID.
 *
 * Conversion options are e.g.
 *  - EXT_PUSH::p_guid, produces a little-endian bytearray/FLATUID
 *  - to_str, produces a big-endian text representation
 *  - and their reverse functions
 */
struct GX_EXPORT GUID {
	operator FLATUID() const;
	void to_str(char *, size_t, unsigned int type = 36) const;
	bool from_str(const char *);
	int compare_4_12(const GUID &) const;
	int compare(const GUID &) const;
	static GUID random_new();
	static const GUID &machine_id();

	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];

#if __cplusplus >= 202000L && defined(__GNUG__) >= 13
	/* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=103733 */
	bool operator==(const FLATUID &) const = default;
#else
	inline bool operator==(const GUID &o) const { return memcmp(this, &o, sizeof(o)) == 0; }
	inline bool operator!=(const GUID &o) const { return !operator==(o); }
#endif
};

struct GX_EXPORT GUID_ARRAY {
	uint32_t count;
	GUID *pguid;
	I_BEGIN_END(pguid, count);
};

struct GX_EXPORT LONG_ARRAY {
	uint32_t count;
	uint32_t *pl; // XXX: should be int32_t
	I_BEGIN_END(pl, count);
};

struct GX_EXPORT LONGLONG_ARRAY {
	uint32_t count;
	uint64_t *pll; // XXX: should be int64_t
	I_BEGIN_END(pll, count);
};

struct GX_EXPORT LPROPTAG_ARRAY {
	uint32_t cvalues;
	uint32_t *pproptag;
	I_BEGIN_END(pproptag, cvalues);
};

struct GX_EXPORT MESSAGE_STATE {
	BINARY source_key;
	uint32_t message_flags;
};

struct GX_EXPORT NOTIF_SINK {
	GUID hsession;
	uint16_t count;
	ADVISE_INFO *padvise;
};

struct GX_EXPORT ONEOFF_ENTRYID {
	uint32_t flags;
	uint16_t version; /* should be 0x0000 */
	uint16_t ctrl_flags;
	char *pdisplay_name;
	char *paddress_type;
	char *pmail_address;
};

struct GX_EXPORT ONEOFF_ARRAY {
	uint32_t count;
	ONEOFF_ENTRYID *pentry_id;
	I_BEGIN_END(pentry_id, count);
};

struct GX_EXPORT PERMISSION_ROW {
	uint32_t flags, member_id, member_rights;
	BINARY entryid;
};

struct GX_EXPORT PERMISSION_SET {
	uint16_t count;
	PERMISSION_ROW *prows;
};

struct GX_EXPORT PROPERTY_NAME {
	uint8_t kind;
	GUID guid;
	uint32_t lid;
	char *pname;

	inline bool operator==(const PROPERTY_NAME& o) const
	{return kind == o.kind && guid == o.guid && (kind == MNID_STRING? !strcmp(pname, o.pname) : lid == o.lid);}
};

struct GX_EXPORT PROPERTY_XNAME {
	PROPERTY_XNAME() = default;
	PROPERTY_XNAME(const PROPERTY_NAME &);
	explicit operator PROPERTY_NAME() const;

	uint8_t kind = KIND_NONE;
	uint32_t lid = 0;
	GUID guid{};
	std::string name;
};

using PROPID_ARRAY = std::vector<gromox::propid_t>;

struct GX_EXPORT PROPNAME_ARRAY {
	uint16_t count;
	PROPERTY_NAME *ppropname;
	I_BEGIN_END(ppropname, count);
};

struct GX_EXPORT PROPTAG_ARRAY {
	size_t indexof(uint32_t tag) const;
	inline bool has(uint32_t tag) const { return indexof(tag) != npos; }
	void emplace_back(uint32_t tag) { pproptag[count++] = tag; }
	std::string repr() const;

	uint16_t count;
	uint32_t *pproptag;
	static constexpr size_t npos = -1;
	I_BEGIN_END(pproptag, count);
};

struct GX_EXPORT SHORT_ARRAY {
	uint32_t count;
	uint16_t *ps; // XXX: should be int16_t
	I_BEGIN_END(ps, count);
};

/**
 * @type:       Proptype. When the MV_INSTANCE bit is set, a multivalue property
 *              will be presented as multiple rows.
 * @table_sort: TBL_ASCEND / TBL_DESCEND
 */
struct GX_EXPORT SORT_ORDER {
	uint16_t type;
	gromox::propid_t propid;
	uint8_t table_sort;

	std::string repr() const;
};

/**
 * https://learn.microsoft.com/en-us/office/client-developer/outlook/mapi/ssortorderset
 */
struct GX_EXPORT SORTORDER_SET {
	uint16_t count;
	uint16_t ccategories;
	uint16_t cexpanded;
	SORT_ORDER *psort;

	std::string repr() const;
};

struct GX_EXPORT STATE_ARRAY {
	uint32_t count;
	MESSAGE_STATE *pstate;
	I_BEGIN_END(pstate, count);
};

struct GX_EXPORT STRING_ARRAY {
	uint32_t count;
	char **ppstr;
	I_BEGIN_END(ppstr, count);
};

struct GX_EXPORT SVREID {
	BINARY *pbin;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t instance;

	int compare(const SVREID &) const;
	std::string repr(bool verbose = true) const;
};

struct GX_EXPORT TAGGED_PROPVAL {
	gromox::proptag_t proptag;
	void *pvalue;

	std::string repr(bool v = true) const;
	std::string type_repr() const;
	std::string value_repr(bool v = true) const;
};

struct tarray_set;
struct TPROPVAL_ARRAY;
extern GX_EXPORT TPROPVAL_ARRAY *tpropval_array_init();
extern GX_EXPORT void tpropval_array_free(TPROPVAL_ARRAY *);
extern GX_EXPORT bool tpropval_array_init_internal(TPROPVAL_ARRAY *);
extern GX_EXPORT void tpropval_array_free_internal(TPROPVAL_ARRAY *);
extern GX_EXPORT tarray_set *tarray_set_init();
extern GX_EXPORT void tarray_set_free(tarray_set *);

struct GX_EXPORT GEN_ARRAY {
	uint32_t count = 0;
	union {
		void *mval = nullptr;
		int16_t *shrt;
		int32_t *lng;
		int64_t *llng;
		float *flt;
		double *dbl;
		const char **str;
		GUID *guid;
		BINARY *bin;
	};
};

struct GX_EXPORT TPROPVAL_ARRAY {
	TAGGED_PROPVAL *find(uint32_t tag) {
		for (size_t i = 0; i < count; ++i)
			if (ppropval[i].proptag == tag)
				return &ppropval[i];
		return nullptr;
	}
	const TAGGED_PROPVAL *find(uint32_t tag) const {
		for (size_t i = 0; i < count; ++i)
			if (ppropval[i].proptag == tag)
				return &ppropval[i];
		return nullptr;
	}
	inline bool has(uint32_t tag) const { return find(tag) != nullptr; }
	inline void *getval(uint32_t tag) {
		auto v = find(tag);
		return v != nullptr ? v->pvalue : nullptr;
	}
	inline const void *getval(uint32_t tag) const {
		auto v = find(tag);
		return v != nullptr ? v->pvalue : nullptr;
	}
	template<typename T> inline const T *get(uint32_t tag) const { return static_cast<const T *>(getval(tag)); }
	template<typename T> inline T *get(uint32_t tag) { return static_cast<T *>(getval(tag)); }
	ec_error_t set(uint32_t tag, const void *d);
	inline ec_error_t set(const TAGGED_PROPVAL &a) { return set(a.proptag, a.pvalue); }
	void emplace_back(uint32_t tag, const void *d) {
		ppropval[count++] = TAGGED_PROPVAL{tag, deconst(d)};
	}
	void erase(uint32_t tag);
	size_t erase_if(bool (*pred)(const TAGGED_PROPVAL &));
	TPROPVAL_ARRAY *dup() const;
	std::string repr() const;

	uint16_t count;
	TAGGED_PROPVAL *ppropval;
	I_BEGIN_END(ppropval, count);
};

struct GX_EXPORT mapidefs1_del {
	inline void operator()(TPROPVAL_ARRAY *x) const { tpropval_array_free(x); }
};

using tpropval_array_ptr = std::unique_ptr<TPROPVAL_ARRAY, mapidefs1_del>;

struct GX_EXPORT LTPROPVAL_ARRAY {
	uint32_t count;
	TAGGED_PROPVAL *propval;
	I_BEGIN_END(propval, count);
};

/* Better known as rowset/row_set in MSMAPI */
struct GX_EXPORT tarray_set {
	void erase(uint32_t index);
	TPROPVAL_ARRAY *emplace();
	inline TPROPVAL_ARRAY *back() { return pparray[count-1]; }
	inline const TPROPVAL_ARRAY *back() const { return pparray[count-1]; }
	gromox::errno_t append_move(tpropval_array_ptr &&);
	tarray_set *dup() const;
	inline gromox::deref_iterator<TPROPVAL_ARRAY> begin() { return pparray; }
	inline gromox::deref_iterator<TPROPVAL_ARRAY> end() { return pparray + count; }
	inline gromox::const_deref_iterator<TPROPVAL_ARRAY> begin() const { return pparray; }
	inline gromox::const_deref_iterator<TPROPVAL_ARRAY> end() const { return pparray + count; }

	uint32_t count;
	TPROPVAL_ARRAY **pparray;
};
using TARRAY_SET = tarray_set;

struct GX_EXPORT RECIPIENT_BLOCK {
	uint8_t reserved;
	uint16_t count;
	TAGGED_PROPVAL *ppropval;

	std::string repr() const;
	I_BEGIN_END(ppropval, count);
};

struct restriction_list;
struct SNotRestriction;
struct SContentRestriction;
struct SPropertyRestriction;
struct SComparePropsRestriction;
struct SBitMaskRestriction;
struct SSizeRestriction;
struct SExistRestriction;
struct SSubRestriction;
struct SCommentRestriction;
struct SCountRestriction;

struct GX_EXPORT SRestriction {
	enum mapi_rtype rt;
	union {
		void *pres;
		restriction_list *andor;
		SNotRestriction *xnot;
		SContentRestriction *cont;
		SPropertyRestriction *prop;
		SComparePropsRestriction *pcmp;
		SBitMaskRestriction *bm;
		SSizeRestriction *size;
		SExistRestriction *exist;
		SSubRestriction *sub;
		SCommentRestriction *comment;
		SCountRestriction *count;
	};

	std::string repr() const;
	SRestriction *dup() const;
};
using RESTRICTION = SRestriction;

struct GX_EXPORT restriction_list {
	uint32_t count;
	SRestriction *pres;

	std::string repr() const;
	restriction_list *dup() const;
	I_BEGIN_END(pres, count);
};
using RESTRICTION_AND_OR = restriction_list;
using SAndRestriction = restriction_list;
using SOrRestriction = restriction_list;

struct GX_EXPORT SNotRestriction {
	RESTRICTION res;

	std::string repr() const;
	SNotRestriction *dup() const;
};
using RESTRICTION_NOT = SNotRestriction;

struct GX_EXPORT SContentRestriction {
	uint32_t fuzzy_level;
	gromox::proptag_t proptag;
	TAGGED_PROPVAL propval;
	bool comparable() const;
	bool eval(const void *) const;

	std::string repr() const;
	SContentRestriction *dup() const;
};
using RESTRICTION_CONTENT = SContentRestriction;

struct GX_EXPORT SPropertyRestriction {
	enum relop relop;
	gromox::proptag_t proptag;
	/*
	 * propval.proptag is only used for proptype information, the propid is
	 * ignored, but generally the same as RESTRICTION_PROPERTY::proptag.
	 */
	TAGGED_PROPVAL propval;
	bool comparable() const;
	bool eval(const void *) const;

	std::string repr() const;
	SPropertyRestriction *dup() const;
};
using RESTRICTION_PROPERTY = SPropertyRestriction;

struct GX_EXPORT SComparePropsRestriction {
	enum relop relop;
	gromox::proptag_t proptag1, proptag2;
	bool comparable() const;

	std::string repr() const;
	SComparePropsRestriction *dup() const;
};
using RESTRICTION_PROPCOMPARE = SComparePropsRestriction;

struct GX_EXPORT SBitMaskRestriction {
	enum bm_relop bitmask_relop;
	gromox::proptag_t proptag;
	uint32_t mask;
	bool comparable() const { return PROP_TYPE(proptag) == PT_LONG; }
	bool eval(const void *) const;

	std::string repr() const;
	SBitMaskRestriction *dup() const;
};
using RESTRICTION_BITMASK = SBitMaskRestriction;

struct GX_EXPORT SSizeRestriction {
	enum relop relop;
	gromox::proptag_t proptag;
	uint32_t size;
	bool eval(const void *) const;

	std::string repr() const;
	SSizeRestriction *dup() const;
};
using RESTRICTION_SIZE = SSizeRestriction;

struct GX_EXPORT SExistRestriction {
	gromox::proptag_t proptag;

	std::string repr() const;
	SExistRestriction *dup() const;
};
using RESTRICTION_EXIST = SExistRestriction;

struct GX_EXPORT SSubRestriction {
	uint32_t subobject;
	RESTRICTION res;

	std::string repr() const;
	SSubRestriction *dup() const;
};
using RESTRICTION_SUBOBJ = SSubRestriction;

struct GX_EXPORT SCommentRestriction {
	uint8_t count;
	TAGGED_PROPVAL *ppropval;
	RESTRICTION *pres;

	std::string repr() const;
	SCommentRestriction *dup() const;
};
using RESTRICTION_COMMENT = SCommentRestriction;

struct GX_EXPORT SCountRestriction {
	uint32_t count;
	RESTRICTION sub_res;

	std::string repr() const;
	SCountRestriction *dup() const;
};
using RESTRICTION_COUNT = SCountRestriction;

struct GX_EXPORT RULE_ACTIONS {
	uint16_t count;
	ACTION_BLOCK *pblock;

	std::string repr() const;
	I_BEGIN_END(pblock, count);
};

struct GX_EXPORT RULE_DATA {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
};

struct GX_EXPORT RULE_LIST {
	uint16_t count;
	RULE_DATA *prule;
	I_BEGIN_END(prule, count);
};

struct GX_EXPORT FORWARDDELEGATE_ACTION {
	uint16_t count;
	RECIPIENT_BLOCK *pblock;

	std::string repr() const;
	I_BEGIN_END(pblock, count);
};

enum { /* for GetSearchCriteria */
	SEARCH_RUNNING      = 0x1,
	SEARCH_REBUILD      = 0x2,
	SEARCH_RECURSIVE    = 0x4,
	SEARCH_COMPLETE     = 0x1000,
	SEARCH_PARTIAL      = 0x2000,
	SEARCH_STATIC       = 0x10000,
	SEARCH_MAYBE_STATIC = 0x20000,
	CI_TOTALLY          = 0x1000000,
	TWIR_TOTALLY        = 0x8000000,
};

enum { /* for SetSearchCriteria */
	STOP_SEARCH                = 0x1,
	RESTART_SEARCH             = 0x2,
	RECURSIVE_SEARCH           = 0x4,
	SHALLOW_SEARCH             = 0x8,
	FOREGROUND_SEARCH          = 0x10,
	BACKGROUND_SEARCH          = 0x20,
	CONTENT_INDEXED_SEARCH     = 0x10000,
	NON_CONTENT_INDEXED_SEARCH = 0x20000,
	STATIC_SEARCH              = 0x40000,
};

enum { /* for APPOINTMENT_RECUR_PAT::recurfrequency */
	IDC_RCEV_PAT_ORB_DAILY   = 0x200a,
	IDC_RCEV_PAT_ORB_WEEKLY  = 0x200b,
	IDC_RCEV_PAT_ORB_MONTHLY = 0x200c,
	IDC_RCEV_PAT_ORB_YEARLY  = 0x200d,
};

enum { /* for APPOINTMENT_RECUR_PAT::endtype */
	IDC_RCEV_PAT_ERB_END         = 0x2021,
	IDC_RCEV_PAT_ERB_AFTERNOCCUR = 0x2022,
	IDC_RCEV_PAT_ERB_NOEND       = 0x2023,
	IDC_RCEV_PAT_ERB_NOEND1      = 0xFFFFFFFF,

	/* MS-OXOCAL v21 p.39: "should be 0x2023 but can be 0xffffffff" */
};

enum { /* for PidLidRecurrenceType */
	rectypeNone = 0,
	rectypeDaily,
	rectypeWeekly,
	rectypeMonthly,
	rectypeYearly,
};

enum { /* for PidLidAppointmentStateFlags */
	asfMeeting  = 0x1U,
	asfReceived = 0x2U,
	asfCanceled = 0x4U,
};

enum { /* for PidLidResponseStatus */
	respNone = 0,
	respOrganized,
	respTentative,
	respAccepted,
	respDeclined,
	respNotResponded,
};

enum {
	MEMBER_ID_DEFAULT = 0,
	MEMBER_ID_ANONYMOUS = -1,
};

/*
 * Not in MSMAPI; Gromox-specific name. Documented for ropOpenMessage,
 * ropOpenEmbeddedMessage, ropOpenAttachment, ropOpenStream, (via OXODLGT,
 * OXOPFFB, OXOSFLD rather than OXCFOLD) ropOpenFolder.
 */
#define MAPI_READONLY 0x0U

/*
 * Documented for ropOpenMessage, ropOpenEmbeddedMessage, ropOpenAttachment,
 * ropOpenStream, {IABLogon, IAddrBook, IMAPIContainer, IMAPIProp,
 * IMAPISession, IMAPISupport, IMessage, IMsgServiceAdmin, IMSLogon,
 * IProviderAdmin, IXPLogon}::OpenEntry, ITnef::OpenTaggedBody.
 */
#define MAPI_MODIFY 0x1U

/* Documented for IMAPIFolder::CreateFolder.*/
#define OPEN_IF_EXISTS 0x1U

/* Documented for IMAPIFolder::GetHierarchyTable. */
#define CONVENIENT_DEPTH 0x1U

/*
 * Documented for ropOpenStream, ropOpenEmbeddedMessage, (loosely)
 * ropGetPropertyIdsFromNames, IMAPIProp::{GetIDsFromNames, OpenEntry},
 * ITnef::OpenTaggedBody.
 */
#define MAPI_CREATE 0x2U

/*
 * Documented for IMAPIFolder::{GetHierarchyTable, GetContentsTable},
 * {IMAPISession, IMAPIContainer}::OpenEntry.
 */
#define SHOW_SOFT_DELETES 0x2U

/*
 * Documented for ropOpenMessage, ropOpenAttachment, various I*::OpenEntry,
 * IMAPISession::OpenMsgStore.
 */
#define MAPI_BEST_ACCESS 0x3U

/*
 * Documented for ropOpenFolder.
 */
#define OPEN_MODE_FLAG_OPENSOFTDELETE 0x4U

/*
 * Documented for ropGetHierarchyTable, IMAPIFolder::{CreateFolder,
 * GetContentsTable, GetHierarchyTable}, various I*::OpenEntry,
 * IMessage::{CreateAttach, GetAttachmentTable, GetRecipientTable}.
 */
#define MAPI_DEFERRED_ERRORS 0x8U

/*
 * Documented for IMAPIFolder::{CreateMessage, GetContentsTable}.
 */
#define MAPI_ASSOCIATED 0x40U

extern GX_EXPORT const FLATUID
	muidStoreWrap, muidEMSAB, WAB_GUID, muidContabDLL, pbLongTermNonPrivateGuid,
	pbExchangeProviderPrimaryUserGuid, pbExchangeProviderPublicGuid,
	pbExchangeProviderDelegateGuid, shared_calendar_provider_guid,
	g_muidStorePrivate, g_muidStorePublic, muidOOP,
	muidECSAB, muidZCSAB, EncodedGlobalId, IID_IStorage,
	IID_IStream, IID_IMessage, IID_IExchangeExportChanges,
	IID_IExchangeImportContentsChanges, IID_IExchangeImportHierarchyChanges;
extern GX_EXPORT const char EncodedGlobalId_hex[];
extern GX_EXPORT const GUID
	GUID_NULL, PSETID_Address, PSETID_Appointment,
	PSETID_BusinessCardView, PSETID_CalendarAssistant, PSETID_Common,
	PSETID_Gromox, PSETID_KC, PSETID_Log, PSETID_Meeting,
	PSETID_Note, PSETID_Remote,
	PSETID_Report, PSETID_Sharing, PSETID_Task, PSETID_UnifiedMessaging,
	PSETID_Zarafa_Archive, PSETID_Zarafa_CalDav,
	PS_INTERNET_HEADERS, PS_MAPI,
	PS_PUBLIC_STRINGS, EWS_Mac_PropertySetId,
	gx_dbguid_store_private, gx_dbguid_store_public,
	exc_replid2, exc_replid3, exc_replid4;
extern GX_EXPORT const uint8_t MACBINARY_ENCODING[9], OLE_TAG[11], ThirdPartyGlobalId[12];

namespace gromox {
extern GX_EXPORT std::string guid2name(const FLATUID);
}
