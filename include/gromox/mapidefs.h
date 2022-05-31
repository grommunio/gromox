#pragma once
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <gromox/defs.h>

#define PROP_ID(x) ((x) >> 16)
#define PROP_TYPE(x) ((x) & 0xFFFF)
#define CHANGE_PROP_TYPE(tag, newtype) (((tag) & ~0xFFFF) | (newtype))

/*
 * x|y yields an unsigned result if either x or y are unsigned.
 * x<<y yields unsigned only if x is unsigned.
 * All the while | and << only make *sense* in an unsigned _context_ anyway
 * (i.e. the operator should have returned unsigned all the time)
 */
#define PROP_TAG(type, tag) ((((unsigned int)tag) << 16) | (type))
enum {
	/*
	 * MAPI sucks, episode #17: INSIDE MAPI pg.36 and
	 * https://docs.microsoft.com/en-us/office/client-developer/outlook/mapi/property-types
	 * have a contradiction, saying PT_LONG is "signed or unsigned", yet
	 * also "This property type is the same as […] the OLE type VT_I4".
	 *
	 * MS-OAUT clearly distinguishes signed and unsigned types, and since
	 * MAPI shares the same enum values, there is ample reason to treat
	 * PT_LONG etc. as signed throughout — especially when comparing values
	 * in restrictions.
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
	PT_SYSTIME = 0x0040, /* VT_FILETIME, PtypTime */
	PT_CLSID = 0x0048, /* VT_CLSID, PtypGuid */
	PT_SVREID = 0x00FB, /* PtypServerId; MS-OXCDATA extension */
	PT_SRESTRICTION = 0x00FD, /* PtypRestriction; edkmdb.h extension */
	PT_ACTIONS = 0x00FE, /* PtypRuleAction; edkmdb.h extension */
	PT_BINARY = 0x0102, /* PtypBinary */
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

#include "mapitags.hpp"

enum {
	MV_FLAG = 0x1000,
	MV_INSTANCE = 0x2000,
	MVI_FLAG = MV_FLAG | MV_INSTANCE,
	FXICS_CODEPAGE_FLAG = 0x8000U,
};

enum {
	PidLidAttendeeCriticalChange = 0x0001,
	PidLidGlobalObjectId = 0x0003,
	PidLidIsException = 0x000A,
	PidLidStartRecurrenceTime = 0x000E,
	PidLidOwnerCriticalChange = 0x001A,
	PidLidCleanGlobalObjectId = 0x0023,
	PidLidCategories = 0x2328,
	PidLidBusinessCardDisplayDefinition = 0x8040,
	PidLidWorkAddressStreet = 0x8045,
	PidLidWorkAddressCity = 0x8046,
	PidLidWorkAddressState = 0x8047,
	PidLidWorkAddressPostalCode = 0x8048,
	PidLidWorkAddressCountry = 0x8049,
	PidLidWorkAddressPostOfficeBox = 0x804A,
	PidLidContactUserField1 = 0x804F,
	PidLidContactUserField2 = 0x8050,
	PidLidContactUserField3 = 0x8051,
	PidLidContactUserField4 = 0x8052,
	PidLidInstantMessagingAddress = 0x8062,
	PidLidEmail1DisplayName = 0x8080,
	PidLidEmail1AddressType = 0x8082,
	PidLidEmail1EmailAddress = 0x8083,
	PidLidEmail2DisplayName = 0x8090,
	PidLidEmail2AddressType = 0x8092,
	PidLidEmail2EmailAddress = 0x8093,
	PidLidEmail3DisplayName = 0x80A0,
	PidLidEmail3AddressType = 0x80A2,
	PidLidEmail3EmailAddress = 0x80A3,
	PidLidFreeBusyLocation = 0x80D8,
	PidLidTaskStatus = 0x8101,
	PidLidPercentComplete = 0x8102,
	PidLidTaskStartDate = 0x8104,
	PidLidTaskDueDate = 0x8105,
	PidLidTaskDateCompleted = 0x810F,
	PidLidTaskComplete = 0x811C,
	PidLidAppointmentSequence = 0x8201,
	PidLidBusyStatus = 0x8205,
	PidLidLocation = 0x8208,
	PidLidAppointmentStartWhole = 0x820D,
	PidLidAppointmentEndWhole = 0x820E,
	PidLidAppointmentDuration = 0x8213,
	PidLidAppointmentSubType = 0x8215,
	PidLidAppointmentRecur = 0x8216,
	PidLidAppointmentStateFlags = 0x8217,
	PidLidRecurring = 0x8223,
	PidLidIntendedBusyStatus = 0x8224,
	PidLidExceptionReplaceTime = 0x8228,
	PidLidTimeZoneStruct = 0x8233,
	PidLidTimeZoneDescription = 0x8234,
	PidLidClipStart = 0x8235,
	PidLidClipEnd = 0x8236,
	PidLidAppointmentProposedStartWhole = 0x8250,
	PidLidAppointmentProposedEndWhole = 0x8251,
	PidLidAppointmentCounterProposal = 0x8257,
	PidLidAppointmentNotAllowPropose = 0x825A,
	PidLidAppointmentTimeZoneDefinitionStartDisplay = 0x825E,
	PidLidAppointmentTimeZoneDefinitionEndDisplay = 0x825F,
	PidLidAppointmentTimeZoneDefinitionRecur = 0x8260,
	PidLidReminderDelta = 0x8501,
	PidLidReminderTime = 0x8502,
	PidLidReminderSet = 0x8503,
	PidLidPrivate = 0x8506,
	PidLidSmartNoAttach = 0x8514,
	PidLidFlagRequest = 0x8530,
	PidLidReminderSignalTime = 0x8560,
	PidLidToDoTitle = 0x85A4,
	PidLidInfoPathFromName = 0x85B1,
	PidLidClassified = 0x85B5,
	PidLidClassification = 0x85B6,
	PidLidClassificationDescription = 0x85B7,
	PidLidClassificationGuid = 0x85B8,
	PidLidClassificationKeep = 0x85BA,
	PROP_ID_INVALID = 0xFFFF,
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
	ATT_INVISIBLE_IN_HTML = 1U << 0,
	ATT_INVISIBLE_IN_RTF  = 1U << 1,
	ATT_MHTML_REF         = 1U << 2,
};

enum { /* for PR_ATTACHMENT_FLAGS */
	afException = 1U << 1, /* OXOCAL v20 §2.2.10.1.2 */
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
	BIT_CH_START        = 1U << 0,
	BIT_CH_END          = 1U << 1,
	BIT_CH_RECUR        = 1U << 2,
	BIT_CH_LOCATION     = 1U << 3,
	BIT_CH_SUBJECT      = 1U << 4,
	BIT_CH_REQATT       = 1U << 5,
	BIT_CH_OPTATT       = 1U << 6,
	BIT_CH_BODY         = 1U << 7,
	BIT_CH_RESPONSE     = 1U << 9,
	BIT_CH_ALLOWPROPOSE = 1U << 10,
	BIT_CH_CNF          = 1U << 11, /* deprecated since OXOCAL v0.1 */
	BIT_CH_REM          = 1U << 12, /* reserved since OXOCAL v0.1 */
	// 1U << 27 was reserved from OXOCAL v0.1 to v4.1,
	// 1U << 31 is reversed since OXOCAL v5.0.
};

enum bm_relop {
	BMR_EQZ = 0,
	BMR_NEZ,
};

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
	/* one-off entryid flags, MS-OXCDATA v17 §2.2.5.1 pg 25 */
	CTRL_FLAG_BINHEX = 0x00,
	CTRL_FLAG_UUENCODE = 0x20,
	CTRL_FLAG_APPLESINGLE = 0x40,
	CTRL_FLAG_APPLEDOUBLE = 0x60,
	CTRL_FLAG_TEXTONLY = 0x06,
	CTRL_FLAG_HTMLONLY = 0x0E,
	CTRL_FLAG_TEXTANDHTML = 0x16,
	CTRL_FLAG_NORICH = 0x01,
	CTRL_FLAG_UNICODE = 0x8000,
	CTRL_FLAG_DONTLOOKUP = 0x1000,
};

enum display_type {
	/* Not all of these are represented in PR_DISPLAY_TYPE_EX (since there is just room for one byte) */
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
	DT_MODIFIABLE = 0x1 << 16,
	DT_GLOBAL = 0x2 << 16,
	DT_LOCAL = 0x3 << 16,
	DT_WAN = 0x4 << 16,
	DT_NOT_SPECIFIC = 0x5 << 16,
	DT_FOLDER = 1 << 24,
	DT_FOLDER_LINK = 1 << 25,
	DT_FOLDER_SPECIAL = 1 << 26,

	DTE_FLAG_ACL_CAPABLE  = 1U << 30,
	DTE_FLAG_REMOTE_VALID = 1U << 31,
	DTE_MASK_REMOTE       = 0xFF00U,
	DTE_MASK_LOCAL        = 0xFFU,
};

enum {
	/* PR_CONTROL_FLAGS (PidTagControlFlags), MS-OXOABKT v14 §2.2.2.1.2 */
	_DT_NONE         = 0U, /* gromox-only */
	DT_MULTILINE     = 1U << 0,
	DT_EDITABLE      = 1U << 1,
	DT_REQUIRED      = 1U << 2,
	DT_SET_IMMEDIATE = 1U << 3,
	DT_PASSWORD_EDIT = 1U << 4,
	DT_ACCEPT_DBCS   = 1U << 5,
	DT_SET_SELECTION = 1U << 6,
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

enum {
	EVENT_TYPE_NEWMAIL = 1U << 1,
	EVENT_TYPE_OBJECTCREATED = 1U << 2,
	EVENT_TYPE_OBJECTDELETED = 1U << 3,
	EVENT_TYPE_OBJECTMODIFIED = 1U << 4,
	EVENT_TYPE_OBJECTMOVED = 1U << 5,
	EVENT_TYPE_OBJECTCOPIED = 1U << 6,
	EVENT_TYPE_SEARCHCOMPLETE = 1U << 7,
};

enum mapi_folder_type {
	FOLDER_ROOT = 0,
	FOLDER_GENERIC = 1,
	FOLDER_SEARCH = 2,
};

enum { /* for PR_FLAG_STATUS */
	followupComplete = 0x1U,
	followupFlagged = 0x2U,
};

enum mapi_importance {
	IMPORTANCE_LOW = 0,
	IMPORTANCE_NORMAL = 1,
	IMPORTANCE_HIGH = 2,
};

enum mapi_object_type {
	MAPI_STORE = 0x1,
	MAPI_ADDRBOOK = 0x2,
	MAPI_FOLDER = 0x3,
	MAPI_ABCONT = 0x4,
	MAPI_MESSAGE = 0x5,
	MAPI_MAILUSER = 0x6,
	MAPI_ATTACH = 0x7,
	MAPI_DISTLIST = 0x8,
	MAPI_PROFSECT = 0x9,
	MAPI_STATUS = 0xA,
	MAPI_SESSION = 0xB,
	MAPI_FORMINFO = 0xC,
};

enum mapi_recipient_type {
	MAPI_ORIG = 0U,
	MAPI_TO = 1U,
	MAPI_CC = 2U,
	MAPI_BCC = 3U,
	MAPI_P1 = 1U << 28, /* a need to resend */
	MAPI_SUBMITTED = 1U << 31, /* no need to resend */
};

enum mapi_sensitivity {
	SENSITIVITY_NONE = 0,
	SENSITIVITY_PERSONAL = 1,
	SENSITIVITY_PRIVATE = 2,
	SENSITIVITY_COMPANY_CONFIDENTIAL = 3,
};

enum {
	MNID_ID = 0,
	MNID_STRING = 1,
	KIND_NONE = 0xff,
};

enum {
	MODRECIP_ADD = 1U << 1,
	MODRECIP_MODIFY = 1U << 2,
	MODRECIP_REMOVE = 1U << 3,
};

enum {
	MSGFLAG_READ               = 1U << 0,
	MSGFLAG_UNMODIFIED         = 1U << 1, /* mfUnmodified */
	MSGFLAG_SUBMITTED          = 1U << 2, /* mfSubmitted */
	MSGFLAG_UNSENT             = 1U << 3,
	MSGFLAG_HASATTACH          = 1U << 4, /* mfHasAttach */
	MSGFLAG_FROMME             = 1U << 5, /* mfFromMe */
	MSGFLAG_ASSOCIATED         = 1U << 6, /* mfFAI */
	MSGFLAG_RESEND             = 1U << 7,
	MSGFLAG_RN_PENDING         = 1U << 8, /* mfNotifyRead */
	MSGFLAG_NRN_PENDING        = 1U << 9, /* mfNotifyUnread */
	MSGFLAG_EVERREAD           = 1U << 10, /* mfEverRead */
	MSGFLAG_ORIGIN_X400        = 1U << 12,
	MSGFLAG_ORIGIN_INTERNET    = 1U << 13, /* mfInternet */
	MSGFLAG_ORIGIN_MISC_EXT    = 1U << 15, /* mfUntrusted */
	MSGFLAG_OUTLOOK_NON_EMS_XP = 1U << 16,
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
	OPENSTORE_USE_ADMIN_PRIVILEGE              = 1U << 0,
	OPENSTORE_PUBLIC                           = 1U << 1,
	OPENSTORE_HOME_LOGON                       = 1U << 2,
	OPENSTORE_TAKE_OWNERSHIP                   = 1U << 3,
	OPENSTORE_OVERRIDE_HOME_MDB                = 1U << 4,
	OPENSTORE_TRANSPORT                        = 1U << 5,
	OPENSTORE_REMOTE_TRANSPORT                 = 1U << 6,
	OPENSTORE_INTERNET_ANONYMOUS               = 1U << 7,
	OPENSTORE_ALTERNATE_SERVER                 = 1U << 8,
	OPENSTORE_IGNORE_HOME_MDB                  = 1U << 9,
	OPENSTORE_NO_MAIL                          = 1U << 10,
	OPENSTORE_OVERRIDE_LAST_MODIFIER           = 1U << 11,
	OPENSTORE_CALLBACK_LOGON                   = 1U << 12,
	OPENSTORE_LOCAL                            = 1U << 13,
	OPENSTORE_FAIL_IF_NO_MAILBOX               = 1U << 14,
	OPENSTORE_CACHE_EXCHANGE                   = 1U << 15,
	OPENSTORE_CLI_WITH_NAMEDPROP_FIX           = 1U << 16,
	OPENSTORE_ENABLE_LAZY_LOGGING              = 1U << 17,
	OPENSTORE_CLI_WITH_REPLID_GUID_MAPPING_FIX = 1U << 18,
	OPENSTORE_NO_LOCALIZATION                  = 1U << 19,
	OPENSTORE_RESTORE_DATABASE                 = 1U << 20,
	OPENSTORE_XFOREST_MOVE                     = 1U << 21,
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
	recipOriginal            = 0x100U,
};

enum relop {
	RELOP_LT = 0x00,
	RELOP_LE,
	RELOP_GT,
	RELOP_GE,
	RELOP_EQ,
	RELOP_NE,
	RELOP_RE,
	RELOP_MEMBER_OF_DL = 0x64,
};

enum res_type {
	RES_AND = 0x00,
	RES_OR = 0x01,
	RES_NOT = 0x02,
	RES_CONTENT = 0x03,
	RES_PROPERTY = 0x04,
	RES_PROPCOMPARE = 0x05,
	RES_BITMASK = 0x06,
	RES_SIZE = 0x07,
	RES_EXIST = 0x08,
	RES_SUBRESTRICTION = 0x09,
	RES_COMMENT = 0x0a,
	RES_COUNT = 0x0b,
	/* https://docs.microsoft.com/en-us/archive/blogs/stephen_griffin/new-restriction-types-seen-in-wrapped-psts */
	RES_ANNOTATION = 0x0c,
	RES_NULL = 0xff, /* aka NULL_RESTRICTION */
};

enum {
	/* right bits */
	frightsReadAny              = 1U << 0, /* 0x001 */
	frightsCreate               = 1U << 1, /* 0x002 */
	frightsGromoxSendAs         = 1U << 2, /* 0x004 */
	frightsEditOwned            = 1U << 3, /* 0x008 */
	frightsDeleteOwned          = 1U << 4, /* 0x010 */
	frightsEditAny              = 1U << 5, /* 0x020 */
	frightsDeleteAny            = 1U << 6, /* 0x040 */
	frightsCreateSubfolder      = 1U << 7, /* 0x080 */
	frightsOwner                = 1U << 8, /* 0x100, "all of the above 8" (i.e. redundant flag?) */
	frightsContact              = 1U << 9, /* 0x200 */
	frightsVisible              = 1U << 10, /* 0x400 */
	frightsFreeBusySimple       = 1U << 11, /* 0x800, cf. IExchangeModifyTable */
	frightsFreeBusyDetailed     = 1U << 12, /* 0x1000, cf. IExchangeModifyTable */
	/*
	 * Special bit that can be set on *IPM_SUBTREE* to toggle the OWNER bit
	 * on *store_object/logon_object* (since Outlook only shows
	 * IPM_SUBTREE / and Gromox has no store-level permission bits really).
	 */
	frightsGromoxStoreOwner     = 1U << 13, /* 0x2000 */

	/* right sets as per edkmdb */
	rightsNone = 0,
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
};

enum { /* ROWENTRY::ulRowFlags bits */
	ROW_ADD    = 1U << 0,
	ROW_MODIFY = 1U << 1,
	ROW_REMOVE = 1U << 2,
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
	STORE_ENTRYID_UNIQUE    = 1U << 0,
	STORE_READONLY          = 1U << 1,
	STORE_SEARCH_OK         = 1U << 2,
	STORE_MODIFY_OK         = 1U << 3,
	STORE_CREATE_OK         = 1U << 4,
	STORE_ATTACH_OK         = 1U << 5,
	STORE_OLE_OK            = 1U << 6,
	STORE_SUBMIT_OK         = 1U << 7,
	STORE_NOTIFY_OK         = 1U << 8,
	STORE_MV_PROPS_OK       = 1U << 9,
	STORE_CATEGORIZE_OK     = 1U << 10,
	STORE_RTF_OK            = 1U << 11,
	STORE_RESTRICTION_OK    = 1U << 12,
	STORE_SORT_OK           = 1U << 13,
	STORE_PUBLIC_FOLDERS    = 1U << 14,
	STORE_UNCOMPRESSED_RTF  = 1U << 15,
	STORE_HTML_OK           = 1U << 16,
	STORE_ANSI_OK           = 1U << 17,
	STORE_UNICODE_OK        = 1U << 18,
	STORE_LOCALSTORE        = 1U << 19,
	STORE_ITEMPROC          = 1U << 21,
	// ??                   = 1U << 22, /* Exch 2019 does present this */
	STORE_PUSHER_OK         = 1U << 23,
	STORE_HAS_SEARCHES      = 1U << 24,
	STORE_FULLTEXT_QUERY_OK = 1U << 25,
	STORE_FILTER_SEARCH_OK  = 1U << 26,
	STORE_RULES_OK          = 1U << 28,
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

enum zics_type {
	ICS_TYPE_CONTENTS = 1,
	ICS_TYPE_HIERARCHY = 2,
};

enum zmapi_group {
	/* Zend resource type groups */
	ZMG_ROOT = 0,
	ZMG_TABLE = 1,
	ZMG_MESSAGE = 2,
	ZMG_ATTACH = 3,
	ZMG_ABCONT = 4,
	ZMG_FOLDER = 5,
	ZMG_SESSION = 6,
	ZMG_ADDRBOOK = 7,
	ZMG_STORE = 8,
	ZMG_MAILUSER = 9,
	ZMG_DISTLIST = 10,
	ZMG_PROFPROPERTY = 11,
	ZMG_ADVISESINK = 12,
	ZMG_ICSDOWNCTX = 13,
	ZMG_ICSUPCTX = 14,
	ZMG_INVALID = 255,
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

enum {
	DEL_MESSAGES = 1U << 0,
	DEL_FOLDERS = 1U << 2,
	DEL_ASSOCIATED = 1U << 3, /* MAPI only, not used in OXCROPS. */
	DELETE_HARD_DELETE = 1U << 4, /* undocumented on MSDN */
};

enum {
	FL_FULLSTRING = 0,
	FL_SUBSTRING,
	FL_PREFIX,

	FL_PREFIX_ON_ANY_WORD = 1U << 4, /* split value and attempt match on each word */
	FL_PHRASE_MATCH       = 1U << 5, /* match exact words and in order only */
	FL_IGNORECASE         = 1U << 16,
	FL_IGNORENONSPACE     = 1U << 17,
	FL_LOOSE              = 1U << 18,
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
	MAXIMUM_SORT_COUNT = 8,
};

enum zaccess_type {
	ACCESS_TYPE_DENIED = 1,
	ACCESS_TYPE_GRANT = 2,
	ACCESS_TYPE_BOTH = 3,
};

enum {
	RIGHT_NORMAL = 0,
	RIGHT_NEW = 1U << 0,
	RIGHT_MODIFY = 1U << 1,
	RIGHT_DELETED = 1U << 2,
	RIGHT_AUTOUPDATE_DENIED = 1U << 3,
};

struct eid_t {
	eid_t() = default;
	constexpr eid_t(uint64_t v) : m_value(v) {}
	constexpr operator uint64_t() const { return m_value; }
	void operator=(uint64_t) = delete;
	uint64_t m_value;
};

struct ACTION_BLOCK {
	uint16_t length;
	uint8_t type;
	uint32_t flavor;
	uint32_t flags;
	void *pdata;
};

struct ADVISE_INFO {
	uint32_t hstore;
	uint32_t sub_id;
};

/*
 * @pv:		may legitimately be nullptr (only if cb==0)
 */
struct BINARY {
	union {
		uint32_t cb, length;
	};
	union {
		union {
			uint8_t *pb, *data;
		};
		union {
			char *pc, *cdata;
		};
		union {
			void *pv, *vdata;
		};
	};

	int compare(const BINARY &) const;
};
using DATA_BLOB = BINARY;

struct BINARY_ARRAY {
	uint32_t count;
	BINARY *pbin;
};

struct DOUBLE_ARRAY {
	uint32_t count;
	double *mval;
};

/**
 * The host-endian view of struct GUID is often not needed, and so a plethora
 * of GUIDs exist as bytearrays/FLATUID, mostly when the consumer does not care
 * about internal layout.
 */
struct FLATUID {
	uint8_t ab[16];
#if __cplusplus >= 202000L && defined(__GNUG__) >= 13
	/* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=103733 */
	bool operator==(const FLATUID &) const = default;
#else
	inline bool operator==(const FLATUID &o) const { return memcmp(ab, o.ab, sizeof(ab)) == 0; }
	inline bool operator!=(const FLATUID &o) const { return !operator==(o); }
#endif
};

struct FLATUID_ARRAY {
	uint32_t cvalues;
	FLATUID **ppguid;
};

struct FLOAT_ARRAY {
	uint32_t count;
	float *mval;
};

struct GLOBCNT {
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
struct GUID {
	void to_str(char *, size_t, unsigned int type = 36) const;
	bool from_str(const char *);
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

struct GUID_ARRAY {
	uint32_t count;
	GUID *pguid;
};

struct LONG_ARRAY {
	uint32_t count;
	uint32_t *pl;
};

struct LONGLONG_ARRAY {
	uint32_t count;
	uint64_t *pll;
};

struct LPROPTAG_ARRAY {
	uint32_t cvalues;
	uint32_t *pproptag;
};

struct MESSAGE_STATE {
	BINARY source_key;
	uint32_t message_flags;
};

struct NOTIF_SINK {
	GUID hsession;
	uint16_t count;
	ADVISE_INFO *padvise;
};

struct ONEOFF_ENTRYID {
	uint32_t flags;
	uint16_t version; /* should be 0x0000 */
	uint16_t ctrl_flags;
	char *pdisplay_name;
	char *paddress_type;
	char *pmail_address;
};

struct ONEOFF_ARRAY {
	uint32_t count;
	ONEOFF_ENTRYID *pentry_id;
};

struct PERMISSION_ROW {
	uint32_t flags;
	BINARY entryid;
	uint32_t member_rights;
};

struct PERMISSION_SET {
	uint16_t count;
	PERMISSION_ROW *prows;
};

struct PROPERTY_NAME {
	uint8_t kind;
	GUID guid;
	uint32_t lid;
	char *pname;
};

struct PROPERTY_XNAME {
	PROPERTY_XNAME() = default;
	PROPERTY_XNAME(const PROPERTY_NAME &);
	explicit operator PROPERTY_NAME() const;

	uint8_t kind = KIND_NONE;
	uint32_t lid = 0;
	GUID guid{};
	std::string name;
};

struct PROPID_ARRAY {
	uint16_t count;
	uint16_t *ppropid;
};

struct PROPNAME_ARRAY {
	uint16_t count;
	PROPERTY_NAME *ppropname;
};

struct PROPTAG_ARRAY {
	size_t indexof(uint32_t tag) const;
	inline bool has(uint32_t tag) const { return indexof(tag) != npos; }

	uint16_t count;
	uint32_t *pproptag;
	static constexpr size_t npos = -1;
};

struct SHORT_ARRAY {
	uint32_t count;
	uint16_t *ps;
};

struct SORT_ORDER {
	uint16_t type; /* pay attention to the 0x2000 bit */
	uint16_t propid;
	uint8_t table_sort;
};

struct SORTORDER_SET {
	uint16_t count;
	uint16_t ccategories;
	uint16_t cexpanded;
	SORT_ORDER *psort;
};

struct STATE_ARRAY {
	uint32_t count;
	MESSAGE_STATE *pstate;
};

struct STRING_ARRAY {
	uint32_t count;
	char **ppstr;
};

struct SVREID {
	BINARY *pbin;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t instance;

	int compare(const SVREID &) const;
};

struct TAGGED_PROPVAL {
	uint32_t proptag;
	void *pvalue;

	std::string repr() const;
};

struct tarray_set;
struct TPROPVAL_ARRAY;
extern GX_EXPORT TPROPVAL_ARRAY *tpropval_array_init();
extern GX_EXPORT void tpropval_array_free(TPROPVAL_ARRAY *);
extern GX_EXPORT bool tpropval_array_init_internal(TPROPVAL_ARRAY *);
extern GX_EXPORT void tpropval_array_free_internal(TPROPVAL_ARRAY *);
extern GX_EXPORT tarray_set *tarray_set_init();
extern GX_EXPORT void tarray_set_free(tarray_set *);

struct TPROPVAL_ARRAY {
	TAGGED_PROPVAL *find(uint32_t tag) const {
		for (size_t i = 0; i < count; ++i)
			if (ppropval[i].proptag == tag)
				return &ppropval[i];
		return nullptr;
	}
	inline bool has(uint32_t tag) const { return find(tag) != nullptr; }
	inline void *getval(uint32_t tag) const {
		auto v = find(tag);
		return v != nullptr ? v->pvalue : nullptr;
	}
	template<typename T> inline T *get(uint32_t tag) const { return static_cast<T *>(getval(tag)); }
	int set(uint32_t tag, const void *d);
	inline int set(const TAGGED_PROPVAL &a) { return set(a.proptag, a.pvalue); }
	void erase(uint32_t tag);
	TPROPVAL_ARRAY *dup() const;

	uint16_t count;
	TAGGED_PROPVAL *ppropval;
};

struct mapidefs1_del {
	inline void operator()(TPROPVAL_ARRAY *x) const { tpropval_array_free(x); }
};

using tpropval_array_ptr = std::unique_ptr<TPROPVAL_ARRAY, mapidefs1_del>;

struct LTPROPVAL_ARRAY {
	uint32_t count;
	TAGGED_PROPVAL *propval;
};

struct tarray_set {
	void erase(uint32_t index);
	TPROPVAL_ARRAY *emplace();
	inline TPROPVAL_ARRAY *back() { return pparray[count-1]; }
	inline const TPROPVAL_ARRAY *back() const { return pparray[count-1]; }
	int append_move(tpropval_array_ptr &&);
	tarray_set *dup() const;

	uint32_t count;
	TPROPVAL_ARRAY **pparray;
};
using TARRAY_SET = tarray_set;

struct NEWMAIL_ZNOTIFICATION {
	BINARY entryid;
	BINARY parentid;
	uint32_t flags; /* unicode or not */
	char *message_class;
	uint32_t message_flags;
};

struct OBJECT_ZNOTIFICATION {
	uint32_t object_type;
	BINARY *pentryid;
	BINARY *pparentid;
	BINARY *pold_entryid;
	BINARY *pold_parentid;
	PROPTAG_ARRAY *pproptags;
};

struct RECIPIENT_BLOCK {
	uint8_t reserved;
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
};

struct RESTRICTION_AND_OR;
struct RESTRICTION_NOT;
struct RESTRICTION_CONTENT;
struct RESTRICTION_PROPERTY;
struct RESTRICTION_PROPCOMPARE;
struct RESTRICTION_BITMASK;
struct RESTRICTION_SIZE;
struct RESTRICTION_EXIST;
struct RESTRICTION_SUBOBJ;
struct RESTRICTION_COMMENT;
struct RESTRICTION_COUNT;

struct RESTRICTION {
	enum res_type rt;
	union {
		void *pres;
		RESTRICTION_AND_OR *andor;
		RESTRICTION_NOT *xnot;
		RESTRICTION_CONTENT *cont;
		RESTRICTION_PROPERTY *prop;
		RESTRICTION_PROPCOMPARE *pcmp;
		RESTRICTION_BITMASK *bm;
		RESTRICTION_SIZE *size;
		RESTRICTION_EXIST *exist;
		RESTRICTION_SUBOBJ *sub;
		RESTRICTION_COMMENT *comment;
		RESTRICTION_COUNT *count;
	};

	std::string repr() const;
};

struct RESTRICTION_AND_OR {
	uint32_t count;
	RESTRICTION *pres;

	std::string repr() const;
};

struct RESTRICTION_NOT {
	RESTRICTION res;

	std::string repr() const;
};

struct RESTRICTION_CONTENT {
	uint32_t fuzzy_level;
	uint32_t proptag;
	TAGGED_PROPVAL propval;

	std::string repr() const;
};

struct RESTRICTION_PROPERTY {
	enum relop relop;
	uint32_t proptag;
	/*
	 * propval.proptag is only used for proptype information, the propid is
	 * ignored, but generally the same as RESTRICTION_PROPERTY::proptag.
	 */
	TAGGED_PROPVAL propval;

	std::string repr() const;
};

struct RESTRICTION_PROPCOMPARE {
	enum relop relop;
	uint32_t proptag1;
	uint32_t proptag2;

	std::string repr() const;
};

struct RESTRICTION_BITMASK {
	enum bm_relop bitmask_relop;
	uint32_t proptag;
	uint32_t mask;

	std::string repr() const;
};

struct RESTRICTION_SIZE {
	enum relop relop;
	uint32_t proptag;
	uint32_t size;

	std::string repr() const;
};

struct RESTRICTION_EXIST {
	uint32_t proptag;

	std::string repr() const;
};

struct RESTRICTION_SUBOBJ {
	uint32_t subobject;
	RESTRICTION res;

	std::string repr() const;
};

struct RESTRICTION_COMMENT {
	uint8_t count;
	TAGGED_PROPVAL *ppropval;
	RESTRICTION *pres;

	std::string repr() const;
};

struct RESTRICTION_COUNT {
	uint32_t count;
	RESTRICTION sub_res;

	std::string repr() const;
};

struct RULE_ACTIONS {
	uint16_t count;
	ACTION_BLOCK *pblock;
};

struct RULE_DATA {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
};

struct RULE_LIST {
	uint16_t count;
	RULE_DATA *prule;
};

struct ZMOVECOPY_ACTION {
	BINARY store_eid; /* zarafa specific */
	BINARY folder_eid; /* zarafa specific */
};

struct ZNOTIFICATION {
	uint32_t event_type;
	void *pnotification_data; /* NEWMAIL_ZNOTIFICATION or OBJECT_ZNOTIFICATION */
};

struct ZNOTIFICATION_ARRAY {
	uint16_t count;
	ZNOTIFICATION **ppnotification;
};

/* reply or OOF action */
struct ZREPLY_ACTION {
	BINARY message_eid; /* zarafa specific */
	GUID template_guid;
};

struct FORWARDDELEGATE_ACTION {
	uint16_t count;
	RECIPIENT_BLOCK *pblock;
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

extern const FLATUID
	muidStoreWrap, muidEMSAB, pbLongTermNonPrivateGuid,
	g_muidStorePrivate, g_muidStorePublic, muidOOP,
	muidECSAB, muidZCSAB, EncodedGlobalId, IID_IStorage,
	IID_IStream, IID_IMessage, IID_IExchangeExportChanges,
	IID_IExchangeImportContentsChanges, IID_IExchangeImportHierarchyChanges;
extern const GUID
	PSETID_ADDRESS, PSETID_AIRSYNC, PSETID_APPOINTMENT, PSETID_ATTACHMENT,
	PSETID_BUSINESSCARDVIEW, PSETID_COMMON, PSETID_GROMOX, PSETID_KC,
	PSETID_KCARCHIVE, PSETID_LOG, PSETID_MEETING, PSETID_MESSAGING,
	PSETID_NOTE, PSETID_POSTRSS, PSETID_REMOTE, PSETID_REPORT,
	PSETID_SHARING, PSETID_TASK, PSETID_UNIFIEDMESSAGING,
	PSETID_XMLEXTRACTEDENTITIES, PS_INTERNET_HEADERS, PS_MAPI,
	PS_PUBLIC_STRINGS;
extern const uint8_t MACBINARY_ENCODING[9], OLE_TAG[11], ThirdPartyGlobalId[12];
