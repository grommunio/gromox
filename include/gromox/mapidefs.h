#pragma once
#include <cstdint>

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
	PT_UNSPECIFIED = 0x0000, /* VT_EMPTY */
	PT_NULL = 0x0001, /* VT_NULL */
	PT_SHORT = 0x0002, /* VT_I2, PT_I2 */
	PT_LONG = 0x0003, /* VT_I4, PT_I4 */
	PT_FLOAT = 0x0004, /* VT_R4, PT_R4 */
	PT_DOUBLE = 0x0005, /* VT_R8, PT_R8 */
	PT_CURRENCY = 0x0006, /* VT_CY */
	PT_APPTIME = 0x0007, /* VT_DATE */
	PT_ERROR = 0x000A, /* VT_ERROR */
	PT_BOOLEAN = 0x000B, /* VT_BOOL */
	PT_OBJECT = 0x000D, /* VT_UNKNOWN */
	// VT_I1 = 0x0010,
	// VT_UI1 = 0x0011,
	// VT_UI2 = 0x0012,
	// VT_UI4 = 0x0013,
	PT_I8 = 0x0014, /* VT_I8 */
	// VT_UI8 = 0x0015,
	PT_STRING8 = 0x001E, /* VT_LPSTR */
	PT_UNICODE = 0x001F, /* VT_LPWSTR */
	PT_SYSTIME = 0x0040, /* VT_FILETIME */
	PT_CLSID = 0x0048, /* VT_CLSID */
	PT_SVREID = 0x00FB, /* MS-OXCDATA extension */
	PT_SRESTRICT = 0x00FD, /* edkmdb.h extension */
	PT_ACTIONS = 0x00FE, /* edkmdb.h extension */
	PT_BINARY = 0x0102,
	PT_MV_SHORT = 0x1002, /* PT_MV_I2 */
	PT_MV_LONG = 0x1003, /* PT_MV_I4 */
	PT_MV_FLOAT = 0x1004, /* PT_MV_R4 */
	PT_MV_DOUBLE = 0x1005, /* PT_MV_R8 */
	PT_MV_CURRENCY = 0x1006, /* PT_MV_CURRENCY */
	PT_MV_APPTIME = 0x1007, /* PT_MV_APPTIME */
	PT_MV_I8 = 0x1014,
	PT_MV_STRING8 = 0x101E,
	PT_MV_UNICODE = 0x101F,
	PT_MV_SYSTIME = 0x1040,
	PT_MV_CLSID = 0x1048,
	PT_MV_BINARY = 0x1102,
};

enum {
	MV_FLAG = 0x1000,
	MV_INSTANCE = 0x2000,
	MVI_FLAG = MV_FLAG | MV_INSTANCE,
};

enum {
	PR_PARENT_KEY = PROP_TAG(PT_BINARY, 0x0025), /* PidTagParentKey */
	PR_SUBJECT_A = PROP_TAG(PT_STRING8, 0x0037),
	PR_SUBJECT = PROP_TAG(PT_UNICODE, 0x0037), /* PidTagSubject */
	PR_SUBJECT_PREFIX_A = PROP_TAG(PT_STRING8, 0x003D),
	PR_SUBJECT_PREFIX = PROP_TAG(PT_UNICODE, 0x003D), /* PidTagSubjectPrefix */
	PR_NORMALIZED_SUBJECT_A = PROP_TAG(PT_STRING8, 0x0E1D),
	PR_NORMALIZED_SUBJECT = PROP_TAG(PT_UNICODE, 0x0E1D), /* PidTagNormalizedSubject */
	PR_DISPLAY_BCC_A = PROP_TAG(PT_STRING8, 0x0E02),
	PR_DISPLAY_BCC = PROP_TAG(PT_UNICODE, 0x0E02), /* PidTagDisplayBcc */
	PR_DISPLAY_CC_A = PROP_TAG(PT_STRING8, 0x0E03),
	PR_DISPLAY_CC = PROP_TAG(PT_UNICODE, 0x0E03), /* PidTagDisplayCc */
	PR_DISPLAY_TO_A = PROP_TAG(PT_STRING8, 0x0E04),
	PR_DISPLAY_TO = PROP_TAG(PT_UNICODE, 0x0E04), /* PidTagDisplayTo */
	PR_PARENT_DISPLAY_A = PROP_TAG(PT_STRING8, 0x0E05),
	PR_PARENT_DISPLAY = PROP_TAG(PT_UNICODE, 0x0E05), /* PidTagParentDisplay */
	PR_MESSAGE_FLAGS = PROP_TAG(PT_LONG, 0x0E07), /* PidTagMessageFlags */
	PR_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x0E08), /* PidTagMessageSize */
	PR_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x0E08), /* PidTagMessageSizeExtended */
	PR_PARENT_ENTRYID = PROP_TAG(PT_BINARY, 0x0E09), /* PidTagParentEntryId */
	PR_PARENT_SVREID = PROP_TAG(PT_SVREID, 0x0E09),
	PR_MESSAGE_RECIPIENTS = PROP_TAG(PT_OBJECT, 0x0E12), /* PidTagMessageRecipients */
	PR_MESSAGE_ATTACHMENTS = PROP_TAG(PT_OBJECT, 0x0E13), /* PidTagMessageAttachments */
	PR_REPL_ITEMID = PROP_TAG(PT_LONG, 0x0E30), /* PidTagReplItemId */
	PR_REPL_CHANGENUM = PROP_TAG(PT_I8, 0x0E33), /* PidTagReplChangenum */
	PR_REPL_VERSIONHISTORY = PROP_TAG(PT_BINARY, 0x0E34), /* PidTagReplVersionhistory */
	PR_REPL_FLAGS = PROP_TAG(PT_LONG, 0x0E38), /* PidTagReplFlags */
	PR_REPL_COPIEDFROM_VERSIONHISTORY = PROP_TAG(PT_BINARY, 0x0E3C), /* PidTagReplCopiedfromVersionhistory */
	PR_REPL_COPIEDFROM_ITEMID = PROP_TAG(PT_BINARY, 0x0E3D), /* PidTagReplCopiedfromItemid */
	PR_READ = PROP_TAG(PT_BOOLEAN, 0x0E69), /* PidTagRead */
	PR_ACCESS = PROP_TAG(PT_LONG, 0x0FF4), /* PidTagAccess */
	PR_ACCESS_LEVEL = PROP_TAG(PT_LONG, 0x0FF7), /* PidTagAccessLevel */
	PR_MAPPING_SIGNATURE = PROP_TAG(PT_BINARY, 0x0FF8), /* PidTagMappingSignature */
	PR_STORE_RECORD_KEY = PROP_TAG(PT_BINARY, 0x0FFA), /* PidTagStoreRecordKey */
	PR_STORE_ENTRYID = PROP_TAG(PT_BINARY, 0x0FFB), /* PidTagStoreEntryId */
	PR_RECORD_KEY = PROP_TAG(PT_BINARY, 0x0FF9), /* PidTagRecordKey */
	PR_OBJECT_TYPE = PROP_TAG(PT_LONG, 0x0FFE), /* PidTagObjectType */
	PR_ENTRYID = PROP_TAG(PT_BINARY, 0x0FFF), /* PidTagEntryId */
	PR_BODY_A = PROP_TAG(PT_STRING8, 0x1000),
	PR_BODY_W = PROP_TAG(PT_UNICODE, 0x1000),
	PR_BODY = PR_BODY_W, /* PidTagBody */
	PR_HTML = PROP_TAG(PT_BINARY, 0x1013), /* PidTagHtml */
	PR_RTF_COMPRESSED = PROP_TAG(PT_BINARY, 0x1009), /* PidTagRtfCompressed */
	PR_DISPLAY_NAME_A = PROP_TAG(PT_STRING8, 0x3001),
	PR_DISPLAY_NAME = PROP_TAG(PT_UNICODE, 0x3001), /* PidTagDisplayName */
	PR_EMAIL_ADDRESS_A = PROP_TAG(PT_STRING8, 0x3003),
	PR_EMAIL_ADDRESS = PROP_TAG(PT_UNICODE, 0x3003), /* PidTagEmailAddress */
	PR_PROVIDER_DISPLAY = PROP_TAG(PT_UNICODE, 0x3006), /* PidTagProviderDisplay */
	PR_CREATION_TIME = PROP_TAG(PT_SYSTIME, 0x3007), /* PidTagCreationTime */
	PR_LAST_MODIFICATION_TIME = PROP_TAG(PT_SYSTIME, 0x3008), /* PidTagLastModificationTime */
	PR_RESOURCE_FLAGS = PROP_TAG(PT_LONG, 0x3009), /* PidTagResourceFlags */
	PR_STORE_STATE = PROP_TAG(PT_LONG, 0x340E), /* PidTagStoreState */
	PR_STORE_SUPPORT_MASK = PROP_TAG(PT_LONG, 0x340D), /* PidTagStoreSupportMask */
	PR_MDB_PROVIDER = PROP_TAG(PT_BINARY, 0x3414), /* PidTagStoreProvider */
	PR_DISPLAY_NAME_PREFIX_A = PROP_TAG(PT_STRING8, 0x3A45),
	PR_DISPLAY_NAME_PREFIX = PROP_TAG(PT_UNICODE, 0x3A45), /* PidTagDisplayNamePrefix */
	PR_IPM_SUBTREE_ENTRYID = PROP_TAG(PT_BINARY, 0x35E0), /* PidTagIpmSubtreeEntryId */
	PR_IPM_OUTBOX_ENTRYID = PROP_TAG(PT_BINARY, 0x35E2), /* PidTagIpmOutboxEntryId */
	PR_IPM_WASTEBASKET_ENTRYID = PROP_TAG(PT_BINARY, 0x35E3), /* PidTagIpmWastebasketEntryId */
	PR_IPM_SENTMAIL_ENTRYID = PROP_TAG(PT_BINARY, 0x35E4), /* PidTagIpmSentMailEntryId */
	PR_VIEWS_ENTRYID = PROP_TAG(PT_BINARY, 0x35E5), /* PidTagViewsEntryId */
	PR_COMMON_VIEWS_ENTRYID = PROP_TAG(PT_BINARY, 0x35E6), /* PidTagCommonViewsEntryId */
	PR_FINDER_ENTRYID = PROP_TAG(PT_BINARY, 0x35E7), /* PidTagFinderEntryId */
	PR_DETAILS_TABLE  = PROP_TAG(PT_OBJECT, 0x3605), /* PidTagDetailsTable */
	PR_IPM_APPOINTMENT_ENTRYID = PROP_TAG(PT_BINARY, 0x36D0), /* PidTagIpmAppointmentEntryId */
	PR_IPM_CONTACT_ENTRYID = PROP_TAG(PT_BINARY, 0x36D1), /* PidTagIpmContactEntryId */
	PR_IPM_JOURNAL_ENTRYID = PROP_TAG(PT_BINARY, 0x36D2), /* PidTagIpmJournalEntryId */
	PR_IPM_NOTE_ENTRYID = PROP_TAG(PT_BINARY, 0x36D3), /* PidTagIpmNoteEntryId */
	PR_IPM_TASK_ENTRYID = PROP_TAG(PT_BINARY, 0x36D4), /* PidTagIpmTaskEntryId */
	PR_IPM_DRAFTS_ENTRYID = PROP_TAG(PT_BINARY, 0x36D7), /* PidTagIpmDraftsEntryId */
	PR_ADDITIONAL_REN_ENTRYIDS = PROP_TAG(PT_MV_BINARY, 0x36D8), /* PidTagAdditionalRenEntryIds */
	PR_ADDITIONAL_REN_ENTRYIDS_EX = PROP_TAG(PT_BINARY, 0x36D9), /* PidTagAdditionalRenEntryIdsEx */
	PR_FREEBUSY_ENTRYIDS = PROP_TAG(PT_MV_BINARY, 0x36E4), /* PidTagFreeBusyEntryIds */
	PR_ATTACH_DATA_BIN = PROP_TAG(PT_BINARY, 0x3701), /* PidTagAttachDataBinary */
	PR_ATTACH_DATA_OBJ = PROP_TAG(PT_OBJECT, 0x3701), /* PidTagAttachDataObject */
	PR_ATTACH_EXTENSION_A = PROP_TAG(PT_STRING8, 0x3703),
	PR_ATTACH_EXTENSION = PROP_TAG(PT_UNICODE, 0x3703), /* PidTagAttachExtension */
	PR_ATTACH_FILENAME_A = PROP_TAG(PT_STRING8, 0x3704),
	PR_ATTACH_FILENAME = PROP_TAG(PT_UNICODE, 0x3704), /* PidTagAttachFilename (8.3 format) */
	PR_ATTACH_LONG_FILENAME_A = PROP_TAG(PT_STRING8, 0x3707),
	PR_ATTACH_LONG_FILENAME = PROP_TAG(PT_UNICODE, 0x3707), /* PidTagAttachLongFilename */
	PR_ATTACH_LONG_PATHNAME_A = PROP_TAG(PT_STRING8, 0x370D),
	PR_ATTACH_LONG_PATHNAME = PROP_TAG(PT_UNICODE, 0x370D), /* PidTagAttachLongPathname */
	PR_DISPLAY_TYPE = PROP_TAG(PT_LONG, 0x3900), /* PidTagDisplayType */
	PR_DISPLAY_TYPE_EX = PROP_TAG(PT_LONG, 0x3905), /* PidTagDisplayTypeEx */
	PR_SMTP_ADDRESS = PROP_TAG(PT_UNICODE, 0x39FE), /* PidTagSmtpAddress */
	PR_RESOURCE_TYPE = PROP_TAG(PT_LONG, 0x3E03), /* PidTagResourceType */
	PR_CONTROL_FLAGS = PROP_TAG(PT_LONG, 0x3F02), /* PidTagControlFlags */
	PR_CONTROL_TYPE = PROP_TAG(PT_LONG, 0x3F02), /* PidTagControlType */
	PR_INTERNET_CPID = PROP_TAG(PT_LONG, 0x3FDE), /* PidTagInternetCodepage */
	PR_MESSAGE_CODEPAGE = PROP_TAG(PT_LONG, 0x3FFD), /* PidTagMessageCodepage */
	PR_MESSAGE_LOCALE_ID = PROP_TAG(PT_LONG, 0x3FF1), /* PidTagMessageLocaleId */
	PR_SOURCE_KEY = PROP_TAG(PT_BINARY, 0x65E0), /* PidTagSourceKey */
	PR_PARENT_SOURCE_KEY = PROP_TAG(PT_BINARY, 0x65E1), /* PidTagParentSourceKey */
	PR_CHANGE_KEY = PROP_TAG(PT_BINARY, 0x65E2), /* PidTagChangeKey */
	PR_PREDECESSOR_CHANGE_LIST = PROP_TAG(PT_BINARY, 0x65E3), /* PidTagPredecessorChangeList */
	PR_IPM_PUBLIC_FOLDERS_ENTRYID = PROP_TAG(PT_BINARY, 0x65E1),
	PR_USER_ENTRYID = PROP_TAG(PT_BINARY, 0x6619), /* PidTagUserEntryId */
	PR_MAILBOX_OWNER_ENTRYID = PROP_TAG(PT_BINARY, 0x661B), /* PidTagMailboxOwnerEntryId */
	PR_MAILBOX_OWNER_NAME = PROP_TAG(PT_UNICODE, 0x661C), /* PidTagMailboxOwnerName */
	PR_SCHEDULE_FOLDER_ENTRYID = PROP_TAG(PT_BINARY, 0x661E),
	PR_IPM_DAF_ENTRYID = PROP_TAG(PT_BINARY, 0x661F),
	PR_NON_IPM_SUBTREE_ENTRYID = PROP_TAG(PT_BINARY, 0x6620), /* PidTagNonIpmSubtreeEntryId */
	PR_EFORMS_REGISTRY_ENTRYID = PROP_TAG(PT_BINARY, 0x6621),
	PR_SPLUS_FREE_BUSY_ENTRYID = PROP_TAG(PT_BINARY, 0x6622), /* PidTagSchedulePlusFreeBusyEntryId */
	PR_OFFLINE_ADDRBOOK_ENTRYID = PROP_TAG(PT_BINARY, 0x6623),
	PR_TEST_LINE_SPEED = PROP_TAG(PT_BINARY, 0x662B),
	PR_IPM_FAVORITES_ENTRYID = PROP_TAG(PT_BINARY, 0x6630),
	PR_STORE_OFFLINE = PROP_TAG(PT_BOOLEAN, 0x6632),
	PR_PST_LRNORESTRICTIONS = PROP_TAG(PT_BOOLEAN, 0x6633), /* PidTagPstLrNoRestrictions */
	PR_HIERARCHY_SERVER_A = PROP_TAG(PT_STRING8, 0x6633),
	PR_HIERARCHY_SERVER_W = PROP_TAG(PT_UNICODE, 0x6633),
	PR_PROFILE_OAB_COUNT_ATTEMPTED_FULLDN = PROP_TAG(PT_LONG, 0x6635), /* PidTagProfileOabCountAttemptedFulldn */
	PR_PST_HIDDEN_COUNT = PROP_TAG(PT_LONG, 0x6635), /* PidTagPstHiddenCount */
	PR_FAVORITES_DEFAULT_NAME_A = PROP_TAG(PT_STRING8, 0x6635),
	PR_FAVORITES_DEFAULT_NAME_W = PROP_TAG(PT_UNICODE, 0x6635),
	PR_PST_HIDDEN_UNREAD = PROP_TAG(PT_LONG, 0x6636), /* PidTagPstHiddenUnread */
	PR_PROFILE_OAB_COUNT_ATTEMPTED_INCRDN = PROP_TAG(PT_LONG, 0x6636), /* PidTagProfileOabCountAttemptedIncrdn */
	PR_RIGHTS = PROP_TAG(PT_LONG, 0x6639), /* PidTagRights */
	PR_ADDRESS_BOOK_ENTRYID = PROP_TAG(PT_BINARY, 0x663B), /* PidTagAddressBookEntryId */
	PR_DELETED_MSG_COUNT = PROP_TAG(PT_LONG, 0x6640), /* PidTagDeletedMessageCount */
	PR_DELETED_FOLDER_COUNT = PROP_TAG(PT_LONG, 0x6641), /* MS-OXPROPS v0.2 §2.570 PidTagDeletedMessageCount */
	PR_DELETED_ASSOC_MSG_COUNT = PROP_TAG(PT_LONG, 0x6643), /* MS-OXPROPS v0.2 §2.568 PidTagDeletedAssociatedMessageCount */
	PR_DAM_ORIGINAL_ENTRYID = PROP_TAG(PT_BINARY, 0x6646), /* PidTagDamOriginalEntryId */
	PR_RULE_FOLDER_ENTRYID = PROP_TAG(PT_BINARY, 0x6651), /* PidTagRuleFolderEntryId */
	PR_MAX_SUBMIT_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x666D), /* PidTagMaximumSubmitMessageSize */
	PR_DELETED_ON = PROP_TAG(PT_SYSTIME, 0x668F), /* PidTagDeletedOn */
	PR_DELETED_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x669B),
	PR_DELETED_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x669B), /* MS-OXPROPS v0.2 §2.571 PidTagDeletedMessageSizeExtended */
	PR_DELETED_NORMAL_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x669C),
	PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x669C), /* MS-OXPROPS v0.2 §2.572 PidTagDeletedNormalMessageSizeExtended */
	PR_DELETED_ASSOC_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x669D),
	PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x669D), /* MS-OXPROPS v0.2 §2.569 PidTagDeletedAssociatedMessageSizeExtended */
	PR_LOCALE_ID = PROP_TAG(PT_LONG, 0x66A1), /* PidTagLocaleId */
	PR_NORMAL_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x66B3), /* MS-OXPROPS v0.2 §2.719 PidTagNormalMessageSize */
	PR_LATEST_PST_ENSURE = PROP_TAG(PT_LONG, 0x66FA), /* PidTagLatestPstEnsure */
	PR_DELETED_COUNT_TOTAL = PROP_TAG(PT_LONG, 0x670B), /* PidTagDeletedCountTotal */
	PR_OOF_STATE = PROP_TAG(PT_LONG, 0x6760), /* PidTagOutOfOfficeState */
	PR_EC_OUTOFOFFICE_MSG = PROP_TAG(PT_UNICODE, 0x6761), /* specific to zcore & grammm-web */
	PR_EC_OUTOFOFFICE_SUBJECT = PROP_TAG(PT_UNICODE, 0x6762),
	PR_EC_OUTOFOFFICE_FROM = PROP_TAG(PT_SYSTIME, 0x6763),
	PR_EC_OUTOFOFFICE_UNTIL = PROP_TAG(PT_SYSTIME, 0x6764),
	PR_EC_ALLOW_EXTERNAL = PROP_TAG(PT_BOOLEAN, 0x6765),
	PR_EC_EXTERNAL_AUDIENCE = PROP_TAG(PT_BOOLEAN, 0x6766),
	PR_EC_EXTERNAL_REPLY = PROP_TAG(PT_UNICODE, 0x6767),
	PR_EC_EXTERNAL_SUBJECT = PROP_TAG(PT_UNICODE, 0x6768),
	PR_LTP_ROW_ID = PROP_TAG(PT_LONG, 0x67F2), /* PidTagLtpRowId */
	PR_LTP_ROW_VER = PROP_TAG(PT_LONG, 0x67F3), /* PidTagLtpRowVer */
	PR_PST_PASSWORD = PROP_TAG(PT_LONG, 0x67FF), /* PidTagPstPassword */
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

enum bm_relop {
	BMR_EQZ = 0,
	BMR_NEZ,
};

enum calendar_scale {
	/* 0x1..0xC,0x17 from winnls.h, the others from MS-OXOCAL v18.1 §2.2.1.44.1 */
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
	/* one-off entryid flags, MS-OXCDATA v15.2 §2.2.5.1 */
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

enum {
	/* PR_CONTROL_FLAGS (PidTagControlFlags), MS-OXOABKT v12 §2.2.2.1.2 */
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
	MSGFLAG_UNMODIFIED         = 1U << 1,
	MSGFLAG_SUBMITTED          = 1U << 2,
	MSGFLAG_UNSENT             = 1U << 3,
	MSGFLAG_HASATTACH          = 1U << 4,
	MSGFLAG_FROMME             = 1U << 5,
	MSGFLAG_ASSOCIATED         = 1U << 6,
	MSGFLAG_RESEND             = 1U << 7,
	MSGFLAG_RN_PENDING         = 1U << 8,
	MSGFLAG_NRN_PENDING        = 1U << 9,
	MSGFLAG_EVERREAD           = 1U << 10, /* non-standard; custom use by groupwares */
	MSGFLAG_ORIGIN_X400        = 1U << 12,
	MSGFLAG_ORIGIN_INTERNET    = 1U << 13,
	MSGFLAG_ORIGIN_MISC_EXT    = 1U << 15,
	MSGFLAG_OUTLOOK_NON_EMS_XP = 1U << 16,
};

enum ol_busy_status {
	olFree = 0,
	olTentative = 1,
	olBusy = 2,
	olOutOfOffice = 3,
	olWorkingElsewhere = 4,
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
	RES_NULL = 0xff,
};

enum {
	frightsReadAny              = 1U << 0,
	frightsCreate               = 1U << 1,
	frightsGromoxSendAs         = 1U << 2,
	frightsEditOwned            = 1U << 3,
	frightsDeleteOwned          = 1U << 4,
	frightsEditAny              = 1U << 5,
	frightsDeleteAny            = 1U << 6,
	frightsCreateSubfolder      = 1U << 7,
	frightsOwner                = 1U << 8,
	frightsContact              = 1U << 9,
	frightsVisible              = 1U << 10,
	frightsFreeBusySimple       = 1U << 11, /* cf. IExchangeModifyTable */
	frightsFreeBusyDetailed     = 1U << 12, /* cf. IExchangeModifyTable */
	frightsGromoxStoreOwner     = 1U << 13,

	rightsNone = 0,
	rightsGromox7 = frightsReadAny | frightsCreate | frightsEditAny |
	                frightsDeleteAny | frightsCreateSubfolder |
	                frightsOwner | frightsVisible,
	/* as per edkmdb */
	rightsAll = frightsReadAny | frightsCreate | frightsEditOwned |
	            frightsDeleteOwned | frightsEditAny | frightsDeleteAny |
	            frightsCreateSubfolder | frightsOwner | frightsVisible,
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

	FL_IGNORECASE = 1 << 16,
	FL_IGNORENONSPACE = 1 << 17,
	FL_LOOSE = 1 << 18,
};

enum {
	MAXIMUM_SORT_COUNT = 8,
};

enum {
	RULE_DATA_FLAG_ADD_ROW = 1U << 0,
	RULE_DATA_FLAG_MODIFY_ROW = 1U << 1,
	RULE_DATA_FLAG_REMOVE_ROW = 1U << 2,
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

struct BINARY {
	uint32_t cb;
	union {
		uint8_t *pb;
		char *pc;
		void *pv;
	};
};

struct BINARY_ARRAY {
	uint32_t count;
	BINARY *pbin;
};

struct FLATUID {
	uint8_t ab[16];
};

struct FLATUID_ARRAY {
	uint32_t cvalues;
	FLATUID **ppguid;
};

struct GUID {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
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
	/* 81.2B.1F.A4.BE.A3.10.19.9D.6E.00.DD.01.0F.54.02 */
	uint8_t provider_uid[16];
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

struct PROPID_ARRAY {
	uint16_t count;
	uint16_t *ppropid;
};

struct PROPNAME_ARRAY {
	uint16_t count;
	PROPERTY_NAME *ppropname;
};

struct PROPTAG_ARRAY {
	uint16_t count;
	uint32_t *pproptag;
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
};

struct TAGGED_PROPVAL {
	uint32_t proptag;
	void *pvalue;
};

struct TPROPVAL_ARRAY {
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
};

struct TARRAY_SET {
	uint32_t count;
	TPROPVAL_ARRAY **pparray;
};

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
};

struct RESTRICTION_AND_OR {
	uint32_t count;
	RESTRICTION *pres;
};

struct RESTRICTION_NOT {
	RESTRICTION res;
};

struct RESTRICTION_CONTENT {
	uint32_t fuzzy_level;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
};

struct RESTRICTION_PROPERTY {
	enum relop relop;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
};

struct RESTRICTION_PROPCOMPARE {
	enum relop relop;
	uint32_t proptag1;
	uint32_t proptag2;
};

struct RESTRICTION_BITMASK {
	enum bm_relop bitmask_relop;
	uint32_t proptag;
	uint32_t mask;
};

struct RESTRICTION_SIZE {
	enum relop relop;
	uint32_t proptag;
	uint32_t size;
};

struct RESTRICTION_EXIST {
	uint32_t proptag;
};

struct RESTRICTION_SUBOBJ {
	uint32_t subobject;
	RESTRICTION res;
};

struct RESTRICTION_COMMENT {
	uint8_t count;
	TAGGED_PROPVAL *ppropval;
	RESTRICTION *pres;
};

struct RESTRICTION_COUNT {
	uint32_t count;
	RESTRICTION sub_res;
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
