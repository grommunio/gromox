#pragma once
#include <cstdint>
#include <string>

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

enum {
	MV_FLAG = 0x1000,
	MV_INSTANCE = 0x2000,
	MVI_FLAG = MV_FLAG | MV_INSTANCE,
	FXICS_CODEPAGE_FLAG = 0x8000U,
};

/*
 * Reserved:                          0x0000
 * Tagged props:                      0x0001..0x7FFF
 *  \_ MAPI-defined props:            0x0001..0x3FFF
 *      \_ Envelope props:            0x0001..0x0BFF
 *      \_ Recipient props:           0x0C00..0x0DFF
 *      \_ Non-transmittable props:   0x0E00..0x0FFF (non-transmittable)
 *      \_ Message content props:     0x1000..0x2FFF
 *      \_ Others:                    0x3000..0x3FFF
 *          \_ Common props:          0x3000..0x33FF
 *          \_ Message store:         0x3400..0x35FF
 *          \_ Container (folder/AB): 0x3600..0x36FF
 *          \_ Attachment:            0x3700..0x38FF
 *          \_ Address book:          0x3900..0x39FF
 *          \_ Mail user:             0x3A00..0x3BFF
 *          \_ Distribution list:     0x3C00..0x3CFF
 *          \_ Profsect:              0x3D00..0x3DFF
 *          \_ Status object:         0x3E00..0x3FFF
 *  \_ Transport-specific props:      0x4000..0x5FFF
 *      \_ Envelope props:            0x4000..0x57FF
 *      \_ Recipient props:           0x5800..0x5FFF
 *  \_ Client-specific props:         0x6000..0x65FF (non-transmittable)
 *  \_ Provider-specific props:       0x6600..0x67FF (non-transmittable)
 *      \_ Secure profile props:      0x67F0..0x67FF
 *  \_ Message class-specific props:  0x6800..0x7FFF
 *      \_ Content props:             0x6800..0x7BFF
 *      \_ Non-transmittable:         0x7C00..0x7FFF (non-transmittable)
 * Mapping range for named props:     0x8000..0xFFFE
 * Reserved:                          0xFFFF
 */
enum {
	PR_NULL = PROP_TAG(PT_NULL, 0x0000), /* PidTagNull */
	PR_IMPORTANCE = PROP_TAG(PT_LONG, 0x0017), /* PidTagImportance */
	PR_MESSAGE_CLASS = PROP_TAG(PT_UNICODE, 0x001A), /* PidTagMessageClass */
	PR_MESSAGE_CLASS_A = PROP_TAG(PT_STRING8, 0x001A),
	PR_PARENT_KEY = PROP_TAG(PT_BINARY, 0x0025), /* PidTagParentKey */
	PR_READ_RECEIPT_REQUESTED = PROP_TAG(PT_BOOLEAN, 0x0029), /* PidTagReadReceiptRequested */
	// PR_ORIGINAL_SENSITIVITY = PROP_TAG(PT_LONG, 0x002E), /* PidTagOriginalSensitivity */
	PR_SENSITIVITY = PROP_TAG(PT_LONG, 0x0036), /* PidTagSensitivity */
	PR_SUBJECT_A = PROP_TAG(PT_STRING8, 0x0037),
	PR_SUBJECT = PROP_TAG(PT_UNICODE, 0x0037), /* PidTagSubject */
	PR_SENT_REPRESENTING_SEARCH_KEY = PROP_TAG(PT_BINARY, 0x003B),
	PR_SUBJECT_PREFIX_A = PROP_TAG(PT_STRING8, 0x003D),
	PR_SUBJECT_PREFIX = PROP_TAG(PT_UNICODE, 0x003D), /* PidTagSubjectPrefix */
	PR_SENT_REPRESENTING_ENTRYID = PROP_TAG(PT_BINARY, 0x0041),
	PR_SENT_REPRESENTING_NAME = PROP_TAG(PT_UNICODE, 0x0042),
	PR_SENT_REPRESENTING_NAME_A = PROP_TAG(PT_STRING8, 0x0042),
	PR_RCVD_REPRESENTING_ENTRYID = PROP_TAG(PT_BINARY, 0x0043),
	PR_RCVD_REPRESENTING_NAME = PROP_TAG(PT_UNICODE, 0x0044),
	PR_RCVD_REPRESENTING_NAME_A = PROP_TAG(PT_STRING8, 0x0044),
	PR_ORIG_MESSAGE_CLASS = PROP_TAG(PT_UNICODE, 0x004B), /* PidTagOriginalMessageClass */
	PR_ORIG_MESSAGE_CLASS_A = PROP_TAG(PT_STRING8, 0x004B),
	PR_RCVD_REPRESENTING_SEARCH_KEY = PROP_TAG(PT_BINARY, 0x0052),
	// PR_ORIGINAL_SENT_REPRESENTING_NAME = PROP_TAG(PT_UNICODE, 0x005D),
	// PR_ORIGINAL_SENT_REPRESENTING_ENTRYID = PROP_TAG(PT_BINARY, 0x005E),
	// PR_ORIGINAL_SENT_REPRESENTING_SEARCH_KEY = PROP_TAG(PT_BINARY, 0x005F),
	PR_SENT_REPRESENTING_ADDRTYPE = PROP_TAG(PT_UNICODE, 0x0064),
	PR_SENT_REPRESENTING_ADDRTYPE_A = PROP_TAG(PT_STRING8, 0x0064),
	PR_SENT_REPRESENTING_EMAIL_ADDRESS = PROP_TAG(PT_UNICODE, 0x0065),
	PR_SENT_REPRESENTING_EMAIL_ADDRESS_A = PROP_TAG(PT_STRING8, 0x0065),
	// PR_ORIGINAL_SENT_REPRESENTING_ADDRTYPE = PROP_TAG(PT_UNICODE, 0x0068),
	// PR_ORIGINAL_SENT_REPRESENTING_EMAIL_ADDRESS = PROP_TAG(PT_UNICODE, 0x0069),
	PR_RCVD_REPRESENTING_ADDRTYPE = PROP_TAG(PT_UNICODE, 0x0077),
	PR_RCVD_REPRESENTING_ADDRTYPE_A = PROP_TAG(PT_STRING8, 0x0077),
	PR_RCVD_REPRESENTING_EMAIL_ADDRESS = PROP_TAG(PT_UNICODE, 0x0078),
	PR_RCVD_REPRESENTING_EMAIL_ADDRESS_A = PROP_TAG(PT_STRING8, 0x0078),
	// PR_EMS_AB_ROOM_CAPACITY = PROP_TAG(PT_LONG, 0x0807), /* PidTagAddressBookRoomCapacity */
	// PR_EMS_AB_ROOM_DESCRIPTION = PROP_TAG(PT_UNICODE, 0x0809), /* PidTagAddressBookRoomDescription */
	PR_NON_RECEIPT_NOTIFICATION_REQUESTED = PROP_TAG(PT_BOOLEAN, 0x0C06), /* PidTagNonReceiptNotificationRequested */
	PR_SENDER_ENTRYID = PROP_TAG(PT_BINARY, 0x0C19), /* PidTagSenderEntryId */
	PR_SENDER_NAME = PROP_TAG(PT_UNICODE, 0x0C1A), /* PidTagSenderName */
	PR_SENDER_NAME_A = PROP_TAG(PT_STRING8, 0x0C1A),
	PR_SUPPLEMENTARY_INFO = PROP_TAG(PT_UNICODE, 0x0C1B), /* PidTagSupplementaryInfo */
	PR_SENDER_SEARCH_KEY = PROP_TAG(PT_BINARY, 0x0C1D), /* PidTagSenderSearchKey */
	PR_SENDER_ADDRTYPE = PROP_TAG(PT_UNICODE, 0x0C1E), /* PidTagSenderAddressType */
	PR_SENDER_ADDRTYPE_A = PROP_TAG(PT_STRING8, 0x0C1E),
	PR_SENDER_EMAIL_ADDRESS = PROP_TAG(PT_UNICODE, 0x0C1F), /* PidTagSenderEmailAddress */
	PR_SENDER_EMAIL_ADDRESS_A = PROP_TAG(PT_STRING8, 0x0C1F),
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
	PR_HASATTACH = PROP_TAG(PT_BOOLEAN, 0x0E1B), /* PidTagHasAttachments */
	PR_NORMALIZED_SUBJECT_A = PROP_TAG(PT_STRING8, 0x0E1D),
	PR_NORMALIZED_SUBJECT = PROP_TAG(PT_UNICODE, 0x0E1D), /* PidTagNormalizedSubject */
	PR_ATTACH_SIZE = PROP_TAG(PT_LONG, 0x0E20), /* PidTagAttachSize */
	PR_ATTACH_NUM = PROP_TAG(PT_LONG, 0x0E21), /* PidTagAttachNumber */
	PR_INTERNET_ARTICLE_NUMBER = PROP_TAG(PT_LONG, 0x0E23), /* PidTagInternetArticleNumber */
	// PR_REPL_ITEMID = PROP_TAG(PT_LONG, 0x0E30), /* PidTagReplItemId */
	// PR_REPL_CHANGENUM = PROP_TAG(PT_I8, 0x0E33), /* PidTagReplChangenum */
	// PR_REPL_VERSIONHISTORY = PROP_TAG(PT_BINARY, 0x0E34), /* PidTagReplVersionhistory */
	// PR_REPL_FLAGS = PROP_TAG(PT_LONG, 0x0E38), /* PidTagReplFlags */
	// PR_REPL_COPIEDFROM_VERSIONHISTORY = PROP_TAG(PT_BINARY, 0x0E3C), /* PidTagReplCopiedfromVersionhistory */
	// PR_REPL_COPIEDFROM_ITEMID = PROP_TAG(PT_BINARY, 0x0E3D), /* PidTagReplCopiedfromItemid */
	PR_CREATOR_SID = PROP_TAG(PT_BINARY, 0x0E58),
	PR_READ = PROP_TAG(PT_BOOLEAN, 0x0E69), /* PidTagRead */
	PR_ACCESS = PROP_TAG(PT_LONG, 0x0FF4), /* PidTagAccess */
	PR_ACCESS_LEVEL = PROP_TAG(PT_LONG, 0x0FF7), /* PidTagAccessLevel */
	PR_MAPPING_SIGNATURE = PROP_TAG(PT_BINARY, 0x0FF8), /* PidTagMappingSignature */
	PR_RECORD_KEY = PROP_TAG(PT_BINARY, 0x0FF9), /* PidTagRecordKey */
	PR_STORE_RECORD_KEY = PROP_TAG(PT_BINARY, 0x0FFA), /* PidTagStoreRecordKey */
	PR_STORE_ENTRYID = PROP_TAG(PT_BINARY, 0x0FFB), /* PidTagStoreEntryId */
	PR_OBJECT_TYPE = PROP_TAG(PT_LONG, 0x0FFE), /* PidTagObjectType */
	PR_ENTRYID = PROP_TAG(PT_BINARY, 0x0FFF), /* PidTagEntryId */
	PR_BODY_A = PROP_TAG(PT_STRING8, 0x1000),
	PR_BODY_W = PROP_TAG(PT_UNICODE, 0x1000),
	PR_RTF_COMPRESSED = PROP_TAG(PT_BINARY, 0x1009), /* PidTagRtfCompressed */
	PR_HTML = PROP_TAG(PT_BINARY, 0x1013), /* PidTagHtml */
	PR_ATTR_HIDDEN = PROP_TAG(PT_BOOLEAN, 0x10F4), /* PidTagAttributeHidden */
	PR_DISPLAY_NAME_A = PROP_TAG(PT_STRING8, 0x3001),
	PR_DISPLAY_NAME = PROP_TAG(PT_UNICODE, 0x3001), /* PidTagDisplayName */
	PR_EMAIL_ADDRESS_A = PROP_TAG(PT_STRING8, 0x3003),
	PR_EMAIL_ADDRESS = PROP_TAG(PT_UNICODE, 0x3003), /* PidTagEmailAddress */
	PR_COMMENT = PROP_TAG(PT_UNICODE, 0x3004), /* PidTagComment */
	PR_PROVIDER_DISPLAY = PROP_TAG(PT_UNICODE, 0x3006), /* PidTagProviderDisplay */
	PR_CREATION_TIME = PROP_TAG(PT_SYSTIME, 0x3007), /* PidTagCreationTime */
	PR_LAST_MODIFICATION_TIME = PROP_TAG(PT_SYSTIME, 0x3008), /* PidTagLastModificationTime */
	PR_RESOURCE_FLAGS = PROP_TAG(PT_LONG, 0x3009), /* PidTagResourceFlags */
	PR_STORE_SUPPORT_MASK = PROP_TAG(PT_LONG, 0x340D), /* PidTagStoreSupportMask */
	PR_STORE_STATE = PROP_TAG(PT_LONG, 0x340E), /* PidTagStoreState */
	PR_MDB_PROVIDER = PROP_TAG(PT_BINARY, 0x3414), /* PidTagStoreProvider */
	PR_IPM_SUBTREE_ENTRYID = PROP_TAG(PT_BINARY, 0x35E0), /* PidTagIpmSubtreeEntryId */
	PR_IPM_OUTBOX_ENTRYID = PROP_TAG(PT_BINARY, 0x35E2), /* PidTagIpmOutboxEntryId */
	PR_IPM_WASTEBASKET_ENTRYID = PROP_TAG(PT_BINARY, 0x35E3), /* PidTagIpmWastebasketEntryId */
	PR_IPM_SENTMAIL_ENTRYID = PROP_TAG(PT_BINARY, 0x35E4), /* PidTagIpmSentMailEntryId */
	PR_VIEWS_ENTRYID = PROP_TAG(PT_BINARY, 0x35E5), /* PidTagViewsEntryId */
	PR_COMMON_VIEWS_ENTRYID = PROP_TAG(PT_BINARY, 0x35E6), /* PidTagCommonViewsEntryId */
	PR_FINDER_ENTRYID = PROP_TAG(PT_BINARY, 0x35E7), /* PidTagFinderEntryId */
	PR_FOLDER_TYPE = PROP_TAG(PT_LONG, 0x3601), /* PidTagFolderType */
	// PR_DETAILS_TABLE  = PROP_TAG(PT_OBJECT, 0x3605), /* PidTagDetailsTable */
	PR_CONTAINER_CLASS = PROP_TAG(PT_UNICODE, 0x3613), /* PidTagContainerClass */
	PR_ASSOC_CONTENT_COUNT = PROP_TAG(PT_LONG, 0x3617), /* PidTagAssociatedContentCount */
	PR_IPM_APPOINTMENT_ENTRYID = PROP_TAG(PT_BINARY, 0x36D0), /* PidTagIpmAppointmentEntryId */
	PR_IPM_CONTACT_ENTRYID = PROP_TAG(PT_BINARY, 0x36D1), /* PidTagIpmContactEntryId */
	PR_IPM_JOURNAL_ENTRYID = PROP_TAG(PT_BINARY, 0x36D2), /* PidTagIpmJournalEntryId */
	PR_IPM_NOTE_ENTRYID = PROP_TAG(PT_BINARY, 0x36D3), /* PidTagIpmNoteEntryId */
	PR_IPM_TASK_ENTRYID = PROP_TAG(PT_BINARY, 0x36D4), /* PidTagIpmTaskEntryId */
	PR_REM_ONLINE_ENTRYID = PROP_TAG(PT_BINARY, 0x36D5), /* PidTagRemindersOnlineEntryId */
	// PR_REM_OFFLINE_ENTRYID = PROP_TAG(PT_BINARY, 0x36D6), /* PidTagRemindersOfflineEntryId */
	PR_IPM_DRAFTS_ENTRYID = PROP_TAG(PT_BINARY, 0x36D7), /* PidTagIpmDraftsEntryId */
	PR_ADDITIONAL_REN_ENTRYIDS = PROP_TAG(PT_MV_BINARY, 0x36D8), /* PidTagAdditionalRenEntryIds */
	PR_ADDITIONAL_REN_ENTRYIDS_EX = PROP_TAG(PT_BINARY, 0x36D9), /* PidTagAdditionalRenEntryIdsEx */
	PR_FREEBUSY_ENTRYIDS = PROP_TAG(PT_MV_BINARY, 0x36E4), /* PidTagFreeBusyEntryIds */
	PR_DEF_POST_MSGCLASS = PROP_TAG(PT_UNICODE, 0x36E5), /* PidTagDefaultPostMessageClass */
	PR_ATTACH_DATA_BIN = PROP_TAG(PT_BINARY, 0x3701), /* PidTagAttachDataBinary */
	PR_ATTACH_DATA_OBJ = PROP_TAG(PT_OBJECT, 0x3701), /* PidTagAttachDataObject */
	PR_ATTACH_ENCODING = PROP_TAG(PT_BINARY, 0x3702), /* PidTagAttachEncoding */
	PR_ATTACH_EXTENSION_A = PROP_TAG(PT_STRING8, 0x3703),
	PR_ATTACH_EXTENSION = PROP_TAG(PT_UNICODE, 0x3703), /* PidTagAttachExtension */
	PR_ATTACH_FILENAME_A = PROP_TAG(PT_STRING8, 0x3704),
	PR_ATTACH_FILENAME = PROP_TAG(PT_UNICODE, 0x3704), /* PidTagAttachFilename (8.3 format) */
	PR_ATTACH_METHOD = PROP_TAG(PT_LONG, 0x3705), /* PidTagAttachMethod */
	PR_ATTACH_LONG_FILENAME_A = PROP_TAG(PT_STRING8, 0x3707),
	PR_ATTACH_LONG_FILENAME = PROP_TAG(PT_UNICODE, 0x3707), /* PidTagAttachLongFilename */
	// PR_ATTACH_PATHNAME = PROP_TAG(PT_UNICODE, 0x3708), /* PidTagAttachPathname */
	PR_ATTACH_RENDERING = PROP_TAG(PT_BINARY, 0x3709), /* PidTagAttachRendering */
	PR_ATTACH_TAG = PROP_TAG(PT_BINARY, 0x370A), /* PidTagAttachTag */
	// PR_ATTACH_TRANSPORT_NAME = PROP_TAG(PT_UNICODE, 0x370C), /* PidTagAttachTransportName */
	PR_ATTACH_TRANSPORT_NAME_A = PROP_TAG(PT_STRING8, 0x370C),
	// PR_ATTACH_LONG_PATHNAME = PROP_TAG(PT_UNICODE, 0x370D), /* PidTagAttachLongPathname */
	PR_ATTACH_MIME_TAG = PROP_TAG(PT_UNICODE, 0x370E), /* PidTagAttachMimeTag */
	PR_ATTACH_ADDITIONAL_INFO = PROP_TAG(PT_BINARY, 0x370F), /* PidTagAttachAdditionalInformation */
	PR_ATTACH_CONTENT_BASE = PROP_TAG(PT_UNICODE, 0x3711), /* PidTagAttachContentBase */
	PR_ATTACH_CONTENT_BASE_A = PROP_TAG(PT_STRING8, 0x3711),
	PR_ATTACH_CONTENT_ID = PROP_TAG(PT_UNICODE, 0x3712), /* PidTagAttachContentId */
	PR_ATTACH_CONTENT_ID_A = PROP_TAG(PT_STRING8, 0x3712),
	PR_ATTACH_CONTENT_LOCATION = PROP_TAG(PT_UNICODE, 0x3713), /* PidTagAttachContentLocation */
	PR_ATTACH_CONTENT_LOCATION_A = PROP_TAG(PT_STRING8, 0x3713),
	PR_ATTACH_FLAGS = PROP_TAG(PT_LONG, 0x3714), /* PidTagAttachFlags */
	// PR_ATTACH_PAYLOAD_PROV_GUID_STR = PROP_TAG(PT_UNICODE, 0x3719), /* PidTagAttachPayloadProviderGuidString */
	PR_ATTACH_PAYLOAD_CLASS = PROP_TAG(PT_UNICODE, 0x371A), /* PidTagAttachPayloadClass */
	PR_ATTACH_PAYLOAD_CLASS_A = PROP_TAG(PT_STRING8, 0x371A),
	PR_DISPLAY_TYPE = PROP_TAG(PT_LONG, 0x3900), /* PidTagDisplayType */
	PR_DISPLAY_TYPE_EX = PROP_TAG(PT_LONG, 0x3905), /* PidTagDisplayTypeEx */
	PR_SMTP_ADDRESS = PROP_TAG(PT_UNICODE, 0x39FE), /* PidTagSmtpAddress */
	PR_EMS_AB_DISPLAY_NAME_PRINTABLE_A = PROP_TAG(PT_STRING8, 0x39FF),
	PR_EMS_AB_DISPLAY_NAME_PRINTABLE = PROP_TAG(PT_UNICODE, 0x39FF), /* PidTagAddressBookDisplayNamePrintable */
	PR_DISPLAY_NAME_PREFIX = PROP_TAG(PT_UNICODE, 0x3A45), /* PidTagDisplayNamePrefix */
	PR_RESOURCE_TYPE = PROP_TAG(PT_LONG, 0x3E03), /* PidTagResourceType */
	PR_CONTROL_FLAGS = PROP_TAG(PT_LONG, 0x3F02), /* PidTagControlFlags */
	PR_CONTROL_TYPE = PROP_TAG(PT_LONG, 0x3F02), /* PidTagControlType */
	PR_INTERNET_CPID = PROP_TAG(PT_LONG, 0x3FDE), /* PidTagInternetCodepage */
	PR_MESSAGE_LOCALE_ID = PROP_TAG(PT_LONG, 0x3FF1), /* PidTagMessageLocaleId */
	PR_STORAGE_QUOTA_LIMIT = PROP_TAG(PT_LONG, 0x3FF5),
	PR_CREATOR_NAME = PROP_TAG(PT_UNICODE, 0x3FF8), /* PidTagCreatorName */
	PR_CREATOR_ENTRYID = PROP_TAG(PT_BINARY, 0x3FF9), /* PidTagCreatorEntryId */
	PR_LAST_MODIFIER_NAME = PROP_TAG(PT_UNICODE, 0x3FFA), /* PidTagLastModifierName */
	PR_LAST_MODIFIER_ENTRYID = PROP_TAG(PT_BINARY, 0x3FFB), /* PidTagLastModifierEntryId */
	PR_MESSAGE_CODEPAGE = PROP_TAG(PT_LONG, 0x3FFD), /* PidTagMessageCodepage */
	PR_SENDER_ID_STATUS = PROP_TAG(PT_LONG, 0x4079), /* PidTagSenderIdStatus */
	PR_SENT_REPRESENTING_SMTP_ADDRESS = PROP_TAG(PT_UNICODE, 0x5D02),
	PR_SOURCE_KEY = PROP_TAG(PT_BINARY, 0x65E0), /* PidTagSourceKey */
	PR_PARENT_SOURCE_KEY = PROP_TAG(PT_BINARY, 0x65E1), /* PidTagParentSourceKey */
	PR_IPM_PUBLIC_FOLDERS_ENTRYID = PROP_TAG(PT_BINARY, 0x65E1),
	PR_CHANGE_KEY = PROP_TAG(PT_BINARY, 0x65E2), /* PidTagChangeKey */
	PR_PREDECESSOR_CHANGE_LIST = PROP_TAG(PT_BINARY, 0x65E3), /* PidTagPredecessorChangeList */
	PR_RULE_MSG_STATE = PROP_TAG(PT_LONG, 0x65E9), /* PidTagRuleMessageState */
	// PR_RULE_MSG_USER_FLAGS = PROP_TAG(PT_LONG, 0x65EA), /* PidTagRuleMessageUserFlags */
	PR_RULE_MSG_PROVIDER = PROP_TAG(PT_UNICODE, 0x65EB), /* PidTagRuleMessageProvider */
	// PR_RULE_MSG_NAME = PROP_TAG(PT_UNICODE, 0x65EC), /* PidTagRuleMessageName */
	// PR_RULE_MSG_LEVEL = PROP_TAG(PT_LONG, 0x65ED), /* PidTagRuleMessageLevel */
	// PR_RULE_MSG_PROVIDER_DATA = PROP_TAG(PT_BINARY, 0x65EE), /* PidTagRuleMessageProviderData */
	PR_RULE_MSG_SEQUENCE = PROP_TAG(PT_LONG, 0x65F3), /* PidTagRuleMessageSequence */
	PR_USER_ENTRYID = PROP_TAG(PT_BINARY, 0x6619), /* PidTagUserEntryId */
	PR_MAILBOX_OWNER_ENTRYID = PROP_TAG(PT_BINARY, 0x661B), /* PidTagMailboxOwnerEntryId */
	PR_MAILBOX_OWNER_NAME = PROP_TAG(PT_UNICODE, 0x661C), /* PidTagMailboxOwnerName */
	PR_OOF_STATE = PROP_TAG(PT_BOOLEAN, 0x661D), /* PidTagOutOfOfficeState */
	PR_SCHEDULE_FOLDER_ENTRYID = PROP_TAG(PT_BINARY, 0x661E),
	// PR_IPM_DAF_ENTRYID = PROP_TAG(PT_BINARY, 0x661F),
	PR_NON_IPM_SUBTREE_ENTRYID = PROP_TAG(PT_BINARY, 0x6620), /* PidTagNonIpmSubtreeEntryId */
	PR_EFORMS_REGISTRY_ENTRYID = PROP_TAG(PT_BINARY, 0x6621),
	// PR_SPLUS_FREE_BUSY_ENTRYID = PROP_TAG(PT_BINARY, 0x6622), /* PidTagSchedulePlusFreeBusyEntryId */
	// PR_OFFLINE_ADDRBOOK_ENTRYID = PROP_TAG(PT_BINARY, 0x6623),
	PR_TEST_LINE_SPEED = PROP_TAG(PT_BINARY, 0x662B),
	PR_IPM_FAVORITES_ENTRYID = PROP_TAG(PT_BINARY, 0x6630),
	PR_STORE_OFFLINE = PROP_TAG(PT_BOOLEAN, 0x6632),
	// PR_PST_LRNORESTRICTIONS = PROP_TAG(PT_BOOLEAN, 0x6633), /* PidTagPstLrNoRestrictions */
	// PR_HIERARCHY_SERVER = PROP_TAG(PT_UNICODE, 0x6633),
	// PR_PROFILE_OAB_COUNT_ATTEMPTED_FULLDN = PROP_TAG(PT_LONG, 0x6635), /* PidTagProfileOabCountAttemptedFulldn */
	// PR_PST_HIDDEN_COUNT = PROP_TAG(PT_LONG, 0x6635), /* PidTagPstHiddenCount */
	// PR_FAVORITES_DEFAULT_NAME = PROP_TAG(PT_UNICODE, 0x6635),
	// PR_PST_HIDDEN_UNREAD = PROP_TAG(PT_LONG, 0x6636), /* PidTagPstHiddenUnread */
	// PR_PROFILE_OAB_COUNT_ATTEMPTED_INCRDN = PROP_TAG(PT_LONG, 0x6636), /* PidTagProfileOabCountAttemptedIncrdn */
	PR_RIGHTS = PROP_TAG(PT_LONG, 0x6639), /* PidTagRights */
	PR_ADDRESS_BOOK_ENTRYID = PROP_TAG(PT_BINARY, 0x663B), /* PidTagAddressBookEntryId */
	PR_HIERARCHY_CHANGE_NUM = PROP_TAG(PT_LONG, 0x663E), /* PidTagHierarchyChangeNumber */
	PR_DELETED_MSG_COUNT = PROP_TAG(PT_LONG, 0x6640), /* PidTagDeletedMessageCount */
	PR_DELETED_FOLDER_COUNT = PROP_TAG(PT_LONG, 0x6641), /* MS-OXPROPS v0.2 §2.570 PidTagDeletedMessageCount */
	PR_DELETED_ASSOC_MSG_COUNT = PROP_TAG(PT_LONG, 0x6643), /* MS-OXPROPS v0.2 §2.568 PidTagDeletedAssociatedMessageCount */
	PR_DAM_ORIGINAL_ENTRYID = PROP_TAG(PT_BINARY, 0x6646), /* PidTagDamOriginalEntryId */
	// PR_RULE_ERROR = PROP_TAG(PT_LONG, 0x6648), /* PidTagRuleError */
	PR_RULE_ACTION_TYPE = PROP_TAG(PT_LONG, 0x6649), /* PidTagRuleActionType */
	PR_RULE_ACTION_NUMBER = PROP_TAG(PT_LONG, 0x6650), /* PidTagRuleActionNumber */
	PR_RULE_FOLDER_ENTRYID = PROP_TAG(PT_BINARY, 0x6651), /* PidTagRuleFolderEntryId */
	PR_PROHIBIT_RECEIVE_QUOTA = PROP_TAG(PT_LONG, 0x666A), /* PidTagProhibitReceiveQuota */
	PR_MAX_SUBMIT_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x666D), /* PidTagMaximumSubmitMessageSize */
	PR_PROHIBIT_SEND_QUOTA = PROP_TAG(PT_LONG, 0x666E), /* PidTagProhibitSendQuota */
	PR_RULE_ID = PROP_TAG(PT_I8, 0x6674), /* PidTagRuleId */
	PR_RULE_IDS = PROP_TAG(PT_BINARY, 0x6675), /* PidTagRuleIds */
	PR_RULE_SEQUENCE = PROP_TAG(PT_LONG, 0x6676), /* PidTagRuleSequence */
	PR_RULE_STATE = PROP_TAG(PT_LONG, 0x6677), /* PidTagRuleState */
	PR_RULE_USER_FLAGS = PROP_TAG(PT_LONG, 0x6678), /* PidTagRuleUserFlags */
	PR_RULE_CONDITION = PROP_TAG(PT_SRESTRICTION, 0x6679), /* PidTagRuleCondition */
	PR_RULE_ACTIONS = PROP_TAG(PT_ACTIONS, 0x6680), /* PidTagRuleActions */
	PR_RULE_PROVIDER = PROP_TAG(PT_UNICODE, 0x6681), /* PidTagRuleProvider */
	PR_RULE_PROVIDER_A = PROP_TAG(PT_STRING8, 0x6681),
	PR_RULE_NAME = PROP_TAG(PT_UNICODE, 0x6682), /* PidTagRuleName */
	PR_RULE_NAME_A = PROP_TAG(PT_STRING8, 0x6682),
	PR_RULE_LEVEL = PROP_TAG(PT_LONG, 0x6683), /* PidTagRuleLevel */
	PR_RULE_PROVIDER_DATA = PROP_TAG(PT_BINARY, 0x6684), /* PidTagRuleProviderData */
	PR_DELETED_ON = PROP_TAG(PT_SYSTIME, 0x668F), /* PidTagDeletedOn */
	PR_DELETED_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x669B),
	PR_DELETED_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x669B), /* MS-OXPROPS v0.2 §2.571 PidTagDeletedMessageSizeExtended */
	PR_DELETED_NORMAL_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x669C),
	PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x669C), /* MS-OXPROPS v0.2 §2.572 PidTagDeletedNormalMessageSizeExtended */
	PR_DELETED_ASSOC_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x669D),
	PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x669D), /* MS-OXPROPS v0.2 §2.569 PidTagDeletedAssociatedMessageSizeExtended */
	PR_LOCALE_ID = PROP_TAG(PT_LONG, 0x66A1), /* PidTagLocaleId */
	// PR_ASSOC_MSG_W_ATTACH_COUNT = PROP_TAG(PT_LONG, 0x66AE),
	PR_NORMAL_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x66B3), /* MS-OXPROPS v0.2 §2.719 PidTagNormalMessageSize */
	PR_NORMAL_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x66B3),
	PR_ASSOC_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x66B4),
	PR_ASSOC_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x66B4),
	// PR_LATEST_PST_ENSURE = PROP_TAG(PT_LONG, 0x66FA), /* PidTagLatestPstEnsure */
	// PR_EMS_AB_MANAGE_DL = PROP_TAG(PT_OBJECT, 0x6704), /* PidTagAddressBookManageDistributionList */
	PR_LOCAL_COMMIT_TIME_MAX = PROP_TAG(PT_SYSTIME, 0x670A), /* PidTagLocalCommitTimeMax */
	PR_DELETED_COUNT_TOTAL = PROP_TAG(PT_LONG, 0x670B), /* PidTagDeletedCountTotal */
	PR_RULE_FOLDER_FID = PROP_TAG(PT_I8, 0x6742), /* Gromox-specific */
	// PidTagAddressBookMessageId = PROP_TAG(PT_I8, 0x674F),
	PR_EC_OUTOFOFFICE = PROP_TAG(PT_LONG, 0x6760),
	PR_EC_OUTOFOFFICE_MSG = PROP_TAG(PT_UNICODE, 0x6761), /* specific to zcore & grommunio-web */
	PR_EC_OUTOFOFFICE_SUBJECT = PROP_TAG(PT_UNICODE, 0x6762),
	PR_EC_OUTOFOFFICE_FROM = PROP_TAG(PT_SYSTIME, 0x6763),
	PR_EC_OUTOFOFFICE_UNTIL = PROP_TAG(PT_SYSTIME, 0x6764),
	PR_EC_ALLOW_EXTERNAL = PROP_TAG(PT_BOOLEAN, 0x6765),
	PR_EC_EXTERNAL_AUDIENCE = PROP_TAG(PT_BOOLEAN, 0x6766),
	PR_EC_EXTERNAL_REPLY = PROP_TAG(PT_UNICODE, 0x6767),
	PR_EC_EXTERNAL_SUBJECT = PROP_TAG(PT_UNICODE, 0x6768),
	PR_ASSOCIATED = PROP_TAG(PT_BOOLEAN, 0x67AA), /* PidTagAssociated */
	// PR_LTP_ROW_ID = PROP_TAG(PT_LONG, 0x67F2), /* PidTagLtpRowId */
	// PR_LTP_ROW_VER = PROP_TAG(PT_LONG, 0x67F3), /* PidTagLtpRowVer */
	// PR_PST_PASSWORD = PROP_TAG(PT_LONG, 0x67FF), /* PidTagPstPassword */
	// PR_OAB_MESSAGE_CLASS = PROP_TAG(PT_LONG, 0x6803), /* PidTagOfflineAddressBookMessageClass */
	PR_ATTACHMENT_LINKID = PROP_TAG(PT_LONG, 0x7FFA), /* PidTagAttachmentLinkId */
	PR_ATTACHMENT_FLAGS = PROP_TAG(PT_LONG, 0x7FFD), /* PidTagAttachmentFlags */
	PR_ATTACHMENT_HIDDEN = PROP_TAG(PT_BOOLEAN, 0x7FFE), /* PidTagAttachmentHidden */
	PR_ATTACHMENT_CONTACTPHOTO = PROP_TAG(PT_BOOLEAN, 0x7FFF), /* PidTagAttachmentContactPhoto */
	// PR_EMS_AB_FOLDER_PATHNAME = PROP_TAG(PT_UNICODE, 0x8004), /* PidTagAddressBookFolderPathname */
	// PR_EMS_AB_MANAGER = PROP_TAG(PT_OBJECT, 0x8005), /* PidTagAddressBookManager */
	// PR_EMS_AB_MANAGER_T = PROP_TAG(PT_UNICODE, 0x8005), /* PidTagAddressBookManagerDistinguishedName */
	PR_EMS_AB_HOME_MDB_A = PROP_TAG(PT_STRING8, 0x8006),
	PR_EMS_AB_HOME_MDB = PROP_TAG(PT_UNICODE, 0x8006), /* PidTagAddressBookHomeMessageDatabase */
	// PR_EMS_AB_IS_MEMBER_OF_DL = PROP_TAG(PT_STRING8, 0x8008), /* PidTagAddressBookIsMemberOfDistributionList */
	// PR_EMS_AB_MEMBER = PROP_TAG(PT_OBJECT, 0x8009), /* PidTagAddressBookMember */
	// PR_EMS_AB_OWNER_O = PROP_TAG(PT_OBJECT, 0x800C), /* PidTagAddressBookOwner */
	// PR_EMS_AB_REPORTS = PROP_TAG(PT_OBJECT, 0x800E), /* PidTagAddressBookReports */
	PR_EMS_AB_PROXY_ADDRESSES_A = PROP_TAG(PT_MV_STRING8, 0x800F),
	PR_EMS_AB_PROXY_ADDRESSES = PROP_TAG(PT_MV_UNICODE, 0x800F), /* PidTagEmsAbProxyAddresses, PidTagAddressBookProxyAddresses */
	// PR_EMS_AB_TARGET_ADDRESS = PROP_TAG(PT_UNICODE, 0x8011), /* PidTagAddressBookTargetAddress */
	PR_EMS_AB_PUBLIC_DELEGATES = PROP_TAG(PT_OBJECT, 0x8015), /* PidTagAddressBookPublicDelegates */
	// PR_EMS_AB_OWNER_BL_O = PROP_TAG(PT_OBJECT, 0x8024), /* PidTagAddressBookOwnerBackLink */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_1 = PROP_TAG(PT_UNICODE, 0x802D), /* PidTagAddressBookExtensionAttribute1 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_2 = PROP_TAG(PT_UNICODE, 0x802E), /* PidTagAddressBookExtensionAttribute2 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_3 = PROP_TAG(PT_UNICODE, 0x802F), /* PidTagAddressBookExtensionAttribute3 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_4 = PROP_TAG(PT_UNICODE, 0x8030), /* PidTagAddressBookExtensionAttribute4 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_5 = PROP_TAG(PT_UNICODE, 0x8031), /* PidTagAddressBookExtensionAttribute5 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_6 = PROP_TAG(PT_UNICODE, 0x8032), /* PidTagAddressBookExtensionAttribute6 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_7 = PROP_TAG(PT_UNICODE, 0x8033), /* PidTagAddressBookExtensionAttribute7 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_8 = PROP_TAG(PT_UNICODE, 0x8034), /* PidTagAddressBookExtensionAttribute8 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_9 = PROP_TAG(PT_UNICODE, 0x8035), /* PidTagAddressBookExtensionAttribute9 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_10 = PROP_TAG(PT_UNICODE, 0x8036), /* PidTagAddressBookExtensionAttribute10 */
	// PR_EMS_AB_OBJ_DIST_NAME = PROP_TAG(PT_UNICODE, 0x803C), /* PidTagAddressBookObjectDistinguishedName */
	// PR_EMS_AB_DELIV_CONT_LENGTH = PROP_TAG(PT_LONG, 0x806A), /* PidTagAddressBookDeliveryContentLength */
	// PR_EMS_AB_DL_MEM_SUBMIT_PERMS_BL_O = PROP_TAG(PT_OBJECT, 0x8073), /* PidTagAddressBookDistributionListMemberSubmitAccepted */
	PR_EMS_AB_NETWORK_ADDRESS_A = PROP_TAG(PT_STRING8, 0x8170),
	PR_EMS_AB_NETWORK_ADDRESS = PROP_TAG(PT_UNICODE, 0x8170), /* PidTagAddressBookNetworkAddress */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_11 = PROP_TAG(PT_UNICODE, 0x8C57), /* PidTagAddressBookExtensionAttribute11 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_12 = PROP_TAG(PT_UNICODE, 0x8C58), /* PidTagAddressBookExtensionAttribute12 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_13 = PROP_TAG(PT_UNICODE, 0x8C59), /* PidTagAddressBookExtensionAttribute13 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_14 = PROP_TAG(PT_UNICODE, 0x8C60), /* PidTagAddressBookExtensionAttribute14 */
	// PR_EMS_AB_EXTENSION_ATTRIBUTE_15 = PROP_TAG(PT_UNICODE, 0x8C61), /* PidTagAddressBookExtensionAttribute15 */
	// PR_EMS_AB_X509_CERT = PROP_TAG(PT_MV_BINARY, 0x8C6A), /* PidTagAddressBookX509Certificate */
	PR_EMS_AB_OBJECT_GUID = PROP_TAG(PT_BINARY, 0x8C6D), /* PidTagAddressBookObjectGuid */
	// PR_EMS_AB_PHONETIC_GIVEN_NAME = PROP_TAG(PT_UNICODE, 0x8C8E), /* PidTagAddressBookPhoneticGivenName */
	// PR_EMS_AB_PHONETIC_SURNAME = PROP_TAG(PT_UNICODE, 0x8C8F), /* PidTagAddressBookPhoneticSurname */
	// PR_EMS_AB_PHONETIC_DEPARTMENT_NAME = PROP_TAG(PT_UNICODE, 0x8C90), /* PidTagAddressBookPhoneticDepartmentName */
	// PR_EMS_AB_PHONETIC_COMPANY_NAME = PROP_TAG(PT_UNICODE, 0x8C91), /* PidTagAddressBookPhoneticCompanyName */
	PR_EMS_AB_PHONETIC_DISPLAY_NAME_A = PROP_TAG(PT_STRING8, 0x8C92),
	PR_EMS_AB_PHONETIC_DISPLAY_NAME = PROP_TAG(PT_UNICODE, 0x8C92), /* PidTagAddressBookPhoneticDisplayName */
	// PR_EMS_AB_DISPLAY_TYPE_EX = PROP_TAG(PT_LONG, 0x8C93), /* PidTagAddressBookDisplayTypeExtended */
	// PR_EMS_AB_HAB_SHOW_IN_DEPARTMENTS = PROP_TAG(PT_OBJECT, 0x8C94), /* PidTagAddressBookHierarchicalShowInDepartments */
	// PR_EMS_AB_ROOM_CONTAINERS = PROP_TAG(PT_MV_UNICODE, 0x8C96), /* PidTagAddressBookRoomContainers */
	// PR_EMS_AB_HAB_DEPARTMENT_MEMBERS = PROP_TAG(PT_OBJECT, 0x8C97), /* PidTagAddressBookHierarchicalDepartmentMembers */
	// PR_EMS_AB_HAB_ROOT_DEPARTMENT = PROP_TAG(PT_STRING8, 0x8C98), /* PidTagAddressBookHierarchicalRootDepartment */
	// PR_EMS_AB_HAB_PARENT_DEPARTMENT = PROP_TAG(PT_OBJECT, 0x8C99), /* PidTagAddressBookHierarchicalParentDepartment */
	// PR_EMS_AB_HAB_CHILD_DEPARTMENTS = PROP_TAG(PT_OBJECT, 0x8C9A), /* PidTagAddressBookHierarchicalChildDepartments */
	// PR_EMS_AB_HAB_SENIORITY_INDEX = PROP_TAG(PT_LONG, 0x8CA0), /* PidTagAddressBookSeniorityIndex */
	// PR_EMS_AB_ORG_UNIT_ROOT_DN = PROP_TAG(PT_UNICODE, 0x8CA8), /* PidTagAddressBookOrganizationalUnitRootDistinguishedName */
	// PR_EMS_AB_DL_SENDER_HINT_TRANSLATIONS = PROP_TAG(PT_MV_UNICODE, 0x8CAC), /* PidTagAddressBookSenderHintTranslations */
	// PR_EMS_AB_ENABLE_MODERATION = PROP_TAG(PT_BOOLEAN, 0x8CB5), /* PidTagAddressBookModerationEnabled */
	// PR_EMS_AB_AUTH_ORIG = PROP_TAG(PT_OBJECT, 0x8CD8), /* PidTagAddressBookAuthorizedSenders */
	// PR_EMS_AB_UNAUTH_ORIG = PROP_TAG(PT_OBJECT, 0x8CD9), /* PidTagAddressBookUnauthorizedSenders */
	// PR_EMS_AB_DL_MEM_SUBMIT_PERMS = PROP_TAG(PT_OBJECT, 0x8CDA), /* PidTagAddressBookDistributionListMemberSubmitRejected */
	// PR_EMS_AB_DL_MEM_REJECT_PERMS = PROP_TAG(PT_OBJECT, 0x8CDB), /* PidTagAddressBookDistributionListRejectMessagesFromDLMembers */
	// PR_EMS_AB_HAB_IS_HIERARCHICAL_GROUP = PROP_TAG(PT_BOOLEAN, 0x8CDD), /* PidTagAddressBookHierarchicalIsHierarchicalGroup */
	// PR_EMS_AB_DL_TOTAL_MEMBER_COUNT = PROP_TAG(PT_LONG, 0x8CE2), /* PidTagAddressBookDistributionListMemberCount */
	// PR_EMS_AB_DL_EXTERNAL_MEMBER_COUNT = PROP_TAG(PT_LONG, 0x8CE3), /* PidTagAddressBookDistributionListExternalMemberCount */
	PR_EMS_AB_IS_MASTER = PROP_TAG(PT_BOOLEAN, 0xFFFB), /* PidTagAddressBookIsMaster */
	PR_EMS_AB_PARENT_ENTRYID = PROP_TAG(PT_BINARY, 0xFFFC), /* PidTagAddressBookParentEntryId */
	PR_EMS_AB_CONTAINERID = PROP_TAG(PT_LONG, 0xFFFD), /* PidTagAddressBookContainerId */
	PR_BODY = PR_BODY_W, /* PidTagBody */
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

enum { /* ROWENTRY::ulRowFlags bits */
	ROW_ADD    = 1U << 0,
	ROW_MODIFY = 1U << 1,
	ROW_REMOVE = 1U << 2,
	ROW_EMPTY  = ROW_ADD | ROW_REMOVE,
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

struct GLOBCNT {
	uint8_t ab[6];
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

struct PROPERTY_XNAME {
	PROPERTY_XNAME() = default;
	PROPERTY_XNAME(const PROPERTY_NAME &);

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

struct LTPROPVAL_ARRAY {
	uint32_t count;
	TAGGED_PROPVAL *propval;
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
