// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <stdexcept>
#include <fmt/format.h>
#include <gromox/mapidefs.h>

namespace gromox::EWS::Exceptions {

/**
 * @brief      Base class for EWS request errors
 */
class InputError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

/**
 * @brief      Deserialization of request data failed
 */
class DeserializationError : public InputError {
	using InputError::InputError;
};

/**
 * @brief      SOAP protocol error
 */
class SOAPError : public InputError {
	using InputError::InputError;
};

/**
 * @brief      Unknown request (no handler defined)
 */
class UnknownRequestError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

/**
 * @brief      Generic error during request processing
 */
class DispatchError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

/**
 * @brief      Specific EWS error class
 *
 * Provides a mechanism to signal specific error codes, as defined in the EWS
 * specification (Messages.xsd:11).
 *
 * EWSErrors should be converted into error response messages instead of a
 * SOAP client or server error.
 */
class EWSError : public DispatchError {
	public:
	EWSError(const char*, const std::string&);

	std::string type;

#define ERR(name) static inline EWSError name(const std::string& m) {return EWSError("Error" #name, m);}
	ERR(AccessDenied) ///< Calling account does not have necessary rights
	ERR(CalendarInvalidRecurrence) ///< Internal structure of the objects that represent the recurrence is invalid.
	ERR(CannotDeleteObject) ///< Exmdb `delete_message` operation failed
	ERR(CannotEmptyFolder) ///< Failed to empty folder
	ERR(CannotFindUser) ///< Not officially documented, used to signal user or domain resolution error
	ERR(CannotUseFolderIdForItemId) ///< Used folder id where item id was expected
	ERR(CannotUseItemIdForFolderId) ///< Used item id where folder id was expected
	ERR(CorruptData) ///< Generic error for corrupt input data
	ERR(CrossMailboxMoveCopy) ///< Attempted move or copy operation across different stores
	ERR(DeleteDistinguishedFolder) ///< Attempt to delete distinguished folder (Wait. That's illegal.)
	ERR(FolderExists) ///< Creating a folder with a name that already exists
	ERR(FolderNotFound) ///< Folder ID could not be converted or resolved
	ERR(FolderPropertyRequestFailed) ///< Failed to retrieve item property
	ERR(FolderSave) ///< Folder creation or updated
	ERR(FreeBusyGenerationFailed) ///< Something went wrong when trying to retrieve freebusy data
	ERR(ImpersonateUserDenied) ///< Insufficient permissions to impersonate user
	ERR(ImpersonationFailed) ///< Impersonation could not be setup properly
	ERR(InternalServerError) ///< Generic error
	ERR(InvalidAttachmentId) ///< Cannot deserialize attachment ID
	ERR(InvalidFolderId) ///< Cannot deserialize folder ID
	ERR(InvalidFreeBusyViewType) ///< Requested free busy view type is invalid
	ERR(InvalidId) ///< ItemId or ChangeKey malformed
	ERR(InvalidIdNotAnItemAttachmentId) ///< Attachment id expected, but got something else
	ERR(InvalidExtendedPropertyValue) ///< Value of extended property does not match its type
	ERR(InvalidOccurrenceId) ///< Cannot deserialize occurrence ID
	ERR(InvalidRecipients) ///< Recipient list is malformed
	ERR(InvalidRestriction) ///< Restriction cannot be deserialized
	ERR(InvalidRoutingType) ///< RoutingType holds an unrecognized value
	ERR(InvalidSendItemSaveSettings) ///< Specifying target folder when not saving
	ERR(InvalidSubscription) ///< Subscription expired
	ERR(InvalidSubscriptionRequest) ///< Inconsistent subscription request
	ERR(InvalidSyncStateData) ///< Transmitted SyncState is invalid
	ERR(ItemCorrupt) ///< Item could not be loaded properly
	ERR(ItemNotFound) ///< Requested message object does not exist
	ERR(ItemPropertyRequestFailed) ///< Failed to retrieve item property
	ERR(ItemSave)  ///< Failed to set item properties
	ERR(MailRecipientNotFound) ///< Username could not be resolved internally
	ERR(MissingRecipients) ///< Failed to send item because no recipients were specified
	ERR(MoveCopyFailed) ///< Exmdb `movecopy_message` operation failed
	ERR(NameResolutionNoResults) ///< Name resolution failed / no results
	ERR(NotEnoughMemory) ///< Out of memory
	ERR(SchemaValidation) ///< XML value is does not confirm to schema
	ERR(SubscriptionAccessDenied) ///< Trying to access subscription from another user
	ERR(TimeZone) ///< Invalid or missing time zone
	ERR(ValueOutOfRange) ///< Value cannot be interpreted correctly (only applied to dates according to official documentation)
#undef ERR
};

/**
 * @brief      Generic error to signal missing functionality
 *
 * Provides an easily searchable marker.
 */
class NotImplementedError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

/**
 * @brief      An invalid value was assigned to an StrEnum
 */
class EnumError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

///////////////////////////////////////////////////////////////////////////////
//Error codes

#define E(num, content) constexpr char E##num[] = "E-" #num ": " content

E(3000, "failed to resolve essdn - invalid essdn");
E(3001, "failed to resolve essdn - malformed essdn");
E(3002, "failed to resolve essdn - user not found");
E(3003, "failed to resolve essdn - invalid user");
E(3004, "failed to resolve essdn - username mismatch");
E(3005, "failed to get user maildir");
inline std::string E3006(const std::string& RoutingType) {return "E-3006: unrecognized RoutingType '" + RoutingType + "'";}
E(3007, "failed to get user maildir");
//3008 removed
inline std::string E3009(const std::string& ExAud) {return "E-3009: unrecognized ExternalAudience '" + ExAud + "'";}
inline std::string E3010(const std::string& RoutingType) {return "E-3010: unrecognized RoutingType '" + RoutingType + "'";}
E(3011, "cannot access OOF state of another user");
E(3012, "cannot modify OOF state of another user");
E(3013, "either \"FreeBusyViewOptions\" or \"SuggestionsViewOptions\" is required.");
E(3014, "\"TimeZone\" is required.");
E(3015, "failed to get named propids");
E(3016, "failed to get some named propids");
E(3017, "failed to get user permissions");
E(3018, "insufficient access rights");
E(3019, "failed to load calendar");
E(3020, "failed to query calendar");
inline std::string E3021(const char* name) {return fmt::format("request '{}' is marked as beta and can be enabled with 'ews_beta = 1'", name);}
E(3022, "failed to get folder entry id");
E(3023, "failed to get folder properties");
E(3024, "failed to get item entry id");
E(3025, "failed to get item properties");
E(3026, "failed to get username from id");
E(3027, "failed to get domain info from id");
inline std::string E3028(int code) {return fmt::format("E-3028: buffer error ({})", code);}
E(3029, "too many tags requested");
E(3030, "failed to get hierarchy sync data");
E(3031, "failed to get content sync data");
E(3032, "too many tags requested");
E(3033, "invalid base64 string");
inline std::string E3034(const std::string_view& name) {return fmt::format("E-3034: element '{}' is empty", name);}
E(3035, "out of memory");
E(3036, "failed to generate sync state given idset data");
E(3037, "failed to generate sync state seen cnset data");
E(3038, "failed to generate sync state seen fai cnset data");
E(3039, "failed to generate sync state read cnset data");
E(3040, "failed to generate sync state");
inline std::string E3041(const std::string_view& name) {return fmt::format("E-3041: element '{}' is empty", name);}
inline std::string E3042(const std::string_view& name, const std::string_view& content) {return fmt::format("E-3042: element '{}={}' has bad format (expected hh:mm:ss)", name, content);}
inline std::string E3043(const std::string_view& name) {return fmt::format("E-3043: element '{}' is empty", name);}
inline std::string E3044(const std::string_view& name, const std::string_view& content, const std::string_view& type) {return fmt::format("E-3044: failed to convert element '{}={}' to {}", name, content, type);}
inline std::string E3045(const std::string_view& name) {return fmt::format("E-3045: failed to find proper type for node '{}'", name);}
inline std::string E3046(const std::string_view& name, const std::string_view& parent) {return fmt::format("E-3046: missing required child element  '{}' in element '{}'", name, parent);}
inline std::string E3047(const std::string_view& name, const std::string_view& parent) {return fmt::format("E-3047: missing required attribute '{}' in element '{}'", name, parent);}
inline std::string E3048(const std::string_view& name, const std::string_view& parent, const std::string_view& content, const std::string_view& type) {return fmt::format("E-3048: failed to convert attribute '{}={}' in '{}' to {}", name, content, parent, type);}
E(3049, "can only convert binary properties to Base64Binary");
E(3050, "folder entry ID data to large");
inline std::string E3051(const std::string_view& name) {return fmt::format("E-3051: unknown distinguished folder id '{}'", name);}
E(3052, "sync state too big");
E(3053, "failed to deserialize given idset");
E(3054, "failed to deserialize seen cnset");
E(3055, "failed to deserialize read cnset");
E(3056, "failed to deserialize seen fai cnset");
E(3057, "failed to generated sync state idset");
E(3058, "failed to generate sync state cnset");
inline std::string E3059(const std::string_view& type) {return fmt::format("E-3059: unknown tag type '{}'", type);}
E(3060, "invalid ExtendedFieldURI: missing name or ID");
E(3061, "invalid ExtendedFieldURI: missing tag or set ID");
E(3062, "failed to convert given id set");
E(3063, "invalid GUID format");
E(3064, "failed to convert sync state");
E(3065, "failed to add changed mid");
E(3066, "failed to set synced change numbers");
E(3067, "failed to get user properties");
E(3068, "failed to get user aliases");
E(3069, "failed to get named property ids");
E(3070, "failed to get named property names");
E(3071, "failed to read message");
E(3072, "failed to export message");
E(3073, "mail export error");
E(3074, "failed to serialize message");
E(3075, "failed to get username from id");
E(3076, "failed to get domain info from id");
E(3077, "failed to load message instance");
E(3078, "failed to load attachment instance");
E(3079, "failed to get attachment count");
E(3080, "failed to get attachment properties");
E(3081, "attachment ID data to large");
E(3082, "bad property for message entry id");
E(3083, "failed to get attachment properties");
E(3084, "failed to allocate change number");
E(3085, "failed to serialize address book entry id");
//3086 removed
E(3087, "failed to load predecessor change list");
//3088 removed
//3089 removed
inline std::string E3090(const std::string_view& username) {return fmt::format("E-3090: invalid username '{}'", username);}
inline std::string E3091(const std::string_view& username) {return fmt::format("E-3091: failed to get user info for '{}'", username);}
E(3092, "failed to set item properties");
E(3093, "failed to remove item properties");
E(3094, "only one of 'Value' or 'Values' allowed");
E(3095, "multi-value property must be set with 'Values'");
E(3096, "single-value property must be set with 'Value'");
E(3097, "no valid item object found");
E(3098, "could not find matching node for variant deserialization");
E(3099, "array too big for container");
inline std::string E3100(const std::string_view& val) {return fmt::format("E-3100: invalid boolean value '{}'", val);}
inline std::string E3101(const std::string_view& val) {return fmt::format("E-3101: invalid short value '{}'", val);}
inline std::string E3102(const std::string_view& val) {return fmt::format("E-3102: invalid long value '{}'", val);}
inline std::string E3103(const std::string_view& val) {return fmt::format("E-3103: invalid float value '{}'", val);}
inline std::string E3104(const std::string_view& val) {return fmt::format("E-3104: invalid double value '{}'", val);}
inline std::string E3105(const std::string_view& val) {return fmt::format("E-3105: invalid boolean value '{}'", val);}
inline std::string E3106(const std::string_view& val) {return fmt::format("E-3106: invalid i8 value '{}'", val);}
inline std::string E3107(const std::string_view& val) {return fmt::format("E-3107: cannot deserialize property of unsupported type {}", val);}
E(3108, "missing child node in SetItemField object");
E(3109, "PidLidAppointmentRecur contents not recognized");
E(3110, "Invalid recurrence type");
E(3111, "failed to load freebusy information");
E(3112, "cannot create message without ID");
inline std::string E3113(const char* type, const std::string& name) {return fmt::format("E-3113: failed to get {} ID for '{}'", type, name);}
inline std::string E3114(const std::string& RoutingType) {return "E-3114: unrecognized RoutingType '" + RoutingType + "'";}
E(3115, "missing recipients");
E(3116, "failed to export message");
inline std::string E3117(ec_error_t code) { return fmt::format("E-3117: failed to send mail ({})", mapi_strerror(code)); }
E(3118, "failed to allocate message ID");
E(3119, "failed to allocate change number");
E(3120, "failed to generate change key");
E(3121, "failed to generate predecessor change list");
E(3122, "failed to generate predecessor change list");
E(3123, "failed to load mime content");
E(3124, "failed to import mail");
E(3125, "failed to get user maildir");
E(3126, "failed to get user maildir");
E(3127, "failed to get item property");
E(3128, "ext buffer oom");
E(3129, "context alloc failed");
E(3130, "cannot write to target folder");
E(3131, "insufficient permissions to delete messages");
E(3132, "failed to allocate message ID");
E(3133, "failed to move message to deleted items");
E(3134, "delete operation failed");
E(3135, "insufficient permission");
E(3136, "cannot access target folder");
E(3137, "cannot access target folder");
E(3138, "cannot access target folder");
E(3139, "cannot access target folder");
E(3140, "save folder ID specified when not saving");
E(3141, "no write access to save folder");
E(3142, "cannot read source item");
E(3143, "failed to load message");
E(3144, "failed to load freebusy information");
E(3145, "misconfigured buffer size");
E(3146, "failed to deserialize item entry id");
E(3147, "failed to deserialize attachment index");
E(3148, "failed to deserialize folder entry id");
E(3149, "failed to deserialize item entry id");
E(3150, "missing date string");
E(3151, "failed to parse date");
E(3152, "failed to convert timestamp");
E(3153, "failed to allocate cn");
E(3154, "folder creation failed");
E(3155, "a folder with that name already exists");
E(3156, "cannot delete distinguished folder");
E(3157, "insufficient permissions to delete folder");
E(3158, "deleted items folder does not exist in public store");
E(3159, "failed to get folder properties");
E(3160, "missing parent folder properties");
E(3161, "folder move failed");
E(3162, "a folder with that name already exists in the target folder");
E(3163, "folder move was aborted");
E(3164, "could not find copied folder");
E(3165, "failed to delete folder");
E(3166, "failed to get parent folder");
E(3167, "cannot write to destination folder");
E(3168, "cannot move folder across stores");
E(3169, "failed to get folder property");
E(3170, "cannot deserialize predecessor change list");
E(3171, "failed to allocate change number");
E(3172, "missing folder target");
E(3173, "failed to update folder change information");
E(3174, "cannot modify target folder");
E(3175, "failed to set folder properties");
E(3176, "failed to remove folder properties");
E(3177, "no valid folder object found");
E(3178, "missing child node in SetFolderField object");
E(3179, "cannot modify target folder");
E(3180, "failed to empty folder");
E(3181, "empty folder to deleted items is not supported");
E(3182, "failed to allocate message id");
E(3183, "movecopy opertaion failed");
E(3184, "cannot write to destination folder");
E(3185, "cannot read from source directory");
E(3186, "move/copy between stores is not supported");
E(3187, "item not found");
E(3188, "inconsistent item id");
E(3189, "source and destination folder are the same");
E(3190, "cannot write to object");
E(3191, "cannot write to target folder");
inline std::string E3192(const char* type, const std::string& dir) {return fmt::format("E-3192: failed to get {} ID for '{}'", type, dir);}
E(3193, "replid not supported");
E(3194, "failed to retrieve store record key");
E(3195, "invalid recurrence type");
E(3196, "malformed subscription id");
E(3197, "invalid subscription id");
E(3198, "SubscribeToAllFolders cannot be combined with FolderIds");
E(3199, "SubscribeToAllFolders cannot be combined with FolderIds");
E(3200, "cannot subscribe to different mailboxes");
E(3201, "invalid subscription ID");
E(3202, "invalid subscription");
E(3203, "only the subscription owner may access the subscription");
E(3204, "failed to create subscription");
E(3205, "occurrence ID data too large");
E(3206, "failed to deserialize occurrence entry id");
E(3207, "failed to deserialize occurrence basedate");
E(3208, "failed to load embedded instance");
E(3209, "requested occurrence not found");
E(3210, "failed to get embedded instances' count");
E(3211, "failed to get embedded instance properties");
E(3212, "unknown entry id type");
E(3213, "wrong ID type - expected folder ID, got item ID");
E(3214, "wrong ID type - expected item ID, got folder ID");
E(3215, "invalid attachement ID");
E(3216, "invalid ID type");
E(3217, "could not initialize message content");
E(3218, "cannot access target folder");
E(3219, "failed to load hierarchy table");
inline std::string E3220(const char* name) {return fmt::format("E-3220: unknown restriction type '{}'", name);}
E(3221, "missing FieldURIOrConstant node");
inline std::string E3223(proptag_t tag1, proptag_t tag2) {return fmt::format("E-3223: properties 0x{:08x} and 0x{:08x} are not comparable", tag1, tag2);}
E(3224, "failed to find tag for Contains path");
E(3225, "invalid Contains property type");
E(3226, "missing Constant node");
inline std::string E3227(const char* mode){return fmt::format("E-3227: invalid ContainmentMode '{}'", mode);}
inline std::string E3228(const char* comp){return fmt::format("E-3228: invalid ContainmentComparison'{}'", comp);}
E(3229, "failed to find tag for Excludes path");
inline std::string E3230(const char* type, proptag_t tag) {return fmt::format("E-3230: cannnot apply bitmask operation to {} tag (0x{:08x})", type, tag);}
E(3231, "missing BitMask node");
E(3232, "failed to find tag for Exist path");
E(3233, "missing child restriction for Not restriction");
E(3234, "missing Value attribute");
inline std::string E3235(const std::string_view& val) {return fmt::format("E-3235: invalid short value '{}'", val);}
inline std::string E3236(const std::string_view& val) {return fmt::format("E-3236: invalid long value '{}'", val);}
inline std::string E3237(const std::string_view& val) {return fmt::format("E-3237: invalid float value '{}'", val);}
inline std::string E3238(const std::string_view& val) {return fmt::format("E-3238: invalid double value '{}'", val);}
inline std::string E3239(const std::string_view& val) {return fmt::format("E-3239: invalid boolean value '{}'", val);}
inline std::string E3240(const std::string_view& val) {return fmt::format("E-3240: invalid i8 value '{}'", val);}
inline std::string E3241(const char* type) {return fmt::format("E-3241: Constant Value of type {} is not supported", type);}
E(3242, "unsupported ConnectingSID for impersonation");
E(3243, "insufficient permissions to impersonate user");
E(3244, "cannot access target folder");
E(3245, "failed to load content table");
E(3246, "failed to get named property id");
E(3247, "too many sort fields");
E(3248, "PidLidTaskRecurrence contents not recognized");
inline std::string E3249(char c) {return fmt::format("E-3249: invalid hex string character '{}'", c);}
E(3250, "invalid hex string size");
E(3251, "public folder IDs are currently not supported");
E(3252, "invalid input id");
E(3253, "output format not supported");
E(3254, "failed to set item properties");
E(3255, "failed to set item properties");
E(3256, "input body size too large");
E(3257, "missing date value");
E(3258, "too many children");
E(3259, "no name resolution results");
E(3260, "invalid day of week for a weekly recurrence");
E(3261, "failed to convert gmtime to tm");
E(3262, "failed to convert gmtime to tm");
E(3263, "failed to convert gmtime to tm");
E(3264, "failed to convert gmtime to tm");
E(3265, "failed to convert gmtime to tm");
E(3266, "daily recurrence interval must be between 1 and 999");
E(3267, "weekly recurrence interval must be between 1 and 99");
E(3268, "invalid first day of week for a weekly recurrence");
E(3269, "weekly recurrence without a day of week");
E(3270, "MonthlyNth recurrence interval must be between 1 and 99");
E(3271, "MonthlyNth recurrence without a day of week");
E(3272, "MonthlyNth invalid occurrence of the recurrence's days");
E(3273, "monthly recurrence interval must be between 1 and 99");
E(3274, "monthly recurrence invalid day of month");
E(3275, "yearly (MonthlyNth) recurrence without a day of week");
E(3276, "invalid ConnectingSID address type for impersonation");
// 3277 removed
// 3278 removed
E(3279, "yearly recurrence invalid day of month");
E(3280, "invalid recurrence type for a calendar item");
E(3281, "invalid recurrence range for a calendar item");
E(3282, "daycount must not be zero");
E(3283, "failed to load permission table");
E(3284, "failed to load permissions");
E(3285, "too many folder members");
E(3286, "failed to update folder permissions");
E(3287, "failed to write folder permissions");
E(3288, "could not initialize recipient list: out of memory");
E(3289, "could not create recipient: out of memory");
E(3290, "missing e-mail address for recipient");
E(3291, "failed to set recipient: out of memory");
E(3292, "erroneous TIMEZONEDEFINITION");
E(3293, "Timezone definition too large");
E(3294, "Failed to generate timezone definition");
inline std::string E3295(int year) {return fmt::format("E-3295: No active rule for year {} in the timezone definition", year);}
inline std::string E3296(const char* uid) {return fmt::format("E-3296: decode_hex_binary failed to convert UID {} containing EncodedGlobalId", uid);}
inline std::string E3297(const char* uid) {return fmt::format("E-3297: Failed to generate goid from UID {}", uid);}
E(3298, "Failed to allocate memory for goid data");
E(3299, "Failed to generate goid data");
E(3300, "Failed to get offset from the timezone definition");
E(3301, "Failed to copy message to sent items");
E(3302, "Failed to get the display name");
E(3303, "failed to load item");
E(3304, "invalid OccurrenceItemId: missing RecurringMasterId or InstanceIndex");
E(3305, "failed to resolve occurrence index: no recurrence blob");
E(3306, "failed to resolve occurrence index: could not parse recurrence blob");
E(3307, "occurrence index out of range");
E(3308, "failed to save modified recurrence blob");
E(3309, "failed to update occurrence exception");
E(3310, "ExpandDL: no email address in request");
E(3311, "ExpandDL: distribution list not found");
E(3312, "delegate access denied: not mailbox owner");
E(3313, "delegate access denied: not mailbox owner");
E(3314, "delegate access denied: not mailbox owner");
E(3315, "delegate access denied: not mailbox owner");
E(3316, "failed to read delegate list");
E(3317, "failed to write delegate list");
E(3318, "failed to read delegate list");
E(3319, "failed to write delegate list");
E(3320, "failed to read delegate list");
E(3321, "failed to allocate goid binary data");
inline std::string E3322(ec_error_t err) {return fmt::format("failed to create folder: exmdb error: {}", mapi_strerror(err));}
E(3323, "folder already exists (zero folder id)");
E(3324, "failed to write imported message");
E(3325, "failed to duplicate calendar item for acceptance");
E(3326, "failed to set message class on calendar item");
E(3327, "failed to set calendar item response properties");
E(3328, "failed to set existing mid on calendar item");
E(3329, "failed to write calendar item to store");
E(3330, "impersonation: user not found");
E(3331, "failed to resolve user home directory");
E(3332, "item corrupt: failed to parse appointment recurrence");
E(3333, "failed to dispatch embedded message load");
E(3334, "occurrence index not found in recurrence");
E(3335, "failed to get attachment count on message instance");
E(3336, "failed to set instance properties on occurrence");
E(3337, "failed to remove body properties on occurrence");
E(3338, "failed to set RTF sync properties on occurrence");
E(3339, "failed to set recurring/class properties on occurrence");
E(3340, "failed to set attachment properties on occurrence");
E(3341, "failed to flush embedded instance");
E(3342, "failed to flush attachment instance");
E(3343, "failed to flush master message instance");
E(3344, "no recurrence blob on item (create occurrence)");
E(3345, "failed to parse recurrence blob (create occurrence)");
E(3346, "failed to create attachment instance for new occurrence");
E(3347, "failed to write attachment instance for new occurrence");
E(3348, "failed to flush new occurrence attachment instance");
E(3349, "failed to flush new occurrence master instance");
E(3350, "failed to save recurrence blob after occurrence update");
E(3351, "failed to update attendee recipients on instance");
E(3352, "failed to get display name for organizer");
E(3353, "failed to set organizer properties on message");
E(3354, "failed to set named meeting properties on message");
E(3355, "failed to flush attendee instance");
E(3356, "failed to parse recurrence range start date");
E(3357, "failed to serialize XID for change key");
E(3358, "failed to set content properties on item");
E(3359, "failed to parse recurrence range start date (toContent)");
E(3360, "invalid recurrence day of week mask (toContent)");
E(3361, "invalid recurrence day of week for monthly (toContent)");
E(3362, "invalid recurrence interval (toContent)");
E(3363, "invalid recurrence day order (toContent)");
E(3364, "invalid recurrence day of week mask for relative (toContent)");
E(3365, "invalid recurrence day of week for relative monthly (toContent)");
E(3366, "invalid recurrence interval for relative (toContent)");
E(3367, "invalid recurrence month for yearly (toContent)");
E(3368, "invalid recurrence day for yearly (toContent)");
E(3369, "invalid recurrence day of week for relative yearly (toContent)");
E(3370, "invalid recurrence end type (toContent)");
E(3371, "recurrence end date before start date (toContent)");
E(3372, "failed to compute recurrence end date (toContent)");
E(3373, "failed to serialize appointment recurrence pattern");
E(3374, "failed to compute timezone offset for end time");
E(3375, "failed to generate global object id");
E(3376, "failed to generate clean global object id");
E(3377, "failed to allocate recipient list for calendar item");
E(3378, "failed to get display name for calendar organizer");
E(3379, "failed to convert username to ESSDN for calendar");
E(3380, "failed to serialize AB entry id for calendar");
E(3381, "failed to allocate recipient list for message");
E(3382, "invalid push subscription: SubscribeToAllFolders with FolderIds");
E(3383, "invalid streaming subscription: SubscribeToAllFolders with FolderIds");
E(3384, "failed to convert username to ESSDN for modifier");
E(3385, "failed to serialize AB entry id for modifier");
E(3386, "failed to get domain users for room list");
E(3387, "failed to get org domain list");
E(3388, "failed to get domain info for room list");
E(3389, "calendar item not found for cancellation");
E(3390, "sent cancellation item not found after copy");
E(3391, "sent meeting request not found after copy");
E(3392, "user configuration item not found (get)");
E(3393, "user configuration: no rows returned (get)");
E(3394, "user configuration: missing message id (get)");
E(3395, "user configuration item not found (update)");
E(3396, "user configuration: query failed (update)");
E(3397, "user configuration: no rows returned (update)");
E(3398, "user configuration: missing message id (update)");
E(3399, "user configuration item not found (delete)");
E(3400, "user configuration: query failed (delete)");
E(3401, "user configuration: no rows returned (delete)");
E(3402, "user configuration: missing message id (delete)");
E(3403, "failed to read message for send item");
E(3404, "failed to read updated message for send");
E(3405, "sent meeting request not found after copy (update)");
E(3406, "failed to allocate memory for cancellation content");
E(3407, "failed to duplicate content for cancellation send");
E(3408, "failed to duplicate content for meeting request send");
E(3409, "failed to set response properties on meeting item");
E(3410, "failed to set properties on sent meeting request");
E(3411, "failed to update message properties after attachment create");
E(3412, "failed to update message properties after attachment delete");
E(3413, "failed to allocate message id for user configuration");
E(3414, "failed to allocate change number for user configuration");
E(3415, "failed to write user configuration message");
E(3416, "failed to update user configuration properties");
E(3417, "failed to set read state on message");
E(3418, "failed to set message properties (update item)");
E(3419, "failed to set properties on sent meeting request (update)");
E(3420, "invalid folder id in create user configuration");
E(3421, "invalid folder id in get user configuration");
E(3422, "invalid folder id in update user configuration");
E(3423, "invalid folder id in delete user configuration");
E(3424, "failed to allocate message id for sent meeting request");
E(3425, "failed to move/copy folder");
E(3426, "failed to allocate message id for sent request (update)");
E(3427, "failed to copy message to sent items (create)");
E(3428, "failed to copy message to sent items (update)");
E(3429, "failed to set initial attachment properties");
E(3430, "failed to write attachment content");
E(3431, "failed to flush attachment instance");
E(3432, "failed to delete attachment instance");
E(3433, "failed to flush instance after attachment delete");
E(3434, "access denied: create user configuration");
E(3435, "access denied: get user configuration");
E(3436, "access denied: update user configuration");
E(3437, "access denied: delete user configuration");
E(3438, "failed to load content table for user configuration (get)");
E(3439, "failed to load content table for user configuration (update)");
E(3440, "failed to load content table for user configuration (delete)");
inline std::string E3441(const char* name) {return fmt::format("E-3441: GetRooms: no email address in {}", name);}
inline std::string E3442(const std::string_view& username) {return fmt::format("E-3442: GetRooms: failed to extract domain for '{}'", username);}
inline std::string E3443(const std::string_view& addr) {return fmt::format("E-3443: GetRooms: failed to extract target domain for '{}'", addr);}
E(3444, "access denied: delete attachment");
E(3445, "access denied: update item");
E(3446, "failed to write updated message content");
E(3447, "failed to delete user configuration message");
E(3448, "failed to append read change number to sync state");
E(3449, "failed to set message id on updated content");
E(3450, "RecurringMasterId is currently not supported");
E(3451, "RecurringMasterId is currently not supported");
E(3452, "RecurringMasterId is currently not supported");

#undef E
}
