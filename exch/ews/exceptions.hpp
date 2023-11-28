// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <fmt/format.h>
#include <stdexcept>

namespace gromox::EWS::Exceptions {

/**
 * @brief      Base class for EWS request errors
 */
class InputError : public std::runtime_error
{using std::runtime_error::runtime_error;};

/**
 * @brief      Deserialization of request data failed
 */
class DeserializationError : public InputError
{using InputError::InputError;};

/**
 * @brief      SOAP protocol error
 */
class SOAPError : public InputError
{using InputError::InputError;};

/**
 * @brief      Unknown request (no handler defined)
 */
class UnknownRequestError : public std::runtime_error
{using std::runtime_error::runtime_error;};

/**
 * @brief      Generic error during request processing
 */
class DispatchError : public std::runtime_error
{
	using std::runtime_error::runtime_error;
	virtual void unused(); ///< Used to define vtable location
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
class EWSError : public DispatchError
{
	virtual void unused() override; ///< Used to define vtable location
public:
	EWSError(const char*, const std::string&);

	std::string type;

#define ERR(name) static inline EWSError name(const std::string& m) {return EWSError("Error" #name, m);}
	ERR(AccessDenied) ///< Calling account does not have necessary rights
	ERR(CannotDeleteObject) ///< Exmdb `delete_message` operation failed
	ERR(CannotEmptyFolder) ///< Failed to empty folder
	ERR(CannotFindUser) ///< Not officially documented, used to signal user or domain resolution error
	ERR(CannotUseFolderIdForItemId) ///< Used folder id where item id was expected
	ERR(CannotUseItemIdForFolderId) ///< Used item id where folder id was expected
	ERR(CrossMailboxMoveCopy) ///< Attempted move or copy operation across different stores
	ERR(DeleteDistinguishedFolder) ///< Attempt to delete distinguished folder (Wait. That's illegal.)
	ERR(FolderExists) ///< Creating a folder with a name that already exists
	ERR(FolderNotFound) ///< Folder ID could not be converted or resolved
	ERR(FolderPropertyRequestFailed) ///< Failed to retrieve item property
	ERR(FolderSave) ///< Folder creation or updated
	ERR(FreeBusyGenerationFailed) ///< Something went wrong when trying to retrieve freebusy data
	ERR(InvalidAttachmentId) ///< Cannot deserialize attachment ID
	ERR(InvalidFolderId) ///< Cannot deserialize folder ID
	ERR(InvalidFreeBusyViewType) ///< Requested free busy view type is invalid
	ERR(InvalidId) ///< ItemId or ChangeKey malformed
	ERR(InvalidIdNotAnItemAttachmentId) ///< Attachment id expected, but got something else
	ERR(InvalidExtendedPropertyValue) ///< Value of extended property does not match its type
	ERR(InvalidOccurrenceId) ///< Cannot deserialize occurrence ID
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
class NotImplementedError : public std::runtime_error
{using std::runtime_error::runtime_error;};

/**
 * @brief      An invalid value was assigned to an StrEnum
 */
class EnumError : public std::runtime_error
{using std::runtime_error::runtime_error;};

///////////////////////////////////////////////////////////////////////////////
//Error codes

#define E(num, content) constexpr char E##num[] = "E-" #num ": " content

E(3000, "failed to resolve essdn - invalid essdn");
E(3001, "failed to resolve essdn - malformed essdn");
E(3002, "failed to resolve essdn - user not found");
E(3003, "failed to resolve essdn - invalid user");
E(3004, "failed to resolve essdn - username mismatch");
E(3005, "failed to get user maildir");
inline std::string E3006(const std::string& RoutingType) {return "E-3006: unrecognized RoutingType '"+RoutingType+"'";}
E(3007, "failed to get user maildir");
//3008 removed
inline std::string E3009(const std::string& ExAud) {return "E-3009: unrecognized ExternalAudience '"+ExAud+"'";}
inline std::string E3010(const std::string& RoutingType) {return "E-3010: unrecognized RoutingType '"+RoutingType+"'";}
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
E(3021, "request is marked as beta and can be enabled with 'ews_beta = 1'");
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
E(3089, "failed to update message");
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
inline std::string E3114(const std::string& RoutingType) {return "E-3114: unrecognized RoutingType '"+RoutingType+"'";}
E(3115, "missing recipients");
E(3116, "failed to export message");
inline std::string E3117(int code) {return fmt::format("E-3117: failed to send mail ({})", code);}
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

#undef E
}
