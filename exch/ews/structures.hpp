// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include <gromox/clock.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>

#include "enums.hpp"

namespace tinyxml2
{
	class XMLElement;
	class XMLAttribute;
}

namespace gromox::EWS
{struct EWSContext;}

namespace gromox::EWS::Structures
{

struct tCalendarFolderType;
struct tContactsFolderType;
struct tDistinguishedFolderId;
struct tFolderId;
struct tFolderType;
struct tItem;
struct tMessage;
struct tSearchFolderType;
struct tSerializableTimeZone;
struct tSyncFolderHierarchyCreate;
struct tSyncFolderHierarchyUpdate;
struct tSyncFolderHierarchyDelete;
struct tSyncFolderItemsCreate;
struct tSyncFolderItemsUpdate;
struct tSyncFolderItemsDelete;
struct tSyncFolderItemsReadFlag;
struct tTasksFolderType;


///////////////////////////////////////////////////////////////////////////////////////////////////
//XML namespace info types

/**
 * @brief Base struct (no namespace) for XML namespace information
 */
struct NSInfo
{
	static constexpr char NS_ABBREV[] = "";
	static constexpr char NS_URL[] = "";
};

struct NS_EWS_Messages : public NSInfo
{
	static constexpr char NS_ABBREV[] = "m:";
	static constexpr char NS_URL[] = "http://schemas.microsoft.com/exchange/services/2006/messages";
};

struct NS_EWS_Types : public NSInfo
{
	static constexpr char NS_ABBREV[] = "t:";
	static constexpr char NS_URL[] = "http://schemas.microsoft.com/exchange/services/2006/types";
};

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Convenience wrapper for Base64 encoded data
 *
 * Automatically en- and decodes during (de-)serialization, providing direct
 * access to the binary data.
 */
struct sBase64Binary : public std::vector<uint8_t>
{
	sBase64Binary() = default;
	sBase64Binary(const TAGGED_PROPVAL&);
	explicit sBase64Binary(const tinyxml2::XMLElement*);
	explicit sBase64Binary(const tinyxml2::XMLAttribute*);

	std::string serialize() const;
	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief     Folder entry ID extension
 *
 * Provides EWS conversions and access utilities.
 */
struct sFolderEntryId : public FOLDER_ENTRYID
{
	sFolderEntryId(const tinyxml2::XMLAttribute*);
	sFolderEntryId(const void*, uint64_t);

	std::string serialize() const;

	uint32_t accountId() const;
	uint64_t folderId() const;
	bool isPrivate() const;
private:
	void init(const void*, uint64_t);
};

/**
 * @brief      Folder specification
 *
 * Resolves folder ID and type either from the distinguished name or
 * the folder target string.
 */
struct sFolderSpec
{
	sFolderSpec() = default;
	explicit sFolderSpec(const tDistinguishedFolderId&);
	sFolderSpec(const std::string&, uint64_t);

	sFolderSpec& normalize();

	std::optional<std::string> target;
	uint64_t folderId;
	enum : uint8_t {AUTO, PRIVATE, PUBLIC} location = AUTO;

private:
	struct DistNameInfo
	{
		const char* name;
		uint64_t id;
		bool isPrivate;
	};

	static const std::array<DistNameInfo, 21> distNameInfo;
};

/**
 * Joint folder type
 */
using sFolder = std::variant<tFolderType, tCalendarFolderType, tContactsFolderType, tSearchFolderType, tTasksFolderType>;

using sItem = std::variant<tItem, tMessage>;

using sNamedPropertyMap = std::unordered_map<uint32_t, PROPERTY_NAME>;

/**
 * @brief      Utility struct to manage property tags and property name information
 */
struct sProptags
{
	std::vector<uint32_t> tags; ///< Properties return from the store
	sNamedPropertyMap namedTags; ///< Tag -> named property mapping
};


/**
 * @brief     Sync state helper class
 */
struct sSyncState
{
	sSyncState();

	void init(const std::string&);
	void update(const EID_ARRAY&, const EID_ARRAY&, uint64_t);
	std::string serialize();

	idset given; ///< Set of known IDs
	idset seen;  ///< Set of known change numbers
	idset read;  ///< Set of read change numbers
	idset seen_fai; ///< Set of seen fai change numbers
	uint32_t readOffset = 0; ///< Number of read states already delivered

private:
	static constexpr uint32_t MetaTagReadOffset = PROP_TAG(PT_LONG, 0x0e69); //PR_READ, but with long type
};

/**
 * @brief     Formatted time string helper struct
 *
 * Parses a time string in hh:mm:ss format into the hour, minute and second
 * members.
 */
struct sTime
{
	sTime(const tinyxml2::XMLElement*);

	uint8_t hour;
	uint8_t minute;
	uint8_t second;
};

/**
 * @brief     Timepoint with time zone offset
 */
struct sTimePoint
{
	sTimePoint(const gromox::time_point&);
	sTimePoint(const gromox::time_point&, const tSerializableTimeZone&);

	void serialize(tinyxml2::XMLElement*) const;

	static sTimePoint fromNT(uint64_t);

	gromox::time_point time;
	std::chrono::minutes offset = std::chrono::minutes(0);
};

///////////////////////////////////////////////////////////////////////////////////////////////////

template<typename T> using vector_inserter = std::back_insert_iterator<std::vector<T>>;

class tBaseItemId
{
public:

	sBase64Binary Id; //Attribute
	std::optional<sBase64Binary> ChangeKey; //Attribute

	tBaseItemId() = default;
	tBaseItemId(const tinyxml2::XMLElement*);
	tBaseItemId(const sBase64Binary&, const std::optional<sBase64Binary>& = std::nullopt);

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6288
 */
struct tCalendarEventDetails
{
	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::string> ID;
	std::optional<std::string> Subject;
	std::optional<std::string> Location;
	bool IsMeeting;
	bool IsRecurring;
	bool IsException;
	bool IsReminderSet;
	bool IsPrivate;
};

/**
 * Types.xsd:6301
 */
struct tCalendarEvent : public NS_EWS_Types
{
	static constexpr char NAME[] = "CalendarEvent";

	tCalendarEvent(time_t start, time_t end, uint32_t btype, const std::string &uid, const char *subj, const char *loc, bool meet, bool recur, bool exc, bool remind, bool pvt, bool detailed);

	void serialize(tinyxml2::XMLElement*) const;

	sTimePoint StartTime;
	sTimePoint EndTime;
	Enum::LegacyFreeBusyType BusyType;
	std::optional<tCalendarEventDetails> CalenderEventDetails;
};

/**
 * @brief      Duration
 *
 * Types.xsd:6316
 */
struct tDuration
{
	static constexpr char NAME[] = "Duration";

	tDuration() = default;
	explicit tDuration(const tinyxml2::XMLElement*);

	void serialize(tinyxml2::XMLElement*) const;

	gromox::time_point StartTime;
	gromox::time_point EndTime;
};

/**
 * @brief      Identifier for a fully resolved email address
 *
 * Types.xsd:273
 */
struct tEmailAddressType
{
	static constexpr char NAME[] = "Mailbox";

	tEmailAddressType() = default;
	explicit tEmailAddressType(const tinyxml2::XMLElement*);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::string> Name;
	std::optional<std::string> EmailAddress;
	std::optional<std::string> RoutingType;
	std::optional<Enum::MailboxTypeType> MailboxType;
	std::optional<std::string> ItemId;
	std::optional<std::string> OriginalDisplayName;
};

/**
 * Types.xsd:1862
 */
struct tFolderId : public tBaseItemId
{
	static constexpr char NAME[] = "FolderId";

	using tBaseItemId::tBaseItemId;
};

/**
 * Types.xsd:1028
 */
struct tGuid : public GUID
{
	explicit tGuid(const tinyxml2::XMLAttribute*);
	tGuid(const GUID&);

	std::string serialize() const;
};

/**
 * Types.xsd:1142
 */
struct tExtendedFieldURI
{
	using TMEntry = std::pair<const char*, uint16_t>;

	static constexpr char NAME[] = "ExtendedFieldURI";

	explicit tExtendedFieldURI(const tinyxml2::XMLElement*);
	explicit tExtendedFieldURI(uint32_t);
	tExtendedFieldURI(uint16_t, const PROPERTY_NAME&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::string> PropertyTag; //Attribute
	Enum::MapiPropertyTypeType PropertyType; //Attribute
	std::optional<int32_t> PropertyId; // Attribute
	//<xs:attribute name="DistinguishedPropertySetId" type="t:DistinguishedPropertySetType" use="optional"/>
	std::optional<tGuid> PropertySetId; // Attribute.
	std::optional<std::string> PropertyName; //Attribute

	void tags(vector_inserter<uint32_t>&, vector_inserter<PROPERTY_NAME>&, vector_inserter<uint16_t>&) const;

	static const char* typeName(uint16_t);

	static std::array<TMEntry, 26> typeMap; ///< Types.xsd:1060
};

/**
 * Types.xsd:1196
 */
struct tExtendedProperty
{
	explicit tExtendedProperty(const TAGGED_PROPVAL&, const PROPERTY_NAME& = PROPERTY_NAME{KIND_NONE, {}, 0, nullptr});

	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;

	void serialize(tinyxml2::XMLElement*) const;
private:
	void serialize(const void*, size_t, uint16_t, tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:1981
 */
struct tBaseFolderType : public NS_EWS_Types
{
	explicit tBaseFolderType(const TPROPVAL_ARRAY&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<tFolderId> FolderId;
	std::optional<tFolderId> ParentFolderId;
	std::optional<std::string> FolderClass;
	std::optional<std::string> DisplayName;
	std::optional<int32_t> TotalCount;
	std::optional<int32_t> ChildFolderCount;
	std::vector<tExtendedProperty> ExtendedProperty;
	//<xs:element name="ManagedFolderInformation" type="t:ManagedFolderInformationType" minOccurs="0"/>
	//<xs:element name="EffectiveRights" type="t:EffectiveRightsType" minOccurs="0"/>
	//<xs:element name="DistinguishedFolderId" type="t:DistinguishedFolderIdNameType" minOccurs="0"/>
	//<xs:element name="PolicyTag" type="t:RetentionTagType" minOccurs="0" />
	//<xs:element name="ArchiveTag" type="t:RetentionTagType" minOccurs="0" />
	//<xs:element name="ReplicaList" type="t:ArrayOfStringsType" minOccurs="0" />

	static sFolder create(const TPROPVAL_ARRAY&);
protected:
	tBaseFolderType(const tBaseFolderType&) = default;
	tBaseFolderType(tBaseFolderType&&) noexcept = default;
	~tBaseFolderType() = default; ///< Abstract class, only available to derived classes
};

/**
 * Types.xsd:
 */
struct tFieldURI
{
	static constexpr char NAME[] = "FieldURI";

	tFieldURI(const tinyxml2::XMLElement*);

	void tags(vector_inserter<uint32_t>&, vector_inserter<PROPERTY_NAME>&, vector_inserter<uint16_t>&) const;

	std::string FieldURI; //Attribute

	static std::unordered_multimap<std::string, uint32_t> tagMap; ///< Types.xsd:402
	static std::unordered_multimap<std::string, std::pair<PROPERTY_NAME, uint16_t>> nameMap; ///< Types.xsd:402
};

/**
 * Types.xsd:2436
 */
struct tFlagType
{
	Enum::FlagStatusType FlagStatus;
	//<xs:element name="FlagStatus" type="t:FlagStatusType" minOccurs="1" maxOccurs="1"/>
	//<xs:element name="StartDate" type="xs:dateTime" minOccurs="0" />
	//<xs:element name="DueDate" type="xs:dateTime" minOccurs="0" />
	//<xs:element name="CompleteDate" type="xs:dateTime" minOccurs="0" />

	void serialize(tinyxml2::XMLElement*) const;
};


/**
 * Types.xsd:1165
 */
struct tPath : public std::variant<tExtendedFieldURI, tFieldURI>
{
	using Base = std::variant<tExtendedFieldURI, tFieldURI>;

	tPath(const tinyxml2::XMLElement*);

	void tags(vector_inserter<uint32_t>&, vector_inserter<PROPERTY_NAME>&, vector_inserter<uint16_t>&) const;
};

/**
 * Types.xsd:2019
 */
struct tFolderType : public tBaseFolderType
{
	static constexpr char NAME[] = "Folder";

	explicit tFolderType(const TPROPVAL_ARRAY&);

	void serialize(tinyxml2::XMLElement*) const;

	//<xs:element name="PermissionSet" type="t:PermissionSetType" minOccurs="0"/>
	std::optional<int32_t> UnreadCount;
};

/**
 * Types.xsd:2031
 */
struct tCalendarFolderType : public tBaseFolderType
{
	static constexpr char NAME[] = "CalendarFolder";

	using tBaseFolderType::tBaseFolderType;

	//void serialize(tinyxml2::XMLElement*) const;

	//<xs:element name="SharingEffectiveRights" type="t:CalendarPermissionReadAccessType" minOccurs="0"/>
	//<xs:element name="PermissionSet" type="t:CalendarPermissionSetType" minOccurs="0"/>
};

/**
 * Types.xsd:2064
 */
struct tContactsFolderType : public tBaseFolderType
{
	static constexpr char NAME[] = "ContactsFolder";

	using tBaseFolderType::tBaseFolderType;

	//void serialize(tinyxml2::XMLElement*) const;

	//<xs:element name="SharingEffectiveRights" type="t:PermissionReadAccessType" minOccurs="0"/>
	//<xs:element name="PermissionSet" type="t:PermissionSetType" minOccurs="0"/>
	//<xs:element name="SourceId" type="xs:string" minOccurs="0"/>
	//<xs:element name="AccountName" type="xs:string" minOccurs="0"/>
};

/**
 * Types.xsd:2078
 */
struct tSearchFolderType : public tBaseFolderType
{
	static constexpr char NAME[] = "SearchFolder";

	using tBaseFolderType::tBaseFolderType;

	//void serialize(tinyxml2::XMLElement*) const;

	//<xs:element name="SearchParameters" type="t:SearchParametersType" minOccurs="0" />

};

/**
 * Types.xsd:2128
 */
struct tItemId : public tBaseItemId
{
	static constexpr char NAME[] = "ItemId";

	using tBaseItemId::tBaseItemId;
};

/**
 * Types.xsd:2353
 */
struct tItem : public NS_EWS_Types
{
	static constexpr char NAME[] = "Item";

	tItem(const TPROPVAL_ARRAY&, const sNamedPropertyMap&);

	//<xs:element name="MimeContent" type="t:MimeContentType" minOccurs="0" />
	std::optional<tItemId> ItemId; ///< PR_ENTRYID+PR_CHANGEKEY
	std::optional<tFolderId> ParentFolderId; ///< PR_PARENT_ENTRYID
	std::optional<std::string> ItemClass; ///< PR_MESSAGE_CLASS
	std::optional<std::string> Subject; ///< PR_SUBJECT
	//<xs:element name="Sensitivity" type="t:SensitivityChoicesType" minOccurs="0" />
	//<xs:element name="Body" type="t:BodyType" minOccurs="0" />
	//<xs:element name="Attachments" type="t:NonEmptyArrayOfAttachmentsType" minOccurs="0" />
	std::optional<sTimePoint> DateTimeReceived; ///< PR_MESSAGE_DELIVERY_TIME
	std::optional<uint64_t> Size; ///< PR_MESSAGE_SIZE_EXTENDED
	//<xs:element name="Categories" type="t:ArrayOfStringsType" minOccurs="0" />
	std::optional<Enum::ImportanceChoicesType> Importance; ///< PR_IMPORTANCE
	std::optional<std::string> InReplyTo; ///< PR_IN_REPLY_TO_ID
	//std::optional<bool> IsSubmitted;
	//std::optional<bool> IsDraft;
	//std::optional<bool> IsFromMe;
	//std::optional<bool> IsResend;
	//std::optional<bool> IsUnmodified;
	//<xs:element name="InternetMessageHeaders" type="t:NonEmptyArrayOfInternetHeadersType" minOccurs="0" />
	std::optional<sTimePoint> DateTimeSent;
	//std::optional<gromox::time_point> DateTimeCreated;
	//<xs:element name="ResponseObjects" type="t:NonEmptyArrayOfResponseObjectsType" minOccurs="0" />
	//std::optional<gromox::time_point> ReminderDueBy;
	//std::optional<bool> ReminderIsSet;
	//std::optional<gromox::time_point> ReminderNextTime;
	//<xs:element name="ReminderMinutesBeforeStart" type="t:ReminderMinutesBeforeStartType" minOccurs="0" />
	std::optional<std::string> DisplayCc;
	std::optional<std::string> DisplayTo;
	std::optional<std::string> DisplayBcc;
	std::optional<bool> HasAttachments;
	std::vector<tExtendedProperty> ExtendedProperty;
	//<xs:element name="Culture" type="xs:language" minOccurs="0"/>
	//<xs:element name="EffectiveRights" type="t:EffectiveRightsType" minOccurs="0" />
	std::optional<std::string> LastModifiedName;
	std::optional<gromox::time_point> LastModifiedTime;
	std::optional<bool> IsAssociated;
	//<xs:element name="WebClientReadFormQueryString" type="xs:string" minOccurs="0" />
	//<xs:element name="WebClientEditFormQueryString" type="xs:string" minOccurs="0" />
	std::optional<tItemId> ConversationId;
	//<xs:element name="UniqueBody" type="t:BodyType" minOccurs="0" />
	std::optional<tFlagType> Flag;
	//<xs:element name="StoreEntryId" type="xs:base64Binary" minOccurs="0" />
	//<xs:element name="InstanceKey" type="xs:base64Binary" minOccurs="0" />
	//<xs:element name="NormalizedBody" type="t:BodyType" minOccurs="0"/>
	//<xs:element name="EntityExtractionResult" type="t:EntityExtractionResultType" minOccurs="0" />
	//<xs:element name="PolicyTag" type="t:RetentionTagType" minOccurs="0" />
	//<xs:element name="ArchiveTag" type="t:RetentionTagType" minOccurs="0" />
	//<xs:element name="RetentionDate" type="xs:dateTime" minOccurs="0" />
	//<xs:element name="Preview" type="xs:string" minOccurs="0" />
	//<xs:element name="RightsManagementLicenseData" type="t:RightsManagementLicenseDataType" minOccurs="0" />
	//<xs:element name="PredictedActionReasons" type="t:NonEmptyArrayOfPredictedActionReasonType" minOccurs="0" />
	//<xs:element name="IsClutter" type="xs:boolean" minOccurs="0" />
	//<xs:element name="BlockStatus" type="xs:boolean" minOccurs="0" />
	//<xs:element name="HasBlockedImages" type="xs:boolean" minOccurs="0" />
	//<xs:element name="TextBody" type="t:BodyType" minOccurs="0"/>
	//<xs:element name="IconIndex" type="t:IconIndexType" minOccurs="0"/>
	//<xs:element name="SearchKey" type="xs:base64Binary" minOccurs="0" />
	//<xs:element name="SortKey" type="xs:long" minOccurs="0" />
	//<xs:element name="Hashtags" type="t:ArrayOfStringsType" minOccurs="0" />
	//<xs:element name="Mentions" type="t:ArrayOfRecipientsType" minOccurs="0" />
	//<xs:element name="MentionedMe" type="xs:boolean" minOccurs="0" />
	//<xs:element name="MentionsPreview" type="t:MentionsPreviewType" minOccurs="0" />
	//<xs:element name="MentionsEx" type="t:NonEmptyArrayOfMentionActionsType" minOccurs="0" />
	//<xs:element name="AppliedHashtags" type="t:NonEmptyArrayOfAppliedHashtagType" minOccurs="0" />
	//<xs:element name="AppliedHashtagsPreview" type="t:AppliedHashtagsPreviewType" minOccurs="0" />
	//<xs:element name="Likes" type="t:NonEmptyArrayOfLikeType" minOccurs="0" />
	//<xs:element name="LikesPreview" type="t:LikesPreviewType" minOccurs="0" />
	//<xs:element name="PendingSocialActivityTagIds" type="t:ArrayOfStringsType" minOccurs="0" />
	//<xs:element name="AtAllMention" type="xs:boolean" minOccurs="0" />
	//<xs:element name="CanDelete" type="xs:boolean" minOccurs="0" />
	//<xs:element name="InferenceClassification" type="t:InferenceClassificationType" minOccurs="0" />

	void serialize(tinyxml2::XMLElement*) const;

	bool mapNamedProperty(const TAGGED_PROPVAL&, const sNamedPropertyMap&);

	static sItem create(const TPROPVAL_ARRAY&, const sNamedPropertyMap& = sNamedPropertyMap());
};


/**
 * Types.xsd:1287
 */
struct tItemResponseShape
{
	tItemResponseShape(const tinyxml2::XMLElement*);

	void tags(vector_inserter<uint32_t>&, vector_inserter<PROPERTY_NAME>&, vector_inserter<uint16_t>&) const;

	//Enum::DefaultShapeNamesType BaseShape;
	//std::optional<bool> IncludeMimeContent;
	//std::optional<Enum::BodyTypeResponseType> BodyType;
	//std::optional<Enum::BodyTypeResponseType> UniqueBodyType;
	//std::optional<Enum::BodyTypeResponseType> NormalizedBodyType;
	//std::optional<bool> FilterHtmlContent;
	//std::optional<std::string> InlineImageUrlTemplate;
	//std::optional<bool> ConvertHtmlCodePageToUTF8;
	//std::optional<bool> AddBlankTargetToLinks;
	//std::optional<int32_t> MaximumBodySize;
	std::optional<std::vector<tPath>> AdditionalProperties;

	static constexpr std::array<uint32_t, 3> tagsIdOnly = {PR_ENTRYID, PR_CHANGE_KEY, PR_MESSAGE_CLASS};
};

/**
 * Types.xsd:2089
 */
struct tTasksFolderType : public tBaseFolderType
{
	static constexpr char NAME[] = "TasksFolder";
	using tBaseFolderType::tBaseFolderType;
};


/**
 * Types.xsd:6372
 */
struct tSerializableTimeZoneTime
{
	explicit tSerializableTimeZoneTime(const tinyxml2::XMLElement*);

	int32_t Bias;
	sTime Time;
	int32_t DayOrder;
	int32_t Month;
	Enum::DayOfWeekType DayOfWeek;
	std::optional<int32_t> Year;
};

/**
 * Types.xsd:6383
 */
struct tSerializableTimeZone
{
	explicit tSerializableTimeZone(const tinyxml2::XMLElement*);

	int32_t Bias;
	tSerializableTimeZoneTime StandardTime;
	tSerializableTimeZoneTime DaylightTime;

	std::chrono::minutes offset(const gromox::time_point&) const;
	gromox::time_point apply(const gromox::time_point&) const;
	gromox::time_point remove(const gromox::time_point&) const;
};

/**
 * Joint hierarchy change type
 *
 * Types.xsd:6223
 */
using tSyncFolderHierarchyChange = std::variant<tSyncFolderHierarchyCreate, tSyncFolderHierarchyUpdate, tSyncFolderHierarchyDelete>;

/**
 * @brief     Joint type for create and update
 *
 * Types.xsd:6223
 */
struct tSyncFolderHierarchyCU : public NS_EWS_Types
{
	tSyncFolderHierarchyCU(sFolder&&);

	sFolder folder;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6223
 */
struct tSyncFolderHierarchyCreate : public tSyncFolderHierarchyCU
{
	using tSyncFolderHierarchyCU::tSyncFolderHierarchyCU;

	static constexpr char NAME[] = "Create";
};

/**
 * Types.xsd:6223
 */
struct tSyncFolderHierarchyUpdate : public tSyncFolderHierarchyCU
{
	static constexpr char NAME[] = "Update";

	using tSyncFolderHierarchyCU::tSyncFolderHierarchyCU;
};

/**
 * Types.xsd:6233
 */
struct tSyncFolderHierarchyDelete : public NS_EWS_Types
{
	static constexpr char NAME[] = "Delete";

	tSyncFolderHierarchyDelete(const sBase64Binary&);

	tFolderId FolderId;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:396
 */
struct tSingleRecipient
{
	tEmailAddressType Mailbox;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:4031
 */
struct tMessage : public tItem
{
	static constexpr char NAME[] = "Message";

	tMessage(const TPROPVAL_ARRAY&, const sNamedPropertyMap& = sNamedPropertyMap());

	std::optional<tSingleRecipient> Sender; ///< PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS, PR_SENDER_NAME
	//std::optional<std::vector<tSingleRecipient>> ToRecipients;
	//std::optional<std::vector<tSingleRecipient>> CcRecipients;
	//std::optional<std::vector<tSingleRecipient>> BccRecipients;
	std::optional<bool> IsReadReceiptRequested;
	std::optional<bool> IsDeliveryReceiptRequested;
	std::optional<sBase64Binary> ConversationIndex; ///< PR_CONVERSATION_INDEX
	std::optional<std::string> ConversationTopic; ///< PR_CONVERSATION_TOPIC
	//<xs:element name="ConversationTopic" type="xs:string" minOccurs="0" />
	std::optional<tSingleRecipient> From;
	std::optional<std::string> InternetMessageId; ///< PR_INTERNET_MESSAGE_ID
	std::optional<bool> IsRead;
	std::optional<bool> IsResponseRequested;
	std::optional<std::string> References; ///< PR_INTERNET_REFERENCES
	//<xs:element name="References" type="xs:string" minOccurs="0" />
	std::optional<std::vector<tSingleRecipient>> ReplyTo;
	std::optional<tSingleRecipient> ReceivedBy;
	std::optional<tSingleRecipient> ReceivedRepresenting;

	//<xs:element name="ApprovalRequestData" type="t:ApprovalRequestDataType" minOccurs="0" />
	//<xs:element name="VotingInformation" type="t:VotingInformationType" minOccurs="0" />
	//<xs:element name="ReminderMessageData" type="t:ReminderMessageDataType" minOccurs="0" />
	//<xs:element name="MessageSafety" type="t:MessageSafetyType" minOccurs="0" />
	//<xs:element name="SenderSMTPAddress" type="t:SmtpAddressType" minOccurs="0"/>
	//<xs:element name="MailboxGuids" minOccurs="0" maxOccurs="1">
	//<xs:complexType>
	//  <xs:sequence>
	//	<xs:element name="MailboxGuid" type="t:GuidType" maxOccurs="unbounded"/>
	//  </xs:sequence>
	//</xs:complexType>
	//</xs:element>
	//<xs:element name="PublishedCalendarItemIcs" type="xs:string" minOccurs="0" />
	//<xs:element name="PublishedCalendarItemName" type="xs:string" minOccurs="0" />

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Joint item change type
 *
 * Types.xsd:6211
 */
using tSyncFolderItemsChange = std::variant<tSyncFolderItemsCreate, tSyncFolderItemsUpdate, tSyncFolderItemsDelete, tSyncFolderItemsReadFlag>;

/**
 * @brief     Joint type for create and update
 *
 * Types.xsd:1634
 */
struct tSyncFolderItemsCU : public NS_EWS_Types
{
	void serialize(tinyxml2::XMLElement*) const;

	sItem item;
};

struct tSyncFolderItemsCreate : public tSyncFolderItemsCU
{static constexpr char NAME[] = "Create";};

struct tSyncFolderItemsUpdate : public tSyncFolderItemsCU
{static constexpr char NAME[] = "Update";};

/**
 * Types.xsd:6198
 */
struct tSyncFolderItemsDelete : public NS_EWS_Types
{
	static constexpr char NAME[] = "Delete";

	tSyncFolderItemsDelete(const TAGGED_PROPVAL&);

	tItemId ItemId;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6204
 */
struct tSyncFolderItemsReadFlag : public NS_EWS_Types
{
	static constexpr char NAME[] = "ReadFlagChange";

	tItemId ItemId;
	bool IsRead;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:1273
 */
struct tFolderResponseShape
{
	tFolderResponseShape(const tinyxml2::XMLElement*);

	void tags(vector_inserter<uint32_t>&, vector_inserter<PROPERTY_NAME>&, vector_inserter<uint16_t>&) const;

	Enum::DefaultShapeNamesType BaseShape;
	std::optional<std::vector<tPath>> AdditionalProperties;

	static constexpr std::array<uint32_t, 3> tagsIdOnly = {PR_ENTRYID, PR_CHANGE_KEY, PR_CONTAINER_CLASS};
	static constexpr std::array<uint32_t, 4> tagsDefault = {PR_DISPLAY_NAME, PR_CONTENT_COUNT, PR_FOLDER_CHILD_COUNT, PR_CONTENT_UNREAD};
};

/**
 * Types.xsd:6400
 */
struct tFreeBusyView
{
	tFreeBusyView() = default;
	tFreeBusyView(const char*, const char*, time_t, time_t, const EWSContext&);

	void serialize(tinyxml2::XMLElement*) const;

	Enum::FreeBusyViewType FreeBusyViewType = "None";
	std::optional<std::string> MergedFreeBusy;
	std::optional<std::vector<tCalendarEvent>> CalendarEventArray;
	//<xs:element minOccurs="0" maxOccurs="1" name="WorkingHours" type="t:WorkingHours" />
};

/**
 * Types.xsd:6348
 */
struct tFreeBusyViewOptions
{
	tFreeBusyViewOptions(const tinyxml2::XMLElement*);

	tDuration TimeWindow;
	std::optional<int32_t> MergedFreeBusyIntervalInMinutes;
	std::optional<Enum::FreeBusyViewType> RequestedView;
};

/**
 * @brief      Mailbox/EmailAddress
 *
 * Types.xsd:6323
 */
struct tMailbox
{
	static constexpr char NAME[] = "Mailbox";

	explicit tMailbox(const tinyxml2::XMLElement*);

	std::optional<std::string> Name;
	std::string Address;
	std::optional<std::string> RoutingType;
};

/**
 * Types.xsd:1847
 */
struct tDistinguishedFolderId
{
	static constexpr char NAME[] = "DistinguishedFolderId";

	explicit tDistinguishedFolderId(const std::string_view&);
	explicit tDistinguishedFolderId(const tinyxml2::XMLElement*);

	std::optional<tEmailAddressType> Mailbox;
	std::optional<std::string> ChangeKey; //Attribute
	Enum::DistinguishedFolderIdNameType Id; //Attribute
};

/**
 * Types.xsd:6409
 */
struct tMailboxData
{
	tMailboxData(const tinyxml2::XMLElement*);

	tMailbox Email;
	Enum::MeetingAttendeeType AttendeeType;
	std::optional<bool> ExcludeConflicts;
};

/**
 * Types.xsd:6987
 */
struct tMailTips
{
	void serialize(tinyxml2::XMLElement*) const;

	tEmailAddressType RecipientAddress;
	Enum::MailTipTypes PendingMailTips;

	//<xs:element minOccurs="0" maxOccurs="1" name="OutOfOffice" type="t:OutOfOfficeMailTip" />
	//<xs:element minOccurs="0" maxOccurs="1" name="MailboxFull" type="xs:boolean" />
	//<xs:element minOccurs="0" maxOccurs="1" name="CustomMailTip" type="xs:string" />
	//<xs:element minOccurs="0" maxOccurs="1" name="TotalMemberCount" type="xs:int" />
	//<xs:element minOccurs="0" maxOccurs="1" name="ExternalMemberCount" type="xs:int" />
	//<xs:element minOccurs="0" maxOccurs="1" name="MaxMessageSize" type="xs:int" />
	//<xs:element minOccurs="0" maxOccurs="1" name="DeliveryRestricted" type="xs:boolean" />
	//<xs:element minOccurs="0" maxOccurs="1" name="IsModerated" type="xs:boolean" />
	//<xs:element minOccurs="0" maxOccurs="1" name="InvalidRecipient" type="xs:boolean" />
	//<xs:element minOccurs="0" maxOccurs="1" name="Scope" type="xs:int" />
	//<xs:element minOccurs="0" maxOccurs="1" name="RecipientSuggestions" type="t:ArrayOfRecipientSuggestionsType" />
	//<xs:element minOccurs="0" maxOccurs="1" name="PreferAccessibleContent" type="xs:boolean" />
};

/**
 * Types.xsd:6982
 */
struct tSmtpDomain
{
	static constexpr char NAME[] = "Domain";

	void serialize(tinyxml2::XMLElement*) const;

	std::string Name;
	std::optional<bool> IncludeSubdomains;
};

/**
 * Types.xsd:7040
 */
struct tMailTipsServiceConfiguration
{
	void serialize(tinyxml2::XMLElement*) const;

	std::vector<tSmtpDomain> InternalDomains;
	int32_t MaxRecipientsPerGetMailTipsRequest = std::numeric_limits<int32_t>::max();
	int32_t MaxMessageSize = std::numeric_limits<int32_t>::max();
	int32_t LargeAudienceThreshold = std::numeric_limits<int32_t>::max();
	int32_t LargeAudienceCap = std::numeric_limits<int32_t>::max();
	bool MailTipsEnabled = false;
	bool PolicyTipsEnabled = false;
	bool ShowExternalRecipientCount = false;
};

/**
 * @brief      Message reply body
 *
 * Type.xsd:6538
 */
struct tReplyBody
{
	template<typename T> explicit tReplyBody(T &&Message) : Message(std::forward<T>(Message)) {}
	explicit tReplyBody(const tinyxml2::XMLElement*);

	std::optional<std::string> Message;
	std::optional<std::string> lang;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6432
 */
struct tSuggestionsViewOptions
{
	explicit tSuggestionsViewOptions(const tinyxml2::XMLElement*);

	std::optional<int32_t> GoodThreshold;
	std::optional<int32_t> MaximumResultsByDay;
	std::optional<int32_t> MaximumNonWorkHourResultsByDay;
	std::optional<int32_t> MeetingDurationInMinutes;
	std::optional<Enum::SuggestionQuality> MinimumSuggestionQuality;
	tDuration DetailedSuggestionsWindow;
	std::optional<gromox::time_point> CurrentMeetingTime;
	std::optional<std::string> GlobalObjectId;
};

/**
 * Types.xsd:1898
 */
struct tTargetFolderIdType
{
	explicit tTargetFolderIdType(std::variant<tFolderId, tDistinguishedFolderId>&&);
	explicit tTargetFolderIdType(const tinyxml2::XMLElement*);

	std::variant<tFolderId, tDistinguishedFolderId> folderId;
};

/**
 * @brief      User out-of-office settings
 *
 * Types.xsd:6551
 */
struct tUserOofSettings
{
	static constexpr char NAME[] = "UserOofSettings";

	tUserOofSettings() = default;
	explicit tUserOofSettings(const tinyxml2::XMLElement*);

	void serialize(tinyxml2::XMLElement*) const;

	Enum::OofState OofState;
	Enum::ExternalAudience ExternalAudience;
	std::optional<tDuration> Duration; ///< Out-of-office duration
	std::optional<tReplyBody> InternalReply; ///< Internal reply message
	std::optional<tReplyBody> ExternalReply; ///< External reply message

	//<xs:element minOccurs="0" maxOccurs="1" name="DeclineMeetingReply" type="t:ReplyBody" />
	//<xs:element minOccurs="0" maxOccurs="1" name="DeclineEventsForScheduledOOF" type="xs:boolean" />
	//<xs:element minOccurs="0" maxOccurs="1" name="DeclineAllEventsForScheduledOOF" type="xs:boolean" />
	//<xs:element minOccurs="0" maxOccurs="1" name="CreateOOFEvent" type="xs:boolean" />
	//<xs:element minOccurs="0" maxOccurs="1" name="OOFEventSubject" type="xs:string" />
	//<xs:element minOccurs="0" maxOccurs="1" name="AutoDeclineFutureRequestsWhenOOF" type="xs:boolean" />
	//<xs:element minOccurs="0" maxOccurs="1" name="OOFEventID" type="xs:string" />
	//<xs:element minOccurs="0" maxOccurs="1" name="EventsToDeleteIDs" type="t:ArrayOfEventIDType" />
};

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Response message type
 *
 * Messages.xsd:550
 */
struct mResponseMessageType : public NS_EWS_Messages
{
	mResponseMessageType() = default;
	explicit mResponseMessageType(const std::string&, const std::optional<std::string>& = std::nullopt,
	                              const std::optional<std::string>& = std::nullopt);

	std::string ResponseClass;
	std::optional<std::string> MessageText;
	std::optional<std::string> ResponseCode;
	std::optional<int32_t> DescriptiveLinkKey;

	mResponseMessageType& success();

	void serialize(tinyxml2::XMLElement*) const;
};

///////////////////////////////////////////////////////////////////////////////

/**
 * Messages.xsd:692
 */
struct mGetFolderRequest
{
	mGetFolderRequest(const tinyxml2::XMLElement*);

	tFolderResponseShape FolderShape;
	std::vector<std::variant<tFolderId, tDistinguishedFolderId>> FolderIds;
};

struct mGetFolderResponseMessage : mResponseMessageType
{
	static constexpr char NAME[] = "GetFolderResponseMessage";

	using mResponseMessageType::mResponseMessageType;
	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement*) const;

	std::vector<sFolder> Folders;
};

/**
 * Messages.xsd:789
 */
struct mGetFolderResponse
{
	void serialize(tinyxml2::XMLElement*) const;

	std::vector<mGetFolderResponseMessage> ResponseMessages;
};

/**
 * @brief      Get mail tips request
 *
 * Messages.xsg:1742
 */
struct mGetMailTipsRequest
{
	explicit mGetMailTipsRequest(const tinyxml2::XMLElement*);

	tEmailAddressType SendingAs;
	std::vector<tEmailAddressType> Recipients;
	Enum::MailTipTypes MailTipsRequested;
};

/**
 * Messages.xsd:1776
 */
struct mMailTipsResponseMessageType : mResponseMessageType
{
	static constexpr char NAME[] = "MailTipsResponseMessageType";

	using mResponseMessageType::success;

	std::optional<tMailTips> MailTips;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      Get mail tips response
 *
 * Messages.xsg:1760
 */
struct mGetMailTipsResponse : mResponseMessageType
{
	using mResponseMessageType::success;

	std::vector<mMailTipsResponseMessageType> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2815
 */
struct mGetServiceConfigurationRequest
{
	explicit mGetServiceConfigurationRequest(const tinyxml2::XMLElement*);

	std::optional<tEmailAddressType> ActingAs;
	std::vector<Enum::ServiceConfigurationType> RequestedConfiguration;
	//<xs:element minOccurs="0" maxOccurs="1" name="ConfigurationRequestDetails" type="t:ConfigurationRequestDetailsType" />
};

/**
 * Messages.xsd:2831
 */
struct mGetServiceConfigurationResponseMessageType : mResponseMessageType
{
	static constexpr char NAME[] = "ServiceConfigurationResponseMessageType";

	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<tMailTipsServiceConfiguration> MailTipsConfiguration;
	//<xs:element name="UnifiedMessagingConfiguration" type="t:UnifiedMessageServiceConfiguration" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="ProtectionRulesConfiguration" type="t:ProtectionRulesServiceConfiguration" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="PolicyNudgeRulesConfiguration" type="t:PolicyNudgeRulesServiceConfiguration" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="SharePointURLsConfiguration" type="t:SharePointURLsServiceConfiguration" minOccurs="0" maxOccurs="1"/>)
};

/**
 * Messages.xsd:2831
 */
struct mGetServiceConfigurationResponse : mResponseMessageType
{
	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement*) const;

	std::vector<mGetServiceConfigurationResponseMessageType> ResponseMessages;
};

/**
 * Messages.xsd:2204
 */
struct mGetUserAvailabilityRequest
{
	explicit mGetUserAvailabilityRequest(const tinyxml2::XMLElement*);

	std::optional<tSerializableTimeZone> TimeZone;
	std::vector<tMailboxData> MailboxDataArray;
	std::optional<tFreeBusyViewOptions> FreeBusyViewOptions;
	std::optional<tSuggestionsViewOptions> SuggestionsViewOptions;
};

/**
 * Messages.xsd:2182
 */
struct mFreeBusyResponse : public NS_EWS_Messages
{

	static constexpr char NAME[] = "FreeBusyResponse";

	mFreeBusyResponse() = default;
	explicit mFreeBusyResponse(tFreeBusyView&&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<tFreeBusyView> FreeBusyView;
	std::optional<mResponseMessageType> ResponseMessage;
};

/**
 * Messages.xsd:2204
 */
struct mGetUserAvailabilityResponse
{
	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::vector<mFreeBusyResponse>> FreeBusyResponseArray;
	//<xs:element minOccurs="0" maxOccurs="1" name="SuggestionsResponse" type="m:SuggestionsResponseType" />
};

/**
 * @brief      Out-of-office settings request
 *
 * Messages.xsg:2215
 */
struct mGetUserOofSettingsRequest
{
	explicit mGetUserOofSettingsRequest(const tinyxml2::XMLElement*);

	tMailbox Mailbox;
};

/**
 * @brief      Out-of-office settings response
 *
 * Messages.xsd:2228
 */
struct mGetUserOofSettingsResponse
{
	mResponseMessageType ResponseMessage;
	std::optional<tUserOofSettings> OofSettings;

	/* OXWOOF v15 §7.1 says it's optional, but OL disagrees */
	std::string AllowExternalOof = "All";

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      Out-of-office settings set request
 *
 * Messages.xsd:2239
 */
struct mSetUserOofSettingsRequest
{
	explicit mSetUserOofSettingsRequest(const tinyxml2::XMLElement*);

	tMailbox Mailbox;
	tUserOofSettings UserOofSettings;
};

/**
 * @brief      Out-of-office settings set response
 *
 * Messages.xsd:2254
 */
struct mSetUserOofSettingsResponse
{
	mResponseMessageType ResponseMessage;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2098
 */
struct mSyncFolderHierarchyRequest
{
	explicit mSyncFolderHierarchyRequest(const tinyxml2::XMLElement*);

	tFolderResponseShape FolderShape;
	std::optional<tTargetFolderIdType> SyncFolderId;
	std::optional<std::string> SyncState;
};

/**
 * Messages.xsd:2111
 */
struct mSyncFolderHierarchyResponseMessage : mResponseMessageType
{
	static constexpr char NAME[] = "SyncFolderHierarchyResponseMessage";

	std::optional<std::string> SyncState;
	std::optional<bool> IncludesLastFolderInRange;
	std::optional<std::vector<tSyncFolderHierarchyChange>> Changes;

	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2122
 */
struct mSyncFolderHierarchyResponse
{
	std::vector<mSyncFolderHierarchyResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2129
 */
struct mSyncFolderItemsRequest
{
	explicit mSyncFolderItemsRequest(const tinyxml2::XMLElement*);

	tItemResponseShape ItemShape;
	tTargetFolderIdType SyncFolderId;
	std::optional<std::string> SyncState;
	int32_t MaxChangesReturned;
	std::optional<Enum::SyncFolderItemsScopeType> SyncScope;

	//<xs:element name="Ignore" type="t:ArrayOfBaseItemIdsType" minOccurs="0"/>
};

struct mSyncFolderItemsResponseMessage : mResponseMessageType
{
	static constexpr char NAME[] = "SyncFolderItemsResponseMessage";

	std::optional<std::string> SyncState;
	std::optional<bool> IncludesLastItemInRange;
	std::vector<tSyncFolderItemsChange> Changes;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2156
 */
struct mSyncFolderItemsResponse
{
	std::vector<mSyncFolderItemsResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

}
