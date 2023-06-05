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
{class EWSContext;}

namespace gromox::EWS::Structures
{

struct tCalendarFolderType;
struct tCalendarItem;
struct tContact;
struct tContactsFolderType;
struct tDistinguishedFolderId;
struct tExtendedFieldURI;
struct tExtendedProperty;
struct tFieldURI;
struct tFileAttachment;
struct tFindResponsePagingAttributes;
struct tFolderId;
struct tFolderResponseShape;
struct tFolderType;
struct tIndexedFieldURI;
struct tItem;
struct tItemAttachment;
struct tItemResponseShape;
struct tPath;
struct tMessage;
struct tReferenceAttachment;
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

using sAttachment = std::variant<tItemAttachment, tFileAttachment, tReferenceAttachment>;

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
	sBase64Binary(const BINARY*);
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
 * @brief     Message entry ID extension
 *
 * Provides EWS conversions and access utilities.
 */
struct sMessageEntryId : public MESSAGE_ENTRYID
{
	sMessageEntryId() = default;
	sMessageEntryId(const void*, uint64_t);
	explicit sMessageEntryId(const TAGGED_PROPVAL&);

	uint32_t accountId() const;
	uint64_t folderId() const;
	eid_t messageId() const;
	bool isPrivate() const;
private:
	void init(const void*, uint64_t);
};

/**
 * @brief      Attachment ID
 *
 * Allows referencing attachments by message entry ID and attachment index.
 *
 * @todo
 */
struct sAttachmentId : public sMessageEntryId
{
	sAttachmentId(const sMessageEntryId&, uint32_t);
	sAttachmentId(const TAGGED_PROPVAL&, uint32_t);
	sAttachmentId(const void*, uint64_t);

	uint32_t attachment_num;

	void serialize(tinyxml2::XMLElement*) const;
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

	// TODO: missing item types
	/*
	<Items>
		<DistributionList/>
		<MeetingMessage/>
		<MeetingRequest/>
		<MeetingResponse/>
		<MeetingCancellation/>
		<Task/>
		<PostItem/>
	</Items>
	*/
using sItem = std::variant<tItem, tMessage, tCalendarItem, tContact>;

using sNamedPropertyMap = std::unordered_map<uint32_t, PROPERTY_NAME>;

class sShape
{
	/**
	 * @brief     Property metadata
	 *
	 * Keep track of how properties were requested and whether they have been
	 * read.
	 * Enables distinction between extended properties and named fields that
	 * may be requested independently from each other.
	 */
	struct PropInfo
	{
		explicit PropInfo(uint8_t=0, const PROPERTY_NAME* = nullptr);
		PropInfo(uint8_t, const TAGGED_PROPVAL*);

		const TAGGED_PROPVAL* prop = nullptr;
		const PROPERTY_NAME* name = nullptr;
		uint8_t flags = 0;
	};

	std::vector<uint32_t> tags; ///< Tags requested + named tags

	std::vector<uint32_t> namedTags; ///< Named tags (ID and type, ID might be 0 if unknown)
	std::vector<PROPERTY_NAME> names; ///< Requested named properties
	std::vector<uint8_t> nameMeta; ///< Flags for named tags

	std::unordered_map<uint32_t, PropInfo> props; ///<

	void collectExtendedProperty(const tExtendedFieldURI&);
	void collectExtendedProperty(const tFieldURI&);
	void collectExtendedProperty(const tIndexedFieldURI&);

	static constexpr PROPERTY_NAME NONAME{KIND_NONE, {}, 0, nullptr};

public:
	static constexpr uint8_t FL_ANY =   0;
	static constexpr uint8_t FL_FIELD = 1 << 0; ///< Tag was requested as field
	static constexpr uint8_t FL_EXT =   1 << 1; ///< Tag was requested as extended attribute

	static constexpr uint64_t ToRecipients =  1 << 0;
	static constexpr uint64_t CcRecipients =  1 << 1;
	static constexpr uint64_t BccRecipients = 1 << 2;
	static constexpr uint64_t Body =          1 << 3;
	static constexpr uint64_t MessageFlags =  1 << 4;
	static constexpr uint64_t MimeContent =   1 << 5;
	static constexpr uint64_t Attachments =   1 << 6;

	static constexpr uint64_t Recipients = ToRecipients | CcRecipients | BccRecipients;

	sShape() = default;
	explicit sShape(const TPROPVAL_ARRAY&);
	explicit sShape(const tFolderResponseShape&);
	explicit sShape(const tItemResponseShape&);

	sShape(const sShape&) = delete;
	sShape(sShape&&) = delete;

	sShape& operator=(const sShape&) = delete;
	sShape& operator=(sShape&&) = delete;

	void clean();
	bool namedProperties(const PROPID_ARRAY&);
	PROPNAME_ARRAY namedProperties() const;
	void properties(const TPROPVAL_ARRAY&);
	PROPTAG_ARRAY proptags() const;

	void add(uint32_t, uint8_t=0);
	void add(const PROPERTY_NAME&, uint16_t, uint8_t=0);

	const TAGGED_PROPVAL* get(uint32_t, uint8_t=FL_FIELD) const;
	const TAGGED_PROPVAL* get(const PROPERTY_NAME&, uint8_t=FL_FIELD) const;
	template<typename T> const T* get(uint32_t, uint8_t=FL_FIELD) const;
	void putExtended(std::vector<tExtendedProperty>&) const;

	uint64_t special = 0; ///< Fields that are not directly accessible by properties
	std::string store; ///< For which store the named properties are valid
};

/**
 * String class to be used in arrays (i.e. Types.xsd:3852)
 */
struct sString : public std::string, public NS_EWS_Types
{
	static constexpr char NAME[] = "String";
	using std::string::string;
};

/**
 * @brief     Sync state helper class
 */
struct sSyncState
{
	sSyncState();

	void convert();
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

/**
 * Types.xsd:1611
 */
struct tAttachment : public NS_EWS_Types
{
	explicit tAttachment(const sAttachmentId&, const TPROPVAL_ARRAY&);

	static sAttachment create(const sAttachmentId&, const TPROPVAL_ARRAY&);

	std::optional<sAttachmentId> AttachmentId;
	std::optional<std::string> Name;
	std::optional<std::string> ContentType;
	std::optional<std::string> ContentId;
	std::optional<std::string> ContentLocation;
	std::optional<std::string> AttachmentOriginalUrl;
	std::optional<int32_t> Size;
	std::optional<sTimePoint> LastModifiedTime;
	std::optional<bool> IsInline;

	void serialize(tinyxml2::XMLElement*) const;
};

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
 * Types.xsd:1560
 */
struct tRequestAttachmentId : public tBaseItemId
{
	static constexpr char NAME[] = "AttachmentId";

	using tBaseItemId::tBaseItemId;
};

/**
 * Types.xsd:1725
 */
struct tBody : public std::string
{
	template<typename T>
	inline tBody(T&& content, const char* type) : std::string(std::forward<T>(content)), BodyType(type)
	{}

	Enum::BodyTypeType BodyType; //Attribute
	std::optional<bool> IsTruncated; //Attribute

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
	std::optional<tCalendarEventDetails> CalendarEventDetails;
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
struct tEmailAddressType : public NS_EWS_Types
{
	static constexpr char NAME[] = "Mailbox";

	tEmailAddressType() = default;
	explicit tEmailAddressType(const tinyxml2::XMLElement*);
	explicit tEmailAddressType(const TPROPVAL_ARRAY&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::string> Name;
	std::optional<std::string> EmailAddress;
	std::optional<std::string> RoutingType;
	std::optional<Enum::MailboxTypeType> MailboxType;
	std::optional<std::string> ItemId;
	std::optional<std::string> OriginalDisplayName;
};

/**
 * Types.xsd:5359
 */
struct tEmailAddressDictionaryEntry
{
	static constexpr char NAME[] = "t:Entry";

	void serialize(tinyxml2::XMLElement*) const;

	explicit tEmailAddressDictionaryEntry(const std::string&, const Enum::EmailAddressKeyType&);

	std::string Entry;
	Enum::EmailAddressKeyType Key; //Attribute
	std::optional<std::string> Name; //Attribute
	std::optional<std::string> RoutingType; //Attribute
	std::optional<Enum::MailboxTypeType> MailboxType; //Attribute
};

/**
 * Types.xsd
 */
struct tPhoneNumberDictionaryEntry
{
	static constexpr char NAME[] = "t:Entry";

	void serialize(tinyxml2::XMLElement*) const;

	explicit tPhoneNumberDictionaryEntry(std::string, Enum::PhoneNumberKeyType);

	std::string Entry;
	Enum::PhoneNumberKeyType Key; //Attribute
};

/**
 * Types.xsd:1665
 */
struct tReferenceAttachment : public tAttachment
{
	static constexpr char NAME[] = "ReferenceAttachment";

	//tReferenceAttachment(const sAttachmentId&, const TPROPVAL_ARRAY&);
	using tAttachment::tAttachment;

	//<xs:element name="AttachLongPathName" type="xs:string" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="ProviderType" type="xs:string" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="ProviderEndpointUrl" type="xs:string" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="AttachmentThumbnailUrl" type="xs:string" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="AttachmentPreviewUrl" type="xs:string" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="PermissionType" type="xs:int" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="OriginalPermissionType" type="xs:int" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="AttachmentIsFolder" type="xs:boolean" minOccurs="0" maxOccurs="1"/>

	//void serialize(tinyxml2::XMLElement*) const;
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
	std::optional<Enum::DistinguishedPropertySetType> DistinguishedPropertySetId; //Attribute
	std::optional<tGuid> PropertySetId; // Attribute.
	std::optional<std::string> PropertyName; //Attribute

	void tags(sShape&) const;

	static const char* typeName(uint16_t);

	static std::array<const GUID*, 10> propsetIds; ///< Same order as Enum::DistinguishedPropertySetType, Types.xsd:1040
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
	void serialize(const void*, uint16_t, tinyxml2::XMLElement*) const;

	template<typename C, typename T>
	void serializeMV(const void*, uint16_t, tinyxml2::XMLElement*, T* C::*) const;
};

/**
 * Types.xsd:1981
 */
struct tBaseFolderType : public NS_EWS_Types
{
	explicit tBaseFolderType(const sShape&);

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

	static sFolder create(const sShape&);
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
	using SMEntry = std::pair<const char*, uint64_t>;

	static constexpr char NAME[] = "FieldURI";

	tFieldURI(const tinyxml2::XMLElement*);

	void tags(sShape&) const;

	std::string FieldURI; //Attribute

	//Types.xsd:402
	static std::unordered_multimap<std::string, uint32_t> tagMap; ///< Mapping for normal properties
	static std::unordered_multimap<std::string, std::pair<PROPERTY_NAME, uint16_t>> nameMap; ///< Mapping for named properties
	static std::array<SMEntry, 10> specialMap; ///< Mapping for special properties
};

/**
 * Types.xsd:1654
 */
struct tFileAttachment : public tAttachment
{
	static constexpr char NAME[] = "FileAttachment";

	tFileAttachment(const sAttachmentId&, const TPROPVAL_ARRAY&);

	std::optional<bool> IsContactPhoto;
	std::optional<sBase64Binary> Content;

	void serialize(tinyxml2::XMLElement*) const;
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
 * Types.xsd:1108
 */
struct tIndexedFieldURI
{
	static constexpr char NAME[] = "IndexedFieldURI";

	tIndexedFieldURI(const tinyxml2::XMLElement*);

	void tags(sShape&) const;

	std::string FieldURI; //Attribute
	std::string FieldIndex; //Attribute
};

/**
 * Types.xsd:1165
 */
struct tPath : public std::variant<tExtendedFieldURI, tFieldURI, tIndexedFieldURI>
{
	using Base = std::variant<tExtendedFieldURI, tFieldURI, tIndexedFieldURI>;

	tPath(const tinyxml2::XMLElement*);

	void tags(sShape&) const;

	inline const Base& asVariant() const {return static_cast<const Base&>(*this);}
};

/**
 * Types.xsd:2019
 */
struct tFolderType : public tBaseFolderType
{
	static constexpr char NAME[] = "Folder";

	explicit tFolderType(const sShape&);

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

	explicit tItem(const sShape&);

	std::optional<sBase64Binary> MimeContent; ///< exmdb::read_message
	std::optional<tItemId> ItemId; ///< PR_ENTRYID+PR_CHANGEKEY
	std::optional<tFolderId> ParentFolderId; ///< PR_PARENT_ENTRYID
	std::optional<std::string> ItemClass; ///< PR_MESSAGE_CLASS
	std::optional<std::string> Subject; ///< PR_SUBJECT
	std::optional<Enum::SensitivityChoicesType> Sensitivity; ///< PR_SENSITIVITY
	std::optional<tBody> Body; ///< PR_BODY or PR_HTML
	std::optional<std::vector<sAttachment>> Attachments;
	std::optional<sTimePoint> DateTimeReceived; ///< PR_MESSAGE_DELIVERY_TIME
	std::optional<int32_t> Size; ///< PR_MESSAGE_SIZE_EXTENDED
	std::optional<std::vector<sString>> Categories; ///< Named property "PS_PUBLIC_STRINGS:Keywords:PT_MV_UNICODE"
	std::optional<Enum::ImportanceChoicesType> Importance; ///< PR_IMPORTANCE
	std::optional<std::string> InReplyTo; ///< PR_IN_REPLY_TO_ID
	std::optional<bool> IsSubmitted;
	std::optional<bool> IsDraft;
	std::optional<bool> IsFromMe;
	std::optional<bool> IsResend;
	std::optional<bool> IsUnmodified;
	//<xs:element name="InternetMessageHeaders" type="t:NonEmptyArrayOfInternetHeadersType" minOccurs="0" />
	std::optional<sTimePoint> DateTimeSent;
	std::optional<sTimePoint> DateTimeCreated;
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
	std::optional<std::string> Culture;
	//<xs:element name="EffectiveRights" type="t:EffectiveRightsType" minOccurs="0" />
	std::optional<std::string> LastModifiedName;
	std::optional<sTimePoint> LastModifiedTime;
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

	static sItem create(const sShape&);
};

/**
 * Types.xsd:4933
 */
struct tCalendarItem : public tItem
{
	static constexpr char NAME[] = "CalendarItem";

	explicit tCalendarItem(const sShape&);

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:5541
 */
struct tContact : public tItem
{
	static constexpr char NAME[] = "Contact";

	explicit tContact(const sShape&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::string> FileAs;
	// <xs:element name="FileAsMapping" type="t:FileAsMappingType" minOccurs="0" />
	std::optional<std::string> DisplayName;
	std::optional<std::string> GivenName;
	std::optional<std::string> Initials;
	std::optional<std::string> MiddleName;
	std::optional<std::string> Nickname;
	// <xs:element name="CompleteName" type="t:CompleteNameType" minOccurs="0" />
	std::optional<std::string> CompanyName;
	std::optional<std::vector<tEmailAddressDictionaryEntry>> EmailAddresses;
	// <xs:element name="AbchEmailAddresses" type="t:AbchEmailAddressDictionaryType" minOccurs="0" />
	// <xs:element name="PhysicalAddresses" type="t:PhysicalAddressDictionaryType" minOccurs="0" />
	std::optional<std::vector<tPhoneNumberDictionaryEntry>> PhoneNumbers;
	std::optional<std::string> AssistantName;
	// <xs:element name="Birthday" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="BusinessHomePage" type="xs:anyURI" minOccurs="0" />
	// <xs:element name="Children" type="t:ArrayOfStringsType" minOccurs="0" />
	// <xs:element name="Companies" type="t:ArrayOfStringsType" minOccurs="0" />
	std::optional<Enum::ContactSourceType> ContactSource;
	std::optional<std::string> Department;
	// <xs:element name="Generation" type="xs:string" minOccurs="0" />
	// <xs:element name="ImAddresses" type="t:ImAddressDictionaryType" minOccurs="0" />
	std::optional<std::string> JobTitle;
	// <xs:element name="Manager" type="xs:string" minOccurs="0" />
	// <xs:element name="Mileage" type="xs:string" minOccurs="0" />
	std::optional<std::string> OfficeLocation;
	// <xs:element name="PostalAddressIndex" type="t:PhysicalAddressIndexType" minOccurs="0" />
	// <xs:element name="Profession" type="xs:string" minOccurs="0" />
	// <xs:element name="SpouseName" type="xs:string" minOccurs="0" />
	std::optional<std::string> Surname;
	// <xs:element name="WeddingAnniversary" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="HasPicture" type="xs:boolean" minOccurs="0" />
	// <xs:element name="PhoneticFullName" type="xs:string" minOccurs="0" />
	// <xs:element name="PhoneticFirstName" type="xs:string" minOccurs="0" />
	// <xs:element name="PhoneticLastName" type="xs:string" minOccurs="0" />
	// <xs:element name="Alias" type="xs:string" minOccurs="0" />
	// <xs:element name="Notes" type="xs:string" minOccurs="0" />
	// <xs:element name="Photo" type="xs:base64Binary" minOccurs="0" />
	// <xs:element name="UserSMIMECertificate" type="t:ArrayOfBinaryType" minOccurs="0" />
	// <xs:element name="MSExchangeCertificate" type="t:ArrayOfBinaryType" minOccurs="0" />
	// <xs:element name="DirectoryId" type="xs:string" minOccurs="0" />
	// <xs:element name="ManagerMailbox" type="t:SingleRecipientType" minOccurs="0" />
	// <xs:element name="DirectReports" type="t:ArrayOfRecipientsType" minOccurs="0" />
	// <xs:element name="AccountName" type="xs:string" minOccurs="0" />
	// <xs:element name="IsAutoUpdateDisabled" type="xs:boolean" minOccurs="0" />
	// <xs:element name="IsMessengerEnabled" type="xs:boolean" minOccurs="0" />
	// <xs:element name="Comment" type="xs:string" minOccurs="0" />
	// <xs:element name="ContactShortId" type="xs:int" minOccurs="0" />
	// <xs:element name="ContactType" type="xs:string" minOccurs="0" />
	// <xs:element name="Gender" type="xs:string" minOccurs="0" />
	// <xs:element name="IsHidden" type="xs:boolean" minOccurs="0" />
	// <xs:element name="ObjectId" type="xs:string" minOccurs="0" />
	// <xs:element name="PassportId" type="xs:long" minOccurs="0" />
	// <xs:element name="IsPrivate" type="xs:boolean" minOccurs="0" />
	// <xs:element name="SourceId" type="xs:string" minOccurs="0" />
	// <xs:element name="TrustLevel" type="xs:int" minOccurs="0" />
	// <xs:element name="CreatedBy" type="xs:string" minOccurs="0" />
	// <xs:element name="Urls" type="t:ContactUrlDictionaryType" minOccurs="0" />
	// <xs:element name="Cid" type="xs:long" minOccurs="0" />
	// <xs:element name="SkypeAuthCertificate" type="xs:string" minOccurs="0" />
	// <xs:element name="SkypeContext" type="xs:string" minOccurs="0" />
	// <xs:element name="SkypeId" type="xs:string" minOccurs="0" />
	// <xs:element name="SkypeRelationship" type="xs:string" minOccurs="0" />
	// <xs:element name="YomiNickname" type="xs:string" minOccurs="0" />
	// <xs:element name="XboxLiveTag" type="xs:string" minOccurs="0" />
	// <xs:element name="InviteFree" type="xs:boolean" minOccurs="0" />
	// <xs:element name="HidePresenceAndProfile" type="xs:boolean" minOccurs="0" />
	// <xs:element name="IsPendingOutbound" type="xs:boolean" minOccurs="0" />
	// <xs:element name="SupportGroupFeeds" type="xs:boolean" minOccurs="0" />
	// <xs:element name="UserTileHash" type="xs:string" minOccurs="0" />
	// <xs:element name="UnifiedInbox" type="xs:boolean" minOccurs="0" />
	// <xs:element name="Mris" type="t:ArrayOfStringsType" minOccurs="0" />
	// <xs:element name="Wlid" type="xs:string" minOccurs="0" />
	// <xs:element name="AbchContactId" type="t:GuidType" minOccurs="0" />
	// <xs:element name="NotInBirthdayCalendar" type="xs:boolean" minOccurs="0" />
	// <xs:element name="ShellContactType" type="xs:string" minOccurs="0" />
	// <xs:element name="ImMri" type="xs:string" minOccurs="0" />
	// <xs:element name="PresenceTrustLevel" type="xs:int" minOccurs="0" />
	// <xs:element name="OtherMri" type="xs:string" minOccurs="0" />
	// <xs:element name="ProfileLastChanged" type="xs:string" minOccurs="0" />
	// <xs:element name="MobileIMEnabled" type="xs:boolean" minOccurs="0" />
	// <xs:element name="PartnerNetworkProfilePhotoUrl" type="xs:string" minOccurs="0" />
	// <xs:element name="PartnerNetworkThumbnailPhotoUrl" type="xs:string" minOccurs="0" />
	// <xs:element name="PersonId" type="xs:string" minOccurs="0" />
	// <xs:element name="ConversationGuid" type="t:GuidType" minOccurs="0" />
};

/**
 * Types.xsd:1611
 */
struct tItemAttachment : public tAttachment
{
	static constexpr char NAME[] = "ItemAttachment";

	//tItemAttachment(const sAttachmentId&, const TPROPVAL_ARRAY&);
	using tAttachment::tAttachment;

	//<xs:element name="Item" type="t:ItemType"/>
	//<xs:element name="Message" type="t:MessageType"/>
	//<xs:element name="SharingMessage" type="t:SharingMessageType"/>
	//<xs:element name="CalendarItem" type="t:CalendarItemType"/>
	//<xs:element name="Contact" type="t:ContactItemType"/>
	//<xs:element name="MeetingMessage" type="t:MeetingMessageType"/>
	//<xs:element name="MeetingRequest" type="t:MeetingRequestMessageType"/>
	//<xs:element name="MeetingResponse" type="t:MeetingResponseMessageType"/>
	//<xs:element name="MeetingCancellation" type="t:MeetingCancellationMessageType"/>
	//<xs:element name="Task" type="t:TaskType"/>
	//<xs:element name="PostItem" type="t:PostItemType"/>
	//<xs:element name="RoleMember" type="t:RoleMemberItemType"/>
	//<xs:element name="Network" type="t:NetworkItemType"/>
	//<xs:element name="Person" type="t:AbchPersonItemType"/>

	//void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:1287
 */
struct tItemResponseShape
{
	explicit tItemResponseShape(const tinyxml2::XMLElement*);

	void tags(sShape&) const;

	//Enum::DefaultShapeNamesType BaseShape;
	std::optional<bool> IncludeMimeContent;
	std::optional<Enum::BodyTypeResponseType> BodyType;
	//std::optional<Enum::BodyTypeResponseType> UniqueBodyType;
	//std::optional<Enum::BodyTypeResponseType> NormalizedBodyType;
	//std::optional<bool> FilterHtmlContent;
	//std::optional<std::string> InlineImageUrlTemplate;
	//std::optional<bool> ConvertHtmlCodePageToUTF8;
	//std::optional<bool> AddBlankTargetToLinks;
	//std::optional<int32_t> MaximumBodySize;
	std::optional<std::vector<tPath>> AdditionalProperties;

	static constexpr std::array<uint32_t, 1> tagsStructural = {PR_MESSAGE_CLASS};
	static constexpr std::array<uint32_t, 2> tagsIdOnly = {PR_ENTRYID, PR_CHANGE_KEY};
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

	explicit tMessage(const sShape&);

	std::optional<tSingleRecipient> Sender; ///< PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS, PR_SENDER_NAME
	std::optional<std::vector<tEmailAddressType>> ToRecipients;
	std::optional<std::vector<tEmailAddressType>> CcRecipients;
	std::optional<std::vector<tEmailAddressType>> BccRecipients;
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
	explicit tFolderResponseShape(const tinyxml2::XMLElement*);

	void tags(sShape&) const;

	Enum::DefaultShapeNamesType BaseShape;
	std::optional<std::vector<tPath>> AdditionalProperties;

	static constexpr uint32_t tagsStructural[] = {PR_CONTAINER_CLASS, PR_FOLDER_TYPE};
	static constexpr uint32_t tagsIdOnly[] = {PR_ENTRYID, PR_CHANGE_KEY};
	static constexpr uint32_t tagsDefault[] = {PR_DISPLAY_NAME, PR_CONTENT_COUNT, PR_FOLDER_CHILD_COUNT, PR_CONTENT_UNREAD};
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
	std::vector<Enum::MailTipTypes> PendingMailTips;

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
	template<typename T> explicit tReplyBody(T &&m) : Message(std::forward<T>(m)) {}
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

/**
 * Types.xsd:1947
 */
struct tFindResponsePagingAttributes
{
	void serialize(tinyxml2::XMLElement*) const;

	std::optional<int> IndexedPagingOffset;
	std::optional<int> NumeratorOffset;
	std::optional<int> AbsoluteDenominator;
	std::optional<bool> IncludesLastItemInRange;
	std::optional<int> TotalItemsInView;
};

/**
 * Types.xsd:4264
 */
struct tResolution : public tFindResponsePagingAttributes
{
	static constexpr char NAME[] = "Resolution";

	tResolution() = default;
	void serialize(tinyxml2::XMLElement*) const;

	tEmailAddressType Mailbox;
	std::optional<tContact> Contact;
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
 * Messages.xsd:1482
 */
struct mGetAttachmentRequest
{
	mGetAttachmentRequest(const tinyxml2::XMLElement*);

	//<xs:element name="AttachmentShape" type="t:AttachmentResponseShapeType" minOccurs="0"/>
	std::vector<tRequestAttachmentId> AttachmentIds;
};

/**
 * Messages.xsd:1492
 */
struct mGetAttachmentResponseMessage : public mResponseMessageType
{
	static constexpr char NAME[] = "GetAttachmentResponseMessage";

	using mResponseMessageType::mResponseMessageType;
	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement*) const;

	std::vector<sAttachment> Attachments;
};

struct mGetAttachmentResponse
{
	void serialize(tinyxml2::XMLElement*) const;

	std::vector<mGetAttachmentResponseMessage> ResponseMessages;
};

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
	//Enum::MailTipTypes MailTipsRequested;
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
	using mResponseMessageType::mResponseMessageType;

	static constexpr char NAME[] = "SyncFolderHierarchyResponseMessage";

	std::optional<std::string> SyncState;
	std::optional<bool> IncludesLastFolderInRange;
	std::optional<std::vector<tSyncFolderHierarchyChange>> Changes;

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
	using mResponseMessageType::mResponseMessageType;

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

/**
 * Messages.xsd:946
 */
struct mGetItemRequest
{
	explicit mGetItemRequest(const tinyxml2::XMLElement*);

	tItemResponseShape ItemShape;
	std::vector<tItemId> ItemIds;

};

struct mGetItemResponseMessage : mResponseMessageType
{
	static constexpr char NAME[] = "GetItemResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::vector<sItem> Items;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1519
 */
struct mGetItemResponse
{
	std::vector<mGetItemResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1676
 */
struct mResolveNamesRequest
{
	explicit mResolveNamesRequest(const tinyxml2::XMLElement*);

	std::optional<std::vector<std::variant<tFolderId, tDistinguishedFolderId>>> ParentFolderIds;
	std::string UnresolvedEntry;

	std::optional<bool> ReturnFullContactData; //Attribute
	std::optional<Enum::ResolveNamesSearchScopeType> SearchScope; //Attribute
	std::optional<Enum::DefaultShapeNamesType> ContactDataShape; //Attribute
};

/**
 * Messages.xsd:1706
 */
struct mResolveNamesResponseMessage : mResponseMessageType
{
	static constexpr char NAME[] = "ResolveNamesResponseMessage";

	std::optional<std::vector<tResolution>> ResolutionSet;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1694
 */
struct mResolveNamesResponse
{
	std::vector<mResolveNamesResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

}
