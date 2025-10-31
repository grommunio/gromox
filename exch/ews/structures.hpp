// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2025 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <atomic>
#include <chrono>
#include <list>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>
#include <gromox/freebusy.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>

#include "enums.hpp"

namespace tinyxml2 {
	class XMLElement;
	class XMLAttribute;
}

namespace gromox::EWS {

class EWSContext;
using clock = std::chrono::system_clock;
using time_point = clock::time_point;

}

namespace gromox::EWS::Exceptions
{
class EWSError;
}

namespace gromox::EWS::Structures {
/// Struct alias shortcut
#define ALIAS(Base, Name) struct a##Name : public Base {static constexpr char NAME[] = #Name; using Base::Base;}

struct tAppendToFolderField;
struct aCopiedEvent;
struct aCreatedEvent;
struct aDeletedEvent;
//struct aFreeBusyChangedEvent;
struct aMovedEvent;
struct aNewMailEvent;
struct aStatusEvent;
class sShape;
struct tAppendToItemField;
struct tCalendarFolderType;
struct tCalendarItem;
struct tContact;
struct tPersona;
struct tContactsFolderType;
struct tDeleteFolderField;
struct tDeleteItemField;
struct tDistinguishedFolderId;
struct tExtendedFieldURI;
struct tExtendedProperty;
struct tFieldURI;
struct tFileAttachment;
struct tFindResponsePagingAttributes;
struct tFolderChange;
struct tFolderId;
struct tFolderResponseShape;
struct tFolderType;
struct tIndexedFieldURI;
struct tItem;
struct tItemAttachment;
struct tItemChange;
struct tItemResponseShape;
struct tPath;
struct tMessage;
struct tMeetingMessage;
struct tMeetingRequestMessage;
struct tMeetingResponseMessage;
struct tMeetingCancellationMessage;
struct tAcceptItem;
struct tTentativelyAcceptItem;
struct tDeclineItem;
struct tModifiedEvent;
struct tReferenceAttachment;
struct tSearchFolderType;
struct tSerializableTimeZone;
struct tSetFolderField;
struct tSetItemField;
struct tSyncFolderHierarchyCreate;
struct tSyncFolderHierarchyUpdate;
struct tSyncFolderHierarchyDelete;
struct tSyncFolderItemsCreate;
struct tSyncFolderItemsUpdate;
struct tSyncFolderItemsDelete;
struct tSyncFolderItemsReadFlag;
struct tTask;
struct tTasksFolderType;


///////////////////////////////////////////////////////////////////////////////////////////////////
//XML namespace info types

/**
 * @brief Base struct (no namespace) for XML namespace information
 */
struct NSInfo {
	static constexpr char NS_ABBREV[] = "";
	static constexpr char NS_URL[] = "";
};

struct NS_EWS_Messages : public NSInfo {
	static constexpr char NS_ABBREV[] = "m:";
	static constexpr char NS_URL[] = "http://schemas.microsoft.com/exchange/services/2006/messages";
};

struct NS_EWS_Types : public NSInfo {
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
struct sBase64Binary : public std::string {
	sBase64Binary() = default;
	sBase64Binary(const TAGGED_PROPVAL&);
	sBase64Binary(const BINARY*);
	explicit sBase64Binary(std::string &&);
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
struct sFolderEntryId : public FOLDER_ENTRYID {
	sFolderEntryId() = default;
	explicit sFolderEntryId(const tinyxml2::XMLAttribute*);
	sFolderEntryId(const void*, uint64_t);

	sBase64Binary serialize() const;

	uint32_t accountId() const;
	uint64_t folderId() const;
	bool isPrivate() const;
	private:
	void init(const void*, uint64_t);
};

using sFolderId = std::variant<tFolderId, tDistinguishedFolderId>;

/// Function to get tag id from property name
using sGetNameId = std::function<uint16_t(const PROPERTY_NAME&)>;

/**
 * @brief     Message entry ID extension
 *
 * Provides EWS conversions and access utilities.
 */
struct sMessageEntryId : public MESSAGE_ENTRYID {
	sMessageEntryId() = default;
	sMessageEntryId(const void*, uint64_t);
	explicit sMessageEntryId(const TAGGED_PROPVAL&);

	uint32_t accountId() const;
	uint64_t folderId() const;
	eid_t messageId() const;
	sMessageEntryId& messageId(eid_t);
	bool isPrivate() const;

	sBase64Binary serialize() const;
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
struct sAttachmentId : public sMessageEntryId {
	sAttachmentId(const sMessageEntryId&, uint32_t);
	sAttachmentId(const TAGGED_PROPVAL&, uint32_t);
	sAttachmentId(const void*, uint64_t);

	uint32_t attachment_num;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      Occurrence ID
 *
 * Allows referencing modified occurrences by message entry ID and basedate.
 */
struct sOccurrenceId : public sMessageEntryId {
	sOccurrenceId(const TAGGED_PROPVAL&, uint32_t);
	sOccurrenceId(const void*, uint64_t);

	uint32_t basedate;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      Folder specification
 *
 * Resolves folder ID and type either from the distinguished name or
 * the folder target string.
 */
struct sFolderSpec {
	sFolderSpec() = default;
	explicit sFolderSpec(const tDistinguishedFolderId&);
	sFolderSpec(const std::string&, uint64_t);

	sFolderSpec& normalize();
	bool isDistinguished() const;

	std::optional<std::string> target;
	uint64_t folderId=0;
	enum : uint8_t {AUTO, PRIVATE, PUBLIC} location = AUTO;

	private:
	struct DistNameInfo {
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

using sFolderChangeDescription = std::variant<tAppendToFolderField, tSetFolderField, tDeleteFolderField>;

	// TODO: missing item types
	/*
	<Items>
		<DistributionList/>
		<PostItem/>
	</Items>
	*/
using sItem = std::variant<tItem, tMessage, tMeetingMessage, tMeetingRequestMessage,
	tMeetingResponseMessage, tMeetingCancellationMessage, tCalendarItem, tContact,
	tTask, tAcceptItem, tTentativelyAcceptItem, tDeclineItem>;

/**
 * c.f. Types.xsd:1502
 */
using sItemChangeDescription = std::variant<tAppendToItemField, tSetItemField, tDeleteItemField>;

/**
 * Mailbox metadata necessary for entry ID generation
 */
struct sMailboxInfo {
	GUID mailboxGuid{}; ///< PR_STORE_RECORD_KEY store property
	uint32_t accountId = 0; ///< MySQL account ID
	bool isPublic = false; ///< Whether it is a public (domain) store
};

using sNamedPropertyMap = std::unordered_map<uint32_t, PROPERTY_NAME>;

using sNotificationEvent = std::variant<aCreatedEvent, aDeletedEvent, tModifiedEvent, aMovedEvent, aCopiedEvent, aNewMailEvent, aStatusEvent/*, aFreeBusyEvent*/>;

class sShape {
	/**
	 * @brief     Property metadata
	 *
	 * Keep track of how properties were requested and whether they have been
	 * read.
	 * Enables distinction between extended properties and named fields that
	 * may be requested independently from each other.
	 */
	struct PropInfo {
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
	std::vector<TAGGED_PROPVAL> namedCache; ///< Properties that were written written before resolving names

	std::vector<TAGGED_PROPVAL> wProps; ///< List of properties meant to be written
	std::vector<uint32_t> dTags; ///< List of tags to remove

	std::unordered_map<uint32_t, PropInfo> props; ///< Tag -> Property mapping

	void collectExtendedProperty(const tExtendedFieldURI&);
	void collectExtendedProperty(const tFieldURI&);
	void collectExtendedProperty(const tIndexedFieldURI&);

	static constexpr PROPERTY_NAME NONAME{KIND_NONE, {}, 0, nullptr};

	public:
	static constexpr uint8_t FL_ANY =   0;
	static constexpr uint8_t FL_FIELD = 1 << 0; ///< Tag was requested as field
	static constexpr uint8_t FL_EXT =   1 << 1; ///< Tag was requested as extended attribute
	static constexpr uint8_t FL_RM =    1 << 2; ///< Tag was requested for removal

	static constexpr uint64_t ToRecipients =      1 << 0;
	static constexpr uint64_t CcRecipients =      1 << 1;
	static constexpr uint64_t BccRecipients =     1 << 2;
	static constexpr uint64_t Body =              1 << 3;
	static constexpr uint64_t MessageFlags =      1 << 4;
	static constexpr uint64_t MimeContent =       1 << 5;
	static constexpr uint64_t Attachments =       1 << 6;
	static constexpr uint64_t RequiredAttendees = 1 << 7;
	static constexpr uint64_t OptionalAttendees = 1 << 8;
	static constexpr uint64_t Resources =         1 << 9;
	static constexpr uint64_t Rights =            1 << 10;
	static constexpr uint64_t Permissions =       1 << 11;

	static constexpr uint64_t Recipients = ToRecipients | CcRecipients | BccRecipients;
	static constexpr uint64_t Attendees = RequiredAttendees | OptionalAttendees | Resources;

	sShape() = default;
	explicit sShape(const TPROPVAL_ARRAY&);
	explicit sShape(const tFolderChange&);
	explicit sShape(const tFolderResponseShape&);
	explicit sShape(const tItemChange&);
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
	uint32_t tag(const PROPERTY_NAME&) const;

	sShape& add(uint32_t, uint8_t=0);
	sShape& add(const PROPERTY_NAME&, uint16_t, uint8_t=0);

	void write(const TAGGED_PROPVAL&);
	void write(const PROPERTY_NAME&, const TAGGED_PROPVAL&);
	TPROPVAL_ARRAY write() const;
	const TAGGED_PROPVAL* writes(uint32_t) const;
	const TAGGED_PROPVAL* writes(const PROPERTY_NAME&) const;

	PROPTAG_ARRAY remove() const;

	bool requested(uint32_t, uint8_t=FL_FIELD) const;
	const TAGGED_PROPVAL* get(uint32_t, uint8_t=FL_FIELD) const;
	const TAGGED_PROPVAL* get(const PROPERTY_NAME&, uint8_t=FL_FIELD) const;
	template<typename T> const T* get(uint32_t, uint8_t=FL_FIELD) const;
	template<typename T> const T* get(const PROPERTY_NAME&, uint8_t=FL_FIELD) const;
	void putExtended(std::vector<tExtendedProperty>&) const;


	uint64_t special = 0; ///< Fields that are not directly accessible by properties
	std::string store; ///< For which store the named properties are valid
	std::optional<std::string> mimeContent; ///< MimeContent to write
	const tinyxml2::XMLElement* permissionSet = nullptr; ///< PermissionSet for update
	const tinyxml2::XMLElement* calendarPermissionSet = nullptr; ///< CalendarPermissionSet for update
	std::vector<uint32_t> offsetProps; ///< Datetime related MAPI props which require timezone offset calculation

};

/**
 * String class to be used in arrays (i.e. Types.xsd:3852)
 */
struct sString : public std::string, public NS_EWS_Types {
	static constexpr char NAME[] = "String";
	using std::string::string;
};

/**
 * @brief     Sync state helper class
 */
struct sSyncState {
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
struct sTime {
	sTime() = default;
	sTime(const tinyxml2::XMLElement*);

	uint8_t hour = 0;
	uint8_t minute = 0;
	uint8_t second = 0;
};

/**
 * @brief     Timepoint with time zone offset
 */
struct sTimePoint {
	explicit sTimePoint(time_point);
	sTimePoint(time_point, const tSerializableTimeZone&);
	explicit sTimePoint(const char*);
	explicit sTimePoint(const tinyxml2::XMLAttribute*);
	explicit sTimePoint(const tinyxml2::XMLElement*);

	void serialize(tinyxml2::XMLElement*) const;

	static sTimePoint fromNT(uint64_t);
	uint64_t toNT() const;
	bool needCalcOffset() const;

	time_point time{};
	std::chrono::minutes offset = std::chrono::minutes(0);
	bool calcOffset = false;
};

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Types.xsd:6659
 */
struct tAlternateIdBase {
	tAlternateIdBase() = default;
	explicit tAlternateIdBase(Enum::IdFormatType);
	explicit tAlternateIdBase(const tinyxml2::XMLElement*);


	void serialize(tinyxml2::XMLElement*) const;

	Enum::IdFormatType Format; //Attribute
};

/**
 * Types.xsd:6668
 */
struct tAlternateId : public tAlternateIdBase {
	static constexpr char NAME[] = "AlternateId";

	explicit tAlternateId(const tinyxml2::XMLElement*);
	tAlternateId(Enum::IdFormatType, std::string, std::string);

	void serialize(tinyxml2::XMLElement*) const;

	std::string Id; //Attribute
	std::string Mailbox; //Attribute
};

/**
 * Types.xsd:6683
 */
struct tAlternatePublicFolderId : public tAlternateIdBase {
	static constexpr char NAME[] = "AlternatePublicFolderId";

	explicit tAlternatePublicFolderId(const tinyxml2::XMLElement*);

	void serialize(tinyxml2::XMLElement*) const;

	std::string FolderId; //Attribute
};

/**
 * Types.xsd:6696
 */
struct tAlternatePublicFolderItemId : public tAlternatePublicFolderId {
	static constexpr char NAME[] = "AlternatePublicFolderItemId";

	explicit tAlternatePublicFolderItemId(const tinyxml2::XMLElement*);

	void serialize(tinyxml2::XMLElement*) const;

	std::string ItemId; //Attribute
};

using sAlternateId = std::variant<tAlternateId, tAlternatePublicFolderId, tAlternatePublicFolderItemId>;

/**
 * Types.xsd:1611
 */
struct tAttachment : public NS_EWS_Types {
	tAttachment() = default;
	explicit tAttachment(const sAttachmentId&, const sShape&);

	static sAttachment create(const sAttachmentId&, sShape&&);

	std::optional<sAttachmentId> AttachmentId;
	std::optional<std::string> Name;///< PR_ATTACH_LONG_FILENAME or PR_DISPLAYNAME
	std::optional<std::string> ContentType; ///< PR_ATTACH_MIME_TAG
	std::optional<std::string> ContentId; ///< PR_ATTACH_CONTENT_ID
	std::optional<std::string> ContentLocation;
	std::optional<std::string> AttachmentOriginalUrl;
	std::optional<int32_t> Size;
	std::optional<sTimePoint> LastModifiedTime; ///< PR_LAST_MODIFICATION_TIME
	std::optional<bool> IsInline; ///< PR_ATTACHMENT_FLAGS & ATT_MHTML_REF

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:2117
 */
struct tBaseItemId : public NS_EWS_Types {
	enum IdType : uint8_t {
		ID_UNKNOWN, ///< Unspecified
		ID_GENERIC, ///< Non-entry id, but uses the same tag layout
		ID_FOLDER, ///< 46 byte folder entry id
		ID_ITEM, ///< 70 byte message entry id
		ID_ATTACHMENT, ///< 70 byte message entry id + 4 byte attachment index
		ID_OCCURRENCE, ///< 70 byte message entry id + 4 byte occurrence day
		ID_GUESS, ///< Special marker to tell constructor to guess id type
	};

	mutable sBase64Binary Id; //Attribute
	std::optional<sBase64Binary> ChangeKey; //Attribute
	IdType type = ID_UNKNOWN;

	tBaseItemId() = default;
	tBaseItemId(const tinyxml2::XMLElement*);
	tBaseItemId(const sBase64Binary&, IdType=ID_UNKNOWN);

	void serialize(tinyxml2::XMLElement*) const;
	std::string serializeId() const;
};

/**
 * Types.xsd:6022
 */
struct tBaseNotificationEvent : public NS_EWS_Types {
	//<xs:element name="Watermark" type="t:WatermarkType" minOccurs="0" />

	inline void serialize(tinyxml2::XMLElement*) const {}
};

ALIAS(tBaseNotificationEvent, StatusEvent);

/**
 * Types.xsd:4192
 *
 * Also provides polymorphic interface for indexed and fractional page view.
 */
struct tBasePagingType {
	explicit tBasePagingType(const tinyxml2::XMLElement* xml);
	virtual ~tBasePagingType() = default;

	std::optional<int32_t> MaxEntriesReturned; // Attribute

	virtual RESTRICTION* restriction(const sGetNameId&) const;
	virtual uint32_t offset(uint32_t) const;
	virtual void update(tFindResponsePagingAttributes&, uint32_t, uint32_t) const;
};

/**
 * Types.xsd:6117
 *
 * Used slightly different than in the specification, as `Watermark` is
 * omitted and `tStreamingSubscriptionRequest` also derives from this struct.
 */
struct tBaseSubscriptionRequest {
	explicit tBaseSubscriptionRequest(const tinyxml2::XMLElement*);

	std::optional<std::vector<sFolderId>> FolderIds;
	std::vector<Enum::NotificationEventType> EventTypes;
	std::optional<bool> SubscribeToAllFolders;

	uint16_t eventMask() const;
	// <xs:element name="Watermark" type="t:WatermarkType" minOccurs="0"/>
};

/**
 * Types.xsd:1560
 */
struct tRequestAttachmentId : public tBaseItemId {
	static constexpr char NAME[] = "AttachmentId";

	using tBaseItemId::tBaseItemId;
};

/**
 * Types.xsd:1725
 */
struct tBody : public std::string {
	template<typename T>
	inline tBody(T&& content, const char* type) : std::string(std::forward<T>(content)), BodyType(type) {}

	explicit tBody(const tinyxml2::XMLElement*);

	Enum::BodyTypeType BodyType; //Attribute
	std::optional<bool> IsTruncated; //Attribute

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6288
 */
struct tCalendarEventDetails {
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
struct tCalendarEvent : public NS_EWS_Types {
	static constexpr char NAME[] = "CalendarEvent";

	tCalendarEvent(const freebusy_event&);

	void serialize(tinyxml2::XMLElement*) const;

	sTimePoint StartTime;
	sTimePoint EndTime;
	Enum::LegacyFreeBusyType BusyType;
	std::optional<tCalendarEventDetails> CalendarEventDetails;
};

struct tContactsView final : public tBasePagingType {
	explicit tContactsView(const tinyxml2::XMLElement*);

	std::optional<std::string> InitialName; // Attribute
	std::optional<std::string> FinalName; // Attribute

	RESTRICTION* restriction(const sGetNameId&) const override;

	static RESTRICTION* namefilter(const std::string&, relop);
};

/**
 * @brief      Duration
 *
 * Types.xsd:6316
 */
struct tDuration {
	static constexpr char NAME[] = "Duration";

	tDuration() = default;
	explicit tDuration(const tinyxml2::XMLElement*);

	void serialize(tinyxml2::XMLElement*) const;

	time_point StartTime{}, EndTime{};
};

/**
 * @brief      Identifier for a fully resolved email address
 *
 * Types.xsd:273
 */
struct tEmailAddressType : public NS_EWS_Types {
	static constexpr char NAME[] = "Mailbox";

	tEmailAddressType() = default;
	explicit tEmailAddressType(const tinyxml2::XMLElement*);
	explicit tEmailAddressType(const TPROPVAL_ARRAY&);

	void mkRecipient(TPROPVAL_ARRAY*, uint32_t) const;

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
struct tEmailAddressDictionaryEntry : public NS_EWS_Types {
	static constexpr char NAME[] = "Entry";

	void serialize(tinyxml2::XMLElement*) const;

	tEmailAddressDictionaryEntry(const std::string&, const Enum::EmailAddressKeyType&);
	explicit tEmailAddressDictionaryEntry(const tinyxml2::XMLElement*);

	std::string Entry;
	Enum::EmailAddressKeyType Key; //Attribute
	std::optional<std::string> Name; //Attribute
	std::optional<std::string> RoutingType; //Attribute
	std::optional<Enum::MailboxTypeType> MailboxType; //Attribute
};

/**
 * Types.xsd
 */
struct tPhoneNumberDictionaryEntry : public NS_EWS_Types {
	static constexpr char NAME[] = "Entry";

	void serialize(tinyxml2::XMLElement*) const;

	tPhoneNumberDictionaryEntry(std::string, Enum::PhoneNumberKeyType);
	explicit tPhoneNumberDictionaryEntry(const tinyxml2::XMLElement*);

	std::string Entry;
	Enum::PhoneNumberKeyType Key; //Attribute
};

/**
 * Types.xsd:8508 (simplified)
 */
struct tPersona : public NS_EWS_Types {
	static constexpr char NAME[] = "Persona";

	void serialize(tinyxml2::XMLElement *) const;

	std::optional<std::string> DisplayName, EmailAddress, Title, Nickname,
		BusinessPhoneNumber, MobilePhoneNumber, HomeAddress, Comment;
};

/**
 * Types.xsd:6136
 */
struct tPullSubscriptionRequest : public tBaseSubscriptionRequest {
	static constexpr char NAME[] = "PullSubscriptionRequest";

	explicit tPullSubscriptionRequest(const tinyxml2::XMLElement*);

	int Timeout;
};

/**
 * Types.xsd:6139
 */
struct tPushSubscriptionRequest : public tBaseSubscriptionRequest {
	static constexpr char NAME[] = "PushSubscriptionRequest";

	explicit tPushSubscriptionRequest(const tinyxml2::XMLElement *);

	int StatusFrequency;
	std::string URL;
	std::optional<std::string> CallerData;
};

/**
 * Types.xsd:1665
 */
struct tReferenceAttachment : public tAttachment {
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
struct tFolderId : public tBaseItemId {
	static constexpr char NAME[] = "FolderId";

	using tBaseItemId::tBaseItemId;
};

ALIAS(tFolderId, OldFolderId);

/**
 * Types.xsd:1028
 */
struct tGuid : public GUID {
	explicit tGuid(const tinyxml2::XMLAttribute*);
	tGuid(const GUID&);

	std::string serialize() const;
};

/**
 * Types.xsd:6874
 */
struct tEffectiveRights {
	explicit tEffectiveRights(uint32_t);

	void serialize(tinyxml2::XMLElement*) const;

	bool CreateAssociated;
	bool CreateContents;
	bool CreateHierarchy;
	bool Delete;
	bool Modify;
	bool Read;
	//std::optional<bool> ViewPrivateItems;
};

/**
 * Types.xsd:1142
 */
struct tExtendedFieldURI {
	using TMEntry = std::pair<const char*, uint16_t>;

	static constexpr char NAME[] = "ExtendedFieldURI";

	tExtendedFieldURI() = default;
	explicit tExtendedFieldURI(const tinyxml2::XMLElement*);
	explicit tExtendedFieldURI(uint32_t);
	tExtendedFieldURI(uint16_t, const PROPERTY_NAME&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<int32_t> PropertyTag; //Attribute
	Enum::MapiPropertyTypeType PropertyType; //Attribute
	std::optional<int32_t> PropertyId; // Attribute
	std::optional<Enum::DistinguishedPropertySetType> DistinguishedPropertySetId; //Attribute
	std::optional<tGuid> PropertySetId; // Attribute.
	std::optional<std::string> PropertyName; //Attribute

	void tags(sShape&, bool=true) const;
	uint16_t type() const;

	uint32_t tag() const;
	uint32_t tag(const sGetNameId&) const;
	PROPERTY_NAME name() const;

	static const char* typeName(uint16_t);

	static std::array<const GUID*, 10> propsetIds; ///< Same order as Enum::DistinguishedPropertySetType, Types.xsd:1040
	static std::array<TMEntry, 26> typeMap; ///< Types.xsd:1060
};

/**
 * Types.xsd:1196
 */
struct tExtendedProperty {
	explicit tExtendedProperty(const tinyxml2::XMLElement*);
	explicit tExtendedProperty(const TAGGED_PROPVAL&, const PROPERTY_NAME& = PROPERTY_NAME{KIND_NONE, {}, 0, nullptr});

	tExtendedFieldURI ExtendedFieldURI;
	TAGGED_PROPVAL propval{};

	void serialize(tinyxml2::XMLElement*) const;
	private:
	void serialize(const void*, uint16_t, tinyxml2::XMLElement*) const;
	void deserialize(const tinyxml2::XMLElement*, uint16_t, void* = nullptr);

	template<typename C, typename T>
	void serializeMV(const void*, uint16_t, tinyxml2::XMLElement*, T* C::*) const;
	template<typename C, typename T>
	void deserializeMV(const tinyxml2::XMLElement*, uint16_t, T* C::*);
};

/**
 * Types.xsd:1981
 */
struct tBaseFolderType : public NS_EWS_Types {
	explicit tBaseFolderType(const sShape&);
	explicit tBaseFolderType(const tinyxml2::XMLElement*);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<tFolderId> FolderId;
	std::optional<tFolderId> ParentFolderId;
	std::optional<std::string> FolderClass;
	std::optional<std::string> DisplayName;
	std::optional<int32_t> TotalCount;
	std::optional<int32_t> ChildFolderCount;
	std::vector<tExtendedProperty> ExtendedProperty;
	//<xs:element name="ManagedFolderInformation" type="t:ManagedFolderInformationType" minOccurs="0"/>
	std::optional<tEffectiveRights> EffectiveRights;
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
struct tFieldURI {
	using SMEntry = std::pair<const char*, uint64_t>;

	static constexpr char NAME[] = "FieldURI";

	tFieldURI(const tinyxml2::XMLElement*);

	void tags(sShape&, bool=true) const;
	uint32_t tag(const sGetNameId&) const;

	std::string FieldURI; //Attribute

	//Types.xsd:402
	static std::unordered_multimap<std::string, uint32_t> tagMap; ///< Mapping for normal properties
	static std::unordered_multimap<std::string, std::pair<PROPERTY_NAME, uint16_t>> nameMap; ///< Mapping for named properties
	static std::array<SMEntry, 17> specialMap; ///< Mapping for special properties
};

/**
 * Types.xsd:1654
 */
struct tFileAttachment : public tAttachment {
	static constexpr char NAME[] = "FileAttachment";

	tFileAttachment() = default;
	tFileAttachment(const tinyxml2::XMLElement *);
	tFileAttachment(const sAttachmentId&, const sShape&);

	std::optional<bool> IsContactPhoto;
	std::optional<sBase64Binary> Content;

	void serialize(tinyxml2::XMLElement*) const;
};


/**
 * Types.xsd:1947
 */
struct tFindResponsePagingAttributes {
	void serialize(tinyxml2::XMLElement*) const;

	std::optional<int> IndexedPagingOffset; // Attribute
	std::optional<int> NumeratorOffset; // Attribute
	std::optional<int> AbsoluteDenominator; // Attribute
	std::optional<bool> IncludesLastItemInRange; // Attribute
	std::optional<int> TotalItemsInView; // Attribute
};

/**
 * Types.xsd:1973
 */
struct tFindFolderParent : public tFindResponsePagingAttributes {
	std::vector<sFolder> Folders;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:5777
 */
struct tGroupedItems : public NS_EWS_Types {
	std::string GroupIndex;
	std::vector<sItem> Items;
	// <xs:element name="GroupSummary" type="t:GroupSummaryType" minOccurs="0" />

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:2345
 */
struct tFindItemParent : public tFindResponsePagingAttributes {
	std::vector<sItem> Items;
	std::vector<tGroupedItems> Groups;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:2436
 */
struct tFlagType : public NS_EWS_Types {
	static constexpr char NAME[] = "Flag";

	tFlagType(const tinyxml2::XMLElement*);
	tFlagType() = default;

	Enum::FlagStatusType FlagStatus;
	std::optional<time_point> StartDate;
	std::optional<time_point> DueDate;
	std::optional<time_point> CompleteDate;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:4212
 */
struct tFractionalPageView final : public tBasePagingType {
	tFractionalPageView(const tinyxml2::XMLElement*);

	int Numerator; // Attribute
	int Denominator; // Attribute

	uint32_t offset(uint32_t) const override;
	void update(tFindResponsePagingAttributes&, uint32_t, uint32_t total) const override;
};


/**
 * Types.xsd:1108
 */
struct tIndexedFieldURI {
	static constexpr char NAME[] = "IndexedFieldURI";

	tIndexedFieldURI(const tinyxml2::XMLElement*);

	void tags(sShape&, bool=true) const;
	uint32_t tag(const sGetNameId&) const;

	std::string FieldURI; //Attribute
	std::string FieldIndex; //Attribute

	using UIKey = std::pair<std::string, std::string>;
	//Types.xsd:988
	static std::array<std::pair<UIKey, uint32_t>, 25> tagMap;
	static std::array<std::pair<UIKey, std::pair<PROPERTY_NAME, uint16_t>>, 25> nameMap;
};

/**
 * Types.xsd:4203
 */
struct tIndexedPageView final : public tBasePagingType {
	explicit tIndexedPageView(const tinyxml2::XMLElement*);

	uint32_t Offset; // Attribute
	Enum::IndexBasePointType BasePoint; // Attribute

	uint32_t offset(uint32_t) const override;
	void update(tFindResponsePagingAttributes&, uint32_t, uint32_t) const override;
};

/**
 * Types.xsd:1538
 */
struct tInternetMessageHeader : public NS_EWS_Types {
	static constexpr char NAME[] = "InternetMessageHeader";

	tInternetMessageHeader(const std::string_view&, const std::string_view&);

	std::string HeaderName;
	std::string content;

	static std::vector<tInternetMessageHeader> parse(const char *);

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:1165
 */
struct tPath : public std::variant<tExtendedFieldURI, tFieldURI, tIndexedFieldURI> {
	using Base = std::variant<tExtendedFieldURI, tFieldURI, tIndexedFieldURI>;

	explicit tPath(const tinyxml2::XMLElement*);
	explicit inline tPath(Base &&b) : Base(std::move(b)) {}

	void tags(sShape&, bool=true) const;
	uint32_t tag(const sGetNameId&) const;

	inline const Base &asVariant() const { return *this; }
};

/**
 * Types.xsd:6722
 */
struct tUserId {
	tUserId() = default;
	explicit tUserId(const tinyxml2::XMLElement*);

	//<xs:element name="SID" type="xs:string" minOccurs="0" maxOccurs="1" />
	std::optional<std::string> PrimarySmtpAddress;
	std::optional<std::string> DisplayName;
	std::optional<Enum::DistinguishedUserType> DistinguishedUser;
	//<xs:element name="ExternalUserIdentity" type="xs:string" minOccurs="0" maxOccurs="1" />

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6909
 */
struct tDelegateUser {
	tUserId UserId;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6773
 */
struct tBasePermission : public NS_EWS_Types {
	explicit tBasePermission(const TPROPVAL_ARRAY&);
	explicit tBasePermission(const tinyxml2::XMLElement*);

	tUserId UserId;
	std::optional<bool> CanCreateItems;
	std::optional<bool> CanCreateSubFolders;
	std::optional<bool> IsFolderOwner;
	std::optional<bool> IsFolderVisible;
	std::optional<bool> IsFolderContact;
	std::optional<Enum::PermissionActionType> EditItems;
	std::optional<Enum::PermissionActionType> DeleteItems;

	void serialize(tinyxml2::XMLElement*) const;
	PERMISSION_DATA write(uint32_t) const;

	static const std::array<uint32_t, 11> profileTable;
	static constexpr size_t profiles = 9;
	static constexpr size_t calendarProfiles = 11;
};

/**
 * Types.xsd:6803
 */
struct tCalendarPermission: public tBasePermission {
	static constexpr char NAME[] = "CalendarPermission";

	explicit tCalendarPermission(const TPROPVAL_ARRAY&);
	explicit tCalendarPermission(const tinyxml2::XMLElement*);

	std::optional<Enum::CalendarPermissionReadAccessType> ReadItems;
	Enum::CalendarPermissionLevelType CalendarPermissionLevel;

	PERMISSION_DATA write() const;
	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6789
 */
struct tPermission: public tBasePermission {
	static constexpr char NAME[] = "Permission";

	explicit tPermission(const TPROPVAL_ARRAY&);
	explicit tPermission(const tinyxml2::XMLElement*);

	std::optional<Enum::PermissionReadAccessType> ReadItems;
	Enum::PermissionLevelType PermissionLevel;

	PERMISSION_DATA write() const;
	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6864
 */
struct tCalendarPermissionSet : public NS_EWS_Types {
	explicit tCalendarPermissionSet(const tinyxml2::XMLElement*);
	explicit tCalendarPermissionSet(const TARRAY_SET&);

	std::vector<tCalendarPermission> CalendarPermissions;
	//std::optional<std::vector<aUnknownEntry>> UnknownEntries;

	std::vector<PERMISSION_DATA> write() const;
	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6854
 */
struct tPermissionSet : public NS_EWS_Types {
	explicit tPermissionSet(const tinyxml2::XMLElement*);
	explicit tPermissionSet(const TARRAY_SET&);

	std::vector<tPermission> Permissions;
	//std::optional<std::vector<aUnknownEntry>> UnknownEntries;

	std::vector<PERMISSION_DATA> write() const;
	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:5992
 */
struct tFieldOrder {
	explicit tFieldOrder(const tinyxml2::XMLElement*);

	static SORTORDER_SET* build(const std::vector<tFieldOrder>&, const sGetNameId&);

	tPath fieldURI;
	Enum::SortDirectionType Order; //Attribute;
};

/**
 * Types.xsd:2019
 */
struct tFolderType : public tBaseFolderType {
	static constexpr char NAME[] = "Folder";

	using tBaseFolderType::tBaseFolderType; // Construct from XML
	explicit tFolderType(const sShape&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<tPermissionSet> PermissionSet;
	std::optional<int32_t> UnreadCount;
};

/**
 * Types.xsd:2031
 */
struct tCalendarFolderType : public tBaseFolderType {
	static constexpr char NAME[] = "CalendarFolder";

	using tBaseFolderType::tBaseFolderType;

	std::optional<tCalendarPermissionSet> PermissionSet;

	//<xs:element name="SharingEffectiveRights" type="t:CalendarPermissionReadAccessType" minOccurs="0"/>

	void serialize(tinyxml2::XMLElement*) const;

};

/**
 * Types.xsd:1386
 */
struct tChangeDescription {
	struct Field {
		using FieldConv = std::function<void(const tinyxml2::XMLElement*, sShape&)>;

		FieldConv conv;
		const char* type = nullptr;
	};

	explicit tChangeDescription(const tinyxml2::XMLElement*);

	tPath fieldURI;

	static const Field* find(const char*, const char*);
	template<typename T>
	static TAGGED_PROPVAL mkProp(uint32_t, const T&);
	static void convProp(const char*, const char*, const tinyxml2::XMLElement*, sShape&);

	static void convBool(uint32_t, const tinyxml2::XMLElement*, sShape&);
	static void convBool(const PROPERTY_NAME &, const tinyxml2::XMLElement *, sShape &);
	static void convDate(uint32_t, const tinyxml2::XMLElement*, sShape&);
	static void convDate(const PROPERTY_NAME&, const tinyxml2::XMLElement*, sShape&);
	static void convText(uint32_t, const tinyxml2::XMLElement*, sShape&);
	static void convText(const PROPERTY_NAME&, const tinyxml2::XMLElement*, sShape&);
	template<typename ET, typename PT=uint32_t>
	static void convEnumIndex(uint32_t,  const tinyxml2::XMLElement*, sShape&);
	template<typename ET, typename PT=uint32_t>
	static void convEnumIndex(const PROPERTY_NAME&,  const tinyxml2::XMLElement*, sShape&);
	static void convStrArray(uint32_t, const tinyxml2::XMLElement*, sShape&);
	static void convStrArray(const PROPERTY_NAME&, const tinyxml2::XMLElement*, sShape&);
	static void convBody(const tinyxml2::XMLElement*, sShape&);

	static std::array<const char*, 15> itemTypes;
	static std::array<const char*, 5> folderTypes;
	static std::unordered_multimap<std::string, Field> fields;
};

/**
 * Types.xsd:1486
 *
 * TODO: implement functionality
 */
struct tAppendToFolderField : public tChangeDescription {
	static constexpr char NAME[] = "AppendToFolderField";

	using tChangeDescription::tChangeDescription;
};

/**
 * Types.xsd:1462
 *
 * TODO: implement functionality
 */
struct tAppendToItemField : public tChangeDescription {
	static constexpr char NAME[] = "AppendToItemField";

	using tChangeDescription::tChangeDescription;
};

/**
 * Types.xsd:6939
 */
struct tConflictResults {
	int Count = 0;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:2064
 */
struct tContactsFolderType : public tBaseFolderType {
	static constexpr char NAME[] = "ContactsFolder";

	using tBaseFolderType::tBaseFolderType;

	void serialize(tinyxml2::XMLElement*) const;

	//<xs:element name="SharingEffectiveRights" type="t:PermissionReadAccessType" minOccurs="0"/>
	std::optional<tPermissionSet> PermissionSet;
	//<xs:element name="SourceId" type="xs:string" minOccurs="0"/>
	//<xs:element name="AccountName" type="xs:string" minOccurs="0"/>
};

/**
 * Types.xsd:1454
 */
struct tDeleteFolderField : public tChangeDescription {
	static constexpr char NAME[] = "DeleteFolderField";

	using tChangeDescription::tChangeDescription;
};

/**
 * Types.xsd:1447
 */
struct tDeleteItemField : public tChangeDescription {
	static constexpr char NAME[] = "DeleteItemField";

	using tChangeDescription::tChangeDescription;
};

/**
 * Types.xsd:2078
 */
struct tSearchFolderType : public tBaseFolderType {
	static constexpr char NAME[] = "SearchFolder";

	using tBaseFolderType::tBaseFolderType;

	//void serialize(tinyxml2::XMLElement*) const;

	//<xs:element name="SearchParameters" type="t:SearchParametersType" minOccurs="0" />

};

/**
 * Types.xsd:2128
 */
struct tItemId : public tBaseItemId {
	static constexpr char NAME[] = "ItemId";

	using tBaseItemId::tBaseItemId;
};

ALIAS(tItemId, OldItemId);

/**
 * Types.xsd:6028
 */
struct tBaseObjectChangedEvent : public NS_EWS_Types {
	tBaseObjectChangedEvent(const sTimePoint&, std::variant<tFolderId, tItemId>&&, tFolderId&&);

	sTimePoint TimeStamp;
	std::variant<tFolderId, tItemId> objectId;
	tFolderId ParentFolderId;

	void serialize(tinyxml2::XMLElement*) const;
};

ALIAS(tBaseObjectChangedEvent, CreatedEvent);
ALIAS(tBaseObjectChangedEvent, DeletedEvent);
//ALIAS(tBaseObjectChangedEvent, FreeBusyChangedEvent);
ALIAS(tBaseObjectChangedEvent, NewMailEvent);

/**
 * Types.xsd:6043
 */
struct tModifiedEvent : public tBaseObjectChangedEvent {
	static constexpr char NAME[] = "ModifiedEvent";

	using tBaseObjectChangedEvent::tBaseObjectChangedEvent;

	std::optional<int32_t> UnreadCount;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6053
 */
struct tMovedCopiedEvent : public tBaseObjectChangedEvent {
	tMovedCopiedEvent(const sTimePoint&, std::variant<tFolderId, tItemId>&&, tFolderId&&, std::variant<aOldFolderId, aOldItemId>&&, tFolderId&&);

	std::variant<aOldFolderId, aOldItemId> oldObjectId;
	tFolderId OldParentFolderId;

	void serialize(tinyxml2::XMLElement*) const;
};

ALIAS(tMovedCopiedEvent, CopiedEvent);
ALIAS(tMovedCopiedEvent, MovedEvent);

/**
 * Types.xsd:396
 */
struct tSingleRecipient {
	tSingleRecipient() = default;
	explicit tSingleRecipient(const tinyxml2::XMLElement*);

	tEmailAddressType Mailbox;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:4419
 */
struct tAttendee : public NS_EWS_Types {
	static constexpr char NAME[] = "Attendee";

	tEmailAddressType Mailbox;
	std::optional<Enum::ResponseTypeType> ResponseType;
	std::optional<time_point> LastResponseTime{}, ProposedStart{}, ProposedEnd{};

	void serialize(tinyxml2::XMLElement*) const;

	tAttendee() = default;
	explicit tAttendee(const TPROPVAL_ARRAY&);
	explicit tAttendee(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4529
 */
struct tRecurrencePatternBase  : public NS_EWS_Types {}; // <xs:complexType name="RecurrencePatternBaseType" abstract="true" />

/**
 * Types.xsd:4531
 */
struct tIntervalRecurrencePatternBase : public tRecurrencePatternBase {
	int Interval;

	void serialize(tinyxml2::XMLElement*) const;

	tIntervalRecurrencePatternBase() = default;
	explicit tIntervalRecurrencePatternBase(const int& i) : Interval(i) {}
	explicit tIntervalRecurrencePatternBase(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4577
 */
struct tRelativeYearlyRecurrencePattern : public tRecurrencePatternBase {
	static constexpr char NAME[] = "RelativeYearlyRecurrence";

	std::string DaysOfWeek;
	Enum::DayOfWeekIndexType DayOfWeekIndex;
	Enum::MonthNamesType Month;

	void serialize(tinyxml2::XMLElement*) const;

	tRelativeYearlyRecurrencePattern() = default;
	explicit tRelativeYearlyRecurrencePattern(const std::string& dow,
		const Enum::DayOfWeekIndexType& dowi, const Enum::MonthNamesType& mnt) :
		DaysOfWeek(dow), DayOfWeekIndex(dowi), Month(mnt) {};
	explicit tRelativeYearlyRecurrencePattern(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4589
 */
struct tAbsoluteYearlyRecurrencePattern : public tRecurrencePatternBase {
	static constexpr char NAME[] = "AbsoluteYearlyRecurrence";

	int DayOfMonth;
	Enum::MonthNamesType Month;

	void serialize(tinyxml2::XMLElement*) const;

	tAbsoluteYearlyRecurrencePattern() = default;
	explicit tAbsoluteYearlyRecurrencePattern(const int& dom, const Enum::MonthNamesType& mnt) :
		DayOfMonth(dom), Month(mnt) {};
	explicit tAbsoluteYearlyRecurrencePattern(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4600
 */
struct tRelativeMonthlyRecurrencePattern : public tIntervalRecurrencePatternBase {
	static constexpr char NAME[] = "RelativeMonthlyRecurrence";

	std::string DaysOfWeek;
	Enum::DayOfWeekIndexType DayOfWeekIndex;

	void serialize(tinyxml2::XMLElement*) const;

	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
	tRelativeMonthlyRecurrencePattern() = default;
	explicit tRelativeMonthlyRecurrencePattern(const int& i, const std::string& dow, const Enum::DayOfWeekIndexType& dowi) :
		tIntervalRecurrencePatternBase(i), DaysOfWeek(dow), DayOfWeekIndex(dowi) {};
	explicit tRelativeMonthlyRecurrencePattern(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4611
 */
struct tAbsoluteMonthlyRecurrencePattern : public tIntervalRecurrencePatternBase {
	static constexpr char NAME[] = "AbsoluteMonthlyRecurrence";
	int DayOfMonth;

	void serialize(tinyxml2::XMLElement*) const;

	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
	tAbsoluteMonthlyRecurrencePattern() = default;
	explicit tAbsoluteMonthlyRecurrencePattern(const int& i, const int& dom) :
		tIntervalRecurrencePatternBase(i), DayOfMonth(dom) {};
	explicit tAbsoluteMonthlyRecurrencePattern(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4621
 */
struct tWeeklyRecurrencePattern : public tIntervalRecurrencePatternBase {
	static constexpr char NAME[] = "WeeklyRecurrence";

	std::string DaysOfWeek;
	std::optional<Enum::DayOfWeekType> FirstDayOfWeek;

	void serialize(tinyxml2::XMLElement*) const;

	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
	tWeeklyRecurrencePattern() = default;
	explicit tWeeklyRecurrencePattern(const int& i, const std::string& dow, const Enum::DayOfWeekType& fdow) :
		tIntervalRecurrencePatternBase(i), DaysOfWeek(dow), FirstDayOfWeek(fdow) {};
	explicit tWeeklyRecurrencePattern(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4632
 */
struct tDailyRecurrencePattern : public tIntervalRecurrencePatternBase {
	static constexpr char NAME[] = "DailyRecurrence";

	void serialize(tinyxml2::XMLElement*) const;

	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
	tDailyRecurrencePattern() = default;
	explicit tDailyRecurrencePattern(const int& i) : tIntervalRecurrencePatternBase(i) {};
};

/**
 * Types.xsd:4545
 * <xs:complexType name="RegeneratingPatternBaseType" abstract="true">
 */
struct tRegeneratingPatternBase : public tIntervalRecurrencePatternBase {
	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
};

/**
 * Types.xsd:4551
 */
struct tDailyRegeneratingPattern : public tIntervalRecurrencePatternBase {
	static constexpr char NAME[] = "DailyRegeneration";

	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
};

/**
 * Types.xsd:4551
 */
struct tWeeklyRegeneratingPattern : public tIntervalRecurrencePatternBase {
	static constexpr char NAME[] = "WeeklyRegeneration";

	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
};

/**
 * Types.xsd:4551
 */
struct tMonthlyRegeneratingPattern : public tIntervalRecurrencePatternBase {
	static constexpr char NAME[] = "MonthlyRegeneration";

	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
};

/**
 * Types.xsd:4551
 */
struct tYearlyRegeneratingPattern : public tIntervalRecurrencePatternBase {
	static constexpr char NAME[] = "YearlyRegeneration";

	using tIntervalRecurrencePatternBase::tIntervalRecurrencePatternBase;
};
/**
 * Types.xsd:4848
 */
// using tRecurrencePattern = std::variant<
// 	tRelativeYearlyRecurrencePattern,
// 	tAbsoluteYearlyRecurrencePattern,
// 	tRelativeMonthlyRecurrencePattern,
// 	tAbsoluteMonthlyRecurrencePattern,
// 	tWeeklyRecurrencePattern,
// 	tDailyRecurrencePattern
// >;

/**
 * Types.xsd:4861
 */
using tRecurrencePattern = std::variant<
	tRelativeYearlyRecurrencePattern,
	tAbsoluteYearlyRecurrencePattern,
	tRelativeMonthlyRecurrencePattern,
	tAbsoluteMonthlyRecurrencePattern,
	tWeeklyRecurrencePattern,
	tDailyRecurrencePattern,
	tDailyRegeneratingPattern,
	tWeeklyRegeneratingPattern,
	tMonthlyRegeneratingPattern,
	tYearlyRegeneratingPattern
>;

/**
 * Types.xsd:4814
 */
struct tRecurrenceRangeBase : public NS_EWS_Types {
	time_point StartDate{};

	void serialize(tinyxml2::XMLElement*) const;

	tRecurrenceRangeBase() = default;
	explicit tRecurrenceRangeBase(time_point sd) : StartDate(sd) {}
	explicit tRecurrenceRangeBase(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4820
 */
struct tNoEndRecurrenceRange : public tRecurrenceRangeBase {
	static constexpr char NAME[] = "NoEndRecurrence";

	void serialize(tinyxml2::XMLElement*) const;

	using tRecurrenceRangeBase::tRecurrenceRangeBase;
	tNoEndRecurrenceRange() = default;
	explicit tNoEndRecurrenceRange(time_point sd) : tRecurrenceRangeBase(sd) {}
	explicit tNoEndRecurrenceRange(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4826
 */
struct tEndDateRecurrenceRange : public tRecurrenceRangeBase {
	static constexpr char NAME[] = "EndDateRecurrence";

	void serialize(tinyxml2::XMLElement*) const;

	time_point EndDate{};

	using tRecurrenceRangeBase::tRecurrenceRangeBase;
	tEndDateRecurrenceRange() = default;
	explicit tEndDateRecurrenceRange(time_point sd, time_point ed) :
		tRecurrenceRangeBase(sd), EndDate(ed) {};
	explicit tEndDateRecurrenceRange(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4836
 */
struct tNumberedRecurrenceRange : public tRecurrenceRangeBase {
	static constexpr char NAME[] = "NumberedRecurrence";

	void serialize(tinyxml2::XMLElement*) const;

	int NumberOfOccurrences;

	using tRecurrenceRangeBase::tRecurrenceRangeBase;
	tNumberedRecurrenceRange() = default;
	explicit tNumberedRecurrenceRange(time_point sd, int noo) :
		tRecurrenceRangeBase(sd), NumberOfOccurrences(noo) {};
	explicit tNumberedRecurrenceRange(const tinyxml2::XMLElement*);
};

/**
 * Types.xsd:4878
 */
using tRecurrenceRange = std::variant<
	tNoEndRecurrenceRange,
	tEndDateRecurrenceRange,
	tNumberedRecurrenceRange
>;

/**
 * Types.xsd:4888
 */
struct tRecurrenceType {
	tRecurrencePattern RecurrencePattern;
	tRecurrenceRange RecurrenceRange;

	tRecurrenceType() = default;
	explicit tRecurrenceType(const tinyxml2::XMLElement*);
	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:4904
 */
struct tOccurrenceInfoType : public NS_EWS_Types {
	static constexpr char NAME[] = "Occurrence";

	sOccurrenceId ItemId;
	time_point Start{}, End{}, OriginalStart{};

	void serialize(tinyxml2::XMLElement*) const;

	tOccurrenceInfoType(const sOccurrenceId id, time_point s, time_point e, time_point os) :
		ItemId(id), Start(s), End(e), OriginalStart(os) {};
};

/**
 * Types.xsd:4919
 */
struct tDeletedOccurrenceInfoType : public NS_EWS_Types {
	static constexpr char NAME[] = "DeletedOccurrence";

	time_point Start{};

	void serialize(tinyxml2::XMLElement*) const;

	tDeletedOccurrenceInfoType(time_point s) : Start(s) {}
};

/**
 * Types.xsd:4895
 */
struct tTaskRecurrence {
	// tTaskRecurrencePattern TaskRecurrencePattern;
	tRecurrencePattern TaskRecurrencePattern;
	tRecurrenceRange RecurrenceRange;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:2353
 */
struct tItem : public NS_EWS_Types {
	static constexpr char NAME[] = "Item";

	explicit tItem(const sShape&);
	explicit tItem(const tinyxml2::XMLElement*);

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
	std::optional<std::vector<tInternetMessageHeader>> InternetMessageHeaders;
	std::optional<sTimePoint> DateTimeSent;
	std::optional<sTimePoint> DateTimeCreated;
	//<xs:element name="ResponseObjects" type="t:NonEmptyArrayOfResponseObjectsType" minOccurs="0" />
	std::optional<time_point> ReminderDueBy;
	std::optional<bool> ReminderIsSet;
	//std::optional<time_point> ReminderNextTime;
	std::optional<int32_t> ReminderMinutesBeforeStart;
	std::optional<std::string> DisplayCc;
	std::optional<std::string> DisplayTo;
	std::optional<std::string> DisplayBcc;
	std::optional<bool> HasAttachments;
	std::vector<tExtendedProperty> ExtendedProperty;
	std::optional<std::string> Culture;
	std::optional<tEffectiveRights> EffectiveRights;
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

	static sItem create(const sShape&);
	void update(const sShape&);
};

/**
 * Types.xsd:4093
 */
struct tTask : public tItem {
	static constexpr char NAME[] = "Task";

	explicit tTask(const sShape&);
	explicit tTask(const tinyxml2::XMLElement*);
	void update(const sShape&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<int> ActualWork; // 0 <= ActualWork < 0x5AE980DF
	std::optional<time_point> AssignedTime, CompleteDate, DueDate, StartDate;
	std::optional<std::string> BillingInformation;
	std::optional<int> ChangeCount;
	std::optional<std::vector<std::string>> Companies;
	std::optional<std::vector<std::string>> Contacts;
	// <xs:element name="DelegationState" type="t:TaskDelegateStateType" minOccurs="0" />
	std::optional<std::string> Delegator;
	std::optional<int> IsAssignmentEditable;
	std::optional<bool> IsComplete;
	std::optional<bool> IsRecurring;
	std::optional<bool> IsTeamTask;
	std::optional<std::string> Mileage;
	std::optional<std::string> Owner;
	std::optional<double> PercentComplete;
	std::optional<tTaskRecurrence> Recurrence;
	std::optional<Enum::TaskStatusType> Status;
	std::optional<std::string> StatusDescription;
	std::optional<int> TotalWork; // 0 <= TotalWork < 0x5AE980DF
};

/**
 * Types.xsd:4933
 */
struct tCalendarItem : public tItem {
	static constexpr char NAME[] = "CalendarItem";

	explicit tCalendarItem(const sShape&);
	explicit tCalendarItem(const tinyxml2::XMLElement*);
	void update(const sShape&);

	void serialize(tinyxml2::XMLElement*) const;

	bool mapNamedProperty(const TAGGED_PROPVAL&, const sNamedPropertyMap&);
	static void setDatetimeFields(sShape&);

	//<!-- iCalendar properties -->
	std::optional<std::string> UID;
	std::optional<time_point> RecurrenceId;
	std::optional<sTimePoint> DateTimeStamp;

	// <!-- Single and Occurrence only -->
	std::optional<sTimePoint> Start;
	std::optional<sTimePoint> End;

	// <!-- Occurrence only -->
	std::optional<time_point> OriginalStart;
	std::optional<bool> IsAllDayEvent;
	std::optional<Enum::LegacyFreeBusyType> LegacyFreeBusyStatus;
	std::optional<std::string> Location;
	// <xs:element name="When" type="xs:string" minOccurs="0" />
	std::optional<bool> IsMeeting;
	std::optional<bool> IsCancelled;
	std::optional<bool> IsRecurring;
	std::optional<bool> MeetingRequestWasSent;
	std::optional<bool> IsResponseRequested;
	std::optional<Enum::CalendarItemTypeType> CalendarItemType;
	std::optional<Enum::ResponseTypeType> MyResponseType;
	std::optional<tSingleRecipient> Organizer;
	std::optional<std::vector<tAttendee>> RequiredAttendees;
	std::optional<std::vector<tAttendee>> OptionalAttendees;
	std::optional<std::vector<tAttendee>> Resources;
	// <xs:element name="InboxReminders" type="t:ArrayOfInboxReminderType" minOccurs="0" />

	// <!-- Conflicting and adjacent meetings -->
	// <xs:element name="ConflictingMeetingCount" type="xs:int" minOccurs="0" />
	// <xs:element name="AdjacentMeetingCount" type="xs:int" minOccurs="0" />
	// <xs:element name="ConflictingMeetings" type="t:NonEmptyArrayOfAllItemsType" minOccurs="0" />
	// <xs:element name="AdjacentMeetings" type="t:NonEmptyArrayOfAllItemsType" minOccurs="0" />
	// <xs:element name="Duration" type="xs:string" minOccurs="0" />
	// <xs:element name="TimeZone" type="xs:string" minOccurs="0" />
	std::optional<time_point> AppointmentReplyTime;
	std::optional<int> AppointmentSequenceNumber;
	std::optional<int> AppointmentState;

	// <!-- Recurrence specific data, only valid if CalendarItemType is RecurringMaster -->
	std::optional<tRecurrenceType> Recurrence;
	// <xs:element name="FirstOccurrence" type="t:OccurrenceInfoType" minOccurs="0" />
	// <xs:element name="LastOccurrence" type="t:OccurrenceInfoType" minOccurs="0" />
	std::optional<std::vector<tOccurrenceInfoType>> ModifiedOccurrences;
	std::optional<std::vector<tDeletedOccurrenceInfoType>> DeletedOccurrences;
	// <xs:element name="MeetingTimeZone" type="t:TimeZoneType" minOccurs="0"/>
	// <xs:element name="StartTimeZone" type="t:TimeZoneDefinitionType" minOccurs="0" maxOccurs="1" />
	// <xs:element name="EndTimeZone" type="t:TimeZoneDefinitionType" minOccurs="0" maxOccurs="1" />
	// <xs:element name="ConferenceType" type="xs:int" minOccurs="0" />
	std::optional<bool> AllowNewTimeProposal;
	// <xs:element name="IsOnlineMeeting" type="xs:boolean" minOccurs="0" />
	// <xs:element name="MeetingWorkspaceUrl" type="xs:string" minOccurs="0" />
	// <xs:element name="NetShowUrl" type="xs:string" minOccurs="0" />
	// <xs:element name="EnhancedLocation" type="t:EnhancedLocationType" minOccurs="0" />
	// <xs:element name="StartWallClock" type="xs:dateTime" minOccurs="0" maxOccurs="1" />
	// <xs:element name="EndWallClock" type="xs:dateTime" minOccurs="0" maxOccurs="1" />
	// <xs:element name="StartTimeZoneId" type="xs:string" minOccurs="0" maxOccurs="1" />
	// <xs:element name="EndTimeZoneId" type="xs:string" minOccurs="0" maxOccurs="1" />
	// <xs:element name="IntendedFreeBusyStatus" type="t:LegacyFreeBusyType" minOccurs="0" />
	// <xs:element name="JoinOnlineMeetingUrl" type="xs:string" minOccurs="0" maxOccurs="1" />
	// <xs:element name="OnlineMeetingSettings" type="t:OnlineMeetingSettingsType" minOccurs="0" maxOccurs="1"/>
	// <xs:element name="IsOrganizer" type="xs:boolean" minOccurs="0" />
	// <xs:element name="CalendarActivityData" type="t:CalendarActivityDataType" minOccurs="0" maxOccurs="1"/>
	// <xs:element name="DoNotForwardMeeting" type="xs:boolean" minOccurs="0"/>
};

/**
 * Types.xsd:4232
 */
struct tCalendarView final : public tBasePagingType {
	explicit tCalendarView(const tinyxml2::XMLElement*);

	std::optional<sTimePoint> StartDate; // Attribute
	std::optional<sTimePoint> EndDate; // Attribute

	RESTRICTION* restriction(const sGetNameId&) const override;

	static RESTRICTION* datefilter(const sTimePoint&, bool, const sGetNameId&);
};

/**
 * Types.xsd:5317
 */
struct tCompleteName : public NS_EWS_Types {
	static constexpr char NAME[] = "CompleteName";

	void serialize(tinyxml2::XMLElement*) const;

	tCompleteName() = default;
	explicit tCompleteName(const tinyxml2::XMLElement*);

	std::optional<std::string> Title;
	std::optional<std::string> FirstName;
	std::optional<std::string> MiddleName;
	std::optional<std::string> LastName;
	std::optional<std::string> Suffix;
	std::optional<std::string> Initials;
	std::optional<std::string> FullName;
	std::optional<std::string> Nickname;
	std::optional<std::string> YomiFirstName;
	std::optional<std::string> YomiLastName;
};

/**
 * Types.xsd:5379
 */
struct tPhysicalAddressDictionaryEntry : public NS_EWS_Types {
	static constexpr char NAME[] = "Entry";

	void serialize(tinyxml2::XMLElement*) const;

	explicit inline tPhysicalAddressDictionaryEntry(Enum::PhysicalAddressKeyType pak) : Key(pak) {}
	explicit tPhysicalAddressDictionaryEntry(const tinyxml2::XMLElement*);

	Enum::PhysicalAddressKeyType Key; // Attribute

	std::optional<std::string> Street;
	std::optional<std::string> City;
	std::optional<std::string> State;
	std::optional<std::string> CountryOrRegion;
	std::optional<std::string> PostalCode;

};

/**
 * Types.xsd:5541
 */
struct tContact : public tItem {
	static constexpr char NAME[] = "Contact";

	explicit tContact(const sShape&);
	explicit tContact(const tinyxml2::XMLElement*);
	void update(const sShape&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::string> FileAs;
	//std::optional<Enum::FileAsMappingType> FileAsMapping;
	std::optional<std::string> DisplayName;
	std::optional<std::string> GivenName;
	std::optional<std::string> Initials;
	std::optional<std::string> MiddleName;
	std::optional<std::string> Nickname;
	std::optional<tCompleteName> CompleteName;
	std::optional<std::string> CompanyName;
	std::optional<std::vector<tEmailAddressDictionaryEntry>> EmailAddresses;
	// <xs:element name="AbchEmailAddresses" type="t:AbchEmailAddressDictionaryType" minOccurs="0" />
	std::optional<std::vector<tPhysicalAddressDictionaryEntry>> PhysicalAddresses;
	std::optional<std::vector<tPhoneNumberDictionaryEntry>> PhoneNumbers;
	std::optional<std::string> AssistantName;
	std::optional<sTimePoint> Birthday;
	std::optional<std::string> BusinessHomePage;
	std::optional<std::vector<sString>> Children;
	// <xs:element name="Companies" type="t:ArrayOfStringsType" minOccurs="0" />
	std::optional<Enum::ContactSourceType> ContactSource;
	std::optional<std::string> Department;
	std::optional<std::string> Generation;
	// <xs:element name="ImAddresses" type="t:ImAddressDictionaryType" minOccurs="0" />
	std::optional<std::string> JobTitle;
	std::optional<std::string> Manager;
	// <xs:element name="Mileage" type="xs:string" minOccurs="0" />
	std::optional<std::string> OfficeLocation;
	std::optional<Enum::PhysicalAddressIndexType> PostalAddressIndex;
	// <xs:element name="Profession" type="xs:string" minOccurs="0" />
	std::optional<std::string> SpouseName;
	std::optional<std::string> Surname;
	std::optional<sTimePoint> WeddingAnniversary;
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

	static constexpr char addressTemplate[] = "{}{}{}{}{}{}{}{}{}"; // Street, city, state, postal code, country

	static std::string mkAddress(const std::optional<std::string>&, const std::optional<std::string>&,
	                             const std::optional<std::string>&, const std::optional<std::string>&,
	                             const std::optional<std::string>&);

	static void genFields(sShape&);
};

struct tItemChange {
	static constexpr char NAME[] = "ItemChange";

	tItemChange(const tinyxml2::XMLElement*);

	tItemId ItemId;
	//<xs:element name="OccurrenceItemId" type="t:OccurrenceItemIdType"/>
	//<xs:element name="RecurringMasterItemId" type="t:RecurringMasterItemIdType"/>
	std::vector<sItemChangeDescription> Updates;
	//<xs:element name="CalendarActivityData" type="t:CalendarActivityDataType" minOccurs="0" maxOccurs="1"/>
};

/**
 * Types.xsd:1287
 */
struct tItemResponseShape {
	tItemResponseShape() = default;
	explicit tItemResponseShape(const tinyxml2::XMLElement*);

	void tags(sShape&) const;

	Enum::DefaultShapeNamesType BaseShape;
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
	static constexpr std::array<uint32_t, 29> tagsDefault = {PR_SUBJECT, PR_HASATTACH,
		PR_ASSOCIATED, PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS, PR_SENDER_NAME,
		PR_LOCAL_COMMIT_TIME, PR_DISPLAY_NAME_PREFIX, PR_GIVEN_NAME, PR_MIDDLE_NAME,
		PR_SURNAME, PR_GENERATION, PR_INITIALS, PR_DISPLAY_NAME, PR_NICKNAME,
		PR_BUSINESS_TELEPHONE_NUMBER, PR_HOME_TELEPHONE_NUMBER, PR_PRIMARY_TELEPHONE_NUMBER,
		PR_BUSINESS2_TELEPHONE_NUMBER, PR_MOBILE_TELEPHONE_NUMBER, PR_PAGER_TELEPHONE_NUMBER,
		PR_BUSINESS_FAX_NUMBER, PR_ASSISTANT_TELEPHONE_NUMBER, PR_HOME2_TELEPHONE_NUMBER,
		PR_COMPANY_MAIN_PHONE_NUMBER, PR_HOME_FAX_NUMBER, PR_OTHER_TELEPHONE_NUMBER,
		PR_CALLBACK_TELEPHONE_NUMBER, PR_RADIO_TELEPHONE_NUMBER};
	static const std::array<std::pair<const PROPERTY_NAME*, uint16_t>, 5> namedTagsDefault;
};

/**
 * Types.xsd:2089
 */
struct tTasksFolderType : public tBaseFolderType {
	static constexpr char NAME[] = "TasksFolder";
	using tBaseFolderType::tBaseFolderType;
};


/**
 * Types.xsd:6372
 */
struct tSerializableTimeZoneTime {
	tSerializableTimeZoneTime() = default;
	explicit tSerializableTimeZoneTime(const tinyxml2::XMLElement*);

	int32_t Bias = 0;
	sTime Time{};
	int32_t DayOrder = 0;
	int32_t Month = 0;
	Enum::DayOfWeekType DayOfWeek{};
	std::optional<int32_t> Year;

	bool valid() const;
};

/**
 * Types.xsd:1433
 */
struct tSetFolderField : public tChangeDescription {
	static constexpr char NAME[] = "SetFolderField";

	explicit tSetFolderField(const tinyxml2::XMLElement*);

	void put(sShape&) const;

	const tinyxml2::XMLElement* folder = nullptr;
};

/**
 * Types.xsd:1409
 */
struct tSetItemField : public tChangeDescription {
	static constexpr char NAME[] = "SetItemField";

	explicit tSetItemField(const tinyxml2::XMLElement*);

	void put(sShape&) const;

	const tinyxml2::XMLElement* item = nullptr;
};

/**
 * Types.xsd:6383
 */
struct tSerializableTimeZone {
	tSerializableTimeZone() = default;
	explicit tSerializableTimeZone(const tinyxml2::XMLElement*);
	explicit tSerializableTimeZone(int32_t bias) : Bias(bias) {}

	int32_t Bias = 0;
	tSerializableTimeZoneTime StandardTime{};
	tSerializableTimeZoneTime DaylightTime{};

	std::chrono::minutes offset(time_point) const;
	time_point apply(time_point) const;
	time_point remove(time_point) const;
	bool hasDst() const;
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
struct tSyncFolderHierarchyCU : public NS_EWS_Types {
	tSyncFolderHierarchyCU(sFolder&&);

	sFolder folder;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6223
 */
struct tSyncFolderHierarchyCreate : public tSyncFolderHierarchyCU {
	using tSyncFolderHierarchyCU::tSyncFolderHierarchyCU;

	static constexpr char NAME[] = "Create";
};

/**
 * Types.xsd:6223
 */
struct tSyncFolderHierarchyUpdate : public tSyncFolderHierarchyCU {
	static constexpr char NAME[] = "Update";

	using tSyncFolderHierarchyCU::tSyncFolderHierarchyCU;
};

/**
 * Types.xsd:6233
 */
struct tSyncFolderHierarchyDelete : public NS_EWS_Types {
	static constexpr char NAME[] = "Delete";

	tSyncFolderHierarchyDelete(const sBase64Binary&);

	tFolderId FolderId;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:4031
 */
struct tMessage : public tItem {
	static constexpr char NAME[] = "Message";

	explicit tMessage(const sShape&);
	explicit tMessage(const tinyxml2::XMLElement*);
	void update(const sShape&);

	std::optional<tSingleRecipient> Sender; ///< PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS, PR_SENDER_NAME
	std::optional<std::vector<tEmailAddressType>> ToRecipients;
	std::optional<std::vector<tEmailAddressType>> CcRecipients;
	std::optional<std::vector<tEmailAddressType>> BccRecipients;
	std::optional<bool> IsReadReceiptRequested;
	std::optional<bool> IsDeliveryReceiptRequested;
	std::optional<sBase64Binary> ConversationIndex; ///< PR_CONVERSATION_INDEX
	std::optional<std::string> ConversationTopic; ///< PR_CONVERSATION_TOPIC
	//<xs:element name="ConversationTopic" type="xs:string" minOccurs="0" />
	std::optional<tSingleRecipient> From; ///< PR_SENT_REPRESENTING_ADDRTYPE, PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENT_REPRESENTING_NAME
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
 * Types.xsd:5026
 */
struct tMeetingMessage : public tMessage {
	static constexpr char NAME[] = "MeetingMessage";

	using tMessage::tMessage;

	// <xs:element name="AssociatedCalendarItemId" type="t:ItemIdType" minOccurs="0"/>
	// <xs:element name="IsDelegated" type="xs:boolean" minOccurs="0" />
	// <xs:element name="IsOutOfDate" type="xs:boolean" minOccurs="0" />
	// <xs:element name="HasBeenProcessed" type="xs:boolean" minOccurs="0" />

	// <!-- Meeting response related properties -->

	// <xs:element name="ResponseType" type="t:ResponseTypeType" minOccurs="0" />

	// <!-- iCalendar properties -->

	// <xs:element name="UID" type="xs:string" minOccurs="0" />
	// <xs:element name="RecurrenceId" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="DateTimeStamp" type="xs:dateTime" minOccurs="0" />

	// <xs:element name="IsOrganizer" type="xs:boolean" minOccurs="0" />
};

/**
 * Types.xsd:5064
 */
struct tMeetingRequestMessage : public tMeetingMessage {
	static constexpr char NAME[] = "MeetingRequest";

	using tMeetingMessage::tMeetingMessage;

	// <!--- MeetingRequest properties -->

	// <xs:element name="MeetingRequestType" type="t:MeetingRequestTypeType" minOccurs="0" />
	// <xs:element name="IntendedFreeBusyStatus" type="t:LegacyFreeBusyType" minOccurs="0" />

	// <!-- Calendar Properties of the associated meeting request -->

	// <!-- Single and Occurrence only -->

	// <xs:element name="Start" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="End" type="xs:dateTime" minOccurs="0" />

	// <!-- Occurrence only -->

	// <xs:element name="OriginalStart" type="xs:dateTime" minOccurs="0" />

	// <xs:element name="IsAllDayEvent" type="xs:boolean" minOccurs="0" />
	// <xs:element name="LegacyFreeBusyStatus" type="t:LegacyFreeBusyType" minOccurs="0" />
	// <xs:element name="Location" type="xs:string" minOccurs="0" />
	// <xs:element name="When" type="xs:string" minOccurs="0" />
	// <xs:element name="IsMeeting" type="xs:boolean" minOccurs="0" />
	// <xs:element name="IsCancelled" type="xs:boolean" minOccurs="0" />
	// <xs:element name="IsRecurring" type="xs:boolean" minOccurs="0" />
	// <xs:element name="MeetingRequestWasSent" type="xs:boolean" minOccurs="0" />
	// <xs:element name="CalendarItemType" type="t:CalendarItemTypeType" minOccurs="0" />
	// <xs:element name="MyResponseType" type="t:ResponseTypeType" minOccurs="0" />
	// <xs:element name="Organizer" type="t:SingleRecipientType" minOccurs="0" />
	// <xs:element name="RequiredAttendees" type="t:NonEmptyArrayOfAttendeesType" minOccurs="0" />
	// <xs:element name="OptionalAttendees" type="t:NonEmptyArrayOfAttendeesType" minOccurs="0" />
	// <xs:element name="Resources" type="t:NonEmptyArrayOfAttendeesType" minOccurs="0" />

	// <!-- Conflicting and adjacent meetings -->

	// <xs:element name="ConflictingMeetingCount" type="xs:int" minOccurs="0" />
	// <xs:element name="AdjacentMeetingCount" type="xs:int" minOccurs="0" />
	// <xs:element name="ConflictingMeetings" type="t:NonEmptyArrayOfAllItemsType" minOccurs="0" />
	// <xs:element name="AdjacentMeetings" type="t:NonEmptyArrayOfAllItemsType" minOccurs="0" />

	// <xs:element name="Duration" type="xs:string" minOccurs="0" />
	// <xs:element name="TimeZone" type="xs:string" minOccurs="0" />

	// <xs:element name="AppointmentReplyTime" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="AppointmentSequenceNumber" type="xs:int" minOccurs="0" />
	// <xs:element name="AppointmentState" type="xs:int" minOccurs="0" />

	// <!-- Recurrence specific data, only valid if CalendarItemType is RecurringMaster -->

	// <xs:element name="Recurrence" type="t:RecurrenceType" minOccurs="0" />
	// <xs:element name="FirstOccurrence" type="t:OccurrenceInfoType" minOccurs="0" />
	// <xs:element name="LastOccurrence" type="t:OccurrenceInfoType" minOccurs="0" />
	// <xs:element name="ModifiedOccurrences" type="t:NonEmptyArrayOfOccurrenceInfoType" minOccurs="0" />
	// <xs:element name="DeletedOccurrences" type="t:NonEmptyArrayOfDeletedOccurrencesType" minOccurs="0" />
	// <xs:element name="MeetingTimeZone" type="t:TimeZoneType" minOccurs="0" />
	// <xs:element name="StartTimeZone" type="t:TimeZoneDefinitionType" minOccurs="0" maxOccurs="1" />
	// <xs:element name="EndTimeZone" type="t:TimeZoneDefinitionType" minOccurs="0" maxOccurs="1" />

	// <xs:element name="ConferenceType" type="xs:int" minOccurs="0" />
	// <xs:element name="AllowNewTimeProposal" type="xs:boolean" minOccurs="0" />
	// <xs:element name="IsOnlineMeeting" type="xs:boolean" minOccurs="0" />
	// <xs:element name="MeetingWorkspaceUrl" type="xs:string" minOccurs="0" />
	// <xs:element name="NetShowUrl" type="xs:string" minOccurs="0" />
	// <xs:element name="EnhancedLocation" type="t:EnhancedLocationType" minOccurs="0" />
	// <xs:element name="ChangeHighlights" type="t:ChangeHighlightsType" minOccurs="0" />

	// <xs:element name="StartWallClock" type="xs:dateTime" minOccurs="0" maxOccurs="1" />
	// <xs:element name="EndWallClock" type="xs:dateTime" minOccurs="0" maxOccurs="1" />
	// <xs:element name="StartTimeZoneId" type="xs:string" minOccurs="0" maxOccurs="1" />
	// <xs:element name="EndTimeZoneId" type="xs:string" minOccurs="0" maxOccurs="1" />
	// <xs:element name="DoNotForwardMeeting" type="xs:boolean" minOccurs="0"/>
};

/**
 * Types.xsd:5142
 */
struct tMeetingResponseMessage : public tMeetingMessage {
	static constexpr char NAME[] = "MeetingResponse";

	using tMeetingMessage::tMeetingMessage;

	// <xs:element name="Start" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="End" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="Location" type="xs:string" minOccurs="0" />
	// <xs:element name="Recurrence" type="t:RecurrenceType" minOccurs="0" />
	// <xs:element name="CalendarItemType" type="xs:string" minOccurs="0" />
	// <xs:element name="ProposedStart" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="ProposedEnd" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="EnhancedLocation" type="t:EnhancedLocationType" minOccurs="0" />
};

/**
 * Types.xsd:5159
 */
struct tMeetingCancellationMessage : public tMeetingMessage {
	static constexpr char NAME[] = "MeetingCancellation";

	using tMeetingMessage::tMeetingMessage;

	// <xs:element name="Start" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="End" type="xs:dateTime" minOccurs="0" />
	// <xs:element name="Location" type="xs:string" minOccurs="0" />
	// <xs:element name="Recurrence" type="t:RecurrenceType" minOccurs="0" />
	// <xs:element name="CalendarItemType" type="xs:string" minOccurs="0" />
	// <xs:element name="EnhancedLocation" type="t:EnhancedLocationType" minOccurs="0" />
	// <xs:element name="DoNotForwardMeeting" type="xs:boolean" minOccurs="0"/>
};

/**
 * Types.xsd:3913
 */
struct tAcceptItem : public tMessage {
	static constexpr char NAME[] = "AcceptItem";

	using tMessage::tMessage;

	tAcceptItem(const tinyxml2::XMLElement *);
	void serialize(tinyxml2::XMLElement *) const;

	std::optional<time_point> ProposedStart, ProposedEnd;
	std::optional<tItemId> ReferenceItemId;
};

struct tTentativelyAcceptItem : public tMessage {
	static constexpr char NAME[] = "TentativelyAcceptItem";

	using tMessage::tMessage;

	tTentativelyAcceptItem(const tinyxml2::XMLElement *);
	void serialize(tinyxml2::XMLElement *) const;

	std::optional<time_point> ProposedStart, ProposedEnd;
	std::optional<tItemId> ReferenceItemId;
};

struct tDeclineItem : public tMessage {
	static constexpr char NAME[] = "DeclineItem";

	using tMessage::tMessage;

	tDeclineItem(const tinyxml2::XMLElement *);
	void serialize(tinyxml2::XMLElement *) const;

	std::optional<time_point> ProposedStart, ProposedEnd;
	std::optional<tItemId> ReferenceItemId;
};

/**
 * Types.xsd:1611
 */
struct tItemAttachment : public tAttachment {
	static constexpr char NAME[] = "ItemAttachment";

	tItemAttachment() = default;
	tItemAttachment(const sAttachmentId &, sShape &&);

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

	std::optional<sItem> Item;

	void serialize(tinyxml2::XMLElement *) const;
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
struct tSyncFolderItemsCU : public NS_EWS_Types {
	void serialize(tinyxml2::XMLElement*) const;

	sItem item;
};

struct tSyncFolderItemsCreate : public tSyncFolderItemsCU {
	static constexpr char NAME[] = "Create";
};

struct tSyncFolderItemsUpdate : public tSyncFolderItemsCU {
	static constexpr char NAME[] = "Update";
};

/**
 * Types.xsd:6198
 */
struct tSyncFolderItemsDelete : public NS_EWS_Types {
	static constexpr char NAME[] = "Delete";

	tSyncFolderItemsDelete(const sBase64Binary&);

	tItemId ItemId;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6204
 */
struct tSyncFolderItemsReadFlag : public NS_EWS_Types {
	static constexpr char NAME[] = "ReadFlagChange";

	tItemId ItemId;
	bool IsRead;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:1273
 */
struct tFolderResponseShape {
	tFolderResponseShape() = default;
	explicit tFolderResponseShape(const tinyxml2::XMLElement*);

	void tags(sShape&) const;

	Enum::DefaultShapeNamesType BaseShape;
	std::optional<std::vector<tPath>> AdditionalProperties;

	static constexpr uint32_t tagsStructural[] = {PR_CONTAINER_CLASS, PR_FOLDER_TYPE};
	static constexpr uint32_t tagsIdOnly[] = {PR_ENTRYID, PR_CHANGE_KEY};
	static constexpr uint32_t tagsDefault[] = {PR_DISPLAY_NAME, PR_CONTENT_COUNT, PR_FOLDER_CHILD_COUNT, PR_CONTENT_UNREAD};
	/*
	https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/baseshape
	"All" = "all the properties used by the Exchange Business Logic layer", for whatever that means.
	Here, it means tagsDefault + {our extra list}.
	*/
	static constexpr uint32_t tagsAll[] = {PR_PARENT_ENTRYID, PR_CREATION_TIME, PR_LAST_MODIFICATION_TIME, PR_ATTR_HIDDEN, PR_ATTR_READONLY, PR_CONTAINER_FLAGS, PR_RECORD_KEY, PR_STORE_ENTRYID, PR_ACCESS, PR_ACCESS_LEVEL};
	static constexpr uint32_t tagsAllRootOnly[] = {PR_IPM_SUBTREE_ENTRYID, PR_SENTMAIL_ENTRYID};
};

/**
 * Types.xsd:6400
 */
struct tFreeBusyView {
	tFreeBusyView() = default;
	tFreeBusyView(const char*, const char*, time_t, time_t);

	void serialize(tinyxml2::XMLElement*) const;

	Enum::FreeBusyViewType FreeBusyViewType = "None";
	std::optional<std::string> MergedFreeBusy;
	std::optional<std::vector<tCalendarEvent>> CalendarEventArray;
	//<xs:element minOccurs="0" maxOccurs="1" name="WorkingHours" type="t:WorkingHours" />
};

/**
 * Types.xsd:6348
 */
struct tFreeBusyViewOptions {
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
struct tMailbox {
	static constexpr char NAME[] = "Mailbox";

	explicit tMailbox(const tinyxml2::XMLElement*);

	std::optional<std::string> Name;
	std::string Address;
	std::optional<std::string> RoutingType;
};

/**
 * Types.xsd:1847
 */
struct tDistinguishedFolderId {
	static constexpr char NAME[] = "DistinguishedFolderId";

	explicit tDistinguishedFolderId(const std::string_view&);
	explicit tDistinguishedFolderId(const tinyxml2::XMLElement*);

	std::optional<tEmailAddressType> Mailbox;
	std::optional<std::string> ChangeKey; //Attribute
	Enum::DistinguishedFolderIdNameType Id; //Attribute

	void serialize(tinyxml2::XMLElement*) const;
};

struct tFolderChange {
	static constexpr char NAME[] = "FolderChange";

	explicit tFolderChange(const tinyxml2::XMLElement*);

	sFolderId folderId;
	std::vector<sFolderChangeDescription> Updates;
};

/**
 * Types.xsd:6409
 */
struct tMailboxData {
	tMailboxData(const tinyxml2::XMLElement*);

	tMailbox Email;
	Enum::MeetingAttendeeType AttendeeType;
	std::optional<bool> ExcludeConflicts;
};

/**
 * @brief      Message reply body
 *
 * Type.xsd:6538
 */
struct tReplyBody {
	template<typename T> explicit tReplyBody(T &&m) : Message(std::forward<T>(m)) {}
	explicit tReplyBody(const tinyxml2::XMLElement*);

	std::optional<std::string> Message;
	std::optional<std::string> lang;

	void serialize(tinyxml2::XMLElement*) const;
};

struct tOutOfOfficeMailTip {
	Enum::OofState OofState;
	std::optional<tDuration> Duration;
	std::optional<tReplyBody> OofReply;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6987
 */
struct tMailTips {
	void serialize(tinyxml2::XMLElement*) const;

	tEmailAddressType RecipientAddress;
	std::vector<Enum::MailTipTypes> PendingMailTips;

	std::optional<tOutOfOfficeMailTip> OutOfOffice;

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
struct tSmtpDomain {
	static constexpr char NAME[] = "Domain";

	void serialize(tinyxml2::XMLElement*) const;

	std::string Name;
	std::optional<bool> IncludeSubdomains;
};

/**
 * Types.xsd:6145
 *
 * Unlike the documentation, derives from tBaseSubscriptionRequest.
 */
struct tStreamingSubscriptionRequest : public tBaseSubscriptionRequest {
	static constexpr char NAME[] = "StreamingSubscriptionRequest";

	using tBaseSubscriptionRequest::tBaseSubscriptionRequest;
};

/**
 * Types.xsd:7040
 */
struct tMailTipsServiceConfiguration {
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
 * Types.xsd:6018
 *
 * While defined only as "NonEmptyStringType" in the speciification, this
 * struct is used to provide additional internal logic.
 */
struct tSubscriptionId {
	static constexpr char NAME[] = "SubscriptionId";

	tSubscriptionId() = default;
	explicit tSubscriptionId(uint32_t);
	tSubscriptionId(uint32_t, uint32_t);
	explicit tSubscriptionId(const tinyxml2::XMLElement*);

	uint32_t ID = 0; ///< Counter value
	uint32_t timeout = 30; ///< subscription timeout (minutes)

	void serialize(tinyxml2::XMLElement*) const;

	inline bool operator==(const tSubscriptionId& other) {return ID == other.ID;}

	private:
	static std::atomic<uint32_t> globcnt;

	static constexpr void encode(uint32_t, char*&);
	static constexpr uint32_t decode(const uint8_t*&);


	static constexpr char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	static constexpr int8_t i64[128] = {-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
		                                -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
		                                -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
		                                52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
		                                -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
		                                15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
		                                -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
		                                41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1};
};

/**
 * Types.xsd:6067
 */
struct tNotification : public NS_EWS_Messages {
	static constexpr char NAME[] = "Notification";

	tSubscriptionId SubscriptionId;
	//<xs:element name="PreviousWatermark" type="t:WatermarkType" minOccurs="0" />
	std::optional<bool> MoreEvents;
	std::list<sNotificationEvent> events;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:6432
 */
struct tSuggestionsViewOptions {
	explicit tSuggestionsViewOptions(const tinyxml2::XMLElement*);

	std::optional<int32_t> GoodThreshold;
	std::optional<int32_t> MaximumResultsByDay;
	std::optional<int32_t> MaximumNonWorkHourResultsByDay;
	std::optional<int32_t> MeetingDurationInMinutes;
	std::optional<Enum::SuggestionQuality> MinimumSuggestionQuality;
	tDuration DetailedSuggestionsWindow;
	std::optional<time_point> CurrentMeetingTime;
	std::optional<std::string> GlobalObjectId;
};

/**
 * Types.xsd:1898
 */
struct tTargetFolderIdType {
	explicit tTargetFolderIdType(sFolderId&&);
	explicit tTargetFolderIdType(const tinyxml2::XMLElement*);

	sFolderId FolderId;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      User out-of-office settings
 *
 * Types.xsd:6551
 */
struct tUserOofSettings {
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
 * Types.xsd:4264
 */
struct tResolution {
	static constexpr char NAME[] = "Resolution";

	tResolution() = default;
	void serialize(tinyxml2::XMLElement*) const;

	tEmailAddressType Mailbox;
	std::optional<tContact> Contact;
};

/**
 * Types.xsd:4264
 */
struct tResolutionSet : public tFindResponsePagingAttributes {
	std::vector<tResolution> Resolution;

	void serialize(tinyxml2::XMLElement *) const;
};

/**
 * Types.xsd:5978
 *
 * Instead of directly mapping the XML data, it is cached to be directly
 * converted to the gromox RESTRICTION structure.
 */
class tRestriction {
	public:
	explicit tRestriction(const tinyxml2::XMLElement*);

	RESTRICTION* build(const sGetNameId&) const;
	static RESTRICTION* all(RESTRICTION*, RESTRICTION*);

	private:
	const tinyxml2::XMLElement* source = nullptr;  ///< XMLElement of the contained restriction

	static void build_andor(RESTRICTION&, const tinyxml2::XMLElement*, const sGetNameId&);
	static void build_compare(RESTRICTION&, const tinyxml2::XMLElement*, relop, const sGetNameId&);
	static void build_contains(RESTRICTION&, const tinyxml2::XMLElement*, const sGetNameId&);
	static void build_excludes(RESTRICTION&, const tinyxml2::XMLElement*, const sGetNameId&);
	static void build_exists(RESTRICTION&, const tinyxml2::XMLElement*, const sGetNameId&);
	static void build_not(RESTRICTION&, const tinyxml2::XMLElement*, const sGetNameId&);
	static void deserialize(RESTRICTION&, const tinyxml2::XMLElement*, const sGetNameId&);

	static void* loadConstant(const tinyxml2::XMLElement*, uint16_t);
	static uint32_t getTag(const tinyxml2::XMLElement*, const sGetNameId&);
};

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Response message type
 *
 * Messages.xsd:550
 */
struct mResponseMessageType : public NS_EWS_Messages {
	mResponseMessageType() = default;
	explicit mResponseMessageType(const std::string&, const std::optional<std::string>& = std::nullopt,
	                              const std::optional<std::string>& = std::nullopt);
	explicit mResponseMessageType(const Exceptions::EWSError&);

	std::string ResponseClass;
	std::optional<std::string> MessageText;
	std::optional<std::string> ResponseCode;
	std::optional<int32_t> DescriptiveLinkKey;

	mResponseMessageType& success();
	mResponseMessageType& error(const std::string&, const std::string&);

	void serialize(tinyxml2::XMLElement*) const;
};

///////////////////////////////////////////////////////////////////////////////

/**
 * Messages.xsd:861
 */
struct mBaseMoveCopyFolder {
	mBaseMoveCopyFolder(const tinyxml2::XMLElement*, bool);

	tTargetFolderIdType ToFolderId;
	std::vector<tFolderId> FolderIds;

	bool copy;
};

/**
 * Messages.xsd:1080
 */
struct mBaseMoveCopyItem {
	mBaseMoveCopyItem(const tinyxml2::XMLElement*, bool);

	tTargetFolderIdType ToFolderId;
	std::vector<tItemId> ItemIds;
	std::optional<bool> ReturnNewItemIds;

	bool copy;
};

/**
 * Messages.xsd:2265
 */
struct mConvertIdRequest {
	explicit mConvertIdRequest(const tinyxml2::XMLElement*);

	std::vector<sAlternateId> SourceIds;
	Enum::IdFormatType DestinationFormat; //Attribute
};

/**
 * Messages.xsd:2293
 */
struct mConvertIdResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "ConvertIdResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::optional<sAlternateId> AlternateId;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2283
 */
struct mConvertIdResponse {
	std::vector<mConvertIdResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};


/**
 * Messages.xsd:799
 */
struct mFolderInfoResponseMessage : public mResponseMessageType {
	using mResponseMessageType::mResponseMessageType;

	std::vector<sFolder> Folders;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:990
 */
struct mItemInfoResponseMessage : public mResponseMessageType {
	using mResponseMessageType::mResponseMessageType;

	std::vector<sItem> Items;

	void serialize(tinyxml2::XMLElement*) const;
};


/**
 * Messages.xsd:879
 */
struct mCopyFolderRequest : public mBaseMoveCopyFolder {
	explicit mCopyFolderRequest(const tinyxml2::XMLElement*);
};

/**
 * Messages.xsd:580
 */
struct mCopyFolderResponseMessage : public mFolderInfoResponseMessage {
	using mFolderInfoResponseMessage::mFolderInfoResponseMessage;
};

/**
 * Messages.xsd:919
 */
struct mCopyFolderResponse {
	std::vector<mCopyFolderResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1099
 */
struct mCopyItemRequest : public mBaseMoveCopyItem {
	explicit mCopyItemRequest(const tinyxml2::XMLElement*);
};

struct mCopyItemResponseMessage : public mItemInfoResponseMessage {
	static constexpr char NAME[] = "CopyItemResponseMessage";

	using mItemInfoResponseMessage::mItemInfoResponseMessage;
};

/**
 * Messages.xsd:1529
 */
struct mCopyItemResponse {
	std::vector<mCopyItemResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:768
 */
struct mCreateFolderRequest {
	explicit mCreateFolderRequest(const tinyxml2::XMLElement*);

	tTargetFolderIdType ParentFolderId;
	std::vector<sFolder> Folders;
};

/**
 * Messages.xsd:575
 */
struct mCreateFolderResponseMessage : public mFolderInfoResponseMessage {
	static constexpr char NAME[] = "CreateFolderResponseMessage";

	using mFolderInfoResponseMessage::mFolderInfoResponseMessage;
};

/**
 * Messages.xsd:896
 */
struct mCreateFolderResponse {
	std::vector<mCreateFolderResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:959
 */
struct mCreateItemRequest {
	explicit mCreateItemRequest(const tinyxml2::XMLElement*);

	std::optional<Enum::MessageDispositionType> MessageDisposition; // Attribute
	std::optional<Enum::CalendarItemCreateOrDeleteOperationType> SendMeetingInvitations; //Attribute

	std::optional<tTargetFolderIdType> SavedItemFolderId;
	std::vector<sItem> Items;
};

struct mCreateItemResponseMessage : public mItemInfoResponseMessage {
	static constexpr char NAME[] = "CreateItemResponseMessage";

	using mItemInfoResponseMessage::mItemInfoResponseMessage;
};

/**
 * Messages.xsd:990
 */
struct mCreateItemResponse {
	std::vector<mCreateItemResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:824
 */
struct mDeleteFolderRequest {
	explicit mDeleteFolderRequest(const tinyxml2::XMLElement*);

	Enum::DisposalType DeleteType; // Attribute

	std::vector<tFolderId> FolderIds;
};

/**
 * Messages.xsd:573
 */
struct mDeleteFolderResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "DeleteFolderResponseMessage";

	using mResponseMessageType::mResponseMessageType;
};

/**
 * Messages.xsd:836
 */
struct mDeleteFolderResponse {
	std::vector<mDeleteFolderResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1040
 */
struct mDeleteItemRequest {
	explicit mDeleteItemRequest(const tinyxml2::XMLElement*);

	Enum::DisposalType DeleteType; // Attribute
	//<xs:attribute name="SendMeetingCancellations" type="t:CalendarItemCreateOrDeleteOperationType" use="optional"/>
	//<xs:attribute name="AffectedTaskOccurrences" type="t:AffectedTaskOccurrencesType" use="optional"/>
	//<xs:attribute name="SuppressReadReceipts" type="xs:boolean" use="optional"/>

	std::vector<tItemId> ItemIds;
};

/**
 * Messages.xsd:1545
 */
struct mDeleteItemResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "DeleteItemResponseMessage";

	using mResponseMessageType::mResponseMessageType;
};

/**
 * Messages.xsd:1537
 */
struct mDeleteItemResponse {
	std::vector<mDeleteItemResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:842
 */
struct mEmptyFolderRequest {
	explicit mEmptyFolderRequest(const tinyxml2::XMLElement*);

	Enum::DisposalType DeleteType; // Attribute
	bool DeleteSubFolders; // Attribute

	std::vector<sFolderId> FolderIds;
};

/**
 * Messages.xsd:574
 */
struct mEmptyFolderResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "EmptyFolderResponseMessage";

	using mResponseMessageType::mResponseMessageType;
};

/**
 * Messages.xsd:855
 */
struct mEmptyFolderResponse {
	std::vector<mEmptyFolderResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:781
 */
struct mFindFolderRequest {
	explicit mFindFolderRequest(const tinyxml2::XMLElement*);

	tFolderResponseShape FolderShape;
	std::optional<tFractionalPageView> FractionalPageFolderView; // Specified as variant, but easier to handle this way
	std::optional<tIndexedPageView> IndexedPageFolderView;
	std::optional<tRestriction> Restriction;
	std::vector<sFolderId> ParentFolderIds;
	Enum::FolderQueryTraversalType Traversal; // Attribute
};

/**
 * Messages.xsd:809
 */
struct mFindFolderResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "FindFolderResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::optional<tFindFolderParent> RootFolder;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:818
 */
struct mFindFolderResponse {
	std::vector<mFindFolderResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1154
 */
struct mFindItemRequest {
	explicit mFindItemRequest(const tinyxml2::XMLElement*);

	tItemResponseShape ItemShape;
	std::optional<tIndexedPageView> IndexedPageItemView;
	std::optional<tFractionalPageView> FractionalPageItemView;
	std::optional<tCalendarView> CalendarView;
	std::optional<tContactsView> ContactsView;
	//<xs:choice minOccurs="0">
	//  <xs:element name="GroupBy" type="t:GroupByType"/>
	//  <xs:element name="DistinguishedGroupBy" type="t:DistinguishedGroupByType"/>
	//</xs:choice>
	std::optional<tRestriction> Restriction;
	std::optional<std::vector<tFieldOrder>> SortOrder;
	//<xs:element name="SortOrder" type="t:NonEmptyArrayOfFieldOrdersType" minOccurs="0"/>
	std::vector<sFolderId> ParentFolderIds;
	//<xs:element name="QueryString" type="m:QueryStringType" minOccurs="0" maxOccurs="1"/>
	Enum::ItemQueryTraversalType Traversal; // Attribute
};

/**
 * Messages.xsd:1553
 */
struct mFindItemResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "FindItemResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::optional<tFindItemParent> RootFolder;
	//<xs:element name="HighlightTerms" type="t:ArrayOfHighlightTermsType" minOccurs="0" />

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1563
 */
struct mFindItemResponse {
	std::vector<mFindItemResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1460
 */
struct mCreateAttachmentRequest {
	mCreateAttachmentRequest(const tinyxml2::XMLElement *);

	tItemId ParentItemId;
	std::vector<tFileAttachment> Attachments;
};

/**
 * Messages.xsd:1471
 */
struct mCreateAttachmentResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "CreateAttachmentResponseMessage";

	using mResponseMessageType::mResponseMessageType;
	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement *) const;

	std::vector<sAttachment> Attachments;
};

struct mCreateAttachmentResponse {
	void serialize(tinyxml2::XMLElement *) const;

	std::vector<mCreateAttachmentResponseMessage> ResponseMessages;
};

/**
 * Messages.xsd:1482
 */
struct mGetAttachmentRequest {
	mGetAttachmentRequest(const tinyxml2::XMLElement*);

	//<xs:element name="AttachmentShape" type="t:AttachmentResponseShapeType" minOccurs="0"/>
	std::vector<tRequestAttachmentId> AttachmentIds;
};

/**
 * Messages.xsd:1492
 */
struct mGetAttachmentResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "GetAttachmentResponseMessage";

	using mResponseMessageType::mResponseMessageType;
	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement*) const;

	std::vector<sAttachment> Attachments;
};

struct mGetAttachmentResponse {
	void serialize(tinyxml2::XMLElement*) const;

	std::vector<mGetAttachmentResponseMessage> ResponseMessages;
};

/**
 * Messages.xsd:2002
 */
struct mGetEventsRequest {
	mGetEventsRequest(const tinyxml2::XMLElement*);

	tSubscriptionId SubscriptionId;
	//<xs:element name="Watermark" type="t:WatermarkType"/>
};

/**
 * Messages.xsd:2016
 */
struct mGetEventsResponseMessage : public mResponseMessageType {
	using mResponseMessageType::mResponseMessageType;

	std::optional<tNotification> Notification; // Only optional in case of error message

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2025
 */
struct mGetEventsResponse {
	std::vector<mGetEventsResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:692
 */
struct mGetFolderRequest {
	mGetFolderRequest(const tinyxml2::XMLElement*);

	tFolderResponseShape FolderShape;
	std::vector<sFolderId> FolderIds;
};

struct mGetFolderResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "GetFolderResponseMessage";

	using mResponseMessageType::mResponseMessageType;
	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement*) const;

	std::vector<sFolder> Folders;
};

/**
 * Messages.xsd:789
 */
struct mGetFolderResponse {
	void serialize(tinyxml2::XMLElement*) const;

	std::vector<mGetFolderResponseMessage> ResponseMessages;
};

/**
 * @brief      Get mail tips request
 *
 * Messages.xsg:1742
 */
struct mGetMailTipsRequest {
	explicit mGetMailTipsRequest(const tinyxml2::XMLElement*);

	tEmailAddressType SendingAs;
	std::vector<tEmailAddressType> Recipients;
	//Enum::MailTipTypes MailTipsRequested;
};

/**
 * Messages.xsd:1776
 */
struct mMailTipsResponseMessageType : public mResponseMessageType {
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
struct mGetMailTipsResponse : public mResponseMessageType {
	using mResponseMessageType::success;

	std::vector<mMailTipsResponseMessageType> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2815
 */
struct mGetServiceConfigurationRequest {
	explicit mGetServiceConfigurationRequest(const tinyxml2::XMLElement*);

	std::optional<tEmailAddressType> ActingAs;
	std::vector<Enum::ServiceConfigurationType> RequestedConfiguration;
	//<xs:element minOccurs="0" maxOccurs="1" name="ConfigurationRequestDetails" type="t:ConfigurationRequestDetailsType" />
};

/**
 * Messages.xsd:2831
 */
struct mGetServiceConfigurationResponseMessageType : public mResponseMessageType {
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
struct mGetServiceConfigurationResponse : public mResponseMessageType {
	using mResponseMessageType::success;

	void serialize(tinyxml2::XMLElement*) const;

	std::vector<mGetServiceConfigurationResponseMessageType> ResponseMessages;
};

/**
 * Messages.xsd:2033
 */
struct mGetStreamingEventsRequest {
	explicit mGetStreamingEventsRequest(const tinyxml2::XMLElement*);

	std::vector<tSubscriptionId> SubscriptionIds;
	int ConnectionTimeout; //Minutes
};

/**
 * Messages.xsd:2048
 */
struct mGetStreamingEventsResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "GetStreamingEventsResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::vector<tNotification> Notifications;
	std::vector<tSubscriptionId> ErrorSubscriptionIds;
	std::optional<Enum::ConnectionStatusType> ConnectionStatus;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2063
 */
struct mGetStreamingEventsResponse {
	std::vector<mGetStreamingEventsResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2204
 */
struct mGetUserAvailabilityRequest {
	explicit mGetUserAvailabilityRequest(const tinyxml2::XMLElement*);

	std::optional<tSerializableTimeZone> TimeZone;
	std::vector<tMailboxData> MailboxDataArray;
	std::optional<tFreeBusyViewOptions> FreeBusyViewOptions;
	std::optional<tSuggestionsViewOptions> SuggestionsViewOptions;
};

/**
 * Messages.xsd:2182
 */
struct mFreeBusyResponse : public NS_EWS_Messages {
	static constexpr char NAME[] = "FreeBusyResponse";

	mFreeBusyResponse() = default;
	explicit mFreeBusyResponse(tFreeBusyView&&);

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<tFreeBusyView> FreeBusyView;
	std::optional<mResponseMessageType> ResponseMessage;
};

/**
 * Messages.xsd:3486
 */
struct mGetAppManifestsRequest {
	explicit inline mGetAppManifestsRequest(const tinyxml2::XMLElement*) {} // nothing to do here for now

	//<xs:element name="ApiVersionSupported" type="xs:string" minOccurs="0" maxOccurs="1" />
	//<xs:element name="SchemaVersionSupported" type="xs:string" minOccurs="0" maxOccurs="1" />
	//<xs:element name="IncludeAllInstalledAddIns" type="xs:boolean" minOccurs="0" maxOccurs="1" />
	//<xs:element name="IncludeEntitlementData" type="xs:boolean" minOccurs="0" maxOccurs="1" />
	//<xs:element name="IncludeManifestData" type="xs:boolean" minOccurs="0" maxOccurs="1" />
	//<xs:element name="IncludeCustomAppsData" type="xs:boolean" minOccurs="0" maxOccurs="1" />
	//<xs:element name="ExtensionIds" type="m:ListOfExtensionIdsType" minOccurs="0" maxOccurs="1" />
	//<xs:element name="AddIns" type="m:ArrayOfPrivateCatalogAddInsType" minOccurs="0" maxOccurs="1"/>
	//<xs:element name="IncludeExtensionMetaData" type="xs:boolean" minOccurs="0" maxOccurs="1" />
};

/**
 * Messages.xsd:3511
 */
struct mGetAppManifestsResponse : public mResponseMessageType {
	using mResponseMessageType::mResponseMessageType;

	void serialize(tinyxml2::XMLElement*) const;
	//<xs:choice>
	//	<xs:element name="Apps" type="t:ArrayOfAppsType" maxOccurs="1"/>
	//	<xs:element name="Manifests" type="m:ArrayOfAppManifestsType" maxOccurs="1"/>
	//</xs:choice>
};

/**
 * Messages.xsd:2204
 */
struct mGetUserAvailabilityResponse {
	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::vector<mFreeBusyResponse>> FreeBusyResponseArray;
	//<xs:element minOccurs="0" maxOccurs="1" name="SuggestionsResponse" type="m:SuggestionsResponseType" />
};

/**
 * Messages.xsd:4116
 */
struct mGetUserPhotoRequest {
	explicit mGetUserPhotoRequest(const tinyxml2::XMLElement*);

	std::string Email;
	// We currently have no means of resizing/converting photos, so we'll ignore the request data
	//<xs:element name="SizeRequested" type="t:UserPhotoSizeType" minOccurs="1" maxOccurs="1" />
	//<xs:element name="TypeRequested" type="t:UserPhotoTypeType" minOccurs="0" maxOccurs="1" />
};

/**
 * Messages.xsd:4131
 *
 * Does not utilize ResponseMessages array indirection,
 * instead contains response data directly.
 */
struct mGetUserPhotoResponse : public mResponseMessageType {
	using mResponseMessageType::mResponseMessageType;

	bool HasChanged = true; // There is currently no mechanism to determine this, so always return true.
	sBase64Binary PictureData;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      Out-of-office settings request
 *
 * Messages.xsg:2215
 */
struct mGetUserOofSettingsRequest {
	explicit mGetUserOofSettingsRequest(const tinyxml2::XMLElement*);

	tMailbox Mailbox;
};

/**
 * @brief      Out-of-office settings response
 *
 * Messages.xsd:2228
 */
struct mGetUserOofSettingsResponse {
	mResponseMessageType ResponseMessage;
	std::optional<tUserOofSettings> OofSettings;

	/* OXWOOF v15 §7.1 says it's optional, but OL disagrees */
	std::string AllowExternalOof = "All";

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:873
 */
struct mMoveFolderRequest : public mBaseMoveCopyFolder {
	explicit mMoveFolderRequest(const tinyxml2::XMLElement*);
};

/**
 * Messages.xsd:579
 */
struct mMoveFolderResponseMessage : public mFolderInfoResponseMessage {
	static constexpr char NAME[] = "MoveFolderResponseMessage";

	using mFolderInfoResponseMessage::mFolderInfoResponseMessage;
};

/**
 * Messages.xsd:914
 */
struct mMoveFolderResponse {
	std::vector<mMoveFolderResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1093
 */
struct mMoveItemRequest : public mBaseMoveCopyItem {
	explicit mMoveItemRequest(const tinyxml2::XMLElement*);
};

/**
 * Messages.xsd:597
 */
struct mMoveItemResponseMessage : public mItemInfoResponseMessage {
	static constexpr char NAME[] = "MoveItemResponseMessage";

	using mItemInfoResponseMessage::mItemInfoResponseMessage;
};

/**
 * Messages.xsd:1524
 */
struct mMoveItemResponse {
	std::vector<mMoveItemResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      Out-of-office settings set request
 *
 * Messages.xsd:2239
 */
struct mSetUserOofSettingsRequest {
	explicit mSetUserOofSettingsRequest(const tinyxml2::XMLElement*);

	tMailbox Mailbox;
	tUserOofSettings UserOofSettings;
};

/**
 * @brief      Out-of-office settings set response
 *
 * Messages.xsd:2254
 */
struct mSetUserOofSettingsResponse {
	mResponseMessageType ResponseMessage;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2098
 */
struct mSyncFolderHierarchyRequest {
	explicit mSyncFolderHierarchyRequest(const tinyxml2::XMLElement*);

	tFolderResponseShape FolderShape;
	std::optional<tTargetFolderIdType> SyncFolderId;
	std::optional<std::string> SyncState;
};

/**
 * Messages.xsd:2111
 */
struct mSyncFolderHierarchyResponseMessage : public mResponseMessageType {
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
struct mSyncFolderHierarchyResponse {
	std::vector<mSyncFolderHierarchyResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2129
 */
struct mSyncFolderItemsRequest {
	explicit mSyncFolderItemsRequest(const tinyxml2::XMLElement*);

	tItemResponseShape ItemShape;
	tTargetFolderIdType SyncFolderId;
	std::optional<std::string> SyncState;
	int32_t MaxChangesReturned;
	std::optional<Enum::SyncFolderItemsScopeType> SyncScope;

	//<xs:element name="Ignore" type="t:ArrayOfBaseItemIdsType" minOccurs="0"/>
};

struct mSyncFolderItemsResponseMessage : public mResponseMessageType {
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
struct mSyncFolderItemsResponse {
	std::vector<mSyncFolderItemsResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:946
 */
struct mGetItemRequest {
	explicit mGetItemRequest(const tinyxml2::XMLElement*);

	tItemResponseShape ItemShape;
	std::vector<tItemId> ItemIds;

};

struct mGetItemResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "GetItemResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::vector<sItem> Items;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1519
 */
struct mGetItemResponse {
	std::vector<mGetItemResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2781 (simplified)
 */
struct mFindPeopleRequest {
	explicit mFindPeopleRequest(const tinyxml2::XMLElement *);

	std::string QueryString;
};

/**
 * Messages.xsd:2788 (simplified)
 */
struct mFindPeopleResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "FindPeopleResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::optional<std::vector<tPersona>> People;
	std::optional<uint32_t> TotalNumberOfPeopleInView;

	void serialize(tinyxml2::XMLElement *) const;
};

struct mFindPeopleResponse {
	std::vector<mFindPeopleResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement *) const;
};

/**
 * Messages.xsd:1676
 */
struct mResolveNamesRequest {
	explicit mResolveNamesRequest(const tinyxml2::XMLElement*);

	std::optional<std::vector<sFolderId>> ParentFolderIds;
	std::string UnresolvedEntry;

	std::optional<bool> ReturnFullContactData; //Attribute
	std::optional<Enum::ResolveNamesSearchScopeType> SearchScope; //Attribute
	std::optional<Enum::DefaultShapeNamesType> ContactDataShape; //Attribute
};

/**
 * Messages.xsd:1706
 */
struct mResolveNamesResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "ResolveNamesResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::optional<tResolutionSet> ResolutionSet;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1694
 */
struct mResolveNamesResponse {
	std::vector<mResolveNamesResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1121
 */
struct mSendItemRequest {
	explicit mSendItemRequest(const tinyxml2::XMLElement*);

	bool SaveItemToFolder;  // Attribute

	std::vector<tItemId> ItemIds;
	std::optional<tTargetFolderIdType> SavedItemFolderId;
};

/**
 * Messages.xsd:572
 */
struct mSendItemResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "SendItemResponseMessage";

	using mResponseMessageType::mResponseMessageType;
};

/**
 * Messages.xsd:1136
 */
struct mSendItemResponse {
	std::vector<mSendItemResponseMessage> Responses;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1951
 */
struct mSubscribeRequest {
	static constexpr char NAME[] = "Subscribe";

	explicit mSubscribeRequest(const tinyxml2::XMLElement*);

	std::variant<tPullSubscriptionRequest, tPushSubscriptionRequest, tStreamingSubscriptionRequest> subscription;
};

/**
 * Messages.xsd:1965
 */
struct mSubscribeResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "SubscribeResponseMessage";

	std::optional<tSubscriptionId> SubscriptionId;
	//<xs:element name="Watermark" type="t:WatermarkType"  minOccurs="0"/>

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:886
 */
struct mUpdateFolderRequest {
	explicit mUpdateFolderRequest(const tinyxml2::XMLElement*);

	std::vector<tFolderChange> FolderChanges;
};

/**
 * Messages.xsd:578
 */
struct mUpdateFolderResponseMessage : public mFolderInfoResponseMessage {
	static constexpr char NAME[] = "UpdateFolderResponseMessage";

	using mFolderInfoResponseMessage::mFolderInfoResponseMessage;
};

/**
 * Messages.xsd:908
 */
struct mUpdateFolderResponse {
	std::vector<mUpdateFolderResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1975
 */
struct mSubscribeResponse {
	std::vector<mSubscribeResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:1982
 */
struct mUnsubscribeRequest {
	mUnsubscribeRequest(const tinyxml2::XMLElement*);

	tSubscriptionId SubscriptionId;
};

/**
 * Implicitely declared at Messages.xsd:1994
 */
struct mUnsubscribeResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "UnsubscribeResponseMessage";

	using mResponseMessageType::mResponseMessageType;
};

/**
 * Messages.xsd:1994
 */
struct mUnsubscribeResponse {
	std::vector<mUnsubscribeResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:973
 */
struct mUpdateItemRequest {
	explicit mUpdateItemRequest(const tinyxml2::XMLElement*);

	//<xs:element name="SavedItemFolderId" type="t:TargetFolderIdType" minOccurs="0"/>
	std::vector<tItemChange> ItemChanges;
	//<xs:attribute name="ConflictResolution" type="t:ConflictResolutionType" use="required"/>
	//<xs:attribute name="MessageDisposition" type="t:MessageDispositionType"  use="optional"/>
	//<xs:attribute name="SendMeetingInvitationsOrCancellations" type="t:CalendarItemUpdateOperationType"  use="optional"/>
	//<xs:attribute name="SuppressReadReceipts" type="xs:boolean" use="optional"/>
};

/**
 * Messages.xsd:1000
 */
struct mUpdateItemResponseMessage : public mItemInfoResponseMessage {
	static constexpr char NAME[] = "UpdateItemResponseMessage";

	using mItemInfoResponseMessage::mItemInfoResponseMessage;

	tConflictResults ConflictResults;

	void serialize(tinyxml2::XMLElement*) const;
};

struct mUpdateItemResponse {
	std::vector<mUpdateItemResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/*
 * Types.xsd:7203
 */
struct tUserConfigurationName : public tTargetFolderIdType {
	explicit tUserConfigurationName(const tinyxml2::XMLElement*);

	std::string Name; //Attribute

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:7227
 */
struct tUserConfigurationDictionaryObject {
	Enum::UserConfigurationDictionaryObjectTypesType Type;
	std::vector<std::string> Value;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:7234
 */
struct tUserConfigurationDictionaryEntry {
	tUserConfigurationDictionaryObject DictionaryKey;
	std::optional<tUserConfigurationDictionaryObject> DictionaryValue;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:7241
 */
struct tUserConfigurationDictionaryType {
	std::vector<tUserConfigurationDictionaryEntry> DictionaryEntry;

	void serialize(tinyxml2::XMLElement*) const;
};

/*
 * Types.xsd:7247
 */
struct tUserConfigurationType {
	tUserConfigurationName UserConfigurationName;
	std::optional<tItemId> ItemId;
	std::optional<tUserConfigurationDictionaryType> Dictionary;
	std::optional<sBase64Binary> XmlData;
	std::optional<sBase64Binary> BinaryData;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsg:2557
 */
struct mGetUserConfigurationRequest {
	explicit mGetUserConfigurationRequest(const tinyxml2::XMLElement*);

	tUserConfigurationName UserConfigurationName;
	Enum::UserConfigurationPropertyType UserConfigurationProperties;
};

/**
 * Messages.xsg:2571
 */
struct mGetUserConfigurationResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "GetUserConfigurationResponseMessage";

	using mResponseMessageType::mResponseMessageType;

	std::optional<tUserConfigurationType> UserConfiguration;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsg:2581
 */
struct mGetUserConfigurationResponse {
	std::vector<mGetUserConfigurationResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Messages.xsd:2321
 */
struct mGetDelegateRequest {
	explicit mGetDelegateRequest(const tinyxml2::XMLElement*);

	tMailbox Mailbox;
	std::optional<std::vector<tUserId>> UserIds;
	std::optional<bool> IncludePermissions;
};

struct mDelegateUserResponseMessage : public mResponseMessageType {
	static constexpr char NAME[] = "DelegateUserResponseMessageType";

	tDelegateUser DelegateUser;

	void serialize(tinyxml2::XMLElement*) const;
};

struct mGetDelegateResponse {
	std::vector<mDelegateUserResponseMessage> ResponseMessages;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      Get inbox rules request
 *
 * Messages.xsg:2935
 */
struct mGetInboxRulesRequest {
	explicit mGetInboxRulesRequest(const tinyxml2::XMLElement*);

	std::optional<std::string> MailboxSmtpAddress;
};

/**
 * @brief      Get inbox rules response
 *
 * Messages.xsg:2959
 */
struct mGetInboxRulesResponse : public mResponseMessageType {
	static constexpr char NAME[] = "GetInboxRulesResponse";

	using mResponseMessageType::success;

	std::optional<bool> OutlookRuleBlobExists;
	// <xs:element name="InboxRules" type="t:ArrayOfRulesType" minOccurs="0" maxOccurs="1" />

	void serialize(tinyxml2::XMLElement*) const;
};

#undef ALIAS

}
