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

struct tSerializableTimeZone;
struct tDistinguishedFolderId;
struct tFolderId;
struct tFolderType;
struct tCalendarFolderType;
struct tContactsFolderType;
struct tSearchFolderType;
struct tTasksFolderType;
struct tSyncFolderHierarchyCreate;
struct tSyncFolderHierarchyUpdate;
struct tSyncFolderHierarchyDelete;

/**
 * @brief      Folder specification
 *
 * Resolves folder ID and type either from the distinguished name or
 * the folder target string.
 */
struct sFolderSpec
{
	enum Type : uint8_t {NORMAL, CALENDAR, CONTACTS, SEARCH, TASKS};

	sFolderSpec() = default;
	explicit sFolderSpec(const tFolderId&);
	explicit sFolderSpec(const tDistinguishedFolderId&);
	sFolderSpec(const std::string&, uint64_t, Type=NORMAL);

	sFolderSpec& normalize();
	std::string serialize() const;

	std::optional<std::string> target;
	uint64_t folderId;
	Type type = NORMAL;
	enum {AUTO, PRIVATE, PUBLIC} location = AUTO;

private:
	struct DistNameInfo
	{
		const char* name;
		uint64_t id;
		Type type;
		bool isPrivate;
	};

	static const std::array<DistNameInfo, 21> distNameInfo;
};

/**
 * Joint folder type
 */
using sFolder = std::variant<tFolderType, tCalendarFolderType, tContactsFolderType, tSearchFolderType, tTasksFolderType>;

/**
 * Joint hierarchy change type
 */
using sSyncFolderHierarchyChange = std::variant<tSyncFolderHierarchyCreate, tSyncFolderHierarchyUpdate, tSyncFolderHierarchyDelete>;

/**
 * @brief     Sync state helper class
 */
struct sSyncState
{
	sSyncState();

	void init(const std::string&);
	void update(const EID_ARRAY&, uint64_t);
	std::string serialize();

	idset given; ///< Set of known IDs
	idset seen;  ///< Set of known change numbers
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

	gromox::time_point time;
	std::chrono::minutes offset = std::chrono::minutes(0);
};

///////////////////////////////////////////////////////////////////////////////////////////////////

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
struct tCalendarEvent
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
struct tFolderId
{
	static constexpr char NAME[] = "FolderId";

	tFolderId() = default;
	tFolderId(const tinyxml2::XMLElement*);
	tFolderId(const sFolderSpec&);

	void serialize(tinyxml2::XMLElement*) const;

	std::string Id; //Attribute
	std::optional<std::string> ChangeKey; //Attribute
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

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<std::string> PropertyTag; //Attribute
	Enum::MapiPropertyTypeType PropertyType; //Attribute
	//<xs:attribute name="PropertyId" type="xs:int" use="optional"/>
	//<xs:attribute name="DistinguishedPropertySetId" type="t:DistinguishedPropertySetType" use="optional"/>
	//<xs:attribute name="PropertySetId" type="t:GuidType" use="optional"/>
	//<xs:attribute name="PropertyName" type="xs:string" use="optional"/>

	uint32_t tag() const;
	static const char* typeName(uint16_t);

	static std::array<TMEntry, 26> typeMap; ///< Types.xsd:1060
};

/**
 * Types.xsd:1196
 */
struct tExtendedProperty
{
	explicit tExtendedProperty(const TAGGED_PROPVAL&);

	TAGGED_PROPVAL propval;

	void serialize(tinyxml2::XMLElement*) const;
private:
	void serialize(const void*, size_t, uint16_t, tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:1981
 */
struct tBaseFolderType
{
	using TagFilter = std::vector<uint32_t>;

	explicit tBaseFolderType(const sFolderSpec&, const TPROPVAL_ARRAY&, const TagFilter& = TagFilter());

	void serialize(tinyxml2::XMLElement*) const;

	std::optional<tFolderId> FolderId;
	std::optional<tFolderId> ParentFolderId;
	std::optional<std::string> FolderClass;
	std::optional<std::string> DisplayName;
	std::optional<int32_t> TotalCount;
	std::optional<int32_t> ChildFolderCount;
	std::vector<tExtendedProperty> ExtendendProperty;
	//<xs:element name="ManagedFolderInformation" type="t:ManagedFolderInformationType" minOccurs="0"/>
	//<xs:element name="EffectiveRights" type="t:EffectiveRightsType" minOccurs="0"/>
	//<xs:element name="DistinguishedFolderId" type="t:DistinguishedFolderIdNameType" minOccurs="0"/>
	//<xs:element name="PolicyTag" type="t:RetentionTagType" minOccurs="0" />
	//<xs:element name="ArchiveTag" type="t:RetentionTagType" minOccurs="0" />
	//<xs:element name="ReplicaList" type="t:ArrayOfStringsType" minOccurs="0" />

	static sFolder create(const std::string&, const TPROPVAL_ARRAY&, const TagFilter& = TagFilter());
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

	uint32_t tag() const;

	std::string FieldURI; //Attribute

	static std::unordered_map<std::string, uint32_t> fieldMap; ///< Types.xsd:402
};

/**
 * Types.xsd:1165
 */
struct tFolderShape : public std::variant<tExtendedFieldURI, tFieldURI>
{
	using Base = std::variant<tExtendedFieldURI, tFieldURI>;

	tFolderShape(const tinyxml2::XMLElement*);

	uint32_t tag() const;
};

/**
 * Types.xsd:2019
 */
struct tFolderType : public tBaseFolderType
{
	static constexpr char NAME[] = "Folder";

	explicit tFolderType(const sFolderSpec&, const TPROPVAL_ARRAY&, const TagFilter& = TagFilter());

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
 * @brief     Joint type for create and update
 *
 * Types.xsd:6223
 */
struct tSyncFolderHierarchyCU
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
struct tSyncFolderHierarchyDelete
{
	static constexpr char NAME[] = "Delete";

	tSyncFolderHierarchyDelete(const std::string&, uint64_t);

	tFolderId FolderId;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * Types.xsd:1273
 */
struct tFolderResponseShape
{
	tFolderResponseShape(const tinyxml2::XMLElement*);

	std::vector<uint32_t> tags() const;

	Enum::DefaultNamesType BaseShape;
	std::optional<std::vector<tFolderShape>> AdditionalProperties;

	static constexpr std::array<uint32_t, 1> tagsIdOnly = {PR_CHANGE_KEY};
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

	tDistinguishedFolderId(const tinyxml2::XMLElement*);

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
struct mResponseMessageType
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
struct mFreeBusyResponse
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
	std::optional<tUserOofSettings> UserOofSettings;

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
	std::optional<std::vector<sSyncFolderHierarchyChange>> Changes;

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

}
