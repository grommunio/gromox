// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <gromox/clock.hpp>
#include <gromox/mapidefs.h>

#include "enums.hpp"

namespace tinyxml2
{class XMLElement;}

namespace gromox::EWS
{struct EWSContext;}

namespace gromox::EWS::Structures
{

struct tSerializableTimeZone;

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
	template<typename T>
	explicit inline tReplyBody(T&& Message) : Message(std::forward<T>(Message)) {}
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
	std::optional<std::string> AllowExternalOof;

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

}
