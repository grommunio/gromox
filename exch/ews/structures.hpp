// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <gromox/clock.hpp>

namespace tinyxml2
{class XMLElement;}

namespace gromox::EWS::Structures
{

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
	std::optional<std::string> MailboxType; ///< Types.xsd:253
	std::optional<std::string> ItemId;
	std::optional<std::string> OriginalDisplayName;
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
 * Types.xsd:6987
 */
struct tMailTips
{
	void serialize(tinyxml2::XMLElement*) const;

	tEmailAddressType RecipientAddress;
	std::string PendingMailTips; ///< MailTipTypes, Types.xsd:6947

	//<xs:element minOccurs="1" maxOccurs="1" name="RecipientAddress" type="t:EmailAddressType" />
	//<xs:element minOccurs="1" maxOccurs="1" name="PendingMailTips" type="t:MailTipTypes" />
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

	std::string OofState; ///< ["Disabled", "Enabled", "Scheduled"], Types.xsd:6522
	std::string ExternalAudience; ///< ["None", "Known", "All"], Types.xsd:6530
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
	std::string ResponseClass;
	std::optional<std::string> MessageText;
	std::optional<std::string> ResponseCode;
	std::optional<int> DescriptiveLinkKey;

	void success();

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
	std::string MailTipsRequested; ///< Types.xsd:6947
};

/**
 * Messages.xsd:1776
 */
struct mMailTipsResponseMessageType
{
	static constexpr char NAME[] = "MailTipsResponseMessageType";

	std::optional<tMailTips> MailTips;

	void serialize(tinyxml2::XMLElement*) const;
};

/**
 * @brief      Get mail tips response
 *
 * Messages.xsg:1760
 */
struct mGetMailTipsResponse
{
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
	std::vector<std::string> RequestedConfiguration; ///< Types.xsd:7019
	//<xs:element minOccurs="0" maxOccurs="1" name="ConfigurationRequestDetails" type="t:ConfigurationRequestDetailsType" />
};

/**
 * Messages.xsd:2831
 */
struct mGetServiceConfigurationResponseMessageType
{
	static constexpr char NAME[] = "ServiceConfigurationResponseMessageType";

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
struct mGetServiceConfigurationResponse
{
	void serialize(tinyxml2::XMLElement*) const;

	std::vector<mGetServiceConfigurationResponseMessageType> ResponseMessages;
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
