// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <array>

#include "exceptions.hpp"

namespace gromox::EWS::Structures
{

/**
 * @brief     String enum
 *
 * Throws when a non-template value is assigned or used for construction.
 */
template<const char* C0, const char*... Cs>
struct StrEnum : public std::string
{
	static constexpr std::array<const char*, 1+sizeof...(Cs)> Choices{C0, Cs...};

	StrEnum() = default;

	template<typename... Args>
	StrEnum(Args&&... args) : std::string(std::forward<Args...>(args...))
	{check(*this);}

	template<typename Arg>
	StrEnum& operator=(Arg&& arg)
	{
		check(arg);
		assign(std::forward<Arg>(arg));
		return *this;
	}

	static void check(const std::string& v)
	{
		for(const char* choice : Choices)
			if(choice == v)
				return;
		std::string msg = "\"";
		msg += v;
		msg += "\" is not one of [\"";
		msg += Choices[0];
		for(auto it = Choices.begin()+1; it != Choices.end(); ++it)
		{
			msg += "\", \"";
			msg += *it;
		}
		msg += "\"]";
		throw gromox::EWS::Exceptions::EnumError(msg);
	}

	ssize_t index() const
	{
		ssize_t i = 0;
		for(const char* choice : Choices)
		{
			if(choice == *this)
				return i;
			++i;
		}
		return -1;
	}
};

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Collection of XML enum types
 */
struct Enum
{

	//String constants used in enums
#define STR(NAME) static constexpr char NAME[] = #NAME
	STR(All);
	STR(Busy);
	STR(Contact);
	STR(CustomMailTip);
	STR(Day);
	STR(DeliveryRestriction);
	STR(Detailed);
	STR(DetailedMerged);
	STR(Disabled);
	STR(Enabled);
	STR(Excellent);
	STR(ExternalMemberCount);
	STR(Fair);
	STR(Free);
	STR(FreeBusy);
	STR(FreeBusyMerged);
	STR(Friday);
	STR(Good);
	STR(GroupMailbox);
	STR(ImplicitContact);
	STR(InvalidRecipient);
	STR(Known);
	STR(Mailbox);
	STR(MailboxFullStatus);
	STR(MailTips);
	STR(MaxMessageSize);
	STR(MergedOnly);
	STR(ModerationStatus);
	STR(Monday);
	STR(NoData);
	STR(None);
	STR(OfficeIntegrationConfiguration);
	STR(OneOff);
	STR(OOF);
	STR(Optional);
	STR(Organizer);
	STR(OutOfOfficeMessage);
	STR(PolicyNudges);
	STR(Poor);
	STR(PreferAccessibleContent);
	STR(PrivateDL);
	STR(ProtectionRules);
	STR(PublicDL);
	STR(PublicFolder);
	STR(RecipientSuggestions);
	STR(Required);
	STR(Resource);
	STR(Room);
	STR(Saturday);
	STR(Scheduled);
	STR(Scope);
	STR(SharePointURLs);
	STR(Sunday);
	STR(Tentative);
	STR(TotalMemberCount);
	STR(Tuesday);
	STR(Thursday);
	STR(UnifiedMessagingConfiguration);
	STR(Unknown);
	STR(User);
	STR(Wednesday);
	STR(Weekday);
	STR(Weekendday);
	STR(WorkingElsewhere);
#undef STR

	//Enum types
	using DayOfWeekType = StrEnum<Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Day, Weekday, Weekendday>; ///< Types.xsd:4481
	using ExternalAudience = StrEnum<None, Known, All>; ///< Types.xsd:6530
	using FreeBusyViewType = StrEnum<None, MergedOnly, FreeBusy, FreeBusyMerged, Detailed, DetailedMerged>; ///< Types.xsd:6333
	using LegacyFreeBusyType = StrEnum<Free, Tentative, Busy, OOF, WorkingElsewhere, NoData>; ///< Types.xsd:4352
	using MailboxTypeType = StrEnum<Unknown, OneOff, Mailbox, PublicDL, PrivateDL, Contact, PublicFolder, GroupMailbox, ImplicitContact, User>; ///< Types.xsd:253
	using MailTipTypes = StrEnum<All, OutOfOfficeMessage, MailboxFullStatus, CustomMailTip, ExternalMemberCount, TotalMemberCount, MaxMessageSize, DeliveryRestriction, ModerationStatus, InvalidRecipient, Scope, RecipientSuggestions, PreferAccessibleContent>; ///< Types.xsd:6947
	using MeetingAttendeeType = StrEnum<Organizer, Required, Optional, Room, Resource>; ///< Types.xsd:6278
	using OofState = StrEnum<Disabled, Enabled, Scheduled>; ///< Types.xsd:6522
	using ServiceConfigurationType = StrEnum<MailTips, UnifiedMessagingConfiguration, ProtectionRules, PolicyNudges, SharePointURLs, OfficeIntegrationConfiguration>; ///< Types.xsd:7019
	using SuggestionQuality = StrEnum<Excellent, Good, Fair, Poor>; ///< Types.xsd:6423
};

}
