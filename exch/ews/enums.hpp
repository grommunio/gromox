// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
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
	STR(AllProperties);
	STR(ApplicationTime);
	STR(ApplicationTimeArray);
	STR(Best);
	STR(Binary);
	STR(BinaryArray);
	STR(Boolean);
	STR(Busy);
	STR(CLSID);
	STR(CLSIDArray);
	STR(Complete);
	STR(Contact);
	STR(Currency);
	STR(CurrencyArray);
	STR(CustomMailTip);
	STR(Day);
	STR(Default);
	STR(DeliveryRestriction);
	STR(Detailed);
	STR(DetailedMerged);
	STR(Disabled);
	STR(Double);
	STR(DoubleArray);
	STR(Enabled);
	STR(Error);
	STR(Excellent); // Smithers
	STR(ExternalMemberCount);
	STR(Fair);
	STR(Flagged);
	STR(Float);
	STR(FloatArray);
	STR(Free);
	STR(FreeBusy);
	STR(FreeBusyMerged);
	STR(Friday);
	STR(Good);
	STR(GroupMailbox);
	STR(HTML);
	STR(High);
	STR(IdOnly);
	STR(ImplicitContact);
	STR(Integer);
	STR(IntegerArray);
	STR(InvalidRecipient);
	STR(Known);
	STR(Long);
	STR(LongArray);
	STR(Low);
	STR(MailTips);
	STR(Mailbox);
	STR(MailboxFullStatus);
	STR(MaxMessageSize);
	STR(MergedOnly);
	STR(ModerationStatus);
	STR(Monday);
	STR(NoData);
	STR(None);
	STR(Normal);
	STR(NormalAndAssociatedItems);
	STR(NormalItems);
	STR(NotFlagged);
	STR(Null);
	STR(OOF);
	STR(Object);
	STR(ObjectArray);
	STR(OfficeIntegrationConfiguration);
	STR(OneOff);
	STR(Optional);
	STR(Organizer);
	STR(OutOfOfficeMessage);
	STR(PcxPeopleSearch);
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
	STR(Short);
	STR(ShortArray);
	STR(String);
	STR(StringArray);
	STR(Sunday);
	STR(SystemTime);
	STR(SystemTimeArray);
	STR(Tentative);
	STR(Text);
	STR(Thursday);
	STR(TotalMemberCount);
	STR(Tuesday);
	STR(UnifiedMessagingConfiguration);
	STR(Unknown);
	STR(User);
	STR(Wednesday);
	STR(Weekday);
	STR(Weekendday);
	STR(WorkingElsewhere);
	STR(adminauditlogs);
	STR(allcategorizeditems);
	STR(alltaggeditems);
	STR(archiv);
	STR(archivedeleteditems);
	STR(archiveinbox);
	STR(archivemsgfolderroot);
	STR(archiverecoverableitemsdeletions);
	STR(archiverecoverableitemsdiscoveryholds);
	STR(archiverecoverableitemspurges);
	STR(archiverecoverableitemsroot);
	STR(archiverecoverableitemsversions);
	STR(archiveroot);
	STR(calendar);
	STR(conflicts);
	STR(contacts);
	STR(conversationhistory);
	STR(deleteditems);
	STR(directory);
	STR(drafts);
	STR(externalcontacts);
	STR(favorites);
	STR(imcontactlist);
	STR(important);
	STR(inbox);
	STR(journal);
	STR(junkemail);
	STR(kaizaladata);
	STR(localfailures);
	STR(mecontact);
	STR(messageingestion);
	STR(msgfolderroot);
	STR(mycontacts);
	STR(notes);
	STR(onedriverecylebin);
	STR(onedriveroot);
	STR(onedrivesystem);
	STR(onedrivevolume);
	STR(orionnotes);
	STR(outbox);
	STR(peopleconnect);
	STR(personmetadata);
	STR(publicfoldersroot);
	STR(quickcontacts);
	STR(recipientcache);
	STR(recoverableitemsdeletions);
	STR(recoverableitemsdiscoveryholds);
	STR(recoverableitemspurges);
	STR(recoverableitemsroot);
	STR(recoverableitemsversions);
	STR(root);
	STR(scheduled);
	STR(searchfolders);
	STR(sentitems);
	STR(serverfailures);
	STR(starred);
	STR(syncissues);
	STR(tagitems);
	STR(tasks);
	STR(teamchat);
	STR(teamchathistory);
	STR(teamspaceactivity);
	STR(teamspacemessaging);
	STR(teamspaceworkitems);
	STR(todosearch);
	STR(voicemail);
	STR(yammerdata);
	STR(yammerfeeds);
	STR(yammerinbound);
	STR(yammeroutbound);
	STR(yammerroot);
#undef STR

	//Enum types
	using BodyTypeResponseType = StrEnum<Best, HTML, Text>; ///< Types.xsd:1265
	using DayOfWeekType = StrEnum<Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Day, Weekday, Weekendday>; ///< Types.xsd:4481
	using DefaultShapeNamesType = StrEnum<IdOnly, Default, AllProperties, PcxPeopleSearch>; ///< Types.xsd:1255
	using DistinguishedFolderIdNameType = StrEnum<calendar, contacts, deleteditems, drafts, inbox, journal, notes, outbox, sentitems, tasks, msgfolderroot, publicfoldersroot, root, junkemail, searchfolders, voicemail, recoverableitemsroot, recoverableitemsdeletions, recoverableitemsversions, recoverableitemspurges, recoverableitemsdiscoveryholds, archiveroot, archivemsgfolderroot, archivedeleteditems, archiveinbox, archiverecoverableitemsroot, archiverecoverableitemsdeletions, archiverecoverableitemsversions, archiverecoverableitemspurges, archiverecoverableitemsdiscoveryholds, syncissues, conflicts, localfailures, serverfailures, recipientcache, quickcontacts, conversationhistory, adminauditlogs, todosearch, mycontacts, directory, imcontactlist, peopleconnect, favorites, mecontact, personmetadata, teamspaceactivity, teamspacemessaging, teamspaceworkitems, scheduled, orionnotes, tagitems, alltaggeditems, allcategorizeditems, externalcontacts, teamchat, teamchathistory, yammerdata, yammerroot, yammerinbound, yammeroutbound, yammerfeeds, kaizaladata, messageingestion, onedriveroot, onedriverecylebin, onedrivesystem, onedrivevolume, important, starred, archiv>; //Types.xsd:1768
	using ExternalAudience = StrEnum<None, Known, All>; ///< Types.xsd:6530
	using FlagStatusType = StrEnum<NotFlagged, Flagged, Complete>; ///< Types.xsd:2445
	using FreeBusyViewType = StrEnum<None, MergedOnly, FreeBusy, FreeBusyMerged, Detailed, DetailedMerged>; ///< Types.xsd:6333
	using LegacyFreeBusyType = StrEnum<Free, Tentative, Busy, OOF, WorkingElsewhere, NoData>; ///< Types.xsd:4352
	using ImportanceChoicesType = StrEnum<Low, Normal, High>; ///< Types.xsd:1708
	using MailboxTypeType = StrEnum<Unknown, OneOff, Mailbox, PublicDL, PrivateDL, Contact, PublicFolder, GroupMailbox, ImplicitContact, User>; ///< Types.xsd:253
	using MailTipTypes = StrEnum<All, OutOfOfficeMessage, MailboxFullStatus, CustomMailTip, ExternalMemberCount, TotalMemberCount, MaxMessageSize, DeliveryRestriction, ModerationStatus, InvalidRecipient, Scope, RecipientSuggestions, PreferAccessibleContent>; ///< Types.xsd:6947
	using MapiPropertyTypeType = StrEnum<ApplicationTime, ApplicationTimeArray, Binary, BinaryArray, Boolean, CLSID, CLSIDArray, Currency, CurrencyArray, Double, DoubleArray, Error, Float, FloatArray, Integer, IntegerArray, Long, LongArray, Null, Object, ObjectArray, Short, ShortArray, SystemTime, SystemTimeArray, String, StringArray>; ///< Types.xsd:1060
	using MeetingAttendeeType = StrEnum<Organizer, Required, Optional, Room, Resource>; ///< Types.xsd:6278
	using OofState = StrEnum<Disabled, Enabled, Scheduled>; ///< Types.xsd:6522
	using ServiceConfigurationType = StrEnum<MailTips, UnifiedMessagingConfiguration, ProtectionRules, PolicyNudges, SharePointURLs, OfficeIntegrationConfiguration>; ///< Types.xsd:7019
	using SuggestionQuality = StrEnum<Excellent, Good, Fair, Poor>; ///< Types.xsd:6423
	using SyncFolderItemsScopeType = StrEnum<NormalItems, NormalAndAssociatedItems>; ///< Types.xsd:6256
};

}
