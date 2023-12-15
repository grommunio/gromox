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
 * Throws when a non-template value or invalid index is assigned or used for
 * construction.
 */
template<const char*... Cs>
class StrEnum
{
public:
	using index_t = uint8_t; ///< Index type. Might be expanded if necessary, for now 255 values should be sufficient.

	static_assert(sizeof...(Cs) > 0, "StrEnum must have at least on option");
	static_assert(sizeof...(Cs) < std::numeric_limits<index_t>::max(), "Too many options for StrEnum");

	static constexpr std::array<const char*, sizeof...(Cs)> Choices{Cs...};

	StrEnum() = default;
	constexpr StrEnum(const std::string_view& v) : idx(check(v)) {}
	constexpr StrEnum(const char* v) : idx(check(v)) {}
	constexpr explicit StrEnum(index_t index) : idx(check(index)) {}

	operator std::string() const { return s(); }
	constexpr operator std::string_view() const {return sv();}
	constexpr operator const char*() const {return c_str();}
	constexpr operator index_t() const {return index();}

	std::string s() const { return Choices[idx]; }
	constexpr std::string_view sv() const {return Choices[idx];}
	constexpr const char* c_str() const {return Choices[idx];}
	constexpr index_t index() const {return idx;}

	constexpr bool operator==(const char* v) const {return strcmp(v, Choices[idx]) == 0;}
	constexpr bool operator==(const StrEnum& o) const {return idx == o.idx;}

	static index_t check(const std::string_view &v)
	{
		for(index_t i = 0; i < Choices.size(); ++i)
			if(v == Choices[i])
				return i;
		std::string msg = fmt::format("\"{}\" is not one of ", v);
		printChoices(msg);
		throw gromox::EWS::Exceptions::EnumError(msg);
	}

	static index_t check(index_t value)
	{
		if(value < sizeof...(Cs))
			return value;
		std::string msg = fmt::format("Invalid index {} for enum ", value);
		printChoices(msg);
		throw gromox::EWS::Exceptions::EnumError(msg);
	}

private:
	index_t idx = 0;

	static void printChoices(std::string& dest)
	{
		dest += "[\"";
		dest += Choices[0];
		for(auto it = Choices.begin()+1; it != Choices.end(); ++it) {
			dest += "\", \"";
			dest += *it;
		}
		dest += "\"]";
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
	STR(Accept);
	STR(ActiveDirectory);
	STR(ActiveDirectoryContacts);
	STR(Address);
	STR(All);
	STR(AllProperties);
	STR(ApplicationTime);
	STR(ApplicationTimeArray);
	STR(Appointment);
	STR(April);
	STR(Ascending);
	STR(AssistantPhone);
	STR(August);
	STR(Beginning);
	STR(Best);
	STR(Binary);
	STR(BinaryArray);
	STR(Boolean);
	STR(BusinessFax);
	STR(BusinessMobile);
	STR(BusinessPhone);
	STR(BusinessPhone2);
	STR(Busy);
	STR(CalendarAssistant);
	STR(Callback);
	STR(CarPhone);
	STR(CLSID);
	STR(CLSIDArray);
	STR(Closed);
	STR(CompanyMainPhone);
	STR(Complete);
	STR(Common);
	STR(Confidential);
	STR(Contact);
	STR(Contacts);
	STR(ContactsActiveDirectory);
	STR(CopiedEvent);
	STR(Currency);
	STR(CurrencyArray);
	STR(CustomMailTip);
	STR(CreatedEvent);
	STR(Day);
	STR(December);
	STR(Decline);
	STR(Deep);
	STR(Default);
	STR(DeletedEvent);
	STR(DeliveryRestriction);
	STR(Descending);
	STR(Detailed);
	STR(DetailedMerged);
	STR(Disabled);
	STR(Double);
	STR(DoubleArray);
	STR(EmailAddress1);
	STR(EmailAddress2);
	STR(EmailAddress3);
	STR(Enabled);
	STR(End);
	STR(Error);
	STR(Excellent); // Smithers
	STR(Exception);
	STR(ExternalMemberCount);
	STR(Fair);
	STR(February);
	STR(First);
	STR(Flagged);
	STR(Float);
	STR(FloatArray);
	STR(Fourth);
	STR(Free);
	STR(FreeBusy);
	STR(FreeBusyChangedEvent);
	STR(FreeBusyMerged);
	STR(Friday);
	STR(Good);
	STR(GroupMailbox);
	STR(HomeFax);
	STR(HomePhone);
	STR(HomePhone2);
	STR(HTML);
	STR(HardDelete);
	STR(High);
	STR(IdOnly);
	STR(ImplicitContact);
	STR(Integer);
	STR(IntegerArray);
	STR(InternetHeaders);
	STR(InvalidRecipient);
	STR(IPPhone);
	STR(IsEqualTo);
	STR(IsGreaterThan);
	STR(IsGreaterThanOrEqual);
	STR(IsLessThan);
	STR(IsLessThanOrEqual);
	STR(IsNotEqualTo);
	STR(Isdn);
	STR(January);
	STR(June);
	STR(July);
	STR(Known);
	STR(Last);
	STR(Long);
	STR(LongArray);
	STR(Low);
	STR(MailTips);
	STR(Mailbox);
	STR(MailboxFullStatus);
	STR(March);
	STR(MaxMessageSize);
	STR(May);
	STR(Meeting);
	STR(MergedOnly);
	STR(Mms);
	STR(MobilePhone);
	STR(ModerationStatus);
	STR(ModifiedEvent);
	STR(Monday);
	STR(MoveToDeletedItems);
	STR(MovedEvent);
	STR(Msn);
	STR(NewMailEvent);
	STR(NoData);
	STR(NoResponseReceived);
	STR(None);
	STR(Normal);
	STR(NormalAndAssociatedItems);
	STR(NormalItems);
	STR(NotFlagged);
	STR(November);
	STR(Null);
	STR(OOF);
	STR(Object);
	STR(ObjectArray);
	STR(Occurrence);
	STR(October);
	STR(OfficeIntegrationConfiguration);
	STR(OK);
	STR(OneOff);
	STR(Optional);
	STR(Organizer);
	STR(OtherFax);
	STR(OtherTelephone);
	STR(OutOfOfficeMessage);
	STR(Pager);
	STR(Personal);
	STR(PcxPeopleSearch);
	STR(PolicyNudges);
	STR(Poor);
	STR(PreferAccessibleContent);
	STR(PrimaryPhone);
	STR(Private);
	STR(PrivateDL);
	STR(ProtectionRules);
	STR(PublicDL);
	STR(PublicFolder);
	STR(PublicStrings);
	STR(RadioPhone);
	STR(RecipientSuggestions);
	STR(RecurringMaster);
	STR(Required);
	STR(Resource);
	STR(Room);
	STR(Saturday);
	STR(SaveOnly);
	STR(Scheduled);
	STR(Scope);
	STR(Second);
	STR(SendAndSaveCopy);
	STR(SendOnly);
	STR(SendOnlyToAll);
	STR(SendToAllAndSaveCopy);
	STR(SendToNone);
	STR(September);
	STR(Shallow);
	STR(SharePointURLs);
	STR(Sharing); //=Caring
	STR(Short);
	STR(ShortArray);
	STR(Single);
	STR(SoftDelete);
	STR(SoftDeleted);
	STR(Store);
	STR(String);
	STR(StringArray);
	STR(Sunday);
	STR(SystemTime);
	STR(SystemTimeArray);
	STR(Task);
	STR(Telex);
	STR(Tentative);
	STR(Text);
	STR(Third);
	STR(Thursday);
	STR(TotalMemberCount);
	STR(TtyTddPhone);
	STR(Tuesday);
	STR(UnifiedMessaging);
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
	using BodyTypeType = StrEnum<HTML, Text>; ///< Types.xsd:1717
	using CalendarItemCreateOrDeleteOperationType = StrEnum<SendToNone, SendOnlyToAll, SendToAllAndSaveCopy>; ///<< Types.xsd:4005
	using CalendarItemTypeType = StrEnum<Single, Occurrence, Exception, RecurringMaster>; ///< Types.xsd:4363
	using ConnectionStatusType = StrEnum<OK, Closed>; ///< Types.xsd:6182
	using ContactSourceType = StrEnum<ActiveDirectory, Store>; ///< Types.xsd:5307
	using DayOfWeekType = StrEnum<Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Day, Weekday, Weekendday>; ///< Types.xsd:4481
	using DayOfWeekIndexType = StrEnum<First, Second, Third, Fourth, Last>; ///<Types.xsd:4500
	using DefaultShapeNamesType = StrEnum<IdOnly, Default, AllProperties, PcxPeopleSearch>; ///< Types.xsd:1255
	using DisposalType = StrEnum<HardDelete, SoftDelete, MoveToDeletedItems>; ///< Types.xsd:1321
	using DistinguishedFolderIdNameType = StrEnum<calendar, contacts, deleteditems, drafts, inbox, journal, notes, outbox, sentitems, tasks, msgfolderroot, publicfoldersroot, root, junkemail, searchfolders, voicemail, recoverableitemsroot, recoverableitemsdeletions, recoverableitemsversions, recoverableitemspurges, recoverableitemsdiscoveryholds, archiveroot, archivemsgfolderroot, archivedeleteditems, archiveinbox, archiverecoverableitemsroot, archiverecoverableitemsdeletions, archiverecoverableitemsversions, archiverecoverableitemspurges, archiverecoverableitemsdiscoveryholds, syncissues, conflicts, localfailures, serverfailures, recipientcache, quickcontacts, conversationhistory, adminauditlogs, todosearch, mycontacts, directory, imcontactlist, peopleconnect, favorites, mecontact, personmetadata, teamspaceactivity, teamspacemessaging, teamspaceworkitems, scheduled, orionnotes, tagitems, alltaggeditems, allcategorizeditems, externalcontacts, teamchat, teamchathistory, yammerdata, yammerroot, yammerinbound, yammeroutbound, yammerfeeds, kaizaladata, messageingestion, onedriveroot, onedriverecylebin, onedrivesystem, onedrivevolume, important, starred, archiv>; //Types.xsd:1768
	using DistinguishedPropertySetType = StrEnum<Meeting, Appointment, Common, PublicStrings, Address, InternetHeaders, CalendarAssistant, UnifiedMessaging, Task, Sharing>; ///< Types.xsd:1040
	using EmailAddressKeyType = StrEnum<EmailAddress1, EmailAddress2, EmailAddress3>; ///< Types.xsd:5205
	using ExternalAudience = StrEnum<None, Known, All>; ///< Types.xsd:6530
	using FlagStatusType = StrEnum<NotFlagged, Flagged, Complete>; ///< Types.xsd:2445
	using FolderQueryTraversalType = StrEnum<Shallow, Deep, SoftDeleted>; ///< Types.xsd:1212
	using FreeBusyViewType = StrEnum<None, MergedOnly, FreeBusy, FreeBusyMerged, Detailed, DetailedMerged>; ///< Types.xsd:6333
	using LegacyFreeBusyType = StrEnum<Free, Tentative, Busy, OOF, WorkingElsewhere, NoData>; ///< Types.xsd:4352
	using ImportanceChoicesType = StrEnum<Low, Normal, High>; ///< Types.xsd:1708
	using IndexBasePointType = StrEnum<Beginning, End>; ///< Types.xsd:4196
	using MailboxTypeType = StrEnum<Unknown, OneOff, Mailbox, PublicDL, PrivateDL, Contact, PublicFolder, GroupMailbox, ImplicitContact, User>; ///< Types.xsd:253
	using MailTipTypes = StrEnum<All, OutOfOfficeMessage, MailboxFullStatus, CustomMailTip, ExternalMemberCount, TotalMemberCount, MaxMessageSize, DeliveryRestriction, ModerationStatus, InvalidRecipient, Scope, RecipientSuggestions, PreferAccessibleContent>; ///< Types.xsd:6947
	using MapiPropertyTypeType = StrEnum<ApplicationTime, ApplicationTimeArray, Binary, BinaryArray, Boolean, CLSID, CLSIDArray, Currency, CurrencyArray, Double, DoubleArray, Error, Float, FloatArray, Integer, IntegerArray, Long, LongArray, Null, Object, ObjectArray, Short, ShortArray, SystemTime, SystemTimeArray, String, StringArray>; ///< Types.xsd:1060
	using MeetingAttendeeType = StrEnum<Organizer, Required, Optional, Room, Resource>; ///< Types.xsd:6278
	using MessageDispositionType = StrEnum<SaveOnly, SendOnly, SendAndSaveCopy>; ///< Types.xsd:3997
	using MonthNamesType = StrEnum<January, February, March, April, May, June, July, August, September, October, November, December>; ///< Types.xsd:4510
	using NotificationEventType = StrEnum<CopiedEvent, CreatedEvent, DeletedEvent, ModifiedEvent, MovedEvent, NewMailEvent, FreeBusyChangedEvent>; ///< Types.xsd:6085
	using PhoneNumberKeyType = StrEnum<AssistantPhone, BusinessFax, BusinessPhone, BusinessPhone2, Callback, CarPhone, CompanyMainPhone, HomeFax, HomePhone, HomePhone2, Isdn, MobilePhone, OtherFax, OtherTelephone, Pager, PrimaryPhone, RadioPhone, Telex, TtyTddPhone, BusinessMobile, IPPhone, Mms, Msn>; ///< Types.xsd:5237
	using ResolveNamesSearchScopeType = StrEnum<ActiveDirectory, ActiveDirectoryContacts, Contacts, ContactsActiveDirectory>; ///< Types.xsd:4255
	using ResponseTypeType = StrEnum<Unknown, Organizer, Tentative, Accept, Decline, NoResponseReceived>; ///< Types.xsd:4372
	using RestrictionRelop = StrEnum<IsLessThan, IsLessThanOrEqual, IsGreaterThan, IsGreaterThanOrEqual, IsEqualTo, IsNotEqualTo>; ///< Helper class, index maps directly to mapi_rtype
	using OofState = StrEnum<Disabled, Enabled, Scheduled>; ///< Types.xsd:6522
	using SensitivityChoicesType = StrEnum<Normal, Personal, Private, Confidential>; ///< Types.xsd:1698
	using ServiceConfigurationType = StrEnum<MailTips, UnifiedMessagingConfiguration, ProtectionRules, PolicyNudges, SharePointURLs, OfficeIntegrationConfiguration>; ///< Types.xsd:7019
	using SortDirectionType = StrEnum<Ascending, Descending>; ///< Types.xsd:5986, in sync with TABLE_SORT_(ASCEND|DESCEND)
	using SuggestionQuality = StrEnum<Excellent, Good, Fair, Poor>; ///< Types.xsd:6423
	using SyncFolderItemsScopeType = StrEnum<NormalItems, NormalAndAssociatedItems>; ///< Types.xsd:6256
};

}
