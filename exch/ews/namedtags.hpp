// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <gromox/mapidefs.h>

// Follow the order in mapitags.hpp
static const PROPERTY_NAME NtGlobalObjectId = {MNID_ID, PSETID_Meeting, PidLidGlobalObjectId};
static const PROPERTY_NAME NtCleanGlobalObjectId = {MNID_ID, PSETID_Meeting, PidLidCleanGlobalObjectId};
static const PROPERTY_NAME NtMeetingType = {MNID_ID, PSETID_Meeting, PidLidMeetingType};
static const PROPERTY_NAME NtCategories = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst("Keywords")};

/* PSETID_Address */
static const PROPERTY_NAME NtBusinessAddress = {MNID_ID, PSETID_Address, PidLidBusinessAddress};
static const PROPERTY_NAME NtBusinessAddressCity = {MNID_ID, PSETID_Address, PidLidWorkAddressCity};
static const PROPERTY_NAME NtBusinessAddressCountry = {MNID_ID, PSETID_Address, PidLidWorkAddressStreet};
static const PROPERTY_NAME NtBusinessAddressPostalCode = {MNID_ID, PSETID_Address, PidLidWorkAddressPostalCode};
static const PROPERTY_NAME NtBusinessAddressState = {MNID_ID, PSETID_Address, PidLidWorkAddressState};
static const PROPERTY_NAME NtBusinessAddressStreet = {MNID_ID, PSETID_Address, PidLidWorkAddressStreet};
static const PROPERTY_NAME NtEmailAddress1 = {MNID_ID, PSETID_Address, PidLidEmail1EmailAddress};
static const PROPERTY_NAME NtEmailAddress2 = {MNID_ID, PSETID_Address, PidLidEmail2EmailAddress};
static const PROPERTY_NAME NtEmailAddress3 = {MNID_ID, PSETID_Address, PidLidEmail3EmailAddress};
static const PROPERTY_NAME NtFileAs = {MNID_ID, PSETID_Address, PidLidFileAs};
static const PROPERTY_NAME NtHomeAddress = {MNID_ID, PSETID_Address, PidLidHomeAddress};
static const PROPERTY_NAME NtImAddress1 = {MNID_ID, PSETID_Address, PidLidInstantMessagingAddress};
static const PROPERTY_NAME NtMailingAddress = {MNID_ID, PSETID_Address, PidLidMailingAdress};
static const PROPERTY_NAME NtOtherAddress = {MNID_ID, PSETID_Address, PidLidOtherAddress};
static const PROPERTY_NAME NtPostalAddressIndex = {MNID_ID, PSETID_Address, PidLidPostalAddressIndex};

/* PSETID_Task */
static const PROPERTY_NAME NtTaskStatus = {MNID_ID, PSETID_Task, PidLidTaskStatus};
static const PROPERTY_NAME NtPercentComplete = {MNID_ID, PSETID_Task, PidLidPercentComplete};
static const PROPERTY_NAME NtTaskStartDate = {MNID_ID, PSETID_Task, PidLidTaskStartDate};
static const PROPERTY_NAME NtTaskDueDate = {MNID_ID, PSETID_Task, PidLidTaskDueDate};
static const PROPERTY_NAME NtTaskDateCompleted = {MNID_ID, PSETID_Task, PidLidTaskDateCompleted};
static const PROPERTY_NAME NtTaskActualEffort = {MNID_ID, PSETID_Task, PidLidTaskActualEffort};
static const PROPERTY_NAME NtTaskEstimatedEffort = {MNID_ID, PSETID_Task, PidLidTaskEstimatedEffort};
static const PROPERTY_NAME NtTaskRecurrence = {MNID_ID, PSETID_Task, PidLidTaskRecurrence};
static const PROPERTY_NAME NtTaskComplete = {MNID_ID, PSETID_Task, PidLidTaskComplete};
static const PROPERTY_NAME NtTaskOwner = {MNID_ID, PSETID_Task, PidLidTaskOwner};
static const PROPERTY_NAME NtTaskFRecurring = {MNID_ID, PSETID_Task, PidLidTaskFRecurring};

/* PSETID_Appointment */
static const PROPERTY_NAME NtAppointmentSequence = {MNID_ID, PSETID_Appointment, PidLidAppointmentSequence};
static const PROPERTY_NAME NtBusyStatus = {MNID_ID, PSETID_Appointment, PidLidBusyStatus};
static const PROPERTY_NAME NtLocation = {MNID_ID, PSETID_Appointment, PidLidLocation};
static const PROPERTY_NAME NtAppointmentReplyTime = {MNID_ID, PSETID_Appointment, PidLidAppointmentReplyTime};
static const PROPERTY_NAME NtAppointmentStartWhole = {MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole};
static const PROPERTY_NAME NtAppointmentEndWhole = {MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole};
static const PROPERTY_NAME NtAppointmentSubType = {MNID_ID, PSETID_Appointment, PidLidAppointmentSubType};
static const PROPERTY_NAME NtAppointmentRecur = {MNID_ID, PSETID_Appointment, PidLidAppointmentRecur};
static const PROPERTY_NAME NtAppointmentStateFlags = {MNID_ID, PSETID_Appointment, PidLidAppointmentStateFlags};
static const PROPERTY_NAME NtResponseStatus = {MNID_ID, PSETID_Appointment, PidLidResponseStatus};
static const PROPERTY_NAME NtRecurring = {MNID_ID, PSETID_Appointment, PidLidRecurring};
static const PROPERTY_NAME NtExceptionReplaceTime = {MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime};
static const PROPERTY_NAME NtFInvited = {MNID_ID, PSETID_Appointment, PidLidFInvited};
static const PROPERTY_NAME NtRecurrenceType = {MNID_ID, PSETID_Appointment, PidLidRecurrenceType};
static const PROPERTY_NAME NtClipStart = {MNID_ID, PSETID_Appointment, PidLidClipStart};
static const PROPERTY_NAME NtClipEnd = {MNID_ID, PSETID_Appointment, PidLidClipEnd};
static const PROPERTY_NAME NtAppointmentNotAllowPropose = {MNID_ID, PSETID_Appointment, PidLidAppointmentNotAllowPropose};
static const PROPERTY_NAME NtAppointmentTimeZoneDefinitionStartDisplay = {MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionStartDisplay};
static const PROPERTY_NAME NtAppointmentTimeZoneDefinitionEndDisplay = {MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionEndDisplay};

/* PSETID_Common */
static const PROPERTY_NAME NtReminderDelta = {MNID_ID, PSETID_Common, PidLidReminderDelta};
static const PROPERTY_NAME NtReminderTime = {MNID_ID, PSETID_Common, PidLidReminderTime};
static const PROPERTY_NAME NtReminderSet = {MNID_ID, PSETID_Common, PidLidReminderSet};
static const PROPERTY_NAME NtPrivate = {MNID_ID, PSETID_Common, PidLidPrivate};
static const PROPERTY_NAME NtCommonStart = {MNID_ID, PSETID_Common, PidLidCommonStart};
static const PROPERTY_NAME NtCommonEnd = {MNID_ID, PSETID_Common, PidLidCommonEnd};
static const PROPERTY_NAME NtMileage = {MNID_ID, PSETID_Common, PidLidMileage};
static const PROPERTY_NAME NtBilling = {MNID_ID, PSETID_Common, PidLidBilling};
static const PROPERTY_NAME NtCompanies = {MNID_ID, PSETID_Common, PidLidCompanies};
static const PROPERTY_NAME NtReminderSignalTime = {MNID_ID, PSETID_Common, PidLidReminderSignalTime};
static const PROPERTY_NAME NtCalendarTimeZone = {MNID_STRING, EWS_Mac_PropertySetId, 0, deconst("CalendarTimeZone")};
