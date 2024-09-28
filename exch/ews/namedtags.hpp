// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <gromox/mapidefs.h>

// Follow the order in mapitags.hpp
static const PROPERTY_NAME NtGlobalObjectId = {MNID_ID, PSETID_Meeting, PidLidGlobalObjectId, deconst("GlobalObjectId")};
static const PROPERTY_NAME NtCategories = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst("Keywords")};

/* PSETID_Address */
static const PROPERTY_NAME NtBusinessAddress = {MNID_ID, PSETID_Address, PidLidBusinessAddress, nullptr};
static const PROPERTY_NAME NtBusinessAddressCity = {MNID_ID, PSETID_Address, PidLidWorkAddressCity, nullptr};
static const PROPERTY_NAME NtBusinessAddressCountry = {MNID_ID, PSETID_Address, PidLidWorkAddressStreet, nullptr};
static const PROPERTY_NAME NtBusinessAddressPostalCode = {MNID_ID, PSETID_Address, PidLidWorkAddressPostalCode, nullptr};
static const PROPERTY_NAME NtBusinessAddressState = {MNID_ID, PSETID_Address, PidLidWorkAddressState, nullptr};
static const PROPERTY_NAME NtBusinessAddressStreet = {MNID_ID, PSETID_Address, PidLidWorkAddressStreet, nullptr};
static const PROPERTY_NAME NtEmailAddress1 = {MNID_ID, PSETID_Address, PidLidEmail1EmailAddress, nullptr};
static const PROPERTY_NAME NtEmailAddress2 = {MNID_ID, PSETID_Address, PidLidEmail2EmailAddress, nullptr};
static const PROPERTY_NAME NtEmailAddress3 = {MNID_ID, PSETID_Address, PidLidEmail3EmailAddress, nullptr};
static const PROPERTY_NAME NtFileAs = {MNID_ID, PSETID_Address, PidLidFileAs, nullptr};
static const PROPERTY_NAME NtHomeAddress = {MNID_ID, PSETID_Address, PidLidHomeAddress, nullptr};
static const PROPERTY_NAME NtImAddress1 = {MNID_ID, PSETID_Address, PidLidInstantMessagingAddress, nullptr};
static const PROPERTY_NAME NtMailingAddress = {MNID_ID, PSETID_Address, PidLidMailingAdress, nullptr};
static const PROPERTY_NAME NtOtherAddress = {MNID_ID, PSETID_Address, PidLidOtherAddress, nullptr};
static const PROPERTY_NAME NtPostalAddressIndex = {MNID_ID, PSETID_Address, PidLidPostalAddressIndex, nullptr};

/* PSETID_Task */
static const PROPERTY_NAME NtTaskStatus = {MNID_ID, PSETID_Task, PidLidTaskStatus, nullptr};
static const PROPERTY_NAME NtPercentComplete = {MNID_ID, PSETID_Task, PidLidPercentComplete, nullptr};
static const PROPERTY_NAME NtTaskStartDate = {MNID_ID, PSETID_Task, PidLidTaskStartDate, nullptr};
static const PROPERTY_NAME NtTaskDueDate = {MNID_ID, PSETID_Task, PidLidTaskDueDate, nullptr};
static const PROPERTY_NAME NtTaskDateCompleted = {MNID_ID, PSETID_Task, PidLidTaskDateCompleted, nullptr};
static const PROPERTY_NAME NtTaskActualEffort = {MNID_ID, PSETID_Task, PidLidTaskActualEffort, nullptr};
static const PROPERTY_NAME NtTaskEstimatedEffort = {MNID_ID, PSETID_Task, PidLidTaskEstimatedEffort, nullptr};
static const PROPERTY_NAME NtTaskRecurrence = {MNID_ID, PSETID_Task, PidLidTaskRecurrence, nullptr};
static const PROPERTY_NAME NtTaskComplete = {MNID_ID, PSETID_Task, PidLidTaskComplete, nullptr};
static const PROPERTY_NAME NtTaskOwner = {MNID_ID, PSETID_Task, PidLidTaskOwner, nullptr};
static const PROPERTY_NAME NtTaskFRecurring = {MNID_ID, PSETID_Task, PidLidTaskFRecurring, nullptr};

/* PSETID_Appointment */
static const PROPERTY_NAME NtAppointmentSequence = {MNID_ID, PSETID_Appointment, PidLidAppointmentSequence, deconst("AppointmentSequence")};
static const PROPERTY_NAME NtBusyStatus = {MNID_ID, PSETID_Appointment, PidLidBusyStatus, deconst("BusyStatus")};
static const PROPERTY_NAME NtLocation = {MNID_ID, PSETID_Appointment, PidLidLocation, deconst("Location")};
static const PROPERTY_NAME NtAppointmentReplyTime = {MNID_ID, PSETID_Appointment, PidLidAppointmentReplyTime, deconst("AppointmentReplyTime")};
static const PROPERTY_NAME NtAppointmentStartWhole = {MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole, deconst("AppointmentStartWhole")};
static const PROPERTY_NAME NtAppointmentEndWhole = {MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole, deconst("AppointmentEndWhole")};
static const PROPERTY_NAME NtAppointmentSubType = {MNID_ID, PSETID_Appointment, PidLidAppointmentSubType, deconst("AppointmentSubType")};
static const PROPERTY_NAME NtAppointmentRecur = {MNID_ID, PSETID_Appointment, PidLidAppointmentRecur, deconst("AppointmentRecur")};
static const PROPERTY_NAME NtAppointmentStateFlags = {MNID_ID, PSETID_Appointment, PidLidAppointmentStateFlags, deconst("AppointmentStateFlags")};
static const PROPERTY_NAME NtResponseStatus = {MNID_ID, PSETID_Appointment, PidLidResponseStatus, deconst("ResponseStatus")};
static const PROPERTY_NAME NtRecurring = {MNID_ID, PSETID_Appointment, PidLidRecurring, deconst("Recurring")};
static const PROPERTY_NAME NtExceptionReplaceTime = {MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime, deconst("ExceptionReplaceTime")};
static const PROPERTY_NAME NtFInvited = {MNID_ID, PSETID_Appointment, PidLidFInvited, deconst("FInvited")};
static const PROPERTY_NAME NtRecurrenceType = {MNID_ID, PSETID_Appointment, PidLidRecurrenceType, deconst("RecurrenceType")};
static const PROPERTY_NAME NtClipStart = {MNID_ID, PSETID_Appointment, PidLidClipStart, deconst("ClipStart")};
static const PROPERTY_NAME NtClipEnd = {MNID_ID, PSETID_Appointment, PidLidClipEnd, deconst("ClipEnd")};
static const PROPERTY_NAME NtAppointmentNotAllowPropose = {MNID_ID, PSETID_Appointment, PidLidAppointmentNotAllowPropose, deconst("AppointmentNotAllowPropose")};

/* PSETID_Common */
static const PROPERTY_NAME NtReminderDelta = {MNID_ID, PSETID_Common, PidLidReminderDelta, nullptr};
static const PROPERTY_NAME NtReminderTime = {MNID_ID, PSETID_Common, PidLidReminderTime, nullptr};
static const PROPERTY_NAME NtReminderSet = {MNID_ID, PSETID_Common, PidLidReminderSet, nullptr};
static const PROPERTY_NAME NtCommonStart = {MNID_ID, PSETID_Common, PidLidCommonStart, deconst("CommonStart")};
static const PROPERTY_NAME NtCommonEnd = {MNID_ID, PSETID_Common, PidLidCommonEnd, deconst("CommonEnd")};
static const PROPERTY_NAME NtMileage = {MNID_ID, PSETID_Common, PidLidMileage, nullptr};
static const PROPERTY_NAME NtBilling = {MNID_ID, PSETID_Common, PidLidBilling, nullptr};
static const PROPERTY_NAME NtCompanies = {MNID_ID, PSETID_Common, PidLidCompanies, nullptr};
