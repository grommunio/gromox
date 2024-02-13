// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <gromox/mapidefs.h>

// Follow the order in mapitags.hpp
static const PROPERTY_NAME NtGlobalObjectId = {MNID_ID, PSETID_MEETING, PidLidGlobalObjectId, deconst("GlobalObjectId")};
static const PROPERTY_NAME NtCategories = {MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst("Keywords")};

/* PSETID_Address */
static const PROPERTY_NAME NtBusinessAddress = {MNID_ID, PSETID_ADDRESS, PidLidBusinessAddress, nullptr};
static const PROPERTY_NAME NtBusinessAddressCity = {MNID_ID, PSETID_ADDRESS, PidLidWorkAddressCity, nullptr};
static const PROPERTY_NAME NtBusinessAddressCountry = {MNID_ID, PSETID_ADDRESS, PidLidWorkAddressStreet, nullptr};
static const PROPERTY_NAME NtBusinessAddressPostalCode = {MNID_ID, PSETID_ADDRESS, PidLidWorkAddressPostalCode, nullptr};
static const PROPERTY_NAME NtBusinessAddressState = {MNID_ID, PSETID_ADDRESS, PidLidWorkAddressState, nullptr};
static const PROPERTY_NAME NtBusinessAddressStreet = {MNID_ID, PSETID_ADDRESS, PidLidWorkAddressStreet, nullptr};
static const PROPERTY_NAME NtEmailAddress1 = {MNID_ID, PSETID_ADDRESS, PidLidEmail1EmailAddress, nullptr};
static const PROPERTY_NAME NtEmailAddress2 = {MNID_ID, PSETID_ADDRESS, PidLidEmail2EmailAddress, nullptr};
static const PROPERTY_NAME NtEmailAddress3 = {MNID_ID, PSETID_ADDRESS, PidLidEmail3EmailAddress, nullptr};
static const PROPERTY_NAME NtFileAs = {MNID_ID, PSETID_ADDRESS, PidLidFileAs, nullptr};
static const PROPERTY_NAME NtHomeAddress = {MNID_ID, PSETID_ADDRESS, PidLidHomeAddress, nullptr};
static const PROPERTY_NAME NtImAddress1 = {MNID_ID, PSETID_ADDRESS, PidLidInstantMessagingAddress, nullptr};
static const PROPERTY_NAME NtMailingAddress = {MNID_ID, PSETID_ADDRESS, PidLidMailingAdress, nullptr};
static const PROPERTY_NAME NtOtherAddress = {MNID_ID, PSETID_ADDRESS, PidLidOtherAddress, nullptr};
static const PROPERTY_NAME NtPostalAddressIndex = {MNID_ID, PSETID_ADDRESS, PidLidPostalAddressIndex, nullptr};

/* PSETID_Task */
static const PROPERTY_NAME NtTaskStatus = {MNID_ID, PSETID_TASK, PidLidTaskStatus, nullptr};
static const PROPERTY_NAME NtPercentComplete = {MNID_ID, PSETID_TASK, PidLidPercentComplete, nullptr};
static const PROPERTY_NAME NtTaskStartDate = {MNID_ID, PSETID_TASK, PidLidTaskStartDate, nullptr};
static const PROPERTY_NAME NtTaskDueDate = {MNID_ID, PSETID_TASK, PidLidTaskDueDate, nullptr};
static const PROPERTY_NAME NtTaskDateCompleted = {MNID_ID, PSETID_TASK, PidLidTaskDateCompleted, nullptr};
static const PROPERTY_NAME NtTaskActualEffort = {MNID_ID, PSETID_TASK, PidLidTaskActualEffort, nullptr};
static const PROPERTY_NAME NtTaskEstimatedEffort = {MNID_ID, PSETID_TASK, PidLidTaskEstimatedEffort, nullptr};
static const PROPERTY_NAME NtTaskRecurrence = {MNID_ID, PSETID_TASK, PidLidTaskRecurrence, nullptr};
static const PROPERTY_NAME NtTaskComplete = {MNID_ID, PSETID_TASK, PidLidTaskComplete, nullptr};
static const PROPERTY_NAME NtTaskOwner = {MNID_ID, PSETID_TASK, PidLidTaskOwner, nullptr};
static const PROPERTY_NAME NtTaskFRecurring = {MNID_ID, PSETID_TASK, PidLidTaskFRecurring, nullptr};

/* PSETID_Appointment */
static const PROPERTY_NAME NtAppointmentSequence = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSequence, deconst("AppointmentSequence")};
static const PROPERTY_NAME NtBusyStatus = {MNID_ID, PSETID_APPOINTMENT, PidLidBusyStatus, deconst("BusyStatus")};
static const PROPERTY_NAME NtLocation = {MNID_ID, PSETID_APPOINTMENT, PidLidLocation, deconst("Location")};
static const PROPERTY_NAME NtAppointmentReplyTime = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentReplyTime, deconst("AppointmentReplyTime")};
static const PROPERTY_NAME NtAppointmentStartWhole = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentStartWhole, nullptr};
static const PROPERTY_NAME NtAppointmentEndWhole = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentEndWhole, nullptr};
static const PROPERTY_NAME NtAppointmentSubType = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSubType, deconst("AppointmentSubType")};
static const PROPERTY_NAME NtAppointmentRecur = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentRecur, deconst("AppointmentRecur")};
static const PROPERTY_NAME NtAppointmentStateFlags = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentStateFlags, deconst("AppointmentStateFlags")};
static const PROPERTY_NAME NtExceptionReplaceTime = {MNID_ID, PSETID_APPOINTMENT, PidLidExceptionReplaceTime, deconst("ExceptionReplaceTime")};
static const PROPERTY_NAME NtFInvited = {MNID_ID, PSETID_APPOINTMENT, PidLidFInvited, deconst("FInvited")};
static const PROPERTY_NAME NtResponseStatus = {MNID_ID, PSETID_APPOINTMENT, PidLidResponseStatus, deconst("ResponseStatus")};
static const PROPERTY_NAME NtRecurring = {MNID_ID, PSETID_APPOINTMENT, PidLidRecurring, deconst("Recurring")};
static const PROPERTY_NAME NtAppointmentNotAllowPropose = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentNotAllowPropose, deconst("AppointmentNotAllowPropose")};

/* PSETID_Common */
static const PROPERTY_NAME NtReminderDelta = {MNID_ID, PSETID_COMMON, PidLidReminderDelta, nullptr};
static const PROPERTY_NAME NtReminderTime = {MNID_ID, PSETID_COMMON, PidLidReminderTime, nullptr};
static const PROPERTY_NAME NtReminderSet = {MNID_ID, PSETID_COMMON, PidLidReminderSet, nullptr};
static const PROPERTY_NAME NtCommonStart = {MNID_ID, PSETID_COMMON, PidLidCommonStart, deconst("CommonStart")};
static const PROPERTY_NAME NtCommonEnd = {MNID_ID, PSETID_COMMON, PidLidCommonEnd, deconst("CommonEnd")};
static const PROPERTY_NAME NtMileage = {MNID_ID, PSETID_COMMON, PidLidMileage, nullptr};
static const PROPERTY_NAME NtBilling = {MNID_ID, PSETID_COMMON, PidLidBilling, nullptr};
static const PROPERTY_NAME NtCompanies = {MNID_ID, PSETID_COMMON, PidLidCompanies, nullptr};
