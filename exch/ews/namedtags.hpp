// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <gromox/mapidefs.h>

static const PROPERTY_NAME NtCategories = {MNID_STRING, PS_PUBLIC_STRINGS, 0, const_cast<char*>("Keywords")};

// Follow the order in mapitags.hpp
static const PROPERTY_NAME NtGlobalObjectId = {MNID_ID, PSETID_MEETING, PidLidGlobalObjectId};

/* PSETID_Address */
static const PROPERTY_NAME NtImAddress1 = {MNID_ID, PSETID_ADDRESS, PidLidInstantMessagingAddress};
static const PROPERTY_NAME NtEmailAddress1 = {MNID_ID, PSETID_ADDRESS, PidLidEmail1EmailAddress};
static const PROPERTY_NAME NtEmailAddress2 = {MNID_ID, PSETID_ADDRESS, PidLidEmail2EmailAddress};
static const PROPERTY_NAME NtEmailAddress3 = {MNID_ID, PSETID_ADDRESS, PidLidEmail3EmailAddress};

/* PSETID_Task */
static const PROPERTY_NAME NtTaskStatus = {MNID_ID, PSETID_TASK, PidLidTaskStatus};
static const PROPERTY_NAME NtPercentComplete = {MNID_ID, PSETID_TASK, PidLidPercentComplete};
static const PROPERTY_NAME NtTaskStartDate = {MNID_ID, PSETID_TASK, PidLidTaskStartDate};
static const PROPERTY_NAME NtTaskDueDate = {MNID_ID, PSETID_TASK, PidLidTaskDueDate};
static const PROPERTY_NAME NtTaskDateCompleted = {MNID_ID, PSETID_TASK, PidLidTaskDateCompleted};
static const PROPERTY_NAME NtTaskActualEffort = {MNID_ID, PSETID_TASK, PidLidTaskActualEffort};
static const PROPERTY_NAME NtTaskEstimatedEffort = {MNID_ID, PSETID_TASK, PidLidTaskEstimatedEffort};
static const PROPERTY_NAME NtTaskComplete = {MNID_ID, PSETID_TASK, PidLidTaskComplete};
static const PROPERTY_NAME NtTaskOwner = {MNID_ID, PSETID_TASK, PidLidTaskOwner};
static const PROPERTY_NAME NtTaskFRecurring = {MNID_ID, PSETID_TASK, PidLidTaskFRecurring};

/* PSETID_Appointment */
static const PROPERTY_NAME NtAppointmentSequence = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSequence};
static const PROPERTY_NAME NtBusyStatus = {MNID_ID, PSETID_APPOINTMENT, PidLidBusyStatus};
static const PROPERTY_NAME NtLocation = {MNID_ID, PSETID_APPOINTMENT, PidLidLocation};
static const PROPERTY_NAME NtAppointmentReplyTime = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentReplyTime};
static const PROPERTY_NAME NtAppointmentSubType = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSubType};
static const PROPERTY_NAME NtAppointmentRecur = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentRecur};
static const PROPERTY_NAME NtAppointmentStateFlags = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentStateFlags};
static const PROPERTY_NAME NtExceptionReplaceTime = {MNID_ID, PSETID_APPOINTMENT, PidLidExceptionReplaceTime};
static const PROPERTY_NAME NtFInvited = {MNID_ID, PSETID_APPOINTMENT, PidLidFInvited};
static const PROPERTY_NAME NtResponseStatus = {MNID_ID, PSETID_APPOINTMENT, PidLidResponseStatus};
static const PROPERTY_NAME NtAppointmentNotAllowPropose = {MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentNotAllowPropose};

/* PSETID_Common */
static const PROPERTY_NAME NtReminderDelta = {MNID_ID, PSETID_COMMON, PidLidReminderDelta};
static const PROPERTY_NAME NtReminderTime = {MNID_ID, PSETID_COMMON, PidLidReminderTime};
static const PROPERTY_NAME NtReminderSet = {MNID_ID, PSETID_COMMON, PidLidReminderSet};
static const PROPERTY_NAME NtCommonStart = {MNID_ID, PSETID_COMMON, PidLidCommonStart};
static const PROPERTY_NAME NtCommonEnd = {MNID_ID, PSETID_COMMON, PidLidCommonEnd};
static const PROPERTY_NAME NtMileage = {MNID_ID, PSETID_COMMON, PidLidMileage};
static const PROPERTY_NAME NtBilling = {MNID_ID, PSETID_COMMON, PidLidBilling};
static const PROPERTY_NAME NtCompanies = {MNID_ID, PSETID_COMMON, PidLidCompanies};
