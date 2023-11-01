// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include "structures.hpp"
#include "ews.hpp"

namespace tinyxml2
{class XMLElement;}

namespace gromox::EWS::Requests
{

#define EWSFUNC(in) void process(gromox::EWS::Structures::in&&, tinyxml2::XMLElement*, const gromox::EWS::EWSContext&)

EWSFUNC(mCreateFolderRequest);
EWSFUNC(mCreateItemRequest);
EWSFUNC(mDeleteFolderRequest);
EWSFUNC(mDeleteItemRequest);
EWSFUNC(mEmptyFolderRequest);
EWSFUNC(mGetAttachmentRequest);
EWSFUNC(mGetEventsRequest);
EWSFUNC(mGetFolderRequest);
EWSFUNC(mGetItemRequest);
EWSFUNC(mGetMailTipsRequest);
EWSFUNC(mGetMailTipsRequest);
EWSFUNC(mGetServiceConfigurationRequest);
void process(gromox::EWS::Structures::mGetStreamingEventsRequest&&, tinyxml2::XMLElement*, gromox::EWS::EWSContext&);
EWSFUNC(mGetUserAvailabilityRequest);
EWSFUNC(mGetUserOofSettingsRequest);
void process(const Structures::mBaseMoveCopyFolder&, tinyxml2::XMLElement*, const gromox::EWS::EWSContext&);
void process(const Structures::mBaseMoveCopyItem&, tinyxml2::XMLElement*, const gromox::EWS::EWSContext&);
EWSFUNC(mResolveNamesRequest);
EWSFUNC(mSendItemRequest);
EWSFUNC(mSetUserOofSettingsRequest);
EWSFUNC(mSubscribeRequest);
EWSFUNC(mSyncFolderHierarchyRequest);
EWSFUNC(mSyncFolderItemsRequest);
EWSFUNC(mUnsubscribeRequest);
EWSFUNC(mUpdateFolderRequest);
EWSFUNC(mUpdateItemRequest);

#undef EWSFUNC

}
