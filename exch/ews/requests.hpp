// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include "structures.hpp"
#include "ews.hpp"

namespace tinyxml2 {
class XMLElement;
}

namespace gromox::EWS::Requests {

#define EWSFUNC(in) void process(gromox::EWS::Structures::in&&, tinyxml2::XMLElement*, const gromox::EWS::EWSContext&)
#define EWSFUNC_NC(in) void process(gromox::EWS::Structures::in&&, tinyxml2::XMLElement*, gromox::EWS::EWSContext&)

EWSFUNC_NC(mConvertIdRequest);
EWSFUNC(mCreateAttachmentRequest);
EWSFUNC(mCreateFolderRequest);
EWSFUNC(mCreateItemRequest);
EWSFUNC(mDeleteFolderRequest);
EWSFUNC(mDeleteItemRequest);
EWSFUNC(mEmptyFolderRequest);
EWSFUNC(mFindFolderRequest);
EWSFUNC(mFindItemRequest);
EWSFUNC(mGetAppManifestsRequest);
EWSFUNC(mGetAttachmentRequest);
EWSFUNC(mGetDelegateRequest);
EWSFUNC(mGetEventsRequest);
EWSFUNC(mGetFolderRequest);
EWSFUNC(mGetInboxRulesRequest);
EWSFUNC(mGetItemRequest);
EWSFUNC(mGetMailTipsRequest);
EWSFUNC(mGetServiceConfigurationRequest);
EWSFUNC_NC(mGetStreamingEventsRequest);
EWSFUNC(mGetUserAvailabilityRequest);
EWSFUNC(mGetUserConfigurationRequest);
EWSFUNC(mGetUserOofSettingsRequest);
EWSFUNC_NC(mGetUserPhotoRequest);
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
