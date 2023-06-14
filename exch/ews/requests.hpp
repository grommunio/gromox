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

EWSFUNC(mGetAttachmentRequest);
EWSFUNC(mGetFolderRequest);
EWSFUNC(mGetItemRequest);
EWSFUNC(mGetMailTipsRequest);
EWSFUNC(mGetMailTipsRequest);
EWSFUNC(mGetServiceConfigurationRequest);
EWSFUNC(mGetUserAvailabilityRequest);
EWSFUNC(mGetUserOofSettingsRequest);
EWSFUNC(mResolveNamesRequest);
EWSFUNC(mSetUserOofSettingsRequest);
EWSFUNC(mSyncFolderHierarchyRequest);
EWSFUNC(mSyncFolderItemsRequest);
EWSFUNC(mUpdateItemRequest);

#undef EWSFUNC

}
