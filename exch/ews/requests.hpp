// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include "structures.hpp"
#include "ews.hpp"

namespace tinyxml2
{class XMLElement;}

namespace gromox::EWS::Requests
{

extern void process(gromox::EWS::Structures::mGetUserOofSettingsRequest &&, tinyxml2::XMLElement *, const gromox::EWS::EWSContext &);

}
