// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <stdexcept>

namespace gromox::EWS::Exceptions {

/**
 * @brief      Base class for EWS request errors
 */
class InputError : public std::runtime_error
{using std::runtime_error::runtime_error;};

/**
 * @brief      Deserialization of request data failed
 */
class DeserializationError : public InputError
{using InputError::InputError;};

/**
 * @brief      SOAP protocol error
 */
class SOAPError : public InputError
{using InputError::InputError;};

/**
 * @brief      Unknown request (no handler defined)
 */
class UnknownRequestError : public std::runtime_error
{using std::runtime_error::runtime_error;};

/**
 * @brief      Generic error during request processing
 */
class DispatchError : public std::runtime_error
{using std::runtime_error::runtime_error;};

/**
 * @brief      Generic error to signal missing functionality
 *
 * Provides an easily searchable marker.
 */
class NotImplementedError : public std::runtime_error
{using std::runtime_error::runtime_error;};

///////////////////////////////////////////////////////////////////////////////
//Error codes

#define E(num, content) constexpr char E##num[] = "E-" #num ": " content

E(3000, "failed to resolve essdn - invalid essdn");
E(3001, "failed to resolve essdn - malformed essdn");
E(3002, "failed to resolve essdn - user not found");
E(3003, "Failed to resolve essdn - invalid user");
E(3004, "Failed to resolve essdn - username mismatch");
E(3005, "Failed to get user maildir");
inline std::string E3006(const std::string& RoutingType) {return "E-2011: unrecognized RoutingType '"+RoutingType+"'";}
E(3007, "Failed to get user maildir");

#undef E
}
