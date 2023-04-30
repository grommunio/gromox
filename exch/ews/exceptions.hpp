// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <fmt/format.h>
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
 * @brief     Caller has insufficient permissions
 */
class AccessDenied : public InputError
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

/**
 * @brief      An invalid value was assigned to an StrEnum
 */
class EnumError : public std::runtime_error
{using std::runtime_error::runtime_error;};

///////////////////////////////////////////////////////////////////////////////
//Error codes

#define E(num, content) constexpr char E##num[] = "E-" #num ": " content

E(3000, "failed to resolve essdn - invalid essdn");
E(3001, "failed to resolve essdn - malformed essdn");
E(3002, "failed to resolve essdn - user not found");
E(3003, "failed to resolve essdn - invalid user");
E(3004, "failed to resolve essdn - username mismatch");
E(3005, "failed to get user maildir");
inline std::string E3006(const std::string& RoutingType) {return "E-3006: unrecognized RoutingType '"+RoutingType+"'";}
E(3007, "failed to get user maildir");
inline std::string E3008(const std::string& OofState) {return "E-3008: unrecognized OofState '"+OofState+"'";}
inline std::string E3009(const std::string& ExAud) {return "E-3009: unrecognized ExternalAudience '"+ExAud+"'";}
inline std::string E3010(const std::string& RoutingType) {return "E-3010: unrecognized RoutingType '"+RoutingType+"'";}
E(3011, "cannot access OOF state of another user");
E(3012, "cannot modify OOF state of another user");
E(3013, "either \"FreeBusyViewOptions\" or \"SuggestionsViewOptions\" is required.");
E(3014, "\"TimeZone\" is required.");
E(3015, "failed to get named propids");
E(3016, "failed to get some named propids");
E(3017, "failed to get user permissions");
E(3018, "insufficient access rights");
E(3019, "failed to load calendar");
E(3020, "failed to query calendar");
E(3021, "request is marked experimental and can be enabled with 'ews_experimental = 1'");
E(3022, "failed to get folder entry id");
E(3023, "failed to get folder properties");
E(3024, "failed to get item entry id");
E(3025, "failed to get item properties");
E(3026, "failed to get username from id");
E(3027, "failed to get domain info from id");
inline std::string E3028(int code) {return fmt::format("E-3028: buffer error ({})", code);}
E(3029, "too many tags requested");
E(3030, "failed to get hierarchy sync data");
E(3031, "failed to get content sync data");
E(3032, "too many tags requested");
E(3033, "invalid base64 string");
inline std::string E3034(const std::string_view& name) {return fmt::format("E-3034: element '{}' is empty", name);}
E(3035, "out of memory");
E(3036, "failed to generate sync state given idset data");
E(3037, "failed to generate sync state seen cnset data");
E(3038, "failed to generate sync state seen fai cnset data");
E(3039, "failed to generate sync state read cnset data");
E(3040, "failed to generate sync state");
inline std::string E3041(const std::string_view& name) {return fmt::format("E-3041: element '{}' is empty", name);}
inline std::string E3042(const std::string_view& name, const std::string_view& content) {return fmt::format("E-3042: element '{}={}' has bad format (expected hh:mm:ss)", name, content);}
inline std::string E3043(const std::string_view& name) {return fmt::format("E-3043: element '{}' is empty", name);}
inline std::string E3044(const std::string_view& name, const std::string_view& content, const std::string_view& type) {return fmt::format("E-3044: failed to convert element '{}={}' to {}", name, content, type);}
inline std::string E3045(const std::string_view& name) {return fmt::format("E-3045: failed to find proper type for node '{}'", name);}
inline std::string E3046(const std::string_view& name, const std::string_view& parent) {return fmt::format("E-3046: missing required child element  '{}' in element '{}'", name, parent);}
inline std::string E3047(const std::string_view& name, const std::string_view& parent) {return fmt::format("E-3047: missing required attribute '{}' in element '{}'", name, parent);}
inline std::string E3048(const std::string_view& name, const std::string_view& parent, const std::string_view& content, const std::string_view& type) {return fmt::format("E-3048: failed to convert attribute '{}={}' in '{}' to {}", name, content, parent, type);}
E(3049, "can only convert binary properties to Base64Binary");
E(3050, "folder entry ID data to large");
inline std::string E3051(const std::string_view& name) {return fmt::format("E-3051: unknown distinguished folder id '{}'", name);}
E(3052, "sync state too big");
E(3053, "failed to deserialize given idset");
E(3054, "failed to deserialize seen cnset");
E(3055, "failed to deserialize read cnset");
E(3056, "failed to deserialize seen fai cnset");
E(3057, "failed to generated sync state idset");
E(3058, "failed to generate sync state cnset");
inline std::string E3059(const std::string_view& type) {return fmt::format("E-3059: unknown tag type '{}'", type);}
E(3060, "invalid ExtendedFieldURI: missing name or ID");
E(3061, "invalid ExtendedFieldURI: missing tag or set ID");
E(3062, "failed to convert given id set");
E(3063, "invalid GUID format");
E(3064, "failed to convert sync state");
E(3065, "failed to add changed mid");
E(3066, "failed to set synced change numbers");
E(3067, "failed to get user properties");
E(3068, "failed to get user aliases");
E(3069, "failed to get named property ids");
E(3070, "failed to get named property names");
E(3071, "failed to read message");
E(3072, "failed to export message");
E(3073, "mail export error");
E(3074, "failed to serialize message");

#undef E
}
