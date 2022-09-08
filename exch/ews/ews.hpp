// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <functional>
#include <optional>

#include <gromox/hpm_common.h>
#include <gromox/mysql_adaptor.hpp>

#include "soaputil.hpp"

namespace gromox::EWS {

namespace Structures
{
struct tMailbox;
}


struct EWSContext;

/**
 * @brief      Aggregation of plugin data and functions
 */
class EWSPlugin
{
public:
	using Handler = std::function<void(const tinyxml2::XMLElement*, tinyxml2::XMLElement*, const EWSContext&)>;

	EWSPlugin();

	BOOL proc(int, const void*, uint64_t);

	static BOOL preproc(int);

	struct _mysql {
		_mysql();

		decltype(mysql_adaptor_get_maildir)* get_maildir;
		decltype(mysql_adaptor_get_username_from_id)* get_username_from_id;
	} mysql; ///< mysql adaptor function pointers

	std::string x500_org_name; ///< organization name or empty string if not configured
private:
	static const std::unordered_map<std::string, Handler> requestMap;

	static void writeheader(int, int, size_t);

	std::pair<std::string, int> dispatch(int, HTTP_AUTH_INFO&, const void*, uint64_t);
	void loadConfig();
};

/**
 * @brief      EWS request context
 */
struct EWSContext
{
	inline EWSContext(int ID, HTTP_AUTH_INFO auth_info, const char* data, uint64_t length, EWSPlugin& plugin) :
		ID(ID), orig(*get_request(ID)), auth_info(auth_info), request(data, length), plugin(plugin)
	{}

	std::string essdn_to_username(const std::string&) const;
	std::string get_maildir(const Structures::tMailbox&) const;
	void normalize(Structures::tMailbox&) const;

	int ID = 0;
	HTTP_REQUEST& orig;
	HTTP_AUTH_INFO auth_info{};
	SOAP::Envelope request;
	SOAP::Envelope response;
	EWSPlugin& plugin;
};

}
