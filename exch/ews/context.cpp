// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2022 grommunio GmbH
// This file is part of Gromox.
#include <fmt/core.h>
#include "exceptions.hpp"
#include "ews.hpp"
#include "structures.hpp"

namespace gromox::EWS
{

using namespace Exceptions;
using namespace Structures;

/**
 * @brief      Convert string to lower case
 *
 * @param      str     String to convert
 *
 * @return     Reference to the string
 */
inline std::string& tolower(std::string& str)
{
	transform(str.begin(), str.end(), str.begin(), ::tolower);
	return str;
}
/**
 * @brief      Convert ESSDN to username
 *
 * @param      essdn   ESSDN to convert
 *
 * @throw      DispatchError   Conversion failed
 *
 * @return     Username
 *
 * @todo       This should probably verify the domain id as well (currently ignored)
 */
std::string EWSContext::essdn_to_username(const std::string& essdn) const
{
	int user_id;
	auto ess_tpl = fmt::format("/o={}/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=", plugin.x500_org_name.c_str());
	if (strncasecmp(essdn.c_str(), ess_tpl.c_str(), ess_tpl.size()) != 0)
		throw DispatchError(E3000);
	if (essdn.size() > ess_tpl.size() + 16 && essdn[ess_tpl.size()+16] != '-')
		throw DispatchError(E3001);
	const char *lcl = essdn.c_str() + ess_tpl.size() + 17;
	user_id = decode_hex_int(essdn.c_str() + ess_tpl.size() + 8);
	std::string username(UADDR_SIZE, 0);
	if (!plugin.mysql.get_username_from_id(user_id, username.data(), UADDR_SIZE))
		throw DispatchError(E3002);
	username.resize(username.find('\0'));
	size_t at = username.find('@');
	if (at == std::string::npos)
		throw DispatchError(E3003);
	if (strncasecmp(username.data(), lcl, at) != 0)
		throw DispatchError(E3004);
	return username;
}

/**
 * @brief      Get user maildir from Mailbox speciication
 *
 * @param      Mailbox   Mailbox structure
 *
 * @throw      DispatchError   Could not retrieve maildir
 *
 * @return     Path to the user's maildir
 */
std::string EWSContext::get_maildir(const tMailbox& Mailbox) const
{
	std::string RoutingType = Mailbox.RoutingType.value_or("smtp");
	std::string Address = Mailbox.Address;
	if(tolower(RoutingType) == "ex"){
		Address = essdn_to_username(Mailbox.Address);
		RoutingType = "smtp";
	}
	if(RoutingType == "smtp") {
		char temp[256];
		if(!plugin.mysql.get_maildir(Address.c_str(), temp, std::size(temp)))
			throw DispatchError(E3007);
		return temp;
	} else
		throw DispatchError(E3006(RoutingType));
}

}
