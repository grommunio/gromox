// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2023 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cctype>
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
static inline std::string &tolower(std::string &str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);
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
std::string EWSContext::get_maildir(const std::string& username) const
{
	char temp[256];
	if(!plugin.mysql.get_maildir(username.c_str(), temp, arsizeof(temp)))
		throw DispatchError(E3007);
	return temp;
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

std::string EWSContext::getDir(const sFolderSpec& folder) const
{
	const char* target = folder.target? folder.target->c_str() : auth_info.username;
	const char* at = strchr(target, '@');
	bool isPublic = folder.location == sFolderSpec::AUTO? at == nullptr : folder.location == sFolderSpec::PUBLIC;
	auto func = isPublic? plugin.mysql.get_homedir : plugin.mysql.get_maildir;
	if(isPublic && at)
		target = at+1;
	char targetDir[256];
	if(!func(target, targetDir, arsizeof(targetDir)))
		throw DispatchError(E3007);
	return targetDir;
}

/**
 * @brief     Get properties of specified folder
 *
 * @param     folder  Folder Specification
 * @param     props   Properties to get
 *
 * @return    Property values
 */
TPROPVAL_ARRAY EWSContext::getFolderProps(const sFolderSpec& folder, const PROPTAG_ARRAY& props) const
{
	std::string targetDir = getDir(folder);
	TPROPVAL_ARRAY result;
	if(!plugin.exmdb.get_folder_properties(targetDir.c_str(), 0, folder.folderId, &props, &result))
		throw DispatchError("Failed to get folder properties");
	return result;
}

/**
 * @brief    Normalize mailbox specification
 *
 * Ensures that `RoutingType` equals "smtp", performing essdn resolution if
 * necessary.
 *
 * @throw      DispatchError   Unsupported RoutingType
 *
 * @param Mailbox
 */
void EWSContext::normalize(tMailbox& Mailbox) const
{
	if(!Mailbox.RoutingType)
		Mailbox.RoutingType = "smtp";
	if(tolower(*Mailbox.RoutingType) == "smtp")
		return;
	if(Mailbox.RoutingType != "ex")
		throw  DispatchError(E3010(*Mailbox.RoutingType));
	Mailbox.Address = essdn_to_username(Mailbox.Address);
	Mailbox.RoutingType = "smtp";
}

}
