// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2023 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cctype>
#include <fmt/core.h>

#include <gromox/rop_util.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail.hpp>
#include <gromox/oxcmail.hpp>

#include "exceptions.hpp"
#include "ews.hpp"
#include "structures.hpp"

namespace gromox::EWS
{

using namespace Exceptions;
using namespace Structures;

namespace
{
/**
 * @brief      Convert string to lower case
 *
 * @param      str     String to convert
 *
 * @return     Reference to the string
 */
inline std::string &tolower(std::string &str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);
	return str;
}

/**
 * @brief     Access contained value, create if empty
 *
 * @param     container   (Possibly empty) container
 * @param     args        Arguments used for creation if container is empty
 *
 * @return    Reference to contained value
 */
template<typename T, typename... Args>
T& defaulted(std::optional<T>& container, Args&&... args)
{return container? *container : container.emplace(std::forward<Args...>(args)...);}

} // Anonymous namespace

/**
 * @brief      Get named property IDs
 *
 * @param      dir       Home directory of user or domain
 * @param      propNames List of property names to retrieve
 *
 * @return     Array of property IDs
 */
PROPID_ARRAY EWSContext::getNamedPropIds(const std::string& dir, const PROPNAME_ARRAY& propNames) const
{
	PROPID_ARRAY namedIds{};
	if(!plugin.exmdb.get_named_propids(dir.c_str(), FALSE, &propNames, &namedIds))
		throw DispatchError(E3069);
	return namedIds;
}

/**
 * @brief      Resolve named tags
 *
 * Resolves the tag names to numeric tags and assembles them to property tags
 * using the types array. names and types must have the same length.
 * Names not resolved are omitted.
 *
 * The resolved tags are appended to result.tags and additionally inserted into
 * result.namedTags mapping tags back to their names.
 *
 * @param      Home directory of the user or domain
 * @param      List of property names to resolve
 * @param      List of property types
 * @param      Result to store resolved tags in
 */
void EWSContext::getNamedTags(const std::string& dir, const std::vector<PROPERTY_NAME>& names,
                              const std::vector<uint16_t>& types, sShape& result) const
{
	PROPNAME_ARRAY propNames{uint16_t(names.size()), const_cast<PROPERTY_NAME*>(names.data())};
	PROPID_ARRAY namedIds = getNamedPropIds(dir, propNames);
	if(namedIds.count != types.size())
		return;
	result.namedTags.reserve(namedIds.count);
	for(size_t i = 0; i < namedIds.count; ++i)
	{
		if(namedIds.ppropid[i] == 0) // Failed to retrieve named property
			continue;
		if(result.namedTags.try_emplace(PROP_TAG(types[i], namedIds.ppropid[i]), names[i]).second)
			result.tags.emplace_back(PROP_TAG(types[i], namedIds.ppropid[i]));
	}
}

/**
 * @brief      Get property name from ID
 *
 * @param      dir     Home directory of user or domain
 * @param      id      Id of the property
 *
 * @return     Property name
 */
PROPERTY_NAME* EWSContext::getPropertyName(const std::string& dir, uint16_t id) const
{
	PROPID_ARRAY propids{1, &id};
	PROPNAME_ARRAY propnames{};
	if(!plugin.exmdb.get_named_propnames(dir.c_str(), &propids, &propnames) || propnames.count != 1)
		throw DispatchError(E3070);
	return propnames.ppropname;
}

/**
 * @brief      Determine tags required for item shape
 *
 * @param      Requested item shape
 * @param      Home directory of the user or domain
 *
 * @return     Tag list and named property map
 */
sShape EWSContext::collectTags(const tItemResponseShape& shape, const std::optional<std::string>& dir) const
{
	sShape result;
	std::vector<PROPERTY_NAME> names;
	std::vector<uint16_t> types;
	auto tagIns = std::back_inserter(result.tags);
	auto nameIns = std::back_inserter(names);
	auto typeIns = std::back_inserter(types);
	shape.tags(tagIns, nameIns, typeIns, result.special);
	if(dir && !dir->empty() && !names.empty())
		getNamedTags(*dir, names, types, result);
	return result;
}

/**
 * @brief      Determine tags required for folder shape
 *
 * @param      Requested folder shape
 * @param      Home directory of the user or domain
 *
 * @return     Tag list and named property map
 */
sShape EWSContext::collectTags(const tFolderResponseShape& shape, const std::optional<std::string>& dir) const
{
	sShape result;
	std::vector<PROPERTY_NAME> names;
	std::vector<uint16_t> types;
	auto tagIns = std::back_inserter(result.tags);
	auto nameIns = std::back_inserter(names);
	auto typeIns = std::back_inserter(types);
	shape.tags(tagIns, nameIns, typeIns, result.special);
	if(dir && !dir->empty() && !names.empty())
		getNamedTags(*dir, names, types, result);
	return result;
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
 * @brief      Assert that experimental mode is enabled
 */
void EWSContext::experimental() const
{
	if(!plugin.experimental)
		throw UnknownRequestError(E3021);
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
 * @brief     Get entry ID property of folder
 *
 * Also works on non-existant folders.
 *
 * @param     folder  Folder specification
 *
 * @return    Tagged property containing the entry ID
 */
TAGGED_PROPVAL EWSContext::getFolderEntryId(const sFolderSpec& folder) const
{
	static constexpr uint32_t propids[] = {PR_ENTRYID};
	PROPTAG_ARRAY proptags{1, const_cast<uint32_t*>(propids)};
	TPROPVAL_ARRAY props = getFolderProps(folder, proptags);
	if(props.count != 1 || props.ppropval->proptag != PR_ENTRYID)
		throw DispatchError(E3022);
	return *props.ppropval;
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
	if (!plugin.exmdb.get_folder_properties(targetDir.c_str(), CP_ACP,
	    folder.folderId, &props, &result))
		throw DispatchError(E3023);
	return result;
}

/**
 * @brief     Get entry ID property of item
 *
 * Also works on non-existant items.
 *
 * @param     folder  Folder specification
 *
 * @return    Tagged property containing the entry ID
 */
TAGGED_PROPVAL EWSContext::getItemEntryId(const std::string& dir, uint64_t mid) const
{
	static const uint32_t propids[] = {PR_ENTRYID};
	PROPTAG_ARRAY proptags{1, const_cast<uint32_t*>(propids)};
	TPROPVAL_ARRAY props = getItemProps(dir, mid, proptags);
	if(props.count != 1 || props.ppropval->proptag != PR_ENTRYID)
		throw DispatchError(E3024);
	return *props.ppropval;
}

/**
 * @brief     Get properties of a message item
 *
 * @param     dir     User home dir
 * @param     mid     Message ID
 * @param     props   Properties to get
 *
 * @return    Property values
 */
TPROPVAL_ARRAY EWSContext::getItemProps(const std::string& dir,	uint64_t mid, const PROPTAG_ARRAY& props) const
{
	TPROPVAL_ARRAY result;
	if (!plugin.exmdb.get_message_properties(dir.c_str(), auth_info.username,
	    CP_ACP, mid, &props, &result))
		throw DispatchError(E3025);
	return result;
}

/**
 * @brief     Stub overload for generic items
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t mid, tItem& item, uint64_t special) const
{
	if(special & sShape::MimeContent)
	{
		auto& exmdb = plugin.exmdb;
		MESSAGE_CONTENT* content;
		if(!exmdb.read_message(dir.c_str(), nullptr, CP_ACP, mid, &content))
			throw DispatchError(E3071);
		MAIL mail;
		auto getPropIds = [&](const PROPNAME_ARRAY* names, PROPID_ARRAY* ids)
		                  {*ids = getNamedPropIds(dir, *names); return TRUE;};
		auto getPropName = [&](uint16_t id, PROPERTY_NAME** name)
		                   {*name = getPropertyName(dir, id); return TRUE;};
		if(!oxcmail_export(content, false, oxcmail_body::plain_and_html, plugin.mimePool, &mail,
		                   alloc, getPropIds, getPropName))
			throw DispatchError(E3072);
		auto mailLen = mail.get_length();
		if(mailLen < 0)
			throw DispatchError(E3073);
		alloc_limiter<stream_block> allocator(mailLen/STREAM_BLOCK_SIZE+1, "ews::loadMime");
		STREAM tempStream(&allocator);
		if(!mail.serialize(&tempStream))
			throw DispatchError(E3074);
		auto& mimeContent = item.MimeContent.emplace();
		mimeContent.reserve(mailLen);
		uint8_t* data;
		unsigned int size = STREAM_BLOCK_SIZE;
		while((data = static_cast<uint8_t*>(tempStream.get_read_buf(&size))) != nullptr) {
			mimeContent.insert(mimeContent.end(), data, data+size);
			size = STREAM_BLOCK_SIZE;
		}
	}
}

/**
 * @brief     Load message attributes not contained in tags
 *
 * @param     dir     Store to load from
 * @param     mid     Message to load
 * @param     message Message object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t mid, tMessage& message, uint64_t special) const
{
	loadSpecial(dir, mid, static_cast<tItem&>(message), special);
	if(special & sShape::Recipients)
	{
		TARRAY_SET rcpts;
		if(!plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts))
		{
			mlog(LV_ERR, "[ews] failed to load message recipients (%s:%lu)", dir.c_str(), mid);
			return;
		}
		for(TPROPVAL_ARRAY** tps = rcpts.pparray; tps < rcpts.pparray+rcpts.count; ++tps)
		{
			uint32_t* recipientType = (*tps)->get<uint32_t>(PR_RECIPIENT_TYPE);
			if(!recipientType)
				continue;
			switch(*recipientType)
			{
			case 1: //Primary recipient
				if(special & sShape::ToRecipients)
					defaulted(message.ToRecipients).emplace_back(**tps);
				break;
			case 2: //Cc recipient
				if(special & sShape::CcRecipients)
					defaulted(message.CcRecipients).emplace_back(**tps);
				break;
			case 3: //Bcc recipient
				if(special & sShape::BccRecipients)
					defaulted(message.BccRecipients).emplace_back(**tps);
				break;
			}
		}
	}
}

/**
 * @brief     Load (message) item from store
 *
 * @param     dir     Store to load item from
 * @param     mid     ID of the message to laod
 * @param     shape   Item shape
 *
 * @return    Loaded item
 */
sItem EWSContext::loadItem(const std::string&dir, uint64_t mid, const sShape& shape) const
{
	PROPTAG_ARRAY requestedTags{uint16_t(shape.tags.size()), const_cast<uint32_t*>(shape.tags.data())};
	TPROPVAL_ARRAY itemProps = getItemProps(dir, mid, requestedTags);
	sItem item = tItem::create(itemProps, shape.namedTags);
	if(shape.special)
		std::visit([&](auto&& item){loadSpecial(dir, mid, item, shape.special);}, item);
	return item;
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

/**
 * @brief     Get folder permissions
 *
 * Always returns full access if target matches username.
 *
 * @param     username    Name of the user requesting access
 * @param     folder      Target folder specification
 * @param     maildir     Target maildir or nullptr to resolve automatically
 *
 * @return    Permission flags
 */
uint32_t EWSContext::permissions(const char* username, const sFolderSpec& folder, const char* maildir) const
{
	if(username == folder.target)
		return 0xFFFFFFFF;
	std::string temp;
	if(!maildir)
	{
		temp = getDir(folder);
		maildir = temp.c_str();
	}
	uint32_t permissions = 0;
	plugin.exmdb.get_folder_perm(maildir, folder.folderId, username, &permissions);
	return permissions;
}

/**
 * @brief     Get folder specification from distinguished folder ID
 *
 * Convenience proxy for sFolderSpec constructor to be used with varian::visit.
 *
 * @param     fId     Distinguished folder ID to resolve
 *
 * @return    Folder specification
 */
sFolderSpec EWSContext::resolveFolder(const tDistinguishedFolderId& fId) const
{return sFolderSpec(fId);}


/**
 * @brief      Get folder specification from entry ID
 *
 * @param      fId    Folder Id
 *
 * @return     Folder specification
 */
sFolderSpec EWSContext::resolveFolder(const tFolderId& fId) const
{
	sFolderEntryId eid(fId.Id.data(), fId.Id.size());
	sFolderSpec folderSpec;
	folderSpec.location = eid.isPrivate()? sFolderSpec::PRIVATE : sFolderSpec::PUBLIC;
	folderSpec.folderId = rop_util_make_eid_ex(1, rop_util_gc_to_value(eid.global_counter));
	if(eid.isPrivate())
	{
		char temp[UADDR_SIZE];
		if(!plugin.mysql.get_username_from_id(eid.accountId(), temp, UADDR_SIZE))
			throw DispatchError(E3026);
		folderSpec.target = temp;
	}
	else
	{
		sql_domain domaininfo;
		if(!plugin.mysql.get_domain_info(eid.accountId(), domaininfo))
			throw DispatchError(E3027);
		folderSpec.target = domaininfo.name;
	}
	return folderSpec;
}

/**
 * @brief      Get specification of folder containing the message
 *
 * @param      eid    Message entry ID
 *
 * @return     Folder specification
 */
sFolderSpec EWSContext::resolveFolder(const sMessageEntryId& eid) const
{
	sFolderSpec folderSpec;
	folderSpec.location = eid.isPrivate()? sFolderSpec::PRIVATE : sFolderSpec::PUBLIC;
	folderSpec.folderId = rop_util_make_eid_ex(1, eid.folderId());
	if(eid.isPrivate())
	{
		char temp[UADDR_SIZE];
		if(!plugin.mysql.get_username_from_id(eid.accountId(), temp, UADDR_SIZE))
			throw DispatchError(E3026);
		folderSpec.target = temp;
	}
	else
	{
		sql_domain domaininfo;
		if(!plugin.mysql.get_domain_info(eid.accountId(), domaininfo))
			throw DispatchError(E3027);
		folderSpec.target = domaininfo.name;
	}
	return folderSpec;
}

/**
 * @brief     Convert EXT_PUSH/EXT_PULL return code to exception
 *
 * @param     code    ext_buffer return code
 *
 * @todo      Add more exceptions for better differentiation
 */
void EWSContext::ext_error(pack_result code)
{
	switch(code)
	{
	case EXT_ERR_SUCCESS: return;
	case EXT_ERR_ALLOC: throw std::bad_alloc();
	default: throw DispatchError(E3028(int(code)));
	}
}

}
