// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2023 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cctype>
#include <fmt/core.h>

#include <libHX/string.h>

#include <gromox/rop_util.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>

#include "exceptions.hpp"
#include "ews.hpp"
#include "namedtags.hpp"
#include "structures.hpp"

namespace gromox::EWS
{

using namespace Exceptions;
using namespace Structures;

namespace
{

/**
 * @brief     Generic deleter struct
 *
 * Provides explicit deleters for classes without destructor.
 */
struct Cleaner
{
	inline void operator()(BINARY* x) {rop_util_free_binary(x);}
};;

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
 * @brief      Create new item
 *
 * @param      parent    Parent folder to create item in
 * @param      item      Item object to store
 *
 * @return     Item object containing ItemId
 */
sItem EWSContext::create(const std::string& dir, const sFolderSpec& parent, const MESSAGE_CONTENT& content) const
{
	ec_error_t error;
	uint64_t* messageId = content.proplist.get<uint64_t>(PidTagMid);
	if(!messageId)
		throw DispatchError(E3112);
	plugin.exmdb.write_message(dir.c_str(), auth_info.username, CP_ACP, parent.folderId, &content, &error);

	sShape retshape = sShape(tItemResponseShape());
	return loadItem(dir, parent.folderId, *messageId, retshape);
}

/**
 * @brief     Get user or domain ID by name
 *
 * @param     name       Name to resolve
 * @param     isDomain   Whether target is a domain
 *
 * @return Account ID
 */
uint32_t EWSContext::getAccountId(const std::string& name, bool isDomain) const
{
	uint32_t accountId, unused1;
	display_type unused2;
	BOOL res;
	if(isDomain)
		res = plugin.mysql.get_domain_ids(name.c_str(), &accountId, &unused1);
	else
		res = plugin.mysql.get_user_ids(name.c_str(), &accountId, &unused1, &unused2);
	if(!res)
		throw EWSError::CannotFindUser(E3113(isDomain? "domain" : "user", name));
	return accountId;
}

/**
 * @brief      Get named property IDs
 *
 * @param      dir       Home directory of user or domain
 * @param      propNames List of property names to retrieve
 * @param      create Whether to create requested names if necessary
 *
 * @return     Array of property IDs
 */
PROPID_ARRAY EWSContext::getNamedPropIds(const std::string& dir, const PROPNAME_ARRAY& propNames, bool create) const
{
	PROPID_ARRAY namedIds{};
	if(!plugin.exmdb.get_named_propids(dir.c_str(), create? TRUE : false, &propNames, &namedIds))
		throw DispatchError(E3069);
	return namedIds;
}

/**
 * @brief      Load named tags into shape
 *
 * Immediatly returns if the shape is already associated with the store.
 *
 * @param      dir    Home directory of user or domain
 * @param      shape  Shape to load tags into
 * @param      create Whether to create requested names if necessary
 */
void EWSContext::getNamedTags(const std::string& dir, sShape& shape, bool create) const
{
	if(shape.store == dir)
		return;
	PROPNAME_ARRAY propNames = shape.namedProperties();
	if(propNames.count == 0)
		return;
	PROPID_ARRAY namedIds = getNamedPropIds(dir, propNames, create);
	if(namedIds.count != propNames.count)
		return;
	shape.namedProperties(namedIds);
	shape.store = dir;
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
	if (!plugin.mysql.get_maildir(username.c_str(), temp, std::size(temp)))
		throw EWSError::CannotFindUser(E3007);
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
			throw EWSError::CannotFindUser(E3125);
		return temp;
	} else
		throw EWSError::InvalidRoutingType(E3006(RoutingType));
}

/**
 * @brief      Get user or domain maildir from folder spec
 *
 * @param      folder  Folder specification
 *
 * @return     Home directory of user or domain
 */
std::string EWSContext::getDir(const sFolderSpec& folder) const
{
	const char* target = folder.target? folder.target->c_str() : auth_info.username;
	const char* at = strchr(target, '@');
	bool isPublic = folder.location == sFolderSpec::AUTO? at == nullptr : folder.location == sFolderSpec::PUBLIC;
	auto func = isPublic? plugin.mysql.get_homedir : plugin.mysql.get_maildir;
	if(isPublic && at)
		target = at+1;
	char targetDir[256];
	if (!func(target, targetDir, std::size(targetDir)))
		throw EWSError::CannotFindUser(E3126);
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
		throw EWSError::FolderPropertyRequestFailed(E3022);
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
		throw EWSError::FolderPropertyRequestFailed(E3023);
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
		throw EWSError::ItemPropertyRequestFailed(E3024);
	return *props.ppropval;
}

/**
 * @brief      Get item property value
 *
 * @param      dir   Store directory
 * @param      mid   Message ID
 * @param      tag   Tag ID
 *
 * @return     Pointer to property value or nullptr if not found
 */
const void* EWSContext::getItemProp(const std::string& dir, uint64_t mid, uint32_t tag) const
{
	PROPTAG_ARRAY proptags{1, &tag};
	TPROPVAL_ARRAY props = getItemProps(dir, mid, proptags);
	if(props.count != 1 || props.ppropval->proptag != tag)
		throw EWSError::ItemPropertyRequestFailed(E3127);
	return props.count == 1 && props.ppropval->proptag == tag? props.ppropval->pvalue : nullptr;
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
		throw EWSError::ItemPropertyRequestFailed(E3025);
	return result;
}

/**
 * @brief     Load attachment
 *
 * @param     dir      Store to load from
 * @param     aid      Attachment ID
 *
 * @return    Attachment structure
 */
sAttachment EWSContext::loadAttachment(const std::string& dir, const sAttachmentId& aid) const
{
	auto aInst = plugin.loadAttachmentInstance(dir, aid.folderId(), aid.messageId(), aid.attachment_num);
	static uint32_t tagIDs[] = {PR_ATTACH_METHOD, PR_DISPLAY_NAME, PR_ATTACH_MIME_TAG, PR_ATTACH_DATA_BIN};
	TPROPVAL_ARRAY props;
	PROPTAG_ARRAY tags{std::size(tagIDs), tagIDs};
	if(!plugin.exmdb.get_instance_properties(dir.c_str(), 0, aInst->instanceId, &tags, &props))
		throw DispatchError(E3083);
	return tAttachment::create(aid, props);
}

/**
 * @brief      Load folder properties
 *
 * @param      folder  Folder specification
 * @param      shape   Requested folder shape
 *
 * @return     Folder data
 */
sFolder EWSContext::loadFolder(const sFolderSpec& folder, Structures::sShape& shape) const
{
	shape.clean();
	getNamedTags(getDir(folder), shape);
	shape.properties(getFolderProps(folder, shape.proptags()));
	return tBaseFolderType::create(shape);
}

/**
 * @brief     Load generic special fields
 *
 * Currently supports
 * - loading of mime content
 * - loading of attachment metadata
 *
 * @param     dir     Store to load from
 * @param     fid     Parent folder ID
 * @param     mid     Message to load
 * @param     item    Message object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fid, uint64_t mid, tItem& item, uint64_t special) const
{
	auto& exmdb = plugin.exmdb;
	if(special & sShape::MimeContent)
	{
		MESSAGE_CONTENT* content;
		if(!exmdb.read_message(dir.c_str(), nullptr, CP_ACP, mid, &content))
			throw EWSError::ItemNotFound(E3071);
		MAIL mail;
		auto getPropIds = [&](const PROPNAME_ARRAY* names, PROPID_ARRAY* ids)
		                  {*ids = getNamedPropIds(dir, *names); return TRUE;};
		auto getPropName = [&](uint16_t id, PROPERTY_NAME** name)
		                   {*name = getPropertyName(dir, id); return TRUE;};
		if(!oxcmail_export(content, false, oxcmail_body::plain_and_html, plugin.mimePool, &mail,
		                   alloc, getPropIds, getPropName))
			throw EWSError::ItemCorrupt(E3072);
		auto mailLen = mail.get_length();
		if(mailLen < 0)
			throw EWSError::ItemCorrupt(E3073);
		alloc_limiter<stream_block> allocator(mailLen/STREAM_BLOCK_SIZE+1, "ews::loadMime");
		STREAM tempStream(&allocator);
		if(!mail.serialize(&tempStream))
			throw EWSError::ItemCorrupt(E3074);
		auto& mimeContent = item.MimeContent.emplace();
		mimeContent.reserve(mailLen);
		uint8_t* data;
		unsigned int size = STREAM_BLOCK_SIZE;
		while((data = static_cast<uint8_t*>(tempStream.get_read_buf(&size))) != nullptr) {
			mimeContent.insert(mimeContent.end(), data, data+size);
			size = STREAM_BLOCK_SIZE;
		}
	}
	if(special & sShape::Attachments)
	{
		static uint32_t tagIDs[] = {PR_ATTACH_METHOD, PR_DISPLAY_NAME, PR_ATTACH_MIME_TAG, PR_ATTACH_SIZE,
		                            PR_LAST_MODIFICATION_TIME};
		auto mInst = plugin.loadMessageInstance(dir, fid, mid);
		uint16_t count;
		if(!exmdb.get_message_instance_attachments_num(dir.c_str(), mInst->instanceId, &count))
			throw DispatchError(E3079);
		sAttachmentId aid(this->getItemEntryId(dir, mid), 0);
		item.Attachments.emplace().reserve(count);
		for(uint16_t i = 0; i < count; ++i)
		{
			auto aInst = plugin.loadAttachmentInstance(dir, fid, mid, i);
			TPROPVAL_ARRAY props;
			PROPTAG_ARRAY tags{std::size(tagIDs), tagIDs};
			if(!exmdb.get_instance_properties(dir.c_str(), 0, aInst->instanceId, &tags, &props))
				throw DispatchError(E3080);
			aid.attachment_num = i;
			item.Attachments->emplace_back(tAttachment::create(aid, props));
		}
	}
}

/**
 * @brief     Load message attributes not contained in tags
 *
 * @param     dir     Store to load from
 * @param     fid     Parent folder ID
 * @param     mid     Message to load
 * @param     message Message object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fid, uint64_t mid, tMessage& message, uint64_t special) const
{
	loadSpecial(dir, fid, mid, static_cast<tItem&>(message), special);
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
 * @brief     Load message attributes not contained in tags
 *
 * @param     dir     Store to load from
 * @param     fid     Parent folder ID
 * @param     mid     Message to load
 * @param     calItem Calendar object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fid, uint64_t mid, tCalendarItem& calItem, uint64_t special) const
{
	loadSpecial(dir, fid, mid, static_cast<tItem&>(calItem), special);
	if(special & sShape::Attendees)
	{
		TARRAY_SET rcpts;
		if(!plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts))
		{
			mlog(LV_ERR, "[ews] failed to load calItem recipients (%s:%lu)", dir.c_str(), mid);
			return;
		}
		for(TPROPVAL_ARRAY** tps = rcpts.pparray; tps < rcpts.pparray+rcpts.count; ++tps)
		{
			uint32_t* recipientType = (*tps)->get<uint32_t>(PR_RECIPIENT_TYPE);
			if(!recipientType)
				continue;
			switch(*recipientType)
			{
			case 1: //Required attendee
				if(special & sShape::RequiredAttendees)
					defaulted(calItem.RequiredAttendees).emplace_back(**tps);
				break;
			case 2: //Optional attendee
				if(special & sShape::OptionalAttendees)
					defaulted(calItem.OptionalAttendees).emplace_back(**tps);
				break;
			case 3: //Resource
				if(special & sShape::Resources)
					defaulted(calItem.Resources).emplace_back(**tps);
				break;
			}
		}
	}
}

/**
 * @brief      Load item
 *
 * @param      dir    Store directory
 * @param      fid    Parent folder ID
 * @param      mid    Message ID
 * @param      shape  Requested item shape
 *
 * @return     The s item.
 */
sItem EWSContext::loadItem(const std::string&dir, uint64_t fid, uint64_t mid, sShape& shape) const
{
	shape.clean();
	getNamedTags(dir, shape);
	shape.properties(getItemProps(dir, mid, shape.proptags()));
	sItem item = tItem::create(shape);
	if(shape.special)
		std::visit([&](auto &&it) { loadSpecial(dir, fid, mid, it, shape.special); }, item);
	return item;
}

/**
 * @brief    Normalize mailbox specification
 *
 * If EmailAddress is empty, nothing happens.
 *
 * Ensures that `RoutingType` equals "smtp", performing essdn resolution if
 * necessary.
 *
 * @throw      DispatchError   Unsupported RoutingType
 *
 * @param Mailbox
 */
void EWSContext::normalize(tEmailAddressType& Mailbox) const
{
	if(!Mailbox.EmailAddress)
		return;
	if(!Mailbox.RoutingType)
		Mailbox.RoutingType = "smtp";
	if(tolower(*Mailbox.RoutingType) == "smtp")
		return;
	if(Mailbox.RoutingType != "ex")
		throw  EWSError::InvalidRoutingType(E3114(*Mailbox.RoutingType));
	Mailbox.EmailAddress = essdn_to_username(*Mailbox.EmailAddress);
	Mailbox.RoutingType = "smtp";
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
		throw  EWSError::InvalidRoutingType(E3010(*Mailbox.RoutingType));
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
{
	sFolderSpec folder = sFolderSpec(fId);
	folder.target = auth_info.username;
	return folder;
}

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
			throw EWSError::CannotFindUser(E3026);
		folderSpec.target = temp;
	}
	else
	{
		sql_domain domaininfo;
		if(!plugin.mysql.get_domain_info(eid.accountId(), domaininfo))
			throw EWSError::CannotFindUser(E3027);
		folderSpec.target = domaininfo.name;
	}
	return folderSpec;
}

/**
 * @brief      Get folder specification form any folder specification
 *
 * @param      fId    Folder Id
 *
 * @return     Folder specification
 */
sFolderSpec EWSContext::resolveFolder(const std::variant<tFolderId, tDistinguishedFolderId>& fId) const
{return std::visit([this](const auto& f){return resolveFolder(f);}, fId);}

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
			throw EWSError::CannotFindUser(E3075);
		folderSpec.target = temp;
	}
	else
	{
		sql_domain domaininfo;
		if(!plugin.mysql.get_domain_info(eid.accountId(), domaininfo))
			throw EWSError::CannotFindUser(E3076);
		folderSpec.target = domaininfo.name;
	}
	return folderSpec;
}

/**
 * @brief     Send message
 *
 * @param     dir      Home directory the message is associtated with
 * @param     content  Message content
 */
void EWSContext::send(const std::string& dir, const MESSAGE_CONTENT& content) const
{
	if(!content.children.prcpts)
		throw EWSError::MissingRecipients(E3115);
	MAIL mail;
	auto getPropIds = [&](const PROPNAME_ARRAY* names, PROPID_ARRAY* ids)
		                  {*ids = getNamedPropIds(dir, *names); return TRUE;};
	auto getPropName = [&](uint16_t id, PROPERTY_NAME** name)
					   {*name = getPropertyName(dir, id); return TRUE;};
	if(!oxcmail_export(&content, false, oxcmail_body::plain_and_html, plugin.mimePool, &mail, alloc, getPropIds,getPropName))
		throw EWSError::ItemCorrupt(E3116);
	std::vector<std::string> rcpts;
	rcpts.reserve(content.children.prcpts->count);
	const auto& prcpts = content.children.prcpts;
	for(TPROPVAL_ARRAY** rcpt = prcpts->pparray; rcpt != prcpts->pparray+prcpts->count; ++rcpt) {
		tEmailAddressType addr(**rcpt);
		if(!addr.EmailAddress)
			continue;
		normalize(addr);
		rcpts.emplace_back(*addr.EmailAddress);
	}
	ec_error_t err = cu_send_mail(mail, "smtp", plugin.smtp_server_ip.c_str(), plugin.smtp_server_port, auth_info.username,
	                              rcpts);
	if(err != ecSuccess)
		throw DispatchError(E3117(err));
}

/**
 * @brief     Convert item to MESSAGE_CONTENT
 *
 * @param     dir      Home directory of the associated store
 * @param     parent   Parent folder to store the message in
 * @param     item     Item to convert
 * @param     persist  Whether the message is to be stored
 *
 * @return MESSAGE_CONTENT structure
 */
MESSAGE_CONTENT EWSContext::toContent(const std::string& dir, const sFolderSpec& parent, sItem& item, bool persist) const
{
	const auto& exmdb = plugin.exmdb;

	uint64_t messageId, changeNumber;
	BINARY *ckey, *pclbin;
	if(persist) {
		if(!exmdb.allocate_message_id(dir.c_str(), parent.folderId, &messageId))
			throw DispatchError(E3118);
		if(!exmdb.allocate_cn(dir.c_str(), &changeNumber))
			throw DispatchError(E3119);

		bool isPublic = parent.location == parent.PUBLIC;
		uint32_t accountId = getAccountId(*parent.target, isPublic);
		XID xid((parent.location == parent.PRIVATE? rop_util_make_user_guid : rop_util_make_domain_guid)(accountId), changeNumber);

		uint8_t* buff = alloc<uint8_t>(22);
		EXT_PUSH ext_push;
		if(!ext_push.init(buff, 22, 0) || ext_push.p_xid(xid) != EXT_ERR_SUCCESS)
			throw DispatchError(E3120);
		ckey = construct<BINARY>(BINARY{ext_push.m_offset, {buff}});

		PCL pcl;
		if(!pcl.append(xid))
			throw DispatchError(E3121);
		pcl.serialize();
		std::unique_ptr<BINARY, Cleaner> pcltemp(pcl.serialize());
		if(!pcltemp)
			throw EWSError::NotEnoughMemory(E3122);

		uint8_t* pcldata = alloc<uint8_t>(pcltemp->cb);
		memcpy(pcldata, pcltemp->pv, pcltemp->cb);
		pclbin = construct<BINARY>(BINARY{pcltemp->cb, {pcldata}});
	}

	sShape shape;
	MESSAGE_CONTENT content{};
	std::visit([&](auto& i){toContent(dir, i, shape, content);}, item);

	if(!shape.writes(PR_LAST_MODIFICATION_TIME))
		shape.write(TAGGED_PROPVAL{PR_LAST_MODIFICATION_TIME, EWSContext::construct<uint64_t>(rop_util_current_nttime())});

	if(persist) {
		shape.write(TAGGED_PROPVAL{PidTagMid, construct<uint64_t>(messageId)});
		shape.write(TAGGED_PROPVAL{PidTagChangeNumber, construct<uint64_t>(changeNumber)});
		shape.write(TAGGED_PROPVAL{PR_CHANGE_KEY, ckey});
		shape.write(TAGGED_PROPVAL{PR_PREDECESSOR_CHANGE_LIST, pclbin});
	}
	getNamedTags(dir, shape, true);

	TPROPVAL_ARRAY proptemp = shape.write();
	content.proplist = TPROPVAL_ARRAY{proptemp.count, alloc<TAGGED_PROPVAL>(proptemp.count)};
	memcpy(content.proplist.ppropval, proptemp.ppropval, sizeof(TAGGED_PROPVAL)*proptemp.count);
	return content;
}

/**
 * @brief      Write calendar item properties to shape
 *
 * Must forward the call to tItem overload.
 *
 * Currently a stub.
 *
 * @param      dir       Home directory of the target store
 * @param      item      Calendar item to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content struct
 *
 * @todo Map remaining fields
 */
void EWSContext::toContent(const std::string& dir, tCalendarItem& item, sShape& shape, MESSAGE_CONTENT& content) const
{toContent(dir, static_cast<tItem&>(item), shape, content);}

/**
 * @brief      Write contact item properties to shape
 *
 * Must forward call to tItem overload.
 *
 * Currently a stub.
 *
 * @param      dir       Home directory of the target store
 * @param      item      Contact item to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content struct
 *
 * @todo Map remaining fields
 */
void EWSContext::toContent(const std::string& dir, tContact& item, sShape& shape, MESSAGE_CONTENT& content) const
{toContent(dir, static_cast<tItem&>(item), shape, content);}

/**
 * @brief      Write item properties to shape
 *
 * Provides base for all derived classes and should be called before further
 * processing.
 *
 * @param      dir       Home directory of the target store
 * @param      item      Item to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content struct
 *
 * @todo Map remaining fields
 */
void EWSContext::toContent(const std::string& dir, tItem& item, sShape& shape, MESSAGE_CONTENT& content) const
{
	if(item.MimeContent) {
		// Convert MimeContent to MESSAGE_CONTENT
		MAIL mail(plugin.mimePool);
		if(!mail.load_from_str_move(reinterpret_cast<char*>(item.MimeContent->data()), item.MimeContent->size()))
			throw EWSError::ItemCorrupt(E3123);
		auto getPropIds = [&](const PROPNAME_ARRAY* names, PROPID_ARRAY* ids)
		{*ids = getNamedPropIds(dir, *names, true); return TRUE;};
		MESSAGE_CONTENT* cnt = oxcmail_import("utf-8", "UTC", &mail, EWSContext::alloc, getPropIds);
		if(!cnt)
			throw EWSError::ItemCorrupt(E3124);
		content = *cnt;
		// Register tags loaded by importer to the shape
		const TAGGED_PROPVAL *end = content.proplist.ppropval+content.proplist.count;
		for(const TAGGED_PROPVAL* prop = content.proplist.ppropval; prop != end; ++prop)
			shape.write(*prop);
	}
	if(item.ItemClass)
		shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, const_cast<char*>(item.ItemClass->c_str())});
	if(item.Sensitivity)
		shape.write(TAGGED_PROPVAL{PR_SENSITIVITY, construct<uint32_t>(item.Sensitivity->index())});
	if(item.Categories && item.Categories->size() && item.Categories->size() <= std::numeric_limits<uint32_t>::max()) {
		uint32_t count = uint32_t(item.Categories->size());
		STRING_ARRAY* categories = construct<STRING_ARRAY>(STRING_ARRAY{count, alloc<char*>(count)});
		char** dest = categories->ppstr;
		for(const std::string& category : *item.Categories) {
			*dest = alloc<char>(category.size()+1);
			HX_strlcpy(*dest++, category.c_str(), category.size()+1);
		}
		shape.write(NtCategories, TAGGED_PROPVAL{PT_MV_UNICODE, categories});
	}
	if(item.Importance)
		shape.write(TAGGED_PROPVAL{PR_IMPORTANCE, construct<uint32_t>(item.Importance->index())});

	for(const tExtendedProperty& prop : item.ExtendedProperty)
		prop.ExtendedFieldURI.tag()? shape.write(prop.propval) : shape.write(prop.ExtendedFieldURI.name(), prop.propval);
}

/**
 * @brief      Write message properties to shape
 *
 * Must forward call to tItem overload.
 *
 * @param      dir       Home directory of the target store
 * @param      item      Message to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content struct
 *
 * @todo Map remaining fields
 */
void EWSContext::toContent(const std::string& dir, tMessage& item, sShape& shape, MESSAGE_CONTENT& content) const
{
	toContent(dir, static_cast<tItem&>(item), shape, content);
	size_t recipients = (item.ToRecipients? item.ToRecipients->size() : 0)
	                    + (item.CcRecipients? item.CcRecipients->size() : 0)
	                    + (item.BccRecipients? item.BccRecipients->size() : 0);
	if(recipients && !content.children.prcpts) {
		//TODO: Add recipients
	}
	if(item.From) {
		if(item.From->Mailbox.RoutingType)
			shape.write(TAGGED_PROPVAL{PR_SENT_REPRESENTING_ADDRTYPE, item.From->Mailbox.RoutingType->data()});
		if(item.From->Mailbox.EmailAddress)
			shape.write(TAGGED_PROPVAL{PR_SENT_REPRESENTING_EMAIL_ADDRESS, item.From->Mailbox.EmailAddress->data()});
		if(item.From->Mailbox.Name)
			shape.write(TAGGED_PROPVAL{PR_SENT_REPRESENTING_NAME, item.From->Mailbox.Name->data()});
	}
}

/**
 * @brief      Mark message as updated
 *
 * @param      dir       Home directory of user or domain
 * @param      username  Account name of the user updating the message
 * @param      mid       Message ID
 *
 * @todo Perhaps this should work on an instance
 */
void EWSContext::updated(const std::string& dir, const sMessageEntryId& mid) const
{
	uint64_t changeNum;
	if(!plugin.exmdb.allocate_cn(dir.c_str(), &changeNum))
		throw DispatchError(E3084);
	TAGGED_PROPVAL _props[8];
	TPROPVAL_ARRAY props{0, _props};
	uint64_t localCommitTime = rop_util_current_nttime();
	_props[props.count].proptag = PR_LOCAL_COMMIT_TIME;
	_props[props.count++].pvalue = &localCommitTime;
	_props[props.count].proptag = PR_LAST_MODIFICATION_TIME;
	_props[props.count++].pvalue = &localCommitTime;

	char displayName[1024];
	_props[props.count].proptag = PR_LAST_MODIFIER_NAME;
	if(!plugin.mysql.get_user_displayname(auth_info.username, displayName, std::size(displayName)) || !*displayName)
		_props[props.count++].pvalue = displayName;
	else
		_props[props.count++].pvalue = const_cast<char*>(auth_info.username);

	uint8_t abEidBuff[1280];
	EXT_PUSH wAbEid;
	std::string essdn = username_to_essdn(auth_info.username);
	EMSAB_ENTRYID abEid{0, 1, DT_MAILUSER, essdn.data()};
	if(!wAbEid.init(abEidBuff, std::size(abEidBuff), EXT_FLAG_UTF16) || wAbEid.p_abk_eid(abEid) != EXT_ERR_SUCCESS)
		throw DispatchError(E3085);
	BINARY abEidContainer{wAbEid.m_offset, {abEidBuff}};
	_props[props.count].proptag = PR_LAST_MODIFIER_ENTRYID;
	_props[props.count++].pvalue = &abEidContainer;

	XID changeKey{(mid.isPrivate()? rop_util_make_user_guid : rop_util_make_domain_guid)(mid.accountId()), changeNum};
	uint8_t ckeyBuff[24];
	EXT_PUSH wCkey;
	if(!wCkey.init(ckeyBuff, std::size(ckeyBuff), 0) || wCkey.p_xid(changeKey) != EXT_ERR_SUCCESS)
		throw DispatchError(E3086);
	BINARY changeKeyContainer{wCkey.m_offset, {ckeyBuff}};
	_props[props.count].proptag = PR_CHANGE_KEY;
	_props[props.count++].pvalue = &changeKeyContainer;

	const BINARY* currentPclContainer = getItemProp<BINARY>(dir, mid.messageId(), PR_PREDECESSOR_CHANGE_LIST);
	PCL pcl;
	if(!currentPclContainer || !pcl.deserialize(currentPclContainer))
		throw DispatchError(E3087);
	pcl.append(changeKey);
	std::unique_ptr<BINARY, Cleaner> serializedPcl(pcl.serialize());
	if(!serializedPcl)
		throw EWSError::NotEnoughMemory(E3088);
	_props[props.count].proptag = PR_PREDECESSOR_CHANGE_LIST;
	_props[props.count++].pvalue = serializedPcl.get();

	_props[props.count].proptag = PidTagChangeNumber;
	_props[props.count++].pvalue = &changeNum;

	PROBLEM_ARRAY problems;
	if(!plugin.exmdb.set_message_properties(dir.c_str(), nullptr, CP_ACP, mid.messageId(), &props, &problems))
		throw DispatchError(E3089);

}

/**
 * @brief      Convert username to ESSDN
 *
 * @param      essdn   Username to convert
 *
 * @throw      DispatchError   Conversion failed
 *
 * @return     ESSDN
 */
std::string EWSContext::username_to_essdn(const std::string& username) const
{
	uint32_t userId, domainId;
	size_t at = username.find('@');
	if(at == username.npos)
		throw EWSError::CannotFindUser(E3090(username));
	std::string_view userpart = std::string_view(username).substr(0, at);
	if(!plugin.mysql.get_user_ids(username.c_str(), &userId, &domainId, nullptr))
		throw EWSError::CannotFindUser(E3091(username));
	return fmt::format("/o={}/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn={:08x}{:08x}-{}",
	                   plugin.x500_org_name.c_str(), domainId, userId, userpart);
}

/**
 * @brief     Convert EXT_PUSH/EXT_PULL return code to exception
 *
 * @param     code           ext_buffer return code
 * @param     msg            Error message
 * @param     responseCode   EWSError response code for generic errors
 *
 * @todo      Add more exceptions for better differentiation
 */
void EWSContext::ext_error(pack_result code, const char* msg, const char* responseCode)
{
	switch(code)
	{
	case EXT_ERR_SUCCESS: return;
	case EXT_ERR_ALLOC: throw Exceptions::EWSError::NotEnoughMemory(msg? msg : E3128);
	case EXT_ERR_BUFSIZE: throw Exceptions::DispatchError(msg? msg : E3145);
	default:
		if(responseCode && msg)
			throw Exceptions::EWSError(responseCode, msg);
		else
			throw DispatchError(Exceptions::E3028(int(code)));
	}
}

}
