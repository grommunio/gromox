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
#include <gromox/usercvt.hpp>

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
 * @brief      Checks if two dates are on the same day
 *
 * @param      tm    First time point
 * @param      tm    Second time point
 *
 * @return     true if both time points are on the same day, false otherwise
 */
inline bool is_same_day(const tm& date1, const tm& date2)
{return date1.tm_year == date2.tm_year && date1.tm_yday == date2.tm_yday;}

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

namespace detail
{

void Cleaner::operator()(BINARY* x) {rop_util_free_binary(x);}
void Cleaner::operator()(MESSAGE_CONTENT *x) {message_content_free(x);}

} // gromox::EWS::detail


///////////////////////////////////////////////////////////////////////////////////////////////////

double EWSContext::age() const
{return std::chrono::duration<double>(std::chrono::high_resolution_clock::now()-m_created).count();}

/**
 * @brief      Create new folder
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder to create folder in
 * @param      folder    Folder object to create
 *
 * @return     Folder object containing FolderId
 */
sFolder EWSContext::create(const std::string& dir, const sFolderSpec& parent, const sFolder& folder) const
{
	sShape shape;
	uint64_t changeNumber;
	if(!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNumber))
		throw DispatchError(E3153);
	const tBaseFolderType& baseFolder = std::visit([](const auto& f) -> const tBaseFolderType&
	                                                 {return static_cast<const tBaseFolderType&>(f);}, folder);
	for(const tExtendedProperty& prop : baseFolder.ExtendedProperty)
		prop.ExtendedFieldURI.tag()? shape.write(prop.propval) : shape.write(prop.ExtendedFieldURI.name(), prop.propval);
	shape.write(TAGGED_PROPVAL{PidTagParentFolderId, const_cast<uint64_t*>(&parent.folderId)});
	const char* fclass = "IPF.Note";
	mapi_folder_type type = FOLDER_GENERIC;
	if(baseFolder.FolderClass)
		fclass = baseFolder.FolderClass->c_str();
	else
		switch(folder.index()) {
		case 1: //CalendarFolder
			fclass = "IPF.Appointment"; break;
		case 2: // ContactsFolder
			fclass = "IPF.Contact"; break;
		case 3: // SearchFolder
			type = FOLDER_SEARCH; break;
		case 4: // TasksFolder
			fclass = "IPF.Task"; break;
		}
	shape.write(TAGGED_PROPVAL{PR_FOLDER_TYPE, &type});
	shape.write(TAGGED_PROPVAL{PR_CONTAINER_CLASS, const_cast<char*>(fclass)});
	if(baseFolder.DisplayName)
		shape.write(TAGGED_PROPVAL{PR_DISPLAY_NAME, const_cast<char*>(baseFolder.DisplayName->c_str())});
	uint64_t now = rop_util_current_nttime();
	shape.write(TAGGED_PROPVAL{PR_CREATION_TIME, &now});
	shape.write({PR_LAST_MODIFICATION_TIME, &now});
	shape.write({PidTagChangeNumber, &changeNumber});

	bool isPublic = parent.location == parent.PUBLIC;
	uint32_t accountId = getAccountId(*parent.target, isPublic);
	XID xid((parent.location == parent.PRIVATE? rop_util_make_user_guid : rop_util_make_domain_guid)(accountId), changeNumber);

	BINARY ckey = serialize(xid);
	shape.write(TAGGED_PROPVAL{PR_CHANGE_KEY, &ckey});

	auto pcl = mkPCL(xid);
	shape.write(TAGGED_PROPVAL{PR_PREDECESSOR_CHANGE_LIST, pcl.get()});

	sFolderSpec created = parent;
	getNamedTags(dir, shape, true);
	TPROPVAL_ARRAY props = shape.write();
	ec_error_t err = ecSuccess;
	if (!m_plugin.exmdb.create_folder(dir.c_str(), CP_ACP, &props,
	    &created.folderId, &err))
		throw EWSError::FolderSave(E3154);
	if (err == ecDuplicateName)
		throw EWSError::FolderExists(E3155);
	if (err != ecSuccess)
		throw EWSError::FolderSave(std::string(E3154) + ": " + mapi_strerror(err));
	if (created.folderId == 0)
		throw EWSError::FolderExists(E3155); // ??

	sShape retshape = sShape(tFolderResponseShape());
	return loadFolder(dir, created.folderId, retshape);
}

/**
 * @brief      Create new item
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder to create item in
 * @param      content   Item content to store
 *
 * @return     Item object containing ItemId
 */
sItem EWSContext::create(const std::string& dir, const sFolderSpec& parent, const MESSAGE_CONTENT& content) const
{
	ec_error_t error;
	uint64_t* messageId = content.proplist.get<uint64_t>(PidTagMid);
	if(!messageId)
		throw DispatchError(E3112);
	m_plugin.exmdb.write_message(dir.c_str(), m_auth_info.username, CP_ACP, parent.folderId, &content, &error);

	sShape retshape = sShape(tItemResponseShape());
	return loadItem(dir, parent.folderId, *messageId, retshape);
}

/**
 * @brief      Schedule notification stream for closing
 */
void EWSContext::disableEventStream()
{
	if(m_notify)
		m_notify->state = NotificationContext::S_CLOSING;
}

/**
 * @brief      Initialize notification context
 *
 * @param      timeout   Stream timeout (minutes)
 */
void EWSContext::enableEventStream(int timeout)
{
	m_state = S_STREAM_NOTIFY;
	gromox::time_point expire = tp_now()+std::chrono::minutes(timeout);
	m_notify = std::make_unique<NotificationContext>(expire);
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
		res = m_plugin.mysql.get_domain_ids(name.c_str(), &accountId, &unused1);
	else
		res = m_plugin.mysql.get_user_ids(name.c_str(), &accountId, &unused1, &unused2);
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
	if(!m_plugin.exmdb.get_named_propids(dir.c_str(), create? TRUE : false, &propNames, &namedIds))
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
	if(!m_plugin.exmdb.get_named_propnames(dir.c_str(), &propids, &propnames) || propnames.count != 1)
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
	auto id2u = [&](int id, std::string &user) -> ec_error_t {
		char buf[UADDR_SIZE];
		if (!m_plugin.mysql.get_username_from_id(id, buf, std::size(buf)))
			throw DispatchError(E3002);
		user = buf;
		return ecSuccess;
	};
	std::string username;
	auto err = gromox::cvt_essdn_to_username(essdn.c_str(),
	           m_plugin.x500_org_name.c_str(), id2u, username);
	if (err == ecSuccess)
		return username;
	if (err == ecUnknownUser)
		throw DispatchError(E3002);
	throw DispatchError(E3003);
}

/**
 * @brief      Assert that experimental mode is enabled
 */
void EWSContext::experimental() const
{
	if(!m_plugin.experimental)
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
	if (!m_plugin.mysql.get_maildir(username.c_str(), temp, std::size(temp)))
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
		Address = essdn_to_username(Address);
		RoutingType = "smtp";
	}
	if(RoutingType == "smtp") {
		char temp[256];
		if(!m_plugin.mysql.get_maildir(Address.c_str(), temp, std::size(temp)))
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
	const char* target = folder.target? folder.target->c_str() : m_auth_info.username;
	const char* at = strchr(target, '@');
	bool isPublic = folder.location == sFolderSpec::AUTO? at == nullptr : folder.location == sFolderSpec::PUBLIC;
	auto func = isPublic? m_plugin.mysql.get_homedir : m_plugin.mysql.get_maildir;
	if(isPublic && at)
		target = at+1;
	char targetDir[256];
	if (!func(target, targetDir, std::size(targetDir)))
		throw EWSError::CannotFindUser(E3126);
	return targetDir;
}

/**
 * @brief      Get cached events from all subscriptions
 *
 * Loads up to 50 cached events as specified in
 * https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/getevents-operation#remarks.
 *
 * @param subscription   Subscription ID
 *
 * @return List of events and indicator whether there are more events
 */
std::pair<std::list<sNotificationEvent>, bool> EWSContext::getEvents(const tSubscriptionId& subscriptionId) const
{
	auto subscription = m_plugin.subscription(subscriptionId.ID, subscriptionId.timeout);
	if(!subscription)
		throw EWSError::InvalidSubscription(E3202);
	if(subscription->username != m_auth_info.username)
		throw EWSError::AccessDenied(E3203);
	std::pair<std::list<sNotificationEvent>, bool> result{{}, subscription->events.size() > 50};
	auto& evt = subscription->events;
	if(result.second) {
		auto it = evt.begin();
		std::advance(it, 50);
		result.first.splice(result.first.end(), evt, evt.begin(), it);
	}
	else
		result.first.splice(result.first.end(), evt);
	return result;
}

/**
 * @brief     Get entry ID property of folder
 *
 * Also works on non-existant folders.
 *
 * @param     dir       Store directory
 * @param     folderId  Folder ID
 *
 * @return    Tagged property containing the entry ID
 */
TAGGED_PROPVAL EWSContext::getFolderEntryId(const std::string& dir, uint64_t folderId) const
{
	static constexpr uint32_t propids[] = {PR_ENTRYID};
	PROPTAG_ARRAY proptags{1, const_cast<uint32_t*>(propids)};
	TPROPVAL_ARRAY props = getFolderProps(dir, folderId, proptags);
	if(props.count != 1 || props.ppropval->proptag != PR_ENTRYID)
		throw EWSError::FolderPropertyRequestFailed(E3022);
	return *props.ppropval;
}

/**
 * @brief     Get properties of specified folder
 *
 * @param     dir       Store directory
 * @param     folderId  Folder ID
 * @param     props     Properties to get
 *
 * @return    Property values
 */
TPROPVAL_ARRAY EWSContext::getFolderProps(const std::string& dir, uint64_t folderId, const PROPTAG_ARRAY& props) const
{
	TPROPVAL_ARRAY result;
	if (!m_plugin.exmdb.get_folder_properties(dir.c_str(), CP_ACP, folderId, &props, &result))
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
 * @brief      Get folder property value
 *
 * @param      dir   Store directory
 * @param      fid   Folder ID
 * @param      tag   Tag ID
 *
 * @return     Pointer to property value or nullptr if not found
 */
const void* EWSContext::getFolderProp(const std::string& dir, uint64_t fid, uint32_t tag) const
{
	PROPTAG_ARRAY proptags{1, &tag};
	TPROPVAL_ARRAY props = getFolderProps(dir, fid, proptags);
	if(props.count != 1 || props.ppropval->proptag != tag)
		throw EWSError::FolderPropertyRequestFailed(E3169);
	return props.ppropval->pvalue;
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
	return props.ppropval->pvalue;
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
	if (!m_plugin.exmdb.get_message_properties(dir.c_str(), m_auth_info.username,
	    CP_ACP, mid, &props, &result))
		throw EWSError::ItemPropertyRequestFailed(E3025);
	return result;
}

/**
 * @brief      Get mailbox GUID from store property
 *
 * @param      dir   Store directory
 *
 * @return     GUID of the mailbox
 */
GUID EWSContext::getMailboxGuid(const std::string& dir) const
{
	static const uint32_t recordKeyTag = PR_STORE_RECORD_KEY;
	static constexpr PROPTAG_ARRAY recordKeyTags{1, const_cast<uint32_t*>(&recordKeyTag)};
	TPROPVAL_ARRAY recordKeyProp;
	if(!m_plugin.exmdb.get_store_properties(dir.c_str(), CP_ACP, &recordKeyTags, &recordKeyProp) ||
	   recordKeyProp.count != 1 || recordKeyProp.ppropval->proptag != PR_STORE_RECORD_KEY)
		throw DispatchError(E3194);
	const BINARY* recordKeyData = static_cast<const BINARY*>(recordKeyProp.ppropval->pvalue);
	EXT_PULL guidPull;
	guidPull.init(recordKeyData->pv, recordKeyData->cb, alloc, 0);
	GUID mailboxGuid;
	ext_error(guidPull.g_guid(&mailboxGuid));
	return mailboxGuid;
}

/**
 * @brief      Collect mailbox metadata
 *
 * @param      dir       Store directory
 * @param      isDomain  Whether target is a domain
 *
 * @return     Mailbox metadata struct
 */
sMailboxInfo EWSContext::getMailboxInfo(const std::string& dir, bool isDomain) const
{
	sMailboxInfo mbinfo{getMailboxGuid(dir), 0, isDomain};
	auto getId = isDomain? m_plugin.mysql.get_id_from_homedir : m_plugin.mysql.get_id_from_maildir;
	if(!getId(dir.c_str(), &mbinfo.accountId))
		throw EWSError::CannotFindUser(E3192(isDomain? "domain" : "user", dir));
	return mbinfo;
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
	auto aInst = m_plugin.loadAttachmentInstance(dir, aid.folderId(), aid.messageId(), aid.attachment_num);
	static uint32_t tagIDs[] = {PR_ATTACH_METHOD, PR_DISPLAY_NAME, PR_ATTACH_MIME_TAG, PR_ATTACH_DATA_BIN,
	                            PR_ATTACH_CONTENT_ID, PR_ATTACH_LONG_FILENAME, PR_ATTACHMENT_FLAGS};
	TPROPVAL_ARRAY props;
	PROPTAG_ARRAY tags{std::size(tagIDs), tagIDs};
	if(!m_plugin.exmdb.get_instance_properties(dir.c_str(), 0, aInst->instanceId, &tags, &props))
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
sFolder EWSContext::loadFolder(const std::string& dir, uint64_t folderId, Structures::sShape& shape) const
{
	shape.clean();
	getNamedTags(dir, shape);
	shape.properties(getFolderProps(dir, folderId, shape.proptags()));
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
	auto& exmdb = m_plugin.exmdb;
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
		if (!oxcmail_export(content, false, oxcmail_body::plain_and_html, &mail,
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
		static uint32_t tagIDs[] = {PR_ATTACH_METHOD, PR_DISPLAY_NAME, PR_ATTACH_MIME_TAG, PR_ATTACH_CONTENT_ID,
			                        PR_ATTACH_LONG_FILENAME, PR_ATTACHMENT_FLAGS};
		auto mInst = m_plugin.loadMessageInstance(dir, fid, mid);
		uint16_t count;
		if(!exmdb.get_message_instance_attachments_num(dir.c_str(), mInst->instanceId, &count))
			throw DispatchError(E3079);
		sAttachmentId aid(this->getItemEntryId(dir, mid), 0);
		item.Attachments.emplace().reserve(count);
		for(uint16_t i = 0; i < count; ++i)
		{
			auto aInst = m_plugin.loadAttachmentInstance(dir, fid, mid, i);
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
	if (!(special & sShape::Recipients))
		return;
	TARRAY_SET rcpts;
	if (!m_plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts))
	{
		mlog(LV_ERR, "[ews] failed to load message recipients (%s:%llu)",
			dir.c_str(), static_cast<unsigned long long>(mid));
		return;
	}
	for (TPROPVAL_ARRAY **tps = rcpts.pparray; tps < &rcpts.pparray[rcpts.count]; ++tps)
	{
		uint32_t *recipientType = (*tps)->get<uint32_t>(PR_RECIPIENT_TYPE);
		if (!recipientType)
			continue;
		switch (*recipientType)
		{
		case MAPI_TO:
			if (special & sShape::ToRecipients)
				defaulted(message.ToRecipients).emplace_back(**tps);
			break;
		case MAPI_CC:
			if (special & sShape::CcRecipients)
				defaulted(message.CcRecipients).emplace_back(**tps);
			break;
		case MAPI_BCC:
			if (special & sShape::BccRecipients)
				defaulted(message.BccRecipients).emplace_back(**tps);
			break;
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
	if (!(special & sShape::Attendees))
		return;
	TARRAY_SET rcpts;
	if (!m_plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts))
	{
		mlog(LV_ERR, "[ews] failed to load calItem recipients (%s:%llu)",
			dir.c_str(), static_cast<unsigned long long>(mid));
		return;
	}
	for (TPROPVAL_ARRAY **tps = rcpts.pparray; tps < &rcpts.pparray[rcpts.count]; ++tps)
	{
		uint32_t *recipientType = (*tps)->get<uint32_t>(PR_RECIPIENT_TYPE);
		if (!recipientType)
			continue;
		switch (*recipientType)
		{
		case 1: //Required attendee
			if (special & sShape::RequiredAttendees)
				defaulted(calItem.RequiredAttendees).emplace_back(**tps);
			break;
		case 2: //Optional attendee
			if (special & sShape::OptionalAttendees)
				defaulted(calItem.OptionalAttendees).emplace_back(**tps);
			break;
		case 3: //Resource
			if (special & sShape::Resources)
				defaulted(calItem.Resources).emplace_back(**tps);
			break;
		}
	}
}

/**
 * @brief update properties of a tCalendarItem
 *
 * @param calItem     Calendar item
 * @param shape       Requested item shape
 * @param props       Properties to update
 */
void EWSContext::updateProps(tCalendarItem& calItem, sShape& shape, const TPROPVAL_ARRAY& props) const
{
	shape.clean();
	shape.properties(props);
	calItem.update(shape);
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
 * @brief      Load occurrence
 *
 * @param      dir      Store directory
 * @param      fid      Parent folder ID
 * @param      mid      Message ID
 * @param      basedate Basedate of the occurrence
 * @param      shape    Requested item shape
 *
 * @return     The s item.
 */
sItem EWSContext::loadOccurrence(const std::string& dir, uint64_t fid, uint64_t mid, uint32_t basedate, sShape& shape) const
{
	auto mInst = m_plugin.loadMessageInstance(dir, fid, mid);
	uint16_t count;
	if(!m_plugin.exmdb.get_message_instance_attachments_num(dir.c_str(), mInst->instanceId, &count))
		throw DispatchError(E3210);

	shape.clean();
	getNamedTags(dir, shape);
	shape.properties(getItemProps(dir, mid, shape.proptags()));
	PROPNAME_ARRAY propnames;
	propnames.count = 1;
	PROPERTY_NAME propname_buff[1];
	propname_buff[0].kind = MNID_ID;
	propname_buff[0].guid = PSETID_APPOINTMENT;
	propname_buff[0].lid = PidLidExceptionReplaceTime;
	propnames.ppropname = propname_buff;
	PROPID_ARRAY namedids = getNamedPropIds(dir, propnames, true);
	auto ex_replace_time_tag = PROP_TAG(PT_SYSTIME, namedids.ppropid[0]);
	TPROPVAL_ARRAY props;
	PROPTAG_ARRAY tags = shape.proptags();
	tags.emplace_back(ex_replace_time_tag);

	time_t basedate_ts = gromox::time_point::clock::to_time_t(rop_util_rtime_to_unix2(basedate));
	struct tm basedate_local;
	localtime_r(&basedate_ts, &basedate_local);

	for(uint16_t i = 0; i < count; ++i)
	{
		auto aInst = m_plugin.loadAttachmentInstance(dir, fid, mid, i);
		auto eInst = m_plugin.loadEmbeddedInstance(dir, aInst->instanceId);
		if(!m_plugin.exmdb.get_instance_properties(dir.c_str(), 0, eInst->instanceId, &tags, &props))
			throw DispatchError(E3211);

		const uint64_t* exstarttime = props.get<uint64_t>(ex_replace_time_tag);
		if(!exstarttime)
			continue;
		time_t exstart = gromox::time_point::clock::to_time_t(rop_util_nttime_to_unix2(*exstarttime));
		struct tm exstart_local;
		localtime_r(&exstart, &exstart_local);
		if(is_same_day(basedate_local, exstart_local))
		{
			sItem item = tItem::create(shape);
			if(shape.special)
				std::visit([&](auto &&it) { loadSpecial(dir, fid, mid, it, shape.special); }, item);
			std::visit([&](auto &&it) { updateProps(it, shape, props); }, item);

			return item;
		}
	}
	throw EWSError::ItemCorrupt(E3209);
}

/**
 * @brief      Generate initial predecessor change list from xid
 *
 * @param      xid  Initial change key
 *
 * @return     Serialized predecessor change list buffer
 */
std::unique_ptr<BINARY, detail::Cleaner> EWSContext::mkPCL(const XID& xid, PCL pcl) const
{
	if(!pcl.append(xid))
		throw DispatchError(E3121);
	std::unique_ptr<BINARY, detail::Cleaner> pcltemp(pcl.serialize());
	if(!pcltemp)
		throw EWSError::NotEnoughMemory(E3122);
	return pcltemp;
}

/**
 * @brief      Move or copy a folder
 *
 * @param      dir         Store directory
 * @param      folderId    Id of the folder to move/copy
 * @param      newParent   Id of the target folder
 * @param      accountId   Account ID of the executing user
 * @param      copy        Whether to copy the folder (instead of moving)
 *
 * @return     ID of the new folder if copied
 */
uint64_t EWSContext::moveCopyFolder(const std::string& dir, const sFolderSpec& folder, uint64_t newParent, uint32_t accountId,
                                    bool copy) const
{
	static uint32_t tagIds[] = {PidTagParentFolderId, PR_DISPLAY_NAME};
	static const PROPTAG_ARRAY tags{std::size(tagIds), tagIds};
	TPROPVAL_ARRAY props;
	if(!m_plugin.exmdb.get_folder_properties(dir.c_str(), CP_ACP, folder.folderId, &tags, &props))
		throw DispatchError(E3159);
	uint64_t* parentFid = props.get<uint64_t>(PidTagParentFolderId);
	const char* folderName = props.get<char>(PR_DISPLAY_NAME);
	if(!parentFid || !folderName)
		throw DispatchError(E3160);
	sFolderSpec parentFolder = folder;
	parentFolder.folderId = *parentFid;
	if(!(permissions(m_auth_info.username, folder, dir.c_str()) & frightsDeleteAny) ||
	   !(permissions(m_auth_info.username, parentFolder, dir.c_str()) & frightsDeleteAny))
			throw EWSError::AccessDenied(E3157);
	ec_error_t errcode = ecSuccess;
	if (!m_plugin.exmdb.movecopy_folder(dir.c_str(), accountId, CP_ACP, false,
	    m_auth_info.username, *parentFid, folder.folderId, newParent,
	    folderName, copy ? TRUE : false, &errcode))
		throw EWSError::MoveCopyFailed(E3161);
	if (errcode == ecDuplicateName)
		throw EWSError::FolderExists(E3162);
	if (errcode != ecSuccess)
		throw EWSError::MoveCopyFailed(std::string(E3163) + ": " + mapi_strerror(errcode));
	if(!copy) {
		updated(dir, folder);
		return folder.folderId;
	}
	uint64_t newFolderId;
	if(!m_plugin.exmdb.get_folder_by_name(dir.c_str(), newParent, folderName, &newFolderId))
		throw DispatchError(E3164);
	return newFolderId;
}

/**
 * @brief      Move or copy message object
 *
 * @param      dir         Store directory
 * @param      itemId      Message iD
 * @param      newParent   Destination folder
 * @param      accountId   Account ID of executing user
 * @param      copy        Whether to copy (instead of moving)
 *
 * @return     New message ID
 */
uint64_t EWSContext::moveCopyItem(const std::string& dir, const sMessageEntryId& meid, uint64_t newParent, bool copy) const
{
	auto& exmdb = m_plugin.exmdb;
	uint64_t newId;
	if(!exmdb.allocate_message_id(dir.c_str(), newParent, &newId))
		throw DispatchError(E3182);
	BOOL success;
	if(!m_plugin.exmdb.movecopy_message(dir.c_str(), 0, CP_ACP, meid.messageId(), newParent, newId, copy? false : TRUE, &success)
	                                  || !success)
		throw EWSError::MoveCopyFailed(E3183);
	return newId;
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
	m_plugin.exmdb.get_folder_perm(maildir, folder.folderId, username, &permissions);
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
	folder.target = m_auth_info.username;
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
	assertIdType(fId.type, tFolderId::ID_FOLDER);
	sFolderEntryId eid(fId.Id.data(), fId.Id.size());
	sFolderSpec folderSpec;
	folderSpec.location = eid.isPrivate()? sFolderSpec::PRIVATE : sFolderSpec::PUBLIC;
	folderSpec.folderId = rop_util_make_eid_ex(1, rop_util_gc_to_value(eid.global_counter));
	if(eid.isPrivate())
	{
		char temp[UADDR_SIZE];
		if(!m_plugin.mysql.get_username_from_id(eid.accountId(), temp, UADDR_SIZE))
			throw EWSError::CannotFindUser(E3026);
		folderSpec.target = temp;
	}
	else
	{
		sql_domain domaininfo;
		if(!m_plugin.mysql.get_domain_info(eid.accountId(), domaininfo))
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
sFolderSpec EWSContext::resolveFolder(const sFolderId& fId) const
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
		if(!m_plugin.mysql.get_username_from_id(eid.accountId(), temp, UADDR_SIZE))
			throw EWSError::CannotFindUser(E3075);
		folderSpec.target = temp;
	}
	else
	{
		sql_domain domaininfo;
		if(!m_plugin.mysql.get_domain_info(eid.accountId(), domaininfo))
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
	if (!oxcmail_export(&content, false, oxcmail_body::plain_and_html,
	    &mail, alloc, getPropIds,getPropName))
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
	ec_error_t err = cu_send_mail(mail, "smtp", m_plugin.smtp_server_ip.c_str(), m_plugin.smtp_server_port, m_auth_info.username,
	                              rcpts);
	if(err != ecSuccess)
		throw DispatchError(E3117(err));
}

/**
 * @brief      Serialize XID to BINARY
 *
 * The internal buffer of the BINARY is stack allocated and must not be
 * manually freed.
 *
 * @param      xid   XID object to serialize
 *
 * @return     BINARY objet containing serialize data
 */
BINARY EWSContext::serialize(const XID& xid) const
{
	uint8_t* buff = alloc<uint8_t>(xid.size);
	EXT_PUSH ext_push;
	if(!ext_push.init(buff, xid.size, 0) || ext_push.p_xid(xid) != EXT_ERR_SUCCESS)
		throw DispatchError(E3120);
	return BINARY{ext_push.m_offset, {buff}};
}

/**
 * @brief      Add subscription to notification context
 *
 * @param      subscriptionId  Subscription to add
 *
 * @return     true if subscription was added, false on error (not found or no access)
 */
bool EWSContext::streamEvents(const tSubscriptionId& subscriptionId) const
{
	if(m_notify)
		m_notify->subscriptions.emplace_back(subscriptionId);
	return m_plugin.linkSubscription(subscriptionId, *this);
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
	const auto& exmdb = m_plugin.exmdb;
	uint64_t messageId, changeNumber;
	BINARY *ckey = nullptr, *pclbin = nullptr;

	if(persist) {
		if(!exmdb.allocate_message_id(dir.c_str(), parent.folderId, &messageId))
			throw DispatchError(E3118);
		if(!exmdb.allocate_cn(dir.c_str(), &changeNumber))
			throw DispatchError(E3119);

		bool isPublic = parent.location == parent.PUBLIC;
		uint32_t accountId = getAccountId(*parent.target, isPublic);
		XID xid((parent.location == parent.PRIVATE? rop_util_make_user_guid : rop_util_make_domain_guid)(accountId), changeNumber);

		ckey = construct<BINARY>(serialize(xid));

		auto pcltemp = mkPCL(xid);
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
		MAIL mail;
		if(!mail.load_from_str_move(reinterpret_cast<char*>(item.MimeContent->data()), item.MimeContent->size()))
			throw EWSError::ItemCorrupt(E3123);
		auto getPropIds = [&](const PROPNAME_ARRAY* names, PROPID_ARRAY* ids)
		{*ids = getNamedPropIds(dir, *names, true); return TRUE;};
		std::unique_ptr<MESSAGE_CONTENT, detail::Cleaner> cnt(oxcmail_import("utf-8", "UTC", &mail, EWSContext::alloc,
		                                                                     getPropIds));
		if(!cnt)
			throw EWSError::ItemCorrupt(E3124);
		content = std::move(*cnt);
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
 * @brief      Mark folder as updated
 *
 * @param      dir       Home directory of user or domain
 * @param      folder    Folder to update
 */
void EWSContext::updated(const std::string& dir, const sFolderSpec& folder) const
{
	if(!folder.target)
		throw DispatchError(E3172);
	const BINARY* pclData = getFolderProp<BINARY>(dir, folder.folderId, PR_PREDECESSOR_CHANGE_LIST);
	PCL pclOld;
	if(pclData && !pclOld.deserialize(pclData))
		throw DispatchError(E3170);
	uint64_t changeNum;
	if(!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNum))
		throw DispatchError(E3171);
	bool isPublic = folder.location == folder.PUBLIC;
	uint32_t accountId = getAccountId(*folder.target, isPublic);
	XID changeKey{(isPublic? rop_util_make_domain_guid : rop_util_make_user_guid)(accountId), changeNum};
	BINARY ckeyBin = serialize(changeKey);
	auto ppcl = mkPCL(changeKey, std::move(pclOld));
	uint64_t now = rop_util_current_nttime();
	TAGGED_PROPVAL props[] = {{PidTagChangeNumber, &changeNum},
		                      {PR_CHANGE_KEY, &ckeyBin,},
		                      {PR_PREDECESSOR_CHANGE_LIST, ppcl.get()},
		                      {PR_LAST_MODIFICATION_TIME, &now}};
	TPROPVAL_ARRAY proplist{std::size(props), props};
	PROBLEM_ARRAY problems;
	if(!m_plugin.exmdb.set_folder_properties(dir.c_str(), CP_ACP, folder.folderId, &proplist, &problems) || problems.count)
		throw EWSError::FolderSave(E3173);
}

/**
 * @brief      Create subscriptions
 *
 * @param      folderIds  Folders to subscribe to
 * @param      eventMask  Events to subscribe to
 * @param      all        Whether to subscribe to all folders
 * @param      timeout    Timeout (minutes) of the subscription
 *
 * @return     Subscription ID
 */
tSubscriptionId EWSContext::subscribe(const std::vector<sFolderId>& folderIds, uint16_t eventMask, bool all, uint32_t timeout) const
{
	tSubscriptionId subscriptionId(timeout);
	auto subscription = m_plugin.mksub(subscriptionId, m_auth_info.username);
	if(folderIds.empty()) {
		subscription->mailboxInfo = getMailboxInfo(m_auth_info.maildir, false);
		detail::ExmdbSubscriptionKey key =
			m_plugin.subscribe(m_auth_info.maildir, eventMask, true, rop_util_make_eid_ex(PRIVATE_FID_IPMSUBTREE, 1),
		                       subscriptionId.ID);
		subscription->subscriptions.emplace_back(key);
		return subscriptionId;
	}
	subscription->subscriptions.reserve(folderIds.size());
	std::string target;
	std::string maildir;
	for(const sFolderId& f : folderIds) {
		sFolderSpec folderspec = std::visit([&](const auto& fid){return resolveFolder(fid);}, f);
		if(!folderspec.target)
			folderspec.target = m_auth_info.username;
		if(target.empty()) {
			target = *folderspec.target;
			maildir = get_maildir(*folderspec.target);
			subscription->mailboxInfo = getMailboxInfo(maildir, folderspec.location == folderspec.PUBLIC);
		} else if(target != *folderspec.target)
			throw EWSError::InvalidSubscriptionRequest(E3200);
		if(!(permissions(m_auth_info.username, folderspec) & frightsReadAny))
			continue; // TODO: proper error handling
		subscription->subscriptions.emplace_back(m_plugin.subscribe(maildir, eventMask, all, folderspec.folderId,
		                                                            subscriptionId.ID));
	}
	return subscriptionId;
}

/**
 * @brief      Create new pull subscription
 *
 * @param      req    Pull subscription request
 *
 * @return     Subscription ID
 */
tSubscriptionId EWSContext::subscribe(const tPullSubscriptionRequest& req) const
{
	bool all = req.SubscribeToAllFolders && *req.SubscribeToAllFolders;
	if(all && req.FolderIds)
		throw EWSError::InvalidSubscriptionRequest(E3198);
	return subscribe(req.FolderIds? *req.FolderIds : std::vector<sFolderId>(), req.eventMask(), all, req.Timeout);
}

/**
 * @brief      Create new streaming subscription
 *
 * @param      req    Streaming subscription request
 *
 * @return     Subscription ID
 */
tSubscriptionId EWSContext::subscribe(const tStreamingSubscriptionRequest& req) const
{
	bool all = req.SubscribeToAllFolders && *req.SubscribeToAllFolders;
	if(all && req.FolderIds)
		throw EWSError::InvalidSubscriptionRequest(E3198);
	return subscribe(req.FolderIds? *req.FolderIds : std::vector<sFolderId>(), req.eventMask(), all, 5);
}

/**
 * @brief     End subscriptions
 *
 * @param subscriptionId   Subscription to remove
 */
bool EWSContext::unsubscribe(const Structures::tSubscriptionId& subscriptionId) const
{return m_plugin.unsubscribe(subscriptionId.ID, m_auth_info.username);}

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
	if(!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNum))
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
	if(!m_plugin.mysql.get_user_displayname(m_auth_info.username, displayName, std::size(displayName)) || !*displayName)
		_props[props.count++].pvalue = displayName;
	else
		_props[props.count++].pvalue = const_cast<char*>(m_auth_info.username);

	uint8_t abEidBuff[1280];
	EXT_PUSH wAbEid;
	std::string essdn = username_to_essdn(m_auth_info.username);
	EMSAB_ENTRYID abEid{0, 1, DT_MAILUSER, essdn.data()};
	if(!wAbEid.init(abEidBuff, std::size(abEidBuff), EXT_FLAG_UTF16) || wAbEid.p_abk_eid(abEid) != EXT_ERR_SUCCESS)
		throw DispatchError(E3085);
	BINARY abEidContainer{wAbEid.m_offset, {abEidBuff}};
	_props[props.count].proptag = PR_LAST_MODIFIER_ENTRYID;
	_props[props.count++].pvalue = &abEidContainer;

	XID changeKey{(mid.isPrivate()? rop_util_make_user_guid : rop_util_make_domain_guid)(mid.accountId()), changeNum};
	BINARY changeKeyContainer = serialize(changeKey);
	_props[props.count].proptag = PR_CHANGE_KEY;
	_props[props.count++].pvalue = &changeKeyContainer;

	const BINARY* currentPclContainer = getItemProp<BINARY>(dir, mid.messageId(), PR_PREDECESSOR_CHANGE_LIST);
	PCL pcl;
	if(!currentPclContainer || !pcl.deserialize(currentPclContainer))
		throw DispatchError(E3087);
	auto serializedPcl = mkPCL(changeKey, std::move(pcl));
	_props[props.count].proptag = PR_PREDECESSOR_CHANGE_LIST;
	_props[props.count++].pvalue = serializedPcl.get();

	_props[props.count].proptag = PidTagChangeNumber;
	_props[props.count++].pvalue = &changeNum;

	PROBLEM_ARRAY problems;
	if(!m_plugin.exmdb.set_message_properties(dir.c_str(), nullptr, CP_ACP, mid.messageId(), &props, &problems))
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
	if(!m_plugin.mysql.get_user_ids(username.c_str(), &userId, &domainId, nullptr))
		throw EWSError::CannotFindUser(E3091(username));
	return fmt::format("/o={}/" EAG_RCPTS "/cn={:08x}{:08x}-{}",
	                   m_plugin.x500_org_name.c_str(), domainId, userId, userpart);
}

/**
 * @brief      Validate consistency of message entry id
 *
 * @param      meid          Message entry id to validate
 * @param      throwOnError  Whether to throw an appropriate EWSError instead of returning
 *
 * @return     true if entry id is consistent, false otherwise (and throwOnError is false)
 */
void EWSContext::validate(const std::string& dir, const sMessageEntryId& meid) const
{
	const uint64_t* parentFid = nullptr;
	try {
		parentFid = getItemProp<uint64_t>(dir, meid.messageId(), PidTagParentFolderId);
	} catch (const DispatchError&) {
	}
	if(!parentFid)
		throw EWSError::ItemNotFound(E3187);
	if(rop_util_get_gc_value(*parentFid) != meid.folderId())
		throw EWSError::InvalidId(E3188);
}

/**
 * @brief     Check whether id is of the correct type
 *
 * @param     have       Observed ID type
 * @param     wanted     Expected ID type
 *
 * @throw     EWSError   Exception with details
 */
void EWSContext::assertIdType(tBaseItemId::IdType have, tBaseItemId::IdType wanted)
{
	using IdType = tBaseItemId::IdType;
	if(have == wanted)
		return;
	if(wanted == IdType::ID_FOLDER && have == IdType::ID_ITEM)
		throw EWSError::CannotUseItemIdForFolderId(E3213);
	else if(wanted == IdType::ID_ITEM && have == IdType::ID_FOLDER)
		throw EWSError::CannotUseFolderIdForItemId(E3214);
	else if(wanted == IdType::ID_ATTACHMENT)
		throw EWSError::InvalidIdNotAnItemAttachmentId(E3215);
	throw EWSError::InvalidId(E3216);
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
	case EXT_ERR_BUFSIZE:
	default:
		if(responseCode && msg)
			throw Exceptions::EWSError(responseCode, msg);
		else
			throw DispatchError(code == EXT_ERR_BUFSIZE? E3145 : Exceptions::E3028(int(code)));
	}
}

}
