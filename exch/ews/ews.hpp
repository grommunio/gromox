// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once
#include <optional>
#include <unordered_map>
#include <variant>

#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/hpm_common.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/mapi_types.hpp>

#include "ObjectCache.hpp"
#include "soaputil.hpp"

struct MIME_POOL;

namespace gromox::EWS {

namespace Structures
{
struct sAttachmentId;
struct sMessageEntryId;
class  sShape;
struct sFolderSpec;
struct tCalendarFolderType;
struct tCalendarItem;
struct tContact;
struct tContactsFolderType;
struct tDistinguishedFolderId;
struct tFileAttachment;
struct tFolderId;
struct tFolderResponseShape;
struct tFolderType;
struct tItem;
struct tItemAttachment;
struct tItemResponseShape;
struct tMailbox;
struct tMessage;
struct tPath;
struct tReferenceAttachment;
struct tSerializableTimeZone;
struct tSearchFolderType;
struct tTasksFolderType;

using sAttachment = std::variant<tItemAttachment, tFileAttachment, tReferenceAttachment>;
using sFolder = std::variant<tFolderType, tCalendarFolderType, tContactsFolderType, tSearchFolderType, tTasksFolderType>;
using sItem = std::variant<tItem, tMessage, tCalendarItem, tContact>;
}


class EWSContext;

/**
 * @brief      Aggregation of plugin data and functions
 */
class EWSPlugin
{
public:
	using Handler = void (*)(const tinyxml2::XMLElement *, tinyxml2::XMLElement *, const EWSContext &);

	EWSPlugin();

	BOOL proc(int, const void*, uint64_t);
	static BOOL preproc(int);

	bool logEnabled(const std::string_view&) const;

	struct _mysql {
		_mysql();

		decltype(mysql_adaptor_get_homedir)* get_homedir;
		decltype(mysql_adaptor_get_maildir)* get_maildir;
		decltype(mysql_adaptor_get_domain_info)* get_domain_info;
		decltype(mysql_adaptor_get_username_from_id)* get_username_from_id;
		decltype(mysql_adaptor_get_user_aliases) *get_user_aliases;
		decltype(mysql_adaptor_get_user_properties) *get_user_properties;
	} mysql; ///< mysql adaptor function pointers

	struct _exmdb {
		_exmdb();

	#define EXMIDL(n, p) BOOL (*n) p;
	#define IDLOUT
	#include <gromox/exmdb_idef.hpp>
	#undef EXMIDL
	#undef IDLOUT
		bool get_message_property(const char*, const char*, cpid_t, uint64_t, uint32_t, void **ppval) const;
	} exmdb;

	struct ExmdbInstance {
		const EWSPlugin& plugin; ///< Plugin used to release the instance
		std::string dir; ///< Home directory of domain or user
		uint32_t instanceId; ///< Instance ID

		ExmdbInstance(const EWSPlugin&, const std::string&, uint32_t);
		ExmdbInstance(const ExmdbInstance&) = delete;
		ExmdbInstance& operator=(const ExmdbInstance&) = delete;
		~ExmdbInstance();
	};

	std::shared_ptr<ExmdbInstance> loadAttachmentInstance(const std::string&, uint64_t, uint64_t, uint32_t) const;
	std::shared_ptr<ExmdbInstance> loadMessageInstance(const std::string&, uint64_t, uint64_t) const;

	std::string x500_org_name; ///< organization name or empty string if not configured
	int request_logging = 0; ///< 0 = none, 1 = request names, 2 = request data
	int response_logging = 0; ///< 0 = none, 1 = response names, 2 = response data
	int pretty_response = 0; ///< 0 = compact output, 1 = pretty printed response
	int experimental = 0; ///< Enable experimental requests, 0 = disabled
	std::chrono::milliseconds cache_interval{10'000}; ///< Interval for cache cleanup
	std::chrono::milliseconds cache_attachment_instance_lifetime{30'000}; /// Lifetime of attachment instances
	std::chrono::milliseconds cache_message_instance_lifetime{30'000}; /// Lifetime of message instances

	std::shared_ptr<MIME_POOL> mimePool;
private:
	struct AttachmentInstanceKey;
	struct MessageInstanceKey;

	using CacheKey = std::variant<AttachmentInstanceKey, MessageInstanceKey>;
	using CacheObj = std::variant<std::shared_ptr<ExmdbInstance>>;
	struct DebugCtx;
	static const std::unordered_map<std::string, Handler> requestMap;

	static void writeheader(int, int, size_t);

	mutable ObjectCache<CacheKey, CacheObj> cache;

	std::unique_ptr<DebugCtx> debug;
	std::vector<std::string> logFilters;
	bool invertFilter = true;

	std::pair<std::string, int> dispatch(int, HTTP_AUTH_INFO&, const void*, uint64_t, bool&);
	void loadConfig();

};

/**
 * @brief      EWS request context
 */
class EWSContext
{
public:
	inline EWSContext(int id, HTTP_AUTH_INFO ai, const char *data, uint64_t length, EWSPlugin &p) :
		ID(id), orig(*get_request(id)), auth_info(ai), request(data, length), plugin(p)
	{}

	std::string essdn_to_username(const std::string&) const;
	std::string get_maildir(const Structures::tMailbox&) const;
	std::string get_maildir(const std::string&) const;
	std::string getDir(const Structures::sFolderSpec&) const;
	TAGGED_PROPVAL getFolderEntryId(const Structures::sFolderSpec&) const;
	TPROPVAL_ARRAY getFolderProps(const Structures::sFolderSpec&, const PROPTAG_ARRAY&) const;
	TAGGED_PROPVAL getItemEntryId(const std::string&, uint64_t) const;
	template<typename T> const T* getItemProp(const std::string&, uint64_t, uint32_t) const;
	TPROPVAL_ARRAY getItemProps(const std::string&, uint64_t, const PROPTAG_ARRAY&) const;
	PROPID_ARRAY getNamedPropIds(const std::string&, const PROPNAME_ARRAY&) const;
	Structures::sAttachment loadAttachment(const std::string&,const Structures::sAttachmentId&) const;
	Structures::sFolder loadFolder(const Structures::sFolderSpec&, Structures::sShape&) const;
	Structures::sItem loadItem(const std::string&, uint64_t, uint64_t, Structures::sShape&) const;
	void normalize(Structures::tMailbox&) const;
	uint32_t permissions(const char*, const Structures::sFolderSpec&, const char* = nullptr) const;
	Structures::sFolderSpec resolveFolder(const Structures::tDistinguishedFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::tFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::sMessageEntryId&) const;

	void experimental() const;

	int ID = 0;
	HTTP_REQUEST& orig;
	HTTP_AUTH_INFO auth_info{};
	SOAP::Envelope request;
	SOAP::Envelope response;
	EWSPlugin& plugin;

	static void* alloc(size_t);
	static void ext_error(pack_result);

private:
	const void* getItemProp(const std::string&, uint64_t, uint32_t) const;
	void getNamedTags(const std::string&, Structures::sShape&) const;

	void loadSpecial(const std::string&, uint64_t, uint64_t, Structures::tItem&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, uint64_t, Structures::tMessage&, uint64_t) const;

	PROPERTY_NAME* getPropertyName(const std::string&, uint16_t) const;
};

/**
 * @brief      Get single item property
 *
 * @param      dir   Store directory
 * @param      mid   Message ID
 * @param      tag   Tag ID
 *
 * @tparam     T     Type to return
 *
 * @return     Pointer to property or nullptr if not found.
 */
template<typename T>
const T* EWSContext::getItemProp(const std::string& dir, uint64_t mid, uint32_t tag) const
{return static_cast<const T*>(getItemProp(dir, mid, tag));}

}
