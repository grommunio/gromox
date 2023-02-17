// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once
#include <optional>
#include <unordered_map>

#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/hpm_common.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/mapi_types.hpp>

#include "soaputil.hpp"

namespace gromox::EWS {

namespace Structures
{
struct sProptags;
struct sFolderSpec;
struct tDistinguishedFolderId;
struct tFolderId;
struct tFolderResponseShape;
struct tItemResponseShape;
struct tMailbox;
struct tPath;
struct tSerializableTimeZone;
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
	} mysql; ///< mysql adaptor function pointers

	struct _exmdb {
		_exmdb();

	#define EXMIDL(n, p) BOOL (*n) p;
	#define IDLOUT
	#include <gromox/exmdb_idef.hpp>
	#undef EXMIDL
	#undef IDLOUT
	} exmdb;

	std::string x500_org_name; ///< organization name or empty string if not configured
	int request_logging = 0; ///< 0 = none, 1 = request names, 2 = request data
	int response_logging = 0; ///< 0 = none, 1 = response names, 2 = response data
	int pretty_response = 0; ///< 0 = compact output, 1 = pretty printed response
	int experimental = 0; ///< Enable experimental requests, 0 = disabled

private:
	static const std::unordered_map<std::string, Handler> requestMap;

	static void writeheader(int, int, size_t);

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
	inline EWSContext(int ID, HTTP_AUTH_INFO auth_info, const char* data, uint64_t length, EWSPlugin& plugin)
       : ID(ID), orig(*get_request(ID)), auth_info(auth_info), request(data, length), plugin(plugin)
	{}

	Structures::sProptags collectTags(const Structures::tItemResponseShape&, const std::optional<std::string>& = std::nullopt) const;
	Structures::sProptags collectTags(const Structures::tFolderResponseShape&, const std::optional<std::string>& = std::nullopt) const;
	std::string essdn_to_username(const std::string&) const;
	std::string get_maildir(const Structures::tMailbox&) const;
	std::string get_maildir(const std::string&) const;
	std::string getDir(const Structures::sFolderSpec&) const;
	TAGGED_PROPVAL getFolderEntryId(const Structures::sFolderSpec&) const;
	TPROPVAL_ARRAY getFolderProps(const Structures::sFolderSpec&, const PROPTAG_ARRAY&) const;
	TAGGED_PROPVAL getItemEntryId(const std::string&, uint64_t) const;
	TPROPVAL_ARRAY getItemProps(const std::string&, uint64_t, const PROPTAG_ARRAY&) const;
	void normalize(Structures::tMailbox&) const;
	uint32_t permissions(const char*, const Structures::sFolderSpec&, const char* = nullptr) const;
	Structures::sFolderSpec resolveFolder(const Structures::tDistinguishedFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::tFolderId&) const;

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
	void getNamedTags(const std::string&, const std::vector<PROPERTY_NAME>&, const
	                  std::vector<uint16_t>&, Structures::sProptags&) const;
};

}
