#pragma once
#include <memory>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/int_hash.hpp>

struct STORE_OBJECT {
	~STORE_OBJECT();
	GUID guid() const;
	BOOL check_owner_mode() const;
	const char *get_account() const { return account; }
	const char *get_dir() const { return dir; }
	BOOL get_named_propnames(const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);
	BOOL get_named_propids(BOOL b_create, const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids);
	/*
	 * Used for message partial change information when saving message, the
	 * return value is maintained by logon object, do not free it outside.
	 */
	PROPERTY_GROUPINFO *get_last_property_groupinfo();
	/* same as get_last_property_groupinfo, do not free it outside */
	PROPERTY_GROUPINFO *get_property_groupinfo(uint32_t group_id);
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL get_permissions(PERMISSION_SET *);

	BOOL b_private = false;
	int account_id = 0;
	char account[UADDR_SIZE]{};
	char dir[256]{};
	GUID mailbox_guid{};
	PROPERTY_GROUPINFO *pgpinfo = nullptr;
	INT_HASH_TABLE *ppropid_hash = nullptr;
	STR_HASH_TABLE *ppropname_hash = nullptr;
	DOUBLE_LIST group_list{};
};

struct PERMISSION_SET;

extern std::unique_ptr<STORE_OBJECT> store_object_create(BOOL b_private, int account_id, const char *account, const char *dir);
