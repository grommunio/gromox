#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>

struct store_object {
	protected:
	store_object() = default;
	NOMOVE(store_object);

	public:
	static std::unique_ptr<store_object> create(BOOL b_private, int account_id, const char *account, const char *dir);
	GUID guid() const;
	bool owner_mode() const;
	bool primary_mode() const;
	const char *get_account() const { return account; }
	const char *get_dir() const { return dir; }
	BOOL get_named_propnames(const PROPID_ARRAY &, PROPNAME_ARRAY *);
	BOOL get_named_propids(BOOL create, const PROPNAME_ARRAY *, PROPID_ARRAY *);
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL get_permissions(PERMISSION_SET *);

	BOOL b_private = false;
	int account_id = 0;
	char account[UADDR_SIZE]{};
	char dir[256]{};
	GUID mailbox_guid{}, mapping_signature{};
	std::unordered_map<uint16_t, PROPERTY_XNAME> propid_hash;
	std::unordered_map<std::string, uint16_t> propname_hash;
};
