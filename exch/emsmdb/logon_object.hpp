#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <gromox/mapi_types.hpp>

enum class logon_mode {
	owner, delegate, guest,
};

struct logon_object {
	protected:
	logon_object() = default;
	NOMOVE(logon_object);

	public:
	static std::unique_ptr<logon_object> create(uint8_t logon_flags, uint32_t open_flags, enum logon_mode, int account_id, int dom_id, const char *account, const char *dir, GUID mailbox_guid, GUID mapping_sig);
	bool is_private() const { return logon_flags & LOGON_FLAG_PRIVATE; }
	GUID guid() const;
	const char *get_account() const { return account; }
	const char *get_dir() const { return dir; }
	BOOL get_named_propname(gromox::propid_t, PROPERTY_NAME *);
	BOOL get_named_propnames(const PROPID_ARRAY &, PROPNAME_ARRAY *);
	BOOL get_named_propid(BOOL create, const PROPERTY_NAME *, gromox::propid_t *);
	BOOL get_named_propids(BOOL create, const PROPNAME_ARRAY *, PROPID_ARRAY *);
	BOOL get_all_proptags(PROPTAG_ARRAY *) const;
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *) const;
	BOOL set_properties(const TPROPVAL_ARRAY *, PROBLEM_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *, PROBLEM_ARRAY *);
	const char *eff_user() const;
	const char *readstate_user() const;

	uint8_t logon_flags = 0;
	uint32_t open_flags = 0;
	enum logon_mode logon_mode = logon_mode::owner;
	int account_id = 0, domain_id = 0;
	char account[UADDR_SIZE]{};
	char dir[256]{};
	GUID mailbox_guid{}, mapping_signature{};
	std::unordered_map<uint32_t, PROPERTY_XNAME> propid_hash;
	std::unordered_map<std::string, uint16_t> propname_hash;
};
