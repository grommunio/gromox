#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct logon_object;

struct folder_object {
	protected:
	folder_object() = default;

	public:
	static std::unique_ptr<folder_object> create(logon_object *, uint64_t folder_id, uint8_t type, uint32_t tag_access);
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	bool is_readonly_prop(uint32_t proptag);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *, PROBLEM_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *, PROBLEM_ARRAY *);

	logon_object *plogon = nullptr;
	uint64_t folder_id = 0;
	uint8_t type = 0;
	uint32_t tag_access = 0;
};
