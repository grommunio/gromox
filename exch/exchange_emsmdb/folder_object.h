#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct LOGON_OBJECT;

struct FOLDER_OBJECT {
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL check_readonly_property(uint32_t proptag);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *, PROBLEM_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *, PROBLEM_ARRAY *);

	LOGON_OBJECT *plogon = nullptr;
	uint64_t folder_id = 0;
	uint8_t type = 0;
	uint32_t tag_access = 0;
};

extern std::unique_ptr<FOLDER_OBJECT> folder_object_create(LOGON_OBJECT *, uint64_t folder_id, uint8_t type, uint32_t tag_access);
