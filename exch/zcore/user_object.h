#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mail_func.hpp>
#include <gromox/mapi_types.hpp>

struct USER_OBJECT {
	BOOL check_valid();
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);

	int base_id = 0;
	uint32_t minid = 0;
};

extern std::unique_ptr<USER_OBJECT> user_object_create(int base_id, uint32_t minid);
