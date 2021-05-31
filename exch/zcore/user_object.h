#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mail_func.hpp>
#include <gromox/mapi_types.hpp>

struct USER_OBJECT {
	int base_id = 0;
	uint32_t minid = 0;
};

extern std::unique_ptr<USER_OBJECT> user_object_create(int base_id, uint32_t minid);
BOOL user_object_check_valid(USER_OBJECT *puser);
BOOL user_object_get_properties(USER_OBJECT *puser,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);
