#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct USER_OBJECT {
	protected:
	USER_OBJECT() = default;

	public:
	static std::unique_ptr<USER_OBJECT> create(int base_id, uint32_t minid);
	BOOL check_valid();
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);

	int base_id = 0;
	uint32_t minid = 0;
};
using user_object = USER_OBJECT;
