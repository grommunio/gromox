#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct user_object {
	protected:
	user_object() = default;

	public:
	static std::unique_ptr<user_object> create(int base_id, uint32_t minid);
	BOOL check_valid();
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);

	int base_id = 0;
	uint32_t minid = 0;
};
