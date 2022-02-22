#pragma once
#include <gromox/common_types.hpp>
#include <gromox/mapidefs.h>

int guid_compare(const GUID *u1, const GUID *u2);
namespace gromox {
extern GUID guid_random_new();
extern const GUID &guid_machine_id();
}
