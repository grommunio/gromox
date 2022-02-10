#pragma once
#include <gromox/common_types.hpp>
void bounce_audit_init(int audit_num, int audit_interval);
BOOL bounce_audit_check(const char *audit_string);
