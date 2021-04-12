#pragma once
#include <cstdint>
#include <gromox/binhex.hpp>
#include <gromox/macbinary.hpp>
#include <gromox/applefile.hpp>

BINARY* apple_util_binhex_to_appledouble(const BINHEX *pbinhex);
BINARY* apple_util_macbinary_to_appledouble(const MACBINARY *pmacbin);
BINARY* apple_util_appledouble_to_macbinary(const APPLEFILE *papplefile,
	const void *pdata, uint32_t data_len);
BINARY* apple_util_applesingle_to_macbinary(const APPLEFILE *papplefile);
BINARY* apple_util_binhex_to_macbinary(const BINHEX *pbinhex);
BINARY* apple_util_applesingle_to_appledouble(const APPLEFILE *papplefile);
