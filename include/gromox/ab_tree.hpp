#pragma once

namespace gromox {

enum class abnode_type : uint8_t {
	remote = 0,
	user = 1, /* person, room, equipment */
	mlist = 2,
	folder = 5,
	domain = 0x81,
	group = 0x82,
	abclass = 0x83,
	containers = 0x81, /* for >= */
};

enum class minid_type : uint8_t {
	address = 0,
	domain = 4,
	group = 5,
	abclass = 6,
	reserved = 7, /* NSPI reserves minids 0..0x10 */
};

}
