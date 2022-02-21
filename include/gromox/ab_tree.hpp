#pragma once

namespace gromox {

enum class abnode_type : uint8_t {
	remote = 0,
	person = 1,
	mlist = 2,
	room = 3,
	equipment = 4,
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
