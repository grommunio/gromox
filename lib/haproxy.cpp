#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <libHX/io.h>

static int haproxy_intervene(int fd, unsigned int level, struct sockaddr_storage *ss)
{
	if (level == 0)
		return 0;
	if (level != 2)
		return -1;
	static constexpr uint8_t sig[12] = {0xd, 0xa, 0xd, 0xa, 0x0, 0xd, 0xa, 0x51, 0x55, 0x49, 0x54, 0xa};
	uint8_t buf[4096];
	if (HXio_fullread(fd, buf, 16) != 16)
		return -1;
	if (memcmp(buf, sig, sizeof(sig)) != 0)
		return -1;
	if (((buf[12] & 0xF0) >> 4) != level)
		return -1;
	if ((buf[12] & 0xF) == 0)
		return 0;
	if ((buf[12] & 0xF) != 1)
		return -1;
	uint16_t hlen = (buf[14] << 8) | buf[15];
	switch (buf[13] & 0xF0) {
	case 0x10: {
		if (hlen != 12 || HXio_fullread(fd, buf, 12) != 12)
			return -1;
		auto peer = reinterpret_cast<sockaddr_in *>(ss);
		*peer = {};
		peer->sin_family = AF_INET;
		memcpy(&peer->sin_addr, &buf[0], sizeof(peer->sin_addr));
		memcpy(&peer->sin_port, &buf[8], sizeof(peer->sin_port));
		static_assert(sizeof(peer->sin_addr) == 4 && sizeof(peer->sin_port) == 2);
		return 0;
	}
	case 0x20: {
		if (hlen != 36 || HXio_fullread(fd, buf, 36) != 36)
			return -1;
		auto peer = reinterpret_cast<sockaddr_in6 *>(ss);
		*peer = {};
		peer->sin6_family = AF_INET6;
		memcpy(&peer->sin6_addr, &buf[0], sizeof(peer->sin6_addr));
		memcpy(&peer->sin6_port, &buf[32], sizeof(peer->sin6_port));
		static_assert(sizeof(peer->sin6_addr) == 16 && sizeof(peer->sin6_port) == 2);
		return 0;
	}
	case 0x30: {
		if (hlen != 216 || HXio_fullread(fd, buf, 216) != 216)
			return -1;
		auto peer = reinterpret_cast<sockaddr_un *>(ss);
		*peer = {};
		peer->sun_family = AF_LOCAL;
		memcpy(&peer->sun_path, &buf[0], std::min(static_cast<size_t>(108), sizeof(peer->sun_path)));
		return 0;
	}
	default:
		while (hlen > 0) {
			int toread = std::min(static_cast<size_t>(hlen), sizeof(buf));
			if (HXio_fullread(fd, buf, toread) != toread)
				return -1;
			hlen -= toread;
		}
		return 0;
	}
	return -1;
}
