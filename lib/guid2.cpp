// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <random>
#include <unistd.h>
#if __linux__ && defined(HAVE_SYS_RANDOM_H)
#	include <sys/random.h>
#endif
#include <gromox/mapidefs.h>
#include <gromox/util.hpp>

using namespace gromox;

const FLATUID muidStoreWrap =
	/* {10bba138-e505-1a10-a1bb-08002b2a56c2} */
	{0x38, 0xA1, 0xBB, 0x10, 0x05, 0xE5, 0x10, 0x1A,
	0xA1, 0xBB, 0x08, 0x00, 0x2B, 0x2A, 0x56, 0xC2};
const FLATUID g_muidStorePrivate =
	/* {20fa551b-66aa-cd11-9bc8-00aa002fc45a} */
	{0x1B, 0x55, 0xFA, 0x20, 0xAA, 0x66, 0x11, 0xCD,
	0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
const GUID gx_dbguid_store_private =
	/* {XXXXXXXX-18a5-6f7b-bcdc-ea1ed03c5657} */
	{0, 0x18a5, 0x6f7b, {0xbc, 0xdc}, {0xea, 0x1e, 0xd0, 0x3c, 0x56, 0x57}};
const GUID gx_dbguid_store_public =
	/* {XXXXXXXX-0afb-7df6-9192-49886aa738ce} */
	{0, 0x0afb, 0x7df6, {0x91, 0x92}, {0x49, 0x88, 0x6a, 0xa7, 0x38, 0xce}};
const FLATUID g_muidStorePublic =
	/* {1002831c-66aa-cd11-9bc8-00aa002fc45a} */
	{0x1C, 0x83, 0x02, 0x10, 0xAA, 0x66, 0x11, 0xCD,
	0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
const FLATUID muidEMSAB =
	/* {c840a7dc-42c0-1a10-b4b9-08002b2fe182} */
	/* also known as GUID_NSPI */
	{0xDC, 0xA7, 0x40, 0xC8, 0xC0, 0x42, 0x10, 0x1A,
	0xB4, 0xB9, 0x08, 0x00, 0x2B, 0x2F, 0xE1, 0x82};
const FLATUID pbLongTermNonPrivateGuid =
	/* {9073441a-66aa-cd11-9bc8-00aa002fc45a} */
	{0x1A, 0x44, 0x73, 0x90, 0xAA, 0x66, 0x11, 0xCD,
	0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4, 0x5A};
const FLATUID muidOOP =
	/* {a41f2b81-a3be-1910-9d6e-00dd010f5402} */
	{0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19,
	0x9D, 0x6E, 0x00, 0xDD, 0x01, 0x0F, 0x54, 0x02};
const FLATUID muidECSAB =
	/* {50a921ac-d340-48ee-b319-fba753304425} */
	/* (ZARAFA6 provider ID (GAB)) */
	{0xAC, 0x21, 0xA9, 0x50, 0x40, 0xD3, 0xEE, 0x48,
	0xB3, 0x19, 0xFB, 0xA7, 0x53, 0x30, 0x44, 0x25};
const FLATUID muidZCSAB =
	/* {30047f72-92e3-da4f-b86a-e52a7fe46571} */
	/* (ZCONTACTS provider ID (PAB)) */
	{0x72, 0x7F, 0x04, 0x30, 0xE3, 0x92, 0x4F, 0xDA,
	0xB8, 0x6A, 0xE5, 0x2A, 0x7F, 0xE4, 0x65, 0x71};
const FLATUID EncodedGlobalId =
	/* MS-OXCICAL v13 §2.1.3.1.1.20.26 pg 67 */
	/* {00000004-0082-00e0-74c5-b7101a82e008} */
	{0x04, 0x00, 0x00, 0x00, 0x82, 0x00, 0xE0, 0x00,
	0x74, 0xC5, 0xB7, 0x10, 0x1A, 0x82, 0xE0, 0x08};
const FLATUID IID_IStorage =
	/* {0000000b-0000-0000-c000-000000000046} */
	{0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
const FLATUID IID_IStream =
	/* {0000000c-0000-0000-c000-000000000046} */
	{0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
const FLATUID IID_IMessage =
	/* {00020307-0000-0000-c000-000000000046} */
	{0x07, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
const FLATUID IID_IExchangeExportChanges =
	/* {a3ea9cc0-d1b2-11cd-80fc-00aa004bba0b} */
	{0xC0, 0x9C, 0xEA, 0xA3, 0xB2, 0xD1, 0xCD, 0x11,
	0x80, 0xFC, 0x00, 0xAA, 0x00, 0x4B, 0xBA, 0x0B};
const FLATUID IID_IExchangeImportContentsChanges =
	/* {f75abfa0-d0e0-11cd-80fc-00aa004bba0b} */
	{0xA0, 0xBF, 0x5A, 0xF7, 0xE0, 0xD0, 0xCD, 0x11,
	0x80, 0xFC, 0x00, 0xAA, 0x00, 0x4B, 0xBA, 0x0B};
#define GX_OLEGUID(a) {(a), 0, 0, {0xC0, 0}, {0, 0, 0, 0, 0, 0x46}}
const GUID PSETID_ADDRESS =
	/* {00062004-0000-0000-C000-000000000046} */
	GX_OLEGUID(0x00062004);
const GUID PSETID_APPOINTMENT =
	/* {00062002-0000-0000-C000-000000000046} */
	GX_OLEGUID(0x00062002);
const GUID PSETID_BUSINESSCARDVIEW =
	/* {0006200b-0000-0000-c000-000000000046} */
	GX_OLEGUID(0x0006200B);
const GUID PSETID_CALENDARASSISTANT =
	/* {11000E07-B51B-40D6-AF21-CAA85EDAB1D0} */
	{0x11000E07, 0xB51B, 0x40D6, {0xAF, 0x21}, {0xCA, 0xA8, 0x5E, 0xDA, 0xB1, 0xD0}};
const GUID PSETID_COMMON =
	/* {00062008-0000-0000-C000-000000000046} */
	GX_OLEGUID(0x00062008);
const GUID PSETID_GROMOX =
	/* {1de937e2-85c6-40a1-bd9d-a6e2b7b787b1} */
	{0x1DE937E2, 0x85C6, 0x40A1, {0xBD, 0x9D}, {0xA6, 0xE2, 0xB7, 0xB7, 0x87, 0xB1}};
const GUID PSETID_KC =
	/* {63aed8c8-4049-4b75-bc88-96df9d723f2f} */
	{0x63AED8C8, 0x4049, 0x4B75, {0xBC, 0x88}, {0x96, 0xDF, 0x9D, 0x72, 0x3F, 0x2F}};
const GUID PSETID_KCARCHIVE =
	/* {72e98ebc-57d2-4ab5-b0aa-d50a7b531cb9} */
	{0x72E98EBC, 0x57D2, 0x4AB5, {0xB0, 0xAA}, {0xD5, 0x0A, 0x7B, 0x53, 0x1C, 0xB9}};
const GUID PSETID_LOG =
	/* {0006200A-0000-0000-C000-000000000046} */
	GX_OLEGUID(0x006200A);
const GUID PSETID_MEETING =
	/* {6ED8DA90-450B-101B-98DA-00AA003F1305} */
	{0x6ED8DA90, 0x450B, 0x101B, {0x98, 0xDA}, {0x00, 0xAA, 0x00, 0x3F, 0x13, 0x05}};
const GUID PSETID_NOTE =
	/* {0006200E-0000-0000-C000-000000000046} */
	GX_OLEGUID(0x0006200E);
const GUID PSETID_REMOTE =
	/* {00062014-0000-0000-c000-000000000046} */
	GX_OLEGUID(0x00062014);
const GUID PSETID_REPORT =
	/* {00062013-0000-0000-c000-000000000046} */
	GX_OLEGUID(0x00062013);
const GUID PSETID_SHARING =
	/* {00062040-0000-0000-C000-000000000046} */
	GX_OLEGUID(0x00062040);
const GUID PSETID_TASK =
	/* {00062003-0000-0000-C000-000000000046} */
	GX_OLEGUID(0x00062003);
const GUID PSETID_UNIFIEDMESSAGING =
	/* {4442858E-A9E3-4E80-B900-317A210CC15B} */
	{0x4442858E, 0xA9E3, 0x4E80, {0xB9, 0x00}, {0x31, 0x7A, 0x21, 0x0C, 0xC1, 0x5B}};
const GUID PS_INTERNET_HEADERS =
	/* {00020386-0000-0000-C000-000000000046} */
	GX_OLEGUID(0x00020386);
const GUID PS_MAPI =
	/* {00020328-0000-0000-c000-000000000046} */
	GX_OLEGUID(0x00020328);
const GUID PS_PUBLIC_STRINGS =
	/* {00020329-0000-0000-c000-000000000046} */
	GX_OLEGUID(0x00020329);
#undef GX_OLEGUID
const FLATUID IID_IExchangeImportHierarchyChanges =
	/* {85a66cf0-d0e0-11cd-80fc-00aa004bba0b} */
	{0xF0, 0x6C, 0xA6, 0x85, 0xE0, 0xD0, 0xCD, 0x11,
	0x80, 0xFC, 0x00, 0xAA, 0x00, 0x4B, 0xBA, 0x0B};
const uint8_t MACBINARY_ENCODING[9] =
	{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x03, 0x0B, 0x01};
const uint8_t OLE_TAG[11] =
	{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x03, 0x0A,
	0x03, 0x02, 0x01};
const uint8_t ThirdPartyGlobalId[12] =
	/* pg 68 // 7643616C2D55696401000000 */
	{0x76, 0x43, 0x61, 0x6c, 0x2d, 0x55, 0x69, 0x64, 0x01, 0x00, 0x00, 0x00};
static GUID machine_guid;
static std::once_flag machine_guid_loaded;

namespace gromox {

static uint32_t gromox_rng_seed()
{
	uint32_t seed = 0;
	ssize_t ret = 0;
#if defined(__linux__) && defined(HAVE_GETRANDOM)
	ret = getrandom(&seed, sizeof(seed), 0);
#endif
	if (ret < 0 || static_cast<size_t>(ret) != sizeof(seed))
		seed = std::chrono::steady_clock::now().time_since_epoch().count() ^ getpid();
	return seed;
}

static std::mt19937 gromox_rng(gromox_rng_seed());

uint32_t rand()
{
	return gromox_rng();
}

static void machine_guid_read()
{
	int fd = open("/etc/machine-id", O_RDONLY);
	if (fd >= 0) {
		char txt[33];
		auto r = read(fd, txt, 32);
		if (r == 32) {
			txt[32] = '\0';
			if (machine_guid.from_str(txt)) {
				close(fd);
				return;
			}
		}
		close(fd);
	}
	machine_guid = GUID::random_new();
}

}

const GUID &GUID::machine_id()
{
	std::call_once(machine_guid_loaded, machine_guid_read);
	return machine_guid;
}

GUID GUID::random_new()
{
	using gromox::rand;
	GUID guid;
	uint32_t v[4] = {rand(), rand(), rand(), rand()};
	static_assert(sizeof(v) == sizeof(guid));
	memcpy(&guid, v, sizeof(guid));
	/* Set the 1-0-x variant as per RFC 4122 §4.1.1 */
	guid.clock_seq[0] &= 0x3F;
	guid.clock_seq[0] |= 0x80;
	/* v4 version as per §4.1.3 */
	guid.time_hi_and_version &= 0x0FFF;
	guid.time_hi_and_version |= 4U << 12;
	return guid;
}

static const char guidfmt32[] = "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x";
static const char guidfmt36[] = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x";
static const char guidfmt38[] = "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}";

void GUID::to_str(char *buf, size_t z, unsigned int type) const
{
	auto fmt = type == 32 ? guidfmt32 : type == 38 ? guidfmt38 : guidfmt36;
	snprintf(buf, z, fmt, time_low, time_mid, time_hi_and_version,
	         clock_seq[0], clock_seq[1], node[0], node[1], node[2],
	         node[3], node[4], node[5]);
}

bool GUID::from_str(const char *s)
{
	auto z = strlen(s);
	const char *fmt;
	if (z == 32)
		fmt = guidfmt32;
	else if (z == 36)
		fmt = guidfmt36;
	else if (z == 38)
		fmt = guidfmt38;
	else
		return false;
	unsigned int v[11];
	if (sscanf(s, fmt, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6],
	    &v[7], &v[8], &v[9], &v[10]) != 11)
		return false;
	time_low = v[0];
	time_mid = v[1];
	time_hi_and_version = v[2];
	clock_seq[0] = v[3];
	clock_seq[1] = v[4];
	node[0] = v[5];
	node[1] = v[6];
	node[2] = v[7];
	node[3] = v[8];
	node[4] = v[9];
	node[5] = v[10];
	return true;
}

/**
 * Compare, from offset 4, 12 bytes.
 */
int GUID::compare_4_12(const GUID &o) const
{
	if (time_mid != o.time_mid)
		return time_mid > o.time_mid ? 1 : -1;
	if (time_hi_and_version != o.time_hi_and_version)
		return time_hi_and_version > o.time_hi_and_version ? 1 : -1;
	auto r = memcmp(clock_seq, o.clock_seq, std::size(clock_seq));
	return r != 0 ? r : memcmp(node, o.node, std::size(node));
}

int GUID::compare(const GUID &o) const
{
	/*
	 * EXC2019 also evaluates restrictions (should be the same as the
	 * outcome of a sort operation) such that GUID fields are compared in
	 * broken-out fashion, host-order.
	 */
	if (time_low != o.time_low)
		return time_low > o.time_low ? 1 : -1;
	return compare_4_12(o);
}
