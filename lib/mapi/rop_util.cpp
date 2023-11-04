// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#define TIME_FIXUP_CONSTANT_INT				11644473600LL

namespace
{
/// NT timestamp unit (100 ns)
using nt_dur = std::chrono::duration<uint64_t, std::ratio<1, 10'000'000>>;
/// Offset for NT timestamps
static constexpr nt_dur nt_offset = std::chrono::duration_cast<nt_dur>(std::chrono::seconds(TIME_FIXUP_CONSTANT_INT));

} // anonymous namespace

using namespace gromox;

uint16_t rop_util_get_replid(eid_t eid)
{
	/* replid is kept in host-endian, see rop_util_make_eid for detail */
	return eid & 0xFFFF;
}

/**
 * The reverse of rop_util_make_eid, see there for details.
 */
uint64_t rop_util_get_gc_value(eid_t eid)
{
	return rop_util_gc_to_value(rop_util_get_gc_array(eid));
}

/**
 * Extract the GC portion of a value produced by rop_util_make_eid.
 */
GLOBCNT rop_util_get_gc_array(eid_t eid)
{
	GLOBCNT gc;
#if !GX_BIG_ENDIAN
	memcpy(gc.ab, reinterpret_cast<uint8_t *>(&eid) + 2, 6);
#else
	memcpy(gc.ab, &eid, 6);
#endif
	return gc;
}

/**
 * @value:	One of the following:
 * 		* Gromox-level change number like 0x800000000005, 0x800000000006, ...,
 * 		* Gromox-level folder identifier like 0xd (inbox), ...,
 * 		* Gromox-level message identifier
 * @gc:		Low 48 bits of @value, encoded as a 48-bit big-endian integer.
 * 		(pursuant to the requirements of MS-OXCFXICS v24 §3.1.5.3
 * 		“increase with time, when compared byte to byte”, which means MSB)
 */
GLOBCNT rop_util_value_to_gc(uint64_t value)
{
	GLOBCNT gc;
	value = cpu_to_be64(value);
	memcpy(gc.ab, reinterpret_cast<uint8_t *>(&value) + 2, 6);
	return gc;
}

/**
 * @gc:		48-bit big-endian encoded integer
 * Decodes the integer and returns it.
 */
uint64_t rop_util_gc_to_value(GLOBCNT gc)
{
	uint64_t value;
	auto v = reinterpret_cast<uint8_t *>(&value);

#if !GX_BIG_ENDIAN
	v[0] = gc.ab[5];
	v[1] = gc.ab[4];
	v[2] = gc.ab[3];
	v[3] = gc.ab[2];
	v[4] = gc.ab[1];
	v[5] = gc.ab[0];
	v[6] = 0;
	v[7] = 0;
#else
	v[0] = 0;
	v[1] = 0;
	memcpy(v + 2, gc.ab, 6);
#endif
	return value;
}

/**
 * @replid:	replica id as per OXCFXICS
 * @gc:		Gromox-level folder/message id/CN encoded as 48-bit big-endian
 *
 * Produces an Exchange-level folder/message identifier (MS-OXCDATA v17
 * §2.2.1.2) — later visible in e.g. PR_RECORD_KEY (see also
 * mapi_types.hpp:FOLDER_ENTRYID), which contains the 48-bit big-endian gc
 * _before_ the 16-bit replid.
 *
 * MFCMAPI does not treat PR_RECORD_KEY's gc part in any way (leaves it as
 * bytes), and does the same to replid. It is not clear if replid should be
 * big-endian. However, given the replid is replaced by a replguid in
 * message_object.cpp:cu_fid_to_entryid and zeroed, it probably
 * does not matter which way.
 *
 * The return value is mixed endianness and mildly useless when printed as a
 * number. Consumers such as message_object.cpp:cu_fid_to_entryid
 * just deconstruct it again for PR_RECORD_KEY.
 */
eid_t rop_util_make_eid(uint16_t replid, GLOBCNT gc)
{
	eid_t eid;
	auto e = reinterpret_cast<uint8_t *>(&eid);

#if !GX_BIG_ENDIAN
	e[0] = 0;
	e[1] = 0;
	memcpy(e + 2, gc.ab, 6);
#else
	memcpy(&eid, gc.ab, 6);
	e[6] = 0;
	e[7] = 0;
#endif
	return (eid | replid);
}

eid_t rop_util_make_eid_ex(uint16_t replid, uint64_t value)
{
	return rop_util_make_eid(replid, rop_util_value_to_gc(value));
}

eid_t rop_util_nfid_to_eid(uint64_t id)
{
	return (id & NFID_UPPER_PART) == 0 ? rop_util_make_eid_ex(1, id) :
	       rop_util_make_eid_ex(id >> 48, id & NFID_LOWER_PART);
}

eid_t rop_util_nfid_to_eid2(uint64_t id)
{
	return (id & NFID_UPPER_PART) == 0 ? rop_util_make_eid_ex(1, id) :
	       rop_util_make_eid_ex(2, id & NFID_LOWER_PART);
}

GUID rop_util_make_user_guid(int user_id)
{
	auto guid = gx_dbguid_store_private;
	guid.time_low = user_id;
	return guid;
}

GUID rop_util_make_domain_guid(int domain_id)
{
	auto guid = gx_dbguid_store_public;
	guid.time_low = domain_id;
	return guid;
}

int rop_util_get_user_id(GUID guid)
{
	return guid.compare_4_12(gx_dbguid_store_private) == 0 ? guid.time_low : -1;
}

int rop_util_get_domain_id(GUID guid)
{
	return guid.compare_4_12(gx_dbguid_store_public) == 0 ? guid.time_low : -1;
}

uint64_t rop_util_unix_to_nttime(time_t unix_time)
{
	uint64_t nt_time;

	nt_time = unix_time;
	nt_time += TIME_FIXUP_CONSTANT_INT;
	nt_time *= 10000000;
	return nt_time;
}

uint64_t rop_util_unix_to_nttime(const gromox::time_point& unix_time)
{return (std::chrono::duration_cast<nt_dur>(unix_time.time_since_epoch())+nt_offset).count();}

time_t rop_util_nttime_to_unix(uint64_t nt_time)
{
	uint64_t unix_time;

	unix_time = nt_time;
	unix_time /= 10000000;
	unix_time -= TIME_FIXUP_CONSTANT_INT;
	return (time_t)unix_time;
}

gromox::time_point rop_util_nttime_to_unix2(uint64_t nt_time)
{
	return gromox::time_point(std::chrono::duration_cast<gromox::time_point::duration>(nt_dur(nt_time) - nt_offset));
}

gromox::time_point rop_util_rtime_to_unix2(uint32_t t)
{return gromox::time_point(nt_dur(rop_util_rtime_to_nttime(t))-nt_offset);}

time_t rop_util_rtime_to_unix(uint32_t t)
{
	return rop_util_nttime_to_unix(rop_util_rtime_to_nttime(t));
}

uint32_t rop_util_unix_to_rtime(time_t t)
{
	return rop_util_nttime_to_rtime(rop_util_unix_to_nttime(t));
}

uint64_t rop_util_current_nttime()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return rop_util_unix_to_nttime(ts.tv_sec) + ts.tv_nsec  / 100;
}

GUID rop_util_binary_to_guid(const BINARY *pbin)
{
	GUID guid;
	guid.time_low = le32p_to_cpu(&pbin->pb[0]);
	guid.time_mid = le16p_to_cpu(&pbin->pb[4]);
	guid.time_hi_and_version = le16p_to_cpu(&pbin->pb[6]);
	memcpy(guid.clock_seq, pbin->pb + 8, 2);
	memcpy(guid.node, pbin->pb + 10, 6);
	return guid;
}

void rop_util_guid_to_binary(GUID guid, BINARY *pbin)
{
	cpu_to_le32p(&pbin->pb[pbin->cb], guid.time_low);
	pbin->cb += sizeof(uint32_t);
	cpu_to_le16p(&pbin->pb[pbin->cb], guid.time_mid);
	pbin->cb += sizeof(uint16_t);
	cpu_to_le16p(&pbin->pb[pbin->cb], guid.time_hi_and_version);
	pbin->cb += sizeof(uint16_t);
	memcpy(pbin->pb + pbin->cb, guid.clock_seq, 2);
	pbin->cb += 2;
	memcpy(pbin->pb + pbin->cb, guid.node, 6);
	pbin->cb += 6;
}

void rop_util_free_binary(BINARY *pbin)
{
	free(pbin->pb);
	free(pbin);
}

XID::XID(GUID g, eid_t change_num) : guid(g), size(22)
{
	memcpy(local_id, rop_util_get_gc_array(change_num).ab, 6);
}

namespace gromox {

uint32_t props_to_defer_interval(const TPROPVAL_ARRAY &pv)
{
	auto cur_time = time(nullptr);
	auto submit_time = rop_util_unix_to_nttime(cur_time);
	auto send_time = pv.get<const uint64_t>(PR_DEFERRED_SEND_TIME);
	if (send_time != nullptr) {
		if (*send_time < submit_time)
			return 0;
		return rop_util_nttime_to_unix(*send_time) - cur_time;
	}
	auto num = pv.get<const uint32_t>(PR_DEFERRED_SEND_NUMBER);
	if (num == nullptr)
		return 0;
	auto unit = pv.get<const uint32_t>(PR_DEFERRED_SEND_UNITS);
	if (unit == nullptr)
		return 0;
	switch (*unit) {
	case 0: return *num * 60;
	case 1: return *num * 3600;
	case 2: return *num * 86400;
	case 3: return *num * 86400 * 7;
	default: return 0;
	}
}

errno_t make_inet_msgid(char *id, size_t bufsize, uint32_t lcid)
{
	if (bufsize < 77)
		return ENOSPC;
	char pack[32];
	strcpy(id, "<gxxx.");
	id[3] = lcid >> 8;
	id[4] = lcid;
	EXT_PUSH ep;
	if (!ep.init(pack, std::size(pack), 0) ||
	    ep.p_guid(GUID::random_new()) != EXT_ERR_SUCCESS)
		return ENOMEM;
	unsigned int ofs = 6;
	encode64(pack, 16, id + ofs, bufsize - ofs, nullptr);
	ofs += 22;
	id[ofs++] = '@';
	ep.m_offset = 0;
	if (ep.p_guid(GUID::random_new()) != EXT_ERR_SUCCESS ||
	    ep.p_guid(GUID::random_new()) != EXT_ERR_SUCCESS)
		return ENOMEM;
	encode64(pack, 32, id + ofs, bufsize - ofs, nullptr);
	ofs += 43;
	strcpy(&id[ofs], ".xz>");
	for (ofs = 0; ofs < 76; ++ofs) {
		if (id[ofs] == '+')
			id[ofs] = '-';
		else if (id[ofs] == '/')
			id[ofs] = '_';
	}
	return 0;
}

}
