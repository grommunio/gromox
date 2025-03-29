// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2025 grommunio GmbH
// This file is part of Gromox.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <libHX/endian.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/mapidefs.h>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>

namespace {

/// NT timestamp unit (100 ns)
using nt_dur = std::chrono::duration<uint64_t, std::ratio<1, 10'000'000>>;
/// Offset for NT timestamps
static constexpr nt_dur nt_offset = std::chrono::duration_cast<nt_dur>(std::chrono::seconds(TIME_FIXUP_CONSTANT_INT));

} // anonymous namespace

using namespace gromox;

uint16_t rop_util_get_replid(eid_t eid)
{
	return eid & 0xFFFF;
}

/**
 * The reverse of rop_util_make_eid, see there for details.
 */
uint64_t rop_util_get_gc_value(eid_t eid)
{
	return __builtin_bswap64(eid.m_value) & eid_t::GCV_MASK;
}

/**
 * Extract the GC portion of a value produced by rop_util_make_eid.
 */
GLOBCNT rop_util_get_gc_array(eid_t eid)
{
	GLOBCNT gc;
	eid.m_value = cpu_to_le64(eid.m_value);
	memcpy(gc.ab, reinterpret_cast<uint8_t *>(&eid) + 2, 6);
	return gc;
}

/**
 * @value:	One of the following:
 * 		* Gromox-level change number
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
	uint64_t value = 0;
	memcpy(reinterpret_cast<uint8_t *>(&value) + 2, gc.ab, 6);
	return be64_to_cpu(value);
}

/**
 * @replid:	replica id as per OXCFXICS
 * @gc:		GCV or CN Gromox-level folder/message id/CN encoded as 48-bit big-endian
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
	return {__builtin_bswap64(rop_util_gc_to_value(gc)) | replid};
}

eid_t rop_util_make_eid_ex(uint16_t replid, uint64_t value)
{
	return {(__builtin_bswap64(value)) | replid};
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
	auto w = static_cast<int64_t>(unix_time) + TIME_FIXUP_CONSTANT_INT;
	if (w < 0)
		return UINT64_MAX;
	uint64_t v = w;
	if (v > INT64_MAX / 10000000)
		return UINT64_MAX;
	return v * 10000000;
}

uint64_t rop_util_unix_to_nttime(std::chrono::system_clock::time_point unix_time)
{return (std::chrono::duration_cast<nt_dur>(unix_time.time_since_epoch())+nt_offset).count();}

time_t rop_util_nttime_to_unix(uint64_t nt_time)
{
	/* After division by >=2, the value will fit in the range for signed int64 */
	int64_t unix_time = nt_time / 10000000;
	unix_time -= TIME_FIXUP_CONSTANT_INT;
	auto min = std::numeric_limits<time_t>::min();
	auto max = std::numeric_limits<time_t>::max();
	if constexpr (std::numeric_limits<time_t>::is_signed) {
		if (unix_time < min)
			return min;
		if (unix_time > max)
			return max;
		return unix_time;
	} else {
		if (unix_time < 0)
			return 0;
		if (static_cast<uint64_t>(unix_time) > static_cast<uint64_t>(max))
			return max;
		return static_cast<time_t>(unix_time);
	}
}

std::chrono::system_clock::time_point rop_util_nttime_to_unix2(uint64_t nt_time)
{
	return std::chrono::system_clock::time_point(std::chrono::duration_cast<std::chrono::system_clock::duration>(nt_dur(nt_time) - nt_offset));
}

std::chrono::system_clock::time_point rop_util_rtime_to_unix2(uint32_t t)
{
	return std::chrono::system_clock::time_point(std::chrono::duration_cast<std::chrono::system_clock::duration>(nt_dur(rop_util_rtime_to_nttime(t)) - nt_offset));
}

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
	auto nt = rop_util_unix_to_nttime(ts.tv_sec);
	if (nt > INT64_MIN)
		return nt;
	return nt + ts.tv_nsec / 100;
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

/**
 * Return the active timezone definition rule for a given year
 */
const TZRULE *active_rule_for_year(const TIMEZONEDEFINITION *tzdef, int year)
{
	for (auto i = tzdef->crules - 1; i >= 0; --i)
		if ((tzdef->prules[i].flags & TZRULE_FLAG_EFFECTIVE_TZREG &&
		    tzdef->prules[i].year <= year) ||
		    tzdef->prules[i].year == year)
			return &tzdef->prules[i];
	return nullptr;
}

/**
 * Calculate the start of daylight saving or standard time
 */
time_t timegm_dststd_start(const int year, const SYSTEMTIME *ruledate)
{
	struct tm tempTm;
	tempTm.tm_year = year;
	tempTm.tm_mon = ruledate->month - 1;
	tempTm.tm_mday = ical_get_dayofmonth(year + 1900, ruledate->month, ruledate->day == 5 ? -1 : ruledate->day, ruledate->dayofweek);
	tempTm.tm_hour = ruledate->hour;
	tempTm.tm_min = ruledate->minute;
	tempTm.tm_sec = ruledate->second;
	tempTm.tm_isdst = 0;
	return timegm(&tempTm);
}

/**
 * Calculate the offset from UTC from the timezone definition
 */
bool offset_from_tz(const TIMEZONEDEFINITION *tzdef, time_t start_time, int64_t &offset)
{
	struct tm start_date;
	gmtime_r(&start_time, &start_date);
	auto rule = active_rule_for_year(tzdef, start_date.tm_year + 1900);
	if (rule == nullptr)
		return false;

	offset = rule->bias;
	if (rule->standarddate.month != 0 && rule->daylightdate.month != 0) {
		/* Convert all times to UTC for comparison */
		time_t std_start = timegm_dststd_start(start_date.tm_year, &rule->standarddate) + offset * 60;
		time_t dst_start = timegm_dststd_start(start_date.tm_year, &rule->daylightdate) + offset * 60;
		start_time += offset * 60;

		if ((dst_start <= std_start && start_time >= dst_start && start_time < std_start) || /* northern hemisphere DST */
		    (dst_start > std_start && (start_time < std_start || start_time > dst_start))) /* southern hemisphere DST */
			offset += rule->daylightbias;
	}
	return true;
}

}
