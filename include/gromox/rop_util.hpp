#pragma once
#include <chrono>
#include <cstdint>
#include <ctime>
#include <gromox/clock.hpp>
#include <gromox/mapi_types.hpp>

/*
 * Use unclear. Has something to do with notifications, and that, in sqlite3,
 * FIDs/MIDs seem to be stored 8:56 bits for replid:gcval, whereas in RPC
 * transport, it's 16:48. The rop_util_make_eid_ex(x>>48,y&56bits) is also
 * questionable (should be y&48bits?).
 */
#define NFID_UPPER_PART 0xFF00000000000000ULL
#define NFID_LOWER_PART 0x00FFFFFFFFFFFFFFULL

#define RTIME_FACTOR 600000000LL

extern GX_EXPORT uint16_t rop_util_get_replid(eid_t);
extern GX_EXPORT uint64_t rop_util_get_gc_value(eid_t);
extern GX_EXPORT GLOBCNT rop_util_get_gc_array(eid_t);
extern GX_EXPORT GLOBCNT rop_util_value_to_gc(uint64_t);
extern GX_EXPORT uint64_t rop_util_gc_to_value(GLOBCNT);
extern GX_EXPORT eid_t rop_util_make_eid(uint16_t replid, GLOBCNT);
extern GX_EXPORT eid_t rop_util_make_eid_ex(uint16_t replid, uint64_t value);
extern GX_EXPORT eid_t rop_util_nfid_to_eid(uint64_t);
extern GX_EXPORT eid_t rop_util_nfid_to_eid2(uint64_t);
extern GX_EXPORT GUID rop_util_make_user_guid(int user_id);
extern GX_EXPORT GUID rop_util_make_domain_guid(int domain_id);
extern GX_EXPORT int rop_util_get_user_id(GUID);
extern GX_EXPORT int rop_util_get_domain_id(GUID);
extern GX_EXPORT uint64_t rop_util_unix_to_nttime(time_t unix_time);
extern GX_EXPORT uint64_t rop_util_unix_to_nttime(std::chrono::system_clock::time_point);
extern GX_EXPORT time_t rop_util_nttime_to_unix(uint64_t nt_time);
extern GX_EXPORT std::chrono::system_clock::time_point rop_util_nttime_to_unix2(uint64_t nt_time);
extern GX_EXPORT std::chrono::system_clock::time_point rop_util_rtime_to_unix2(uint32_t t);
inline uint32_t rop_util_nttime_to_rtime(uint64_t t) { return t / RTIME_FACTOR; }
inline uint64_t rop_util_rtime_to_nttime(uint32_t t) { return t * RTIME_FACTOR; }
extern GX_EXPORT uint32_t rop_util_unix_to_rtime(time_t);
extern GX_EXPORT time_t rop_util_rtime_to_unix(uint32_t);
extern GX_EXPORT uint64_t rop_util_current_nttime();
extern GX_EXPORT GUID rop_util_binary_to_guid(const BINARY *pbin);
extern GX_EXPORT void rop_util_guid_to_binary(GUID guid, BINARY *pbin);
extern GX_EXPORT void rop_util_free_binary(BINARY *pbin);

namespace gromox {

extern GX_EXPORT uint64_t apptime_to_nttime_approx(double);
extern GX_EXPORT uint32_t props_to_defer_interval(const TPROPVAL_ARRAY &);
extern GX_EXPORT errno_t make_inet_msgid(char *, size_t, uint32_t);
extern GX_EXPORT const TZRULE *active_rule_for_year(const TIMEZONEDEFINITION *, int);
extern GX_EXPORT time_t timegm_dststd_start(const int, const SYSTEMTIME *);
extern GX_EXPORT bool offset_from_tz(const TIMEZONEDEFINITION *, time_t, int64_t &);

}
