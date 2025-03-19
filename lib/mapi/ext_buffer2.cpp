// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <limits>
#include <string>
#include <vector>
#include <gromox/ext_buffer.hpp>
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != pack_result::success) return klfdv; } while (false)
using namespace gromox;

/*
 * T: underlying scalar type
 * t: name fragment of scalar push function for T
 * C: type for array size
 * c: name fragment of scalar push function for C
 */
#define PUSH_A(T, t, C, c, fn) \
	pack_result EXT_PUSH::p_ ## fn ## _a(const std::vector<T> &r) \
	{ \
		if (r.size() > std::numeric_limits<C>::max()) \
			return pack_result::format; \
		TRY(p_ ## c(r.size())); \
		for (size_t i = 0; i < r.size(); ++i) \
			TRY(p_ ## t(r[i])); \
		return pack_result::success; \
	}

#define PULL_AN(T, t, fn) \
	pack_result EXT_PULL::g_ ## fn ## _an(std::vector<T> *r, size_t count) try \
	{ \
		r->resize(count); \
		if (count == 0) \
			return pack_result::success; \
		for (size_t i = 0; i < count; ++i) \
			TRY(g_ ## t(&(*r)[i])); \
		return pack_result::success; \
	} catch (const std::bad_alloc &) { \
		return pack_result::alloc; \
	}

#define PULL_AC(T, t, C, c, fn) \
	pack_result EXT_PULL::g_ ## fn ## _a(std::vector<T> *r) \
	{ \
		C count; \
		TRY(g_ ## c(&count)); \
		count = std::min(count, std::numeric_limits<C>::max()); \
		return g_ ## t ## _an(r, count); \
	}

#define PULL_A(T, t, C, c, fn) \
	PULL_AN(T, t, fn) \
	PULL_AC(T, t, C, c, fn)

PULL_A(uint16_t, uint16, uint32_t, uint32, uint16)
PUSH_A(uint16_t, uint16, uint32_t, uint32, uint16)
PULL_A(uint32_t, uint32, uint32_t, uint32, uint32)
PUSH_A(uint32_t, uint32, uint32_t, uint32, uint32)
PULL_A(uint64_t, uint64, uint32_t, uint32, uint64)
PUSH_A(uint64_t, uint64, uint32_t, uint32, uint64)
PULL_A(float, float, uint32_t, uint32, float)
PUSH_A(float, float, uint32_t, uint32, float)
PULL_A(double, double, uint32_t, uint32, double)
PUSH_A(double, double, uint32_t, uint32, double)
PULL_A(GUID, guid, uint32_t, uint32, guid)
PUSH_A(GUID, guid, uint32_t, uint32, guid)
PULL_A(std::string, str, uint32_t, uint32, str)
PULL_A(std::string, wstr, uint32_t, uint32, wstr)

pack_result EXT_PULL::g_propid_a(std::vector<uint16_t> *a)
{
	uint16_t count;
	TRY(g_uint16(&count));
	count = std::min(count, std::numeric_limits<uint16_t>::max());
	return g_uint16_an(a, count);
}

PUSH_A(uint16_t, uint16, uint16_t, uint16, propid)

#undef PUSH_A
#undef PULL_A
#undef PULL_AN
#undef PULL_AC

pack_result EXT_PULL::g_fb(freebusy_event *fb_event)
{
	int64_t t;
	TRY(g_int64(&t));
	fb_event->start_time = t;
	TRY(g_int64(&t));
	fb_event->end_time = t;
	TRY(g_uint32(&fb_event->busy_status));
	BOOL b;
	TRY(g_bool(&b));
	fb_event->has_details = b;

	if (b) {
		TRY(g_str(&fb_event->m_id));
		TRY(g_str(&fb_event->m_subject));
		fb_event->id = fb_event->m_id.c_str();
		fb_event->subject = fb_event->m_subject.c_str();
		TRY(g_bool(&b));
		if (b) {
			TRY(g_str(&fb_event->m_location));
			fb_event->location = fb_event->m_location.c_str();
		}
		TRY(g_bool(&b)); fb_event->is_meeting     = b;
		TRY(g_bool(&b)); fb_event->is_recurring   = b;
		TRY(g_bool(&b)); fb_event->is_exception   = b;
		TRY(g_bool(&b)); fb_event->is_reminderset = b;
		TRY(g_bool(&b)); fb_event->is_private     = b;
	}

	return pack_result::success;
}

pack_result EXT_PULL::g_fb_a(std::vector<freebusy_event> *r) try
{
	uint32_t count = 0;
	TRY(g_uint32(&count));
	if (count == 0) {
		r->clear();
		return pack_result::success;
	}
	count = std::min(count, std::numeric_limits<uint32_t>::max());
	r->resize(count);
	for (size_t i = 0; i < count; ++i)
		TRY(g_fb(&(*r)[i]));
	return pack_result::success;
} catch (const std::bad_alloc &) {
	return pack_result::alloc;
}

pack_result EXT_PUSH::p_fbevent(const freebusy_event &r)
{
	TRY(p_int64(r.start_time));
	TRY(p_int64(r.end_time));
	TRY(p_uint32(r.busy_status));
	TRY(p_bool(r.has_details));
	if (r.has_details) {
		TRY(p_str(r.id));
		TRY(p_str(r.subject));
		TRY(p_bool(r.location != nullptr));
		if (r.location != nullptr)
			TRY(p_str(r.location));
		TRY(p_bool(r.is_meeting));
		TRY(p_bool(r.is_recurring));
		TRY(p_bool(r.is_exception));
		TRY(p_bool(r.is_reminderset));
		TRY(p_bool(r.is_private));
	}
	return pack_result::ok;
}

static pack_result ext_push_persistdata(EXT_PUSH &x, const PERSISTDATA &r)
{
	TRY(x.p_uint16(r.persist_id));
	if (r.persist_id == PERSIST_SENTINEL)
		return x.p_uint16(0);
	if (r.element_id == RSF_ELID_HEADER) {
		TRY(x.p_uint16(8));
		TRY(x.p_uint16(r.element_id));
		TRY(x.p_uint16(4));
		return x.p_uint32(0);
	} else if (r.element_id == RSF_ELID_ENTRYID) {
		uint16_t z = std::min(r.entryid.size(), static_cast<size_t>(UINT16_MAX - 2));
		TRY(x.p_uint16(2 + z));
		TRY(x.p_uint16(r.element_id));
		TRY(x.p_uint16(z));
		return x.p_bytes(r.entryid.c_str(), z);
	}
	return pack_result::bad_switch;
}

pack_result EXT_PUSH::p_persistdata_a(std::span<const PERSISTDATA> pdlist)
{
	for (const auto &pd : pdlist)
		TRY(ext_push_persistdata(*this, pd));
	return ext_push_persistdata(*this, {PERSIST_SENTINEL, ELEMENT_SENTINEL});
}
