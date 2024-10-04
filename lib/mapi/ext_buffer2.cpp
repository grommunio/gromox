// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2024 grommunio GmbH
// This file is part of Gromox.
#include <limits>
#include <string>
#include <vector>
#include <gromox/ext_buffer.hpp>
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != pack_result::success) return klfdv; } while (false)
using namespace gromox;

#define AP(T, t, C, c) \
	pack_result EXT_PUSH::p_ ## t ## _a(const std::vector<T> &r) \
	{ \
		if (r.size() > std::numeric_limits<C>::max()) \
			return pack_result::format; \
		TRY(p_ ## c(r.size())); \
		for (size_t i = 0; i < r.size(); ++i) \
			TRY(p_ ## t(r[i])); \
		return pack_result::success; \
	}

#define AN(T, t) \
	pack_result EXT_PULL::g_ ## t ## _an(std::vector<T> *r, size_t count) try \
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

#define A(T, t, C, c) \
	AN(T, t) \
	pack_result EXT_PULL::g_ ## t ## _a(std::vector<T> *r) \
	{ \
		C count; \
		TRY(g_ ## c(&count)); \
		return count != 0 ? g_ ## t ## _an(r, count) : pack_result::success; \
	}

A(uint16_t, uint16, uint32_t, uint32)
AP(uint16_t, uint16, uint32_t, uint32)
A(uint32_t, uint32, uint32_t, uint32)
AP(uint32_t, uint32, uint32_t, uint32)
A(uint64_t, uint64, uint32_t, uint32)
AP(uint64_t, uint64, uint32_t, uint32)
A(float, float, uint32_t, uint32)
AP(float, float, uint32_t, uint32)
A(double, double, uint32_t, uint32)
AP(double, double, uint32_t, uint32)
A(GUID, guid, uint32_t, uint32)
AP(GUID, guid, uint32_t, uint32)
A(std::string, str, uint32_t, uint32)
A(std::string, wstr, uint32_t, uint32)

#undef A
#undef AN
#undef AP

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
