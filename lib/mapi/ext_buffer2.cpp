// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2024 grommunio GmbH
// This file is part of Gromox.
#include <gromox/ext_buffer.hpp>
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != pack_result::success) return klfdv; } while (false)
using namespace gromox;

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
