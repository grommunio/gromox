// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021–2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <libHX/string.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/propval.hpp>
#include <gromox/resource_pool.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#undef assert
#define assert(x) do { if (!(x)) return EXIT_FAILURE; } while (false)
using namespace gromox;
#define s_rgbSPlus "040000008200E00074C5B7101A82E008"

static int t_extpp()
{
	auto s = hex2bin(s_rgbSPlus "000000009b2dbdb2255659027cf33d2a183706db6bc9240adbd249557c96f6783dcc06d8f9c48b1f");
	EXT_PULL ep;
	ep.init(s.data(), s.size(), zalloc, 0);
	GLOBALOBJECTID goid;
	auto ret = ep.g_goid(&goid);
	assert(ret == EXT_ERR_SUCCESS && goid.unparsed);
#define s_date "0000000066b5d6b711d901010000000000000000"
	s = hex2bin(s_rgbSPlus s_date "01000000ffff");
	ep.init(s.data(), s.size(), zalloc, 0);
	assert(ep.g_goid(&goid) == EXT_ERR_SUCCESS);
	assert((!goid.unparsed && goid.data.cb == 1) ||
	       (goid.unparsed && goid.data.cb == 6));
	s = hex2bin(s_rgbSPlus s_date "02000000ff");
	ep.init(s.data(), s.size(), zalloc, 0);
	assert(ep.g_goid(&goid) == EXT_ERR_SUCCESS);
	assert(goid.unparsed && goid.data.cb == 5);
#undef s_date
	return EXIT_SUCCESS;
}

static void t_convert()
{
	char out[1];
	if (!string_to_utf8("cp1252", "foo", out, std::size(out)))
		/* ignore */;
	if (!string_from_utf8("cp1252", "foo", out, std::size(out)))
		/* ignore */;
}

static int t_emailaddr()
{
	EMAIL_ADDR em;
	for (const auto s : {"u@d.at", "<u@d.at>", "\"u@d.at\"", "U D <u@d.at>",
	     "\"U D\" <u@d.at>", "\"U\\\"D\" <u@d.at>",
	     "=?utf-8?Q?=C3=A5 D?= <u@d.at>", "\"U D\"", "\"U D\" <>"}) {
		printf("%s:\n", s);
		em = {};
		parse_mime_addr(&em, s);
		printf("\tmime: <%s> <%s> <%s>\n", em.display_name, em.local_part, em.domain);
	}
	return EXIT_SUCCESS;
}

static int t_id1()
{
	idset s(true, REPL_TYPE_ID);
	/* right-side half overlap */
	s.append_range(1, 1, 17);
	s.append_range(1, 14, 21);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().low_value == 1);
	assert(l.front().high_value == 21);
	return EXIT_SUCCESS;
}

static int t_id2()
{
	idset s(true, REPL_TYPE_ID);
	/* left-side half overlap */
	s.append_range(1, 14, 21);
	s.append_range(1, 1, 17);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().low_value == 1);
	assert(l.front().high_value == 21);
	return EXIT_SUCCESS;
}

static int t_id3()
{
	idset s(true, REPL_TYPE_ID);
	/* right-side adjacency */
	s.append_range(1, 1, 19);
	s.append_range(1, 20, 29);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().low_value == 1);
	assert(l.front().high_value == 29);
	return EXIT_SUCCESS;
}

static int t_id4()
{
	idset s(true, REPL_TYPE_ID);
	/* left-side adjacency */
	s.append_range(1, 20, 29);
	s.append_range(1, 1, 19);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().low_value == 1);
	assert(l.front().high_value == 29);
	return EXIT_SUCCESS;
}

static int t_id5()
{
	idset s(true, REPL_TYPE_ID);
	/* inner overlap */
	s.append_range(1, 1, 40);
	s.append_range(1, 15, 19);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().low_value == 1);
	assert(l.front().high_value == 40);
	return EXIT_SUCCESS;
}

static int t_id6()
{
	idset s(true, REPL_TYPE_ID);
	/* outer overlap */
	s.append_range(1, 15, 19);
	s.append_range(1, 1, 40);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().low_value == 1);
	assert(l.front().high_value == 40);
	return EXIT_SUCCESS;
}

static int t_id7()
{
	idset s(true, REPL_TYPE_ID);
	s.append_range(1, 11, 19);
	s.append_range(1, 71, 79);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 2);
	assert(l.front().low_value == 11);
	assert(l.front().high_value == 19);
	assert(l.back().low_value == 71);
	assert(l.back().high_value == 79);
	s.append_range(1, 41, 49);
	assert(l.size() == 3);
	assert(l.front().low_value == 11);
	assert(l.front().high_value == 19);
	assert(std::next(l.begin())->low_value == 41);
	assert(std::next(l.begin())->high_value == 49);
	assert(l.back().low_value == 71);
	assert(l.back().high_value == 79);
	/* gap filler */
	s.append_range(1, 20, 40);
	assert(l.size() == 2);
	assert(l.front().low_value == 11);
	assert(l.front().high_value == 49);
	assert(l.back().low_value == 71);
	assert(l.back().high_value == 79);
	s.append_range(1, 50, 70);
	assert(l.size() == 1);
	assert(l.front().low_value == 11);
	assert(l.front().high_value == 79);
	return EXIT_SUCCESS;
}

static int t_id8()
{
	idset s(true, REPL_TYPE_ID);
	unsigned int cnt = 0;
	do {
		unsigned int lo = cnt += 0x10, hi = cnt += 0x10;
		s.append_range(1, lo, hi);
		cnt += 0x10;
	} while (s.get_repl_list().size() < s.get_repl_list().capacity());
	s.remove(rop_util_make_eid_ex(1, 0x12));
	s.dump();
	return EXIT_SUCCESS;
}

static int t_interval()
{
	const char *in = " 1 d 1 h 1 min 1 s ";
	unsigned int exp = 86400 + 3600 + 60 + 1;
	auto got = HX_strtoull_sec(in, nullptr);
	if (got != exp) {
		printf("IN \"%s\" EXP %u GOT %llu\n", in, exp, got);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static void t_respool()
{
	struct S {};
	struct M {
		M() = default;
		M(int z) : zz(z) {}
		NOMOVE(M);
		int zz = 21;
	};
	resource_pool<M> m;
	resource_pool<S> s;
	m.resize(2);
	auto mt = m.get_wait(44);
	printf("%d\n", mt->zz);
}

static int t_cmp_binary()
{
	uint8_t x[] = "X", xy[] = "XY";
	BINARY p = {1, x}, q = {2, xy};
	assert(p.compare(q) < 0);
	return EXIT_SUCCESS;
}

static int t_cmp_guid()
{
	GUID g1 = {0x01}, g2 = {0x0100};
	assert(g1.compare(g2) < 0);
	return EXIT_SUCCESS;
}

static int t_cmp_svreid()
{
	uint8_t eid1[] = "\x02\x00\x00\x01", eid2[] = "\x03\x00\x00\x00\x01";
	EXT_PULL ep;
	SVREID s1, s2;
	ep.init(eid1, sizeof(eid1), zalloc, 0);
	ep.g_svreid(&s1);
	ep.init(eid2, sizeof(eid2), zalloc, 0);
	ep.g_svreid(&s2);
	assert(s1.compare(s2) < 0);
	assert(s1.compare(s1) == 0);
	assert(s2.compare(s1) > 0);
	assert(SVREID_compare(nullptr, &s1) < 0);
	assert(SVREID_compare(nullptr, &s2) < 0);
	assert(SVREID_compare(nullptr, nullptr) == 0);
	assert(SVREID_compare(&s1, nullptr) > 0);
	assert(SVREID_compare(&s2, nullptr) > 0);
	return EXIT_SUCCESS;
}

static int t_base64()
{
	static constexpr char cpool[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
	char out[120];
	size_t outlen;
	if (encode64(cpool, 60, out, 80, &outlen) >= 0)
		return printf("TB-1 failed\n");
	if (encode64(cpool, 60, out, 81, &outlen) < 0)
		return printf("TB-2 failed\n");
	if (encode64_ex(cpool, 60, out, 84, &outlen) >= 0)
		return printf("TB-3 failed\n");
	if (encode64_ex(cpool, 60, out, 85, &outlen) < 0)
		return printf("TB-4 failed\n");

	if (decode64("MTIz", 4, out, 3, &outlen) >= 0)
		return printf("TB-11 failed\n");
	if (decode64("", 0, out, 0, &outlen) >= 0)
		return printf("TB-12 failed\n");
	if (decode64("", 0, out, 1, &outlen) < 0)
		return printf("TB-13 failed\n");
	if (decode64("MTIz", 4, out, 4, &outlen) < 0)
		return printf("TB-5 failed\n");
	if (decode64("MTIz", 1, out, 4, &outlen) >= 0 &&
	    outlen != 0)
		return printf("TB-16 failed\n");
	if (decode64_ex("MTIz", 4, out, 3, &outlen) >= 0)
		return printf("TB-6 failed\n");
	if (decode64_ex("MTIz", 4, out, 4, &outlen) < 0)
		printf("TB-7 failed\n");
	if (decode64_ex("", 0, out, 0, &outlen) >= 0)
		return printf("TB-14 failed\n");
	if (decode64_ex("", 0, out, 1, &outlen) < 0)
		return printf("TB-15 failed\n");
	if (decode64_ex("MTIz", 1, out, 4, &outlen) >= 0 &&
	    outlen != 0)
		return printf("TB-17 failed\n");

	if (decode64_ex(cpool, arsizeof(cpool) - 1, out, arsizeof(out), &outlen) < 0)
		return printf("TB-8 failed\n");
	if (decode64_ex("MTIz\nMTIz\nMTIz\n", 15, out, arsizeof(out), &outlen) < 0)
		return printf("TB-9 failed\n");
	else if (memcmp(out, "123123123", 9) != 0)
		return printf("TB-10 failed\n");

	if (uuencode(0666, "file", cpool, 60, out, 89, &outlen) >= 0)
		return printf("TU-1 failed\n");
	if (uuencode(0666, nullptr, cpool, 60, out, 90, &outlen) < 0)
		return printf("TU-2 failed\n");
	if (uuencode(0666, nullptr, cpool, 1, out, 90, &outlen) < 0)
		return printf("TU-3 failed\n");
	else if (strcmp(out, "!,3(S\r\n`\r\n") != 0)
		return printf("TU-4 failed\n");
	if (uudecode("!,3(S\n`\n", 8, nullptr, nullptr, 0, out, 1, &outlen) >= 0)
		return printf("TU-5 failed\n");
	if (uudecode("!,3(S\n`\n", 8, nullptr, nullptr, 0, out, 2, &outlen) < 0)
		return printf("TU-6 failed\n");

	if (qp_encode_ex(out, 3, "\x01", 1) >= 0)
		return printf("TQ-1 failed\n");
	if (qp_encode_ex(out, 4, "\x01", 1) < 0)
		return printf("TQ-2 failed\n");
	if (qp_decode_ex(out, 1, "=3D", 3) >= 0)
		return printf("TQ-3 failed\n");
	if (qp_decode_ex(out, 2, "=3D", 3) < 0)
		return printf("TQ-4 failed\n");
	return 0;
}

static int t_cmp_icaltime()
{
	ICAL_TIME a{}, b{};
	a.second = b.second = 59;
	a.leap_second = 60;
	if (a.twcompare(b) != -b.twcompare(a))
		return printf("ICAL_TIME::compare failed\n");
	return 0;
}

int main()
{
	char buf[2];
	randstring(buf + 2, 0, "A");
	randstring(buf, 1, "");

	if (t_extpp() != 0)
		return EXIT_FAILURE;
	t_convert();
	if (t_emailaddr() != 0)
		return EXIT_FAILURE;
	if (t_base64() != 0)
		return EXIT_FAILURE;
	using fpt = decltype(&t_interval);
	fpt fct[] = {t_interval, t_id1, t_id2, t_id3, t_id4, t_id5, t_id6,
	             t_id7, t_id8};
	for (auto f : fct) {
		auto ret = f();
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	t_respool();
	auto ret = t_cmp_binary();
	if (ret != 0)
		return ret;
	ret = t_cmp_guid();
	if (ret != 0)
		return ret;
	ret = t_cmp_svreid();
	if (ret != 0)
		return ret;
	ret = t_cmp_icaltime();
	if (ret != 0)
		return ret;
	t_convert();
	return EXIT_SUCCESS;
}
