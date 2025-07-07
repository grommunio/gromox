// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <libHX/endian.h>
#include <libHX/string.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/msgchg_grouping.hpp>
#include <gromox/paths.h>
#include <gromox/propval.hpp>
#include <gromox/resource_pool.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#undef assert
#define assert(x) do { if (!(x)) { printf("%s failed\n", #x); return EXIT_FAILURE; } } while (false)
using namespace gromox;

static int t_utf7()
{
	auto a = "Gelöschte Elemente", b = "Gel&APY-schte Elemente";
	char buf[80];
	utf8_to_mutf7(a, strlen(a), buf, std::size(buf));
	assert(strcmp(buf, b) == 0);
	utf8_to_mutf7(b, strlen(b), buf, std::size(buf));
	assert(strcmp(buf, "Gel&-APY-schte Elemente") == 0);
	assert(mutf7_to_utf8("INBOX", 5, buf, 6) == 5);
	assert(mutf7_to_utf8("INBOX2", 6, buf, 6) < 0);
	assert(mutf7_to_utf8("", 0, buf, 6) == 0);
	return EXIT_SUCCESS;
}

static int t_extpp()
{
	std::string encid(reinterpret_cast<const char *>(EncodedGlobalId.ab), std::size(EncodedGlobalId.ab));
	auto s = encid + hex2bin("000000009b2dbdb2255659027cf33d2a183706db6bc9240adbd249557c96f6783dcc06d8f9c48b1f");
	EXT_PULL ep;
	ep.init(s.data(), s.size(), zalloc, 0);
	GLOBALOBJECTID goid;
	auto ret = ep.g_goid(&goid);
	assert(ret == pack_result::ok && goid.unparsed);
#define s_date "0000000066b5d6b711d901010000000000000000"
	s = encid + hex2bin(s_date "01000000ffff");
	ep.init(s.data(), s.size(), zalloc, 0);
	assert(ep.g_goid(&goid) == pack_result::ok);
	assert((!goid.unparsed && goid.data.cb == 1) ||
	       (goid.unparsed && goid.data.cb == 6));
	s = encid + hex2bin(s_date "02000000ff");
	ep.init(s.data(), s.size(), zalloc, 0);
	assert(ep.g_goid(&goid) == pack_result::ok);
	assert(goid.unparsed && goid.data.cb == 5);
#undef s_date
	return EXIT_SUCCESS;
}

static int t_convert()
{
	char out[1];
	if (!string_mb_to_utf8("cp1252", "foo", out, std::size(out)))
		/* ignore */;
	if (!string_utf8_to_mb("cp1252", "foo", out, std::size(out)))
		/* ignore */;
	char largeout[1024] = "foo";
	if (!string_mb_to_utf8("utf-8", "utf-8", largeout, std::size(largeout)))
		return EXIT_FAILURE;
	gx_strlcpy(largeout, "\xef\xbb\xff foo \xef\xbb\xbf", std::size(largeout));
	if (utf8_valid(&largeout[0]))
		return EXIT_FAILURE;
	if (!utf8_valid(&largeout[3]))
		return EXIT_FAILURE;
	utf8_filter(largeout);
	if (strcmp(largeout, "??? foo \xef\xbb\xbf") != 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

static int t_emailaddr()
{
	for (const auto s : {"u@d.at", "<u@d.at>", "\"u@d.at\"", "U D <u@d.at>",
	     "\"U D\" <u@d.at>", "\"U\\\"D\" <u@d.at>",
	     "=?utf-8?Q?=C3=A5 D?= <u@d.at>", "\"U D\"", "\"U D\" <>"}) {
		printf("%s:\n", s);
		EMAIL_ADDR em(s);
		printf("\tmime: <%s> <%s> <%s>\n", em.display_name, em.local_part, em.domain);
	}
	return EXIT_SUCCESS;
}

static int t_id1()
{
	idset s(idset::type::id_loose);
	/* right-side half overlap */
	s.append_range(1, 1, 17);
	s.append_range(1, 14, 21);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().lo == 1 && l.front().hi == 21);
	return EXIT_SUCCESS;
}

static int t_id2()
{
	idset s(idset::type::id_loose);
	/* left-side half overlap */
	s.append_range(1, 14, 21);
	s.append_range(1, 1, 17);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().lo == 1 && l.front().hi == 21);
	return EXIT_SUCCESS;
}

static int t_id3()
{
	idset s(idset::type::id_loose);
	/* right-side adjacency */
	s.append_range(1, 1, 19);
	s.append_range(1, 20, 29);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().lo == 1 && l.front().hi == 29);
	return EXIT_SUCCESS;
}

static int t_id4()
{
	idset s(idset::type::id_loose);
	/* left-side adjacency */
	s.append_range(1, 20, 29);
	s.append_range(1, 1, 19);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().lo == 1 && l.front().hi == 29);
	return EXIT_SUCCESS;
}

static int t_id5()
{
	idset s(idset::type::id_loose);
	/* inner overlap */
	s.append_range(1, 1, 40);
	s.append_range(1, 15, 19);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().lo == 1 && l.front().hi == 40);
	return EXIT_SUCCESS;
}

static int t_id6()
{
	idset s(idset::type::id_loose);
	/* outer overlap */
	s.append_range(1, 15, 19);
	s.append_range(1, 1, 40);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 1);
	assert(l.front().lo == 1 && l.front().hi == 40);
	return EXIT_SUCCESS;
}

static int t_id7()
{
	idset s(idset::type::id_loose);
	s.append_range(1, 11, 19);
	s.append_range(1, 71, 79);
	auto &l = s.get_repl_list().front().range_list;
	assert(l.size() == 2);
	assert(l.front().lo == 11 && l.front().hi == 19);
	assert(l.back().lo == 71 && l.back().hi == 79);
	s.append_range(1, 41, 49);
	assert(l.size() == 3);
	assert(l.front().lo == 11 && l.front().hi == 19);
	assert(std::next(l.begin())->lo == 41 && std::next(l.begin())->hi == 49);
	assert(l.back().lo == 71 && l.back().hi == 79);
	/* gap filler */
	s.append_range(1, 20, 40);
	assert(l.size() == 2);
	assert(l.front().lo == 11 && l.front().hi == 49);
	assert(l.back().lo == 71 && l.back().hi == 79);
	s.append_range(1, 50, 70);
	assert(l.size() == 1);
	assert(l.front().lo == 11 && l.front().hi == 79);
	return EXIT_SUCCESS;
}

static int t_id8()
{
	idset s(idset::type::id_loose);
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

static int t_id9()
{
	printf("\n== t_id9: range_set\n");
	gromox::range_set<int> s;
	s.insert(61, 63);
	s.insert(51, 53);
	assert(!s.contains(50));
	assert(s.contains(51));
	assert(s.contains(52));
	assert(s.contains(53));
	assert(!s.contains(54));
	assert(!s.contains(60));
	assert(s.contains(61));
	assert(s.contains(62));
	assert(s.contains(63));
	assert(!s.contains(64));
	s.insert(100, INT_MAX);
	assert(!s.contains(50));
	assert(s.contains(51));
	assert(s.contains(52));
	assert(s.contains(53));
	assert(!s.contains(54));
	assert(!s.contains(60));
	assert(s.contains(61));
	assert(s.contains(62));
	assert(s.contains(63));
	assert(!s.contains(64));
	assert(!s.contains(99));
	assert(s.contains(100));
	assert(s.contains(INT_MAX));
	return EXIT_SUCCESS;
}

static int t_seq()
{
	imap_seq_list r;
	auto err = parse_imap_seq(r, "1,3:4,6:*,,");
	assert(err == 0);
	assert(r.size() == 3);
	err = parse_imap_seq(r, "4:3,*:6");
	assert(err == 0);
	assert(r.size() == 2);
	err = parse_imap_seq(r, "1,*");
	assert(err == 0);
	assert(r.size() == 2);
	return 0;
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
		~M() { printf("~M\n"); }
		NOMOVE(M);
		int zz = 21;
	};
	resource_pool<M> m;
	resource_pool<S> s;
	m.resize(5);
	auto mt3 = m.get_wait(45);
	{
		auto mt = m.get_wait(44);
		printf("%d\n", mt->zz);
		auto mt2 = m.get_wait(45);
		printf("%d\n", mt2->zz);
		/* mt, mt2 get returned to the pool... */
	}
	/* Pool now has capacity=4 available=2 (inflight=1), so two ~M are expected now */
	m.resize(0);
	printf("Pool shrinkage complete\n");
	/* Now the third ~M */
}

static int t_cmp_binary()
{
	uint8_t x[] = "X", xy[] = "XY";
	BINARY p = {1, {x}}, q = {2, {xy}};
	assert(p.compare(q) < 0);
	return EXIT_SUCCESS;
}

static int t_cmp_guid()
{
	GUID g1 = {0x01}, g2 = {0x0100};
	assert(g1.compare(g2) < 0);

	char buf[sizeof(FLATUID)];
	EXT_PUSH ep;
	ep.init(buf, sizeof(buf), 0);
	if (ep.p_guid(PSETID_Address) != pack_result::success)
		return EXIT_FAILURE;
	assert(memcmp(ep.m_udata, "\x04\x20\x06\x00", 4) == 0);
	static_assert(std::is_same_v<decltype(PSETID_Address), const GUID>);

	ep.init(buf, sizeof(buf), 0);
	if (ep.p_guid(muidEMSAB) != pack_result::ok)
		return EXIT_FAILURE;
	assert(memcmp(ep.m_udata, "\xDC\xA7\x40\xC8", 4) == 0);
	static_assert(std::is_same_v<decltype(muidEMSAB), const FLATUID>);
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

	if (decode64_ex(cpool, std::size(cpool) - 1, out, std::size(out), &outlen) < 0)
		return printf("TB-8 failed\n");
	if (decode64_ex("MTIz\nMTIz\nMTIz\n", 15, out, std::size(out), &outlen) < 0)
		return printf("TB-9 failed\n");
	else if (memcmp(out, "123123123", 9) != 0)
		return printf("TB-10 failed\n");

	if (decode64_ex("\xff\xff\xff\xff", 4, out, std::size(out), &outlen) >= 0)
		return printf("TB-18 failed\n");
#if 0 /* implementation too lenient */
	if (decode64_ex("====", 4, out, std::size(out), &outlen) >= 0)
		return printf("TB-19 failed\n");
	if (decode64_ex("A===", 4, out, std::size(out), &outlen) >= 0)
		return printf("TB-20 failed\n");
	if (decode64_ex("AA==", 4, out, std::size(out), &outlen) >= 0)
		return printf("TB-21 failed\n");
#endif

	if (qp_encode_ex(out, 3, "\x01", 1) >= 0)
		return printf("TQ-1 failed\n");
	if (qp_encode_ex(out, 4, "\x01", 1) < 0)
		return printf("TQ-2 failed\n");
	if (qp_decode_ex(out, 1, "=3D", 3) >= 0)
		return printf("TQ-3 failed\n");
	if (qp_decode_ex(out, 2, "=3D", 3) < 0)
		return printf("TQ-4 failed\n");

	char thebuf[1];
	thebuf[0] = '=';
	if (qp_decode_ex(out, 4, &thebuf[0], 1) > 0)
		return printf("TQ-5 failed\n");
	if (qp_decode_ex(out, 0, &thebuf[0], 1) >= 0)
		return printf("TQ-6 failed\n");
	return 0;
}

static int t_cmp_icaltime()
{
	ical_time a{}, b{};
	a.second = b.second = 59;
	a.leap_second = 60;
	if (a.twcompare(b) != -b.twcompare(a))
		return printf("ical_time::compare failed\n");
	return 0;
}

static int t_wildcard()
{
	return wildcard_match("[", "*", true) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int t_utf8_prefix()
{
	static constexpr char s[] = "Aß\r\n";
	if (utf8_printable_prefix(s, std::size(s) - 1) != std::size(s) - 1)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

static int t_msgchg()
{
	const char *mpath = getenv("TEST_PATH");
	if (mpath == nullptr)
		mpath = PKGDATADIR;
	if (msgchg_grouping_run(mpath) != 0)
		return EXIT_FAILURE;
	auto pgi = msgchg_grouping_get_groupinfo([](void *store, BOOL create, const PROPERTY_NAME *pn, uint16_t *id) -> BOOL {
		static propid_t propid = 0x8000;
		*id = propid++;
		return TRUE;
	}, nullptr, 1);
	assert(pgi->group_id == 1);
	assert(pgi->count == 25);
	assert(pgi->pgroups[0].count == 5);
	assert(is_nameprop_id(PROP_ID(pgi->pgroups[7].pproptag[0])));
	assert(PROP_TYPE(pgi->pgroups[7].pproptag[0]) != 0);
	return 0;
}

static int t_eidcvt()
{
	uint8_t network_input[] = {2,0,0,0,0,0x1,0xff,0xfe};
	EXT_PULL ep;
	ep.init(network_input, sizeof(network_input), malloc, 0);
	uint64_t eid = 0;
	ep.g_uint64(&eid);
	assert(rop_util_get_replid(eid) == 2);
	assert(rop_util_get_gc_value(eid) == 0x1fffe);
	auto gc = rop_util_get_gc_array(eid);
	assert(memcmp(gc.ab, &network_input[2], 6) == 0);
	assert(rop_util_gc_to_value(gc) == 0x1fffe);
	assert(rop_util_make_eid(2, gc) == eid);
	assert(rop_util_make_eid_ex(2, 0x1fffe) == eid);

	XID xid{GUID_NULL, rop_util_make_eid_ex(1, 0x8877665544332211ULL)};
	assert(memcmp(xid.local_id, "\x66\x55\x44\x33\x22\x11", 6) == 0);
	return EXIT_SUCCESS;
}

static int t_bin2cstr()
{
	static constexpr char input[] = "\1""0\10""0\100""0";
	static constexpr char exp[] = "\\0010\\b0@0";
	auto got = bin2cstr(input, strlen(input));
	if (strcmp(got.c_str(), exp) != 0) {
		fprintf(stderr, "bin2cstr: expected %s, got %s\n", exp, got.c_str());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int t_string()
{
	auto p = search_string("foobar", "oba", 3);
	assert(p == nullptr);
	p = search_string("foobar", "foo", 3);
	assert(p != nullptr);
	p = search_string("", "foo", 0);
	assert(p == nullptr);
	return EXIT_SUCCESS;
}

static bool negative_time_possible()
{
	time_t spot = -1;
	return gmtime(&spot) != nullptr;
}

static int t_time()
{
#define SYSTEMTIME_MAX 0x7fff35f4f06c7fffLL

	printf("It is now approximately %lld (mapitime_t)\n",
		static_cast<long long>(rop_util_unix_to_nttime(std::chrono::system_clock::now())));

	assert(rop_util_unix_to_nttime(INT_MAX) > 0);

	if (sizeof(time_t) >= sizeof(int64_t)) {
		/* this libc supports 64-bit time */
		auto r = rop_util_unix_to_nttime(SYSTEMTIME_MAX / 10000000 - TIME_FIXUP_CONSTANT_INT);
		assert(r < SYSTEMTIME_MAX);
		r = rop_util_unix_to_nttime((SYSTEMTIME_MAX + 1) / 10000000 - TIME_FIXUP_CONSTANT_INT);
		assert(r > SYSTEMTIME_MAX);
		r = rop_util_unix_to_nttime(INT64_MAX / 10000000 - TIME_FIXUP_CONSTANT_INT - 1);
		assert(r > 0);
		r = rop_util_unix_to_nttime(INT64_MAX / 10000000 - TIME_FIXUP_CONSTANT_INT);
		assert(r > 0);
		r = rop_util_unix_to_nttime(INT64_MAX / 10000000 - TIME_FIXUP_CONSTANT_INT + 1);
		assert(r > SYSTEMTIME_MAX);
	}
	if (negative_time_possible()) {
		assert(rop_util_unix_to_nttime(-1) > 0);
		assert(rop_util_unix_to_nttime(-TIME_FIXUP_CONSTANT_INT) == 0);
		assert(rop_util_unix_to_nttime(INT32_MIN) > 0);
		if (sizeof(time_t) >= sizeof(int64_t))
			assert(rop_util_unix_to_nttime(INT64_MIN) > SYSTEMTIME_MAX);

		assert(rop_util_nttime_to_unix((TIME_FIXUP_CONSTANT_INT * 10000000) - 1) < 0);
		assert(rop_util_nttime_to_unix(0) <= INT32_MIN);
	}
	assert(rop_util_nttime_to_unix(TIME_FIXUP_CONSTANT_INT * 10000000) == 0);
	assert(rop_util_nttime_to_unix(INT64_MAX) >= INT32_MAX);
	return EXIT_SUCCESS;
}

static int runner()
{
	if (t_utf7() != 0)
		return EXIT_FAILURE;
	char buf[2];
	randstring(buf + 2, 0, "A");
	randstring(buf, 1, "");

	using fpt = decltype(&t_interval);
	static constexpr fpt fct[] = {
		t_msgchg, t_extpp, t_convert, t_emailaddr, t_base64,
		t_interval, t_id1, t_id2, t_id3, t_id4, t_id5, t_id6,
		t_id7, t_id8, t_id9, t_seq,
		t_cmp_binary, t_cmp_guid, t_cmp_svreid, t_cmp_icaltime,
		t_wildcard, t_utf8_prefix, t_eidcvt, t_bin2cstr, t_string,
		t_time,
	};
	for (auto f : fct) {
		auto ret = f();
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	t_respool();
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	static_assert(sizeof(cpu_to_le16(0)) == sizeof(uint16_t));
	static_assert(sizeof(cpu_to_le32(0)) == sizeof(uint32_t));
	static_assert(sizeof(cpu_to_le64(0)) == sizeof(uint64_t));
	static_assert(sizeof(cpu_to_be16(0)) == sizeof(uint16_t));
	static_assert(sizeof(cpu_to_be32(0)) == sizeof(uint32_t));
	static_assert(sizeof(cpu_to_be64(0)) == sizeof(uint64_t));
	static_assert(sizeof(le16_to_cpu(0)) == sizeof(uint16_t));
	static_assert(sizeof(le32_to_cpu(0)) == sizeof(uint32_t));
	static_assert(sizeof(le64_to_cpu(0)) == sizeof(uint64_t));
	static_assert(sizeof(be16_to_cpu(0)) == sizeof(uint16_t));
	static_assert(sizeof(be32_to_cpu(0)) == sizeof(uint32_t));
	static_assert(sizeof(be64_to_cpu(0)) == sizeof(uint64_t));
	if (argc >= 3 && strcmp(argv[1], "nttime") == 0) {
		auto nt = strtoll(argv[2], nullptr, 0);
		auto ut = rop_util_nttime_to_unix(nt);
		printf("...is unixtime %lld\n", static_cast<long long>(ut));
		char buf[64];
		auto tm = localtime(&ut);
		strftime(buf, std::size(buf), "%FT%T", tm);
		printf("...is calendar %s\n", buf);
		return EXIT_SUCCESS;
	} else if (argc >= 3 && strcmp(argv[1], "unixtime") == 0) {
		time_t ut = strtoll(argv[2], nullptr, 0);
		auto nt = rop_util_unix_to_nttime(ut);
		printf("...is nttime %lld\n", static_cast<long long>(nt));
		char buf[64];
		auto tm = localtime(&ut);
		strftime(buf, std::size(buf), "%FT%T", tm);
		printf("...is calendar %s\n", buf);
		return EXIT_SUCCESS;
	}
	auto ret = runner();
	if (ret != EXIT_SUCCESS)
		printf("FAILED\n");
	return ret;
}
