#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <gromox/mapi_types.hpp>
#include <gromox/resource_pool.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp> 
using namespace gromox;

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
	const char *in = " 1 d 1 h 1 m 1 s ";
	long exp = 86400 + 3600 + 60 + 1;
	auto got = atoitvl(in);
	if (got != exp) {
		printf("IN \"%s\" EXP %ld GOT %ld\n", in, exp, got);
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

static void t_cmp_binary()
{
	uint8_t x[] = "X", xy[] = "XY";
	BINARY p = {1, x}, q = {2, xy};
	assert(p.compare(q) < 0);
}

int main()
{
	using fpt = decltype(&t_interval);
	fpt fct[] = {t_interval, t_id1, t_id2, t_id3, t_id4, t_id5, t_id6,
	             t_id7, t_id8};
	for (auto f : fct) {
		auto ret = f();
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	t_respool();
	t_cmp_binary();
	return EXIT_SUCCESS;
}
