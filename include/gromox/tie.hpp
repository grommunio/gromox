// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH licensing exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#pragma once
#include <memory>

namespace gromox {

/*
 * For functions which return their result through an argument pointer,
 * a temporary variable may be necessary when one wishes to use unique_ptr:
 * 	unique_ptr<char> u; char *x; bla_alloc(&x); u.reset(x);
 * With unique_tie, this gets shorter:
 * 	unique_ptr<char> u; bla_alloc(&unique_tie(u));
 */
template<typename T, typename D> class unique_proxy {
	public:
	unique_proxy(std::unique_ptr<T, D> &a) : u(a), p(u.get()) {}
	~unique_proxy() { u.reset(p); }
	typename std::unique_ptr<T, D>::pointer *operator&() { return &p; }
	private:
	std::unique_ptr<T, D> &u;
	typename std::unique_ptr<T, D>::pointer p;
};

template<typename T, typename D> unique_proxy<T, D>
unique_tie(std::unique_ptr<T, D> &u)
{
	return unique_proxy<T, D>(u);
}

} /* namespace */
