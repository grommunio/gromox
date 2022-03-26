// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH licensing exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
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
 *
 * Functionality like this has found its way into C++ standards proposal
 * P1132R0 and then C++23, as std::out_ptr and std::inout_ptr.
 */
template<typename T, typename D> class unique_proxy {
	public:
	unique_proxy(std::unique_ptr<T, D> &a) : u(a), p(u.get()) {}
	~unique_proxy() { u.reset(p); }
	typename std::unique_ptr<T, D>::pointer *operator&() { return &p; }
	unique_proxy &operator~() { u.reset(); p = nullptr; return *this; }
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
