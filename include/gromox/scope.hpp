// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <exception>
#include <utility>

namespace gromox {

/*
 * Modeled upon the C++ standards proposal P0052r10 / Library Fundamentals v3.
 * Not yet present in GNU stdlibc++ or clang libc++.
 */
template<typename F> class scope_exit {
	private:
	F m_func;
	bool m_eod = false;

	public:
	explicit scope_exit(F &&f) : m_func(std::move(f)), m_eod(true) {}
	scope_exit(scope_exit &&o) : m_func(std::move(o.m_func)), m_eod(o.m_eod) {
		o.m_eod = false;
	}
	~scope_exit() try {
		if (m_eod)
			m_func();
	} catch (...) {
	}
	void operator=(scope_exit &&) = delete;
	void release() noexcept { m_eod = false; }
};

template<typename F> scope_exit<F> make_scope_exit(F &&f)
{
	return scope_exit<F>(std::move(f));
}

} /* namespace */
