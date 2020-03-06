#pragma once
#include <exception>
#include <utility>

namespace gromox {

/* P0052r5 (C++2020) */
template<typename F> class scope_success {
	private:
	F m_func;
	bool m_eod = false;

	public:
	explicit scope_success(F &&f) : m_func(std::move(f)), m_eod(true) {}
	scope_success(scope_success &&o) : m_func(std::move(o.m_func)), m_eod(o.m_eod) {}
	~scope_success() noexcept(noexcept(m_func()))
	{
#if __cplusplus >= 201700L
		if (m_eod && std::uncaught_exceptions() == 0)
			m_func();
#else
		if (m_eod && !std::uncaught_exception())
			m_func();
#endif
	}
	void operator=(scope_success &&) = delete;
};

template<typename F> scope_success<F> make_scope_success(F &&f)
{
	return scope_success<F>(std::move(f));
}

} /* namespace */
