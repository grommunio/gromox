#pragma once
#include <cstddef>
#include <mysql.h>
#include <gromox/defs.h>

namespace gromox {

using DB_LENGTHS = unsigned long *;
using DB_ROW = char **;

struct mysql_delete {
	inline void operator()(MYSQL *x) const { mysql_close(x); }
};

class GX_EXPORT DB_RESULT final {
	public:
	DB_RESULT() = default;
	DB_RESULT(MYSQL_RES *r) noexcept : m_res(r) {}
	DB_RESULT(DB_RESULT &&o) noexcept : m_res(o.m_res) { o.m_res = nullptr; }
	~DB_RESULT() { clear(); }

	DB_RESULT &operator=(DB_RESULT &&o) noexcept
	{
		clear();
		m_res = o.m_res;
		o.m_res = nullptr;
		return *this;
	}
	void clear() {
		if (m_res != nullptr)
			mysql_free_result(m_res);
		m_res = nullptr;
	}
	operator bool() const noexcept { return m_res != nullptr; }
	bool operator==(std::nullptr_t) const noexcept { return m_res == nullptr; }
	bool operator!=(std::nullptr_t) const noexcept { return m_res != nullptr; }
	MYSQL_RES *get() const noexcept { return m_res; }
	void *release() noexcept
	{
		void *p = m_res;
		m_res = nullptr;
		return p;
	}

	size_t num_rows() const { return mysql_num_rows(m_res); }
	DB_ROW fetch_row() { return mysql_fetch_row(m_res); }
	DB_LENGTHS row_lengths() { return mysql_fetch_lengths(m_res); }

	private:
	MYSQL_RES *m_res = nullptr;
};

}
