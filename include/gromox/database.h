#pragma once
#ifndef __cplusplus
#	include <stdbool.h>
#	include <stdio.h>
#	include <string.h>
#else
#	include <cstdio>
#	include <cstring>
#endif
#include <mysql.h>
#include <sqlite3.h>
#include <gromox/defs.h>

#ifdef __cplusplus
namespace gromox {

using DB_LENGTHS = unsigned long *;
using DB_ROW = char **;

class GX_EXPORT DB_RESULT final {
	public:
	DB_RESULT() = default;
	DB_RESULT(MYSQL_RES *r) noexcept : m_res(r) {}
	DB_RESULT(DB_RESULT &&o) noexcept : m_res(o.m_res) { o.m_res = nullptr; }
	~DB_RESULT()
	{
		if (m_res != nullptr)
			mysql_free_result(m_res);
	}

	DB_RESULT &operator=(DB_RESULT &&o) noexcept
	{
		if (m_res != nullptr)
			mysql_free_result(m_res);
		m_res = o.m_res;
		o.m_res = nullptr;
		return *this;
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

	private:
	MYSQL_RES *m_res = nullptr;
};

}
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline bool gx_sql_prep(sqlite3 *db, const char *query, sqlite3_stmt **out)
{
	int ret = sqlite3_prepare_v2(db, query, -1, out, nullptr);
	if (ret == SQLITE_OK)
		return true;
	printf("sqlite3_prepare_v2 \"%s\": %s\n", query, sqlite3_errstr(ret));
	return false;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
