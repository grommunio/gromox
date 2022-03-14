#pragma once
#include <cstdint>
#include <sqlite3.h>
#include <gromox/defs.h>

class GX_EXPORT xtransaction {
	public:
	constexpr xtransaction(sqlite3 *d = nullptr) { m_db = d; }
	xtransaction(xtransaction &&) noexcept = delete;
	~xtransaction();
	void commit();
	xtransaction &operator=(xtransaction &&) noexcept;

	protected:
	sqlite3 *m_db = nullptr;
};

struct xstmt {
	xstmt() = default;
	xstmt(xstmt &&o) noexcept : m_ptr(o.m_ptr) { o.m_ptr = nullptr; }
	~xstmt() {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
	}
	void finalize() { *this = nullptr; }
	void operator=(std::nullptr_t) {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
		m_ptr = nullptr;
	}
	void operator=(xstmt &&o) noexcept {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
		m_ptr = o.m_ptr;
		o.m_ptr = nullptr;
	}
	operator sqlite3_stmt *() { return m_ptr; }
	sqlite3_stmt *m_ptr = nullptr;
};

enum {
	SQLEXEC_SILENT_CONSTRAINT = 0x1U,
};

extern GX_EXPORT struct xstmt gx_sql_prep(sqlite3 *, const char *);
extern GX_EXPORT xtransaction gx_sql_begin_trans(sqlite3 *);
extern GX_EXPORT int gx_sql_exec(sqlite3 *, const char *query, unsigned int flags = 0);

static inline uint64_t gx_sql_col_uint64(sqlite3_stmt *s, int c)
{
	auto x = sqlite3_column_int64(s, c);
	return x >= 0 ? x : 0;
}

extern GX_EXPORT unsigned int gx_sqlite_debug;
