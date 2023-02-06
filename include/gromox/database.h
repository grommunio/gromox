#pragma once
#include <cstdint>
#include <sqlite3.h>
#include <gromox/defs.h>

namespace gromox {

class GX_EXPORT xtransaction {
	public:
	constexpr xtransaction(sqlite3 *d = nullptr) { m_db = d; }
	xtransaction(xtransaction &&) noexcept = delete;
	~xtransaction();
	int commit();
	xtransaction &operator=(xtransaction &&) noexcept;
	operator bool() const { return m_db != nullptr; }

	protected:
	sqlite3 *m_db = nullptr;
};

extern GX_EXPORT int gx_sql_step(sqlite3_stmt *, unsigned int flags = 0);

struct GX_EXPORT xstmt {
	xstmt() = default;
	xstmt(xstmt &&o) noexcept : m_ptr(o.m_ptr) { o.m_ptr = nullptr; }
	~xstmt() {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
	}
	inline int bind_null(unsigned int col) { return sqlite3_bind_null(m_ptr, col); }
	inline int bind_int64(unsigned int col, uint64_t v) { return sqlite3_bind_int64(m_ptr, col, v); }
	inline int bind_text(unsigned int col, const char *s) { return sqlite3_bind_text(m_ptr, col, s, -1, SQLITE_STATIC); }
	inline int bind_blob(unsigned int col, const void *d, size_t z) { return sqlite3_bind_blob64(m_ptr, col, d, z, SQLITE_STATIC); }
	inline const char *col_text(unsigned int col) { return reinterpret_cast<const char *>(sqlite3_column_text(m_ptr, col)); }
	inline int64_t col_int64(unsigned int col) { return sqlite3_column_int64(m_ptr, col); }
	inline uint64_t col_uint64(unsigned int col) {
		auto x = sqlite3_column_int64(m_ptr, col);
		return x >= 0 ? x : 0;
	}
	inline int step() { return gx_sql_step(m_ptr); }
	inline int reset() { return sqlite3_reset(m_ptr); }
	inline void finalize() { *this = nullptr; }
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

}
