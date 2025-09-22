#pragma once
#include <cstdint>
#include <string>
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

	private:
	void teardown();
};

/**
 * SQLite3 SAVEPOINT wrapper
 * @m_db:   database handle
 * @m_name: identifier for the savepoint
 */
class GX_EXPORT xsavepoint {
	public:
	xsavepoint(sqlite3 *, const char *sp_name);
	NOMOVE(xsavepoint);
	~xsavepoint();
	inline operator bool() const { return m_db != nullptr; }
	int commit();
	int rollback();

	private:
	sqlite3 *m_db = nullptr;
	std::string m_name;
};

extern GX_EXPORT int gx_sql_step(sqlite3_stmt *, unsigned int flags = 0);

struct GX_EXPORT xstmt {
	xstmt() = default;
	xstmt(xstmt &&o) noexcept : m_ptr(o.m_ptr) { o.m_ptr = nullptr; }
	~xstmt() {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
	}
	/*
	 * How sqlite treats literals in SQL command text:
	 * - if L is a hex integer literal (0x prefix),
	 *   it will be byte-reinterpreted as a signed 64-bit int
	 * - if L is an integer literal >= 9223372036854775808,
	 *   it will be converted to a floating-point type
	 *
	 * ...which is why we also just pass uint64_t to bind_int64
	 * and vice-versa.
	 */
	inline int bind_null(unsigned int col) { return sqlite3_bind_null(m_ptr, col); }
	inline int bind_int64(unsigned int col, uint64_t v) { return sqlite3_bind_int64(m_ptr, col, v); }
	inline int bind_text(unsigned int col, std::string_view s) { return sqlite3_bind_text(m_ptr, col, s.data(), s.size(), SQLITE_STATIC); }
	inline int bind_blob(unsigned int col, const void *d, size_t z) { return sqlite3_bind_blob64(m_ptr, col, d, z, SQLITE_STATIC); }
	inline const char *col_text(unsigned int col) { return reinterpret_cast<const char *>(sqlite3_column_text(m_ptr, col)); }
	inline int64_t col_int64(unsigned int col) { return sqlite3_column_int64(m_ptr, col); }
	inline uint64_t col_uint64(unsigned int col) { return sqlite3_column_int64(m_ptr, col); }
	inline int step(unsigned int flags = 0) { return gx_sql_step(m_ptr, flags); }
	inline int reset() { return sqlite3_reset(m_ptr); }
	void finalize() {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
		m_ptr = nullptr;
	}
	inline void operator=(std::nullptr_t) { finalize(); }
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

enum class txn_mode {
	read, write,
};

extern GX_EXPORT struct xstmt gx_sql_prep(sqlite3 *, const char *);
inline GX_EXPORT struct xstmt gx_sql_prep(sqlite3 *d, const std::string &q) { return gx_sql_prep(d, q.c_str()); }
extern GX_EXPORT xtransaction gx_sql_begin3(const std::string &, sqlite3 *, txn_mode);
#define gx_sql_begin(...) gx_sql_begin3(std::string(__FILE__) + ":" + std::to_string(__LINE__), __VA_ARGS__)
extern GX_EXPORT int gx_sql_exec(sqlite3 *, const char *query, unsigned int flags = 0);
inline GX_EXPORT int gx_sql_exec(sqlite3 *d, const std::string &q, unsigned int fl = 0) { return gx_sql_exec(d, q.c_str(), fl); }

static inline uint64_t gx_sql_col_uint64(sqlite3_stmt *s, int c)
{
	auto x = sqlite3_column_int64(s, c);
	return x >= 0 ? x : 0;
}

extern GX_EXPORT unsigned int gx_sqlite_debug, gx_force_write_txn;
extern GX_EXPORT unsigned int gx_sql_deep_backtrace;

}
