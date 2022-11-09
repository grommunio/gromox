#pragma once
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <memory>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <gromox/defs.h>

struct BINARY;

#ifdef COMPILE_DIAG
/* Compiler generates important -Wformat-truncation diagnostics */
#define gx_snprintf snprintf
#define gx_vsnprintf vsnprintf
#else
#define gx_snprintf(buf, size, fmt, ...) gx_snprintf1((buf), (size), __FILE__, __LINE__, (fmt), ## __VA_ARGS__)
#define gx_vsnprintf(buf, size, fmt, ...) gx_vsnprintf1((buf), (size), __FILE__, __LINE__, (fmt), ## __VA_ARGS__)
#endif
extern GX_EXPORT int gx_snprintf1(char *, size_t, const char *, unsigned int, const char *, ...) __attribute__((format(printf, 5, 6)));
extern GX_EXPORT int gx_vsnprintf1(char *, size_t, const char *, unsigned int, const char *, va_list);
extern GX_EXPORT gromox::errno_t read_file_by_line(const char *file, std::vector<std::string> &);

namespace gromox {

struct file_deleter {
	inline void operator()(DIR *d) const { closedir(d); }
	inline void operator()(FILE *f) const { fclose(f); }
};

struct DIR_mp {
	std::string m_path;
	std::unique_ptr<DIR, file_deleter> m_dir;
};

class wrapfd {
	public:
	wrapfd(int z) : m_fd{z} {}
	wrapfd(wrapfd &&) noexcept = delete;
	~wrapfd();
	int get() const { return m_fd; }
	int release() { int t = m_fd; m_fd = -1; return t; }
	void close() { if (m_fd >= 0) ::close(m_fd); m_fd = -1; }
	void operator=(wrapfd &&o) noexcept {
		if (m_fd >= 0)
			::close(m_fd);
		m_fd = o.m_fd;
		o.m_fd = -1;
	}
	private:
	int m_fd = -1;
};

extern GX_EXPORT std::string iconvtext(const char *, size_t, const char *from, const char *to);
extern GX_EXPORT pid_t popenfd(const char *const *, int *, int *, int *, const char *const *);
extern GX_EXPORT ssize_t feed_w3m(const void *in, size_t insize, std::string &out);
extern GX_EXPORT std::vector<std::string> gx_split(const std::string_view &, char sep);
extern GX_EXPORT DIR_mp opendir_sd(const char *, const char *);
extern GX_EXPORT std::unique_ptr<FILE, file_deleter> fopen_sd(const char *, const char *);
extern GX_EXPORT std::string resource_parse_stcode_line(const char *);
extern GX_EXPORT void startup_banner(const char *);
extern GX_EXPORT void gx_reexec_finish();
extern GX_EXPORT errno_t gx_reexec(const char *const *);
extern GX_EXPORT void gx_reexec_record(int);
extern GX_EXPORT unsigned long gx_gettid();
extern GX_EXPORT std::string zstd_decompress(std::string_view);
extern GX_EXPORT size_t gx_decompressed_size(const char *);
extern GX_EXPORT errno_t gx_decompress_file(const char *, BINARY &, void *(*)(size_t), void *(*)(void *, size_t));
extern GX_EXPORT errno_t gx_compress_tofile(std::string_view, const char *outfile, uint8_t complvl = 0);
extern GX_EXPORT std::string base64_decode(const std::string_view &);
extern GX_EXPORT std::string sss_obf_reverse(const std::string_view &);
extern GX_EXPORT int open_tmpfile(const char *, std::string *, unsigned int, unsigned int = 0600);

}
