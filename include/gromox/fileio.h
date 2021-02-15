#pragma once
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <dirent.h>
#include <memory>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <gromox/defs.h>

#define gx_snprintf(buf, size, fmt, ...) gx_snprintf1((buf), (size), __FILE__, __LINE__, (fmt), ## __VA_ARGS__)
#define gx_vsnprintf(buf, size, fmt, ...) gx_vsnprintf1((buf), (size), __FILE__, __LINE__, (fmt), ## __VA_ARGS__)
extern GX_EXPORT int gx_snprintf1(char *, size_t, const char *, unsigned int, const char *, ...) __attribute__((format(printf, 5, 6)));
extern GX_EXPORT int gx_vsnprintf1(char *, size_t, const char *, unsigned int, const char *, va_list);
extern char **read_file_by_line(const char *file);

namespace gromox {

struct file_deleter {
	void operator()(DIR *d) { closedir(d); }
	void operator()(FILE *f) { fclose(f); }
};

struct DIR_mp {
	std::string m_path;
	std::unique_ptr<DIR, file_deleter> m_dir;
};

class wrapfd {
	public:
	wrapfd(int z) : m_fd{z} {}
	wrapfd(wrapfd &&) = delete;
	~wrapfd() { if (m_fd >= 0) ::close(m_fd); }
	int get() const { return m_fd; }
	void close() { if (m_fd >= 0) ::close(m_fd); m_fd = -1; }
	void operator=(wrapfd &&o) {
		if (m_fd >= 0)
			::close(m_fd);
		m_fd = o.m_fd;
		o.m_fd = -1;
	}
	private:
	int m_fd = -1;
};

extern std::string iconvtext(const char *, size_t, const char *from, const char *to);
extern GX_EXPORT pid_t popenfd(const char *const *, int *, int *, int *, const char *const *);
extern GX_EXPORT ssize_t feed_w3m(const void *in, size_t insize, std::string &out);
extern GX_EXPORT std::vector<std::string> gx_split(const std::string_view &, char sep);
extern GX_EXPORT DIR_mp opendir_sd(const char *, const char *);
extern GX_EXPORT std::unique_ptr<FILE, file_deleter> fopen_sd(const char *, const char *);
extern GX_EXPORT std::string slurp_file(FILE *);
extern GX_EXPORT std::string slurp_file(const char *filename);

}
