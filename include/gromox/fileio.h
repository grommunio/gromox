#pragma once
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

extern GX_EXPORT gromox::errno_t read_file_by_line(const char *file, std::vector<std::string> &);
extern GX_EXPORT gromox::errno_t read_file_by_line(const char *file, const char *sdlist, std::vector<std::string> &);

namespace gromox {

struct GX_EXPORT file_deleter {
	inline void operator()(DIR *d) const { closedir(d); }
	inline void operator()(FILE *f) const { fclose(f); }
};

struct GX_EXPORT DIR_mp {
	std::string m_path;
	std::unique_ptr<DIR, file_deleter> m_dir;
};

/**
 * open_anon():	make a file
 * open_link():	make a file that can subsequently be linked into the filesystem
 * linkto():	make the temporary permannt using a given name
 * 		[requires open_link to be used]
 */
class GX_EXPORT tmpfile {
	public:
	~tmpfile() { close(); }
	operator int() const { return m_fd; }
	void close();
	int open_anon(const char *dir, unsigned int flags, unsigned int mode = FMODE_PRIVATE);
	int open_linkable(const char *dir, unsigned int flags, unsigned int mode = FMODE_PRIVATE);
	errno_t link_to_overwrite(const char *newpath);
	errno_t link_to_noreplace(const char *newpath);

	int m_fd = -1;
	std::string m_path;

	private:
	int open_impl(const char *dir, unsigned int flags, unsigned int mode, bool anon);
};

class GX_EXPORT wrapfd {
	public:
	wrapfd() = default;
	wrapfd(int z) : m_fd{z} {}
	wrapfd(wrapfd &&) noexcept = delete;
	~wrapfd() { close_rd(); }
	int get() const { return m_fd; }
	int release() { int t = m_fd; m_fd = -1; return t; }
	errno_t close_rd() noexcept;
	errno_t close_wr() noexcept __attribute__((warn_unused_result)) { return close_rd(); };
	void operator=(wrapfd &&o) noexcept {
		close_rd();
		m_fd = o.m_fd;
		o.m_fd = -1;
	}
	private:
	int m_fd = -1;
};

extern GX_EXPORT errno_t canonical_hostname(std::string &);
extern GX_EXPORT pid_t popenfd(const char *const *, int *, int *, int *, const char *const *);
extern GX_EXPORT int feed_w3m(std::string_view, const char *in_cset, std::string &out);
extern GX_EXPORT DIR_mp opendir_sd(const char *, const char *);
extern GX_EXPORT std::unique_ptr<FILE, file_deleter> fopen_sd(const char *, const char *);
extern GX_EXPORT std::string zstd_decompress(std::string_view);
extern GX_EXPORT size_t gx_decompressed_size(const char *);
extern GX_EXPORT errno_t gx_decompress_file(const char *, BINARY &, void *(*)(size_t), void *(*)(void *, size_t));
extern GX_EXPORT errno_t gx_compress_tofd(std::string_view, int fd, uint8_t complvl = 0);
extern GX_EXPORT errno_t gx_compress_tofile(std::string_view, const char *outfile, uint8_t complvl = 0, unsigned int mode = FMODE_PRIVATE);
extern GX_EXPORT int gx_mkbasedir(const char *file, unsigned int mode);

}
