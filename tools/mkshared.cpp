#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include "mkshared.hpp"

void adjust_rights(int fd)
{
	uid_t uid = -1;
	gid_t gid = -1;
	unsigned int mode = S_IRUSR | S_IWUSR;
	auto sp = getpwnam("gromox");
	if (sp != nullptr)
		uid = sp->pw_uid;
	auto gr = getgrnam("gromox");
	if (gr != nullptr) {
		gid = gr->gr_gid;
		mode |= S_IRGRP | S_IWGRP;
	}
	if (fchown(fd, uid, gid) < 0)
		perror("fchown");
	if (fchmod(fd, mode) < 0)
		perror("fchmod");
}

void adjust_rights(const char *file)
{
	int fd = open(file, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open %s O_RDWR: %s\n", file, strerror(errno));
		return;
	}
	adjust_rights(fd);
	close(fd);
}
