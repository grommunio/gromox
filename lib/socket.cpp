// SPDX-License-Identifier: AGPL-3.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include <fcntl.h>
#include <sys/socket.h>
#include <gromox/socket.h>

int gx_reexec_top_fd = -1;

void gx_reexec_record(int new_fd)
{
	for (int fd = gx_reexec_top_fd; fd <= new_fd; ++fd) {
		unsigned int flags = 0;
		socklen_t fz = sizeof(flags);
		if (fd < 0 || getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN,
		    &flags, &fz) != 0 || !flags ||
		    fcntl(fd, F_GETFL, &flags) != 0)
			continue;
		flags &= ~FD_CLOEXEC;
		if (fcntl(fd, F_SETFL, flags) != 0)
			/* ignore */;
	}
	if (new_fd > gx_reexec_top_fd)
		gx_reexec_top_fd = new_fd;
}
