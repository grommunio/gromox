#pragma once
#include <string>
#include <vector>
#include <gromox/defs.h>

namespace gromox {

class GX_EXPORT socketpass_worker {
	public:
	~socketpass_worker() { stop(); }
	bool running();
	errno_t start(const char *prog, char **argv);
	errno_t restart(const char *prog, char **argv);
	errno_t pass(std::string_view, int fd) const;
	int stop();

	private:
	errno_t start_raw(const char *prog, char **argv);

	int m_channel = -1;
	pid_t m_pid = -1;
};

extern GX_EXPORT errno_t socketpass_receive(int control_fd, std::string &pkt, int &client_fd);

}
