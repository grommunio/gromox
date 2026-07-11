#pragma once
#include <any>
#include <chrono>
#include <condition_variable>
#include <pthread.h>
#include <string>
#include <vector>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/defs.h>

namespace gromox {

struct GX_EXPORT workqueue {
	public:
	~workqueue();
	errno_t insert_task(const char *name, std::chrono::nanoseconds, void (*)(std::any &), std::any && = {}) __attribute__((nonnull(2, 4)));
	void delete_task(const char *) __attribute__((nonnull(2)));

	protected:
	struct task {
		auto operator<=>(const task &o) const { return start_time <=> o.start_time; }
		gromox::time_point start_time;
		std::chrono::nanoseconds period;
		std::any obj;
		void (*func)(std::any &);
		const char *name = nullptr;
	};

	bool task_exists(const char *) const __attribute__((nonnull(2)));
	void mainloop();
	void stop();
	int launch_ondemand();

	std::vector<task> m_tasklist;
	pthread_t m_thrid{};
	gromox::atomic_bool m_stop{false};
	std::condition_variable m_cv;
	std::mutex m_tasklock; /* protects m_tasks */
	std::mutex m_thrlock; /* protects m_thrid */
};

extern GX_EXPORT workqueue global_workqueue;

}
