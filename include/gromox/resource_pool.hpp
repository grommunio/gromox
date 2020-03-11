#pragma once
#include <condition_variable>
#include <list>
#include <mutex>
#include <utility>

namespace gromox {

template<typename Tp> class resource_pool {
	public:
	Tp get_wait() {
		std::unique_lock<std::mutex> lk(m_mtx);
		m_cv.wait(lk, [this]() { return m_list.size() != 0; });
		auto c = std::move(*m_list.begin());
		m_list.pop_front();
		return c;
	}
	void put(Tp &&x) {
		std::unique_lock<std::mutex> lk(m_mtx);
		m_list.push_back(std::move(x));
		lk.unlock();
		m_cv.notify_one();
	}
	void clear() { m_list.clear(); }
	private:
	std::mutex m_mtx;
	std::condition_variable m_cv;
	std::list<Tp> m_list;
};

}
