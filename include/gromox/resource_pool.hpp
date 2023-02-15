// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH licensing exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <optional>
#include <utility>

namespace gromox {

/*
 * Resource pool with generational support. Since Tp objects may become
 * "outdated" and be purged through the use of bump(), it does not make a lot
 * of sense to construct them a-priori, so the API only supports lazy
 * construction. For this, get_wait() needs to know some ctor args for when a
 * new T needs construction.
 */
template<typename Tp> class resource_pool {
	public:
	class token {
		/* automatically return connection back to pool when going out of scope */
		public:
		token(resource_pool &pool, std::list<Tp> &&holder, unsigned int gen) noexcept :
			m_pool(pool), m_holder(std::move(holder)), m_gen(gen)
		{}
		token(token &&o) noexcept :
			m_pool(o.m_pool), m_holder(std::move(o.m_holder)),
			m_gen(o.m_gen)
		{}
		~token() {
			if (m_holder.size() > 0)
				finish();
		}
		inline Tp &operator*() { return m_holder.front(); }
		inline const Tp &operator*() const { return m_holder.front(); }
		inline Tp *operator->() { return &m_holder.front(); }
		inline const Tp *operator->() const { return &m_holder.front(); }
		void operator=(token &&) noexcept = delete;
		void finish() noexcept {
			try {
				m_pool.put(std::move(m_holder), m_gen);
			} catch (...) {
				m_pool.put_slot();
			}
		}
		protected:
		resource_pool &m_pool;
		std::list<Tp> m_holder;
		unsigned int m_gen = 0;
	};

	template<typename... A> std::optional<token> get(A &&...args) {
		std::list<Tp> holder;
		std::unique_lock<std::mutex> lk(m_mtx);
		if (m_numslots == 0)
			return {};
		--m_numslots;
		if (m_list.size() > 0)
			holder.splice(holder.end(), m_list, m_list.begin());
		else
			holder.emplace_back(std::forward<A>(args)...);
		return {std::in_place_t{}, *this, std::move(holder), m_gen};
	}
	template<typename... A> token get_wait(A &&...args) {
		std::list<Tp> holder;
		std::unique_lock<std::mutex> lk(m_mtx);
		m_cv.wait(lk, [this]() { return m_numslots > 0; });
		--m_numslots;
		if (m_list.size() > 0)
			holder.splice(holder.end(), m_list, m_list.begin());
		else
			holder.emplace_back(std::forward<A>(args)...);
		return {*this, std::move(holder), m_gen};
	}
	void put_slot() noexcept {
		++m_numslots;
		m_cv.notify_one();
	}

	private:
	void put(std::list<Tp> &&holder, unsigned int gen) {
		std::unique_lock<std::mutex> lk(m_mtx);
		if (m_gen == gen)
			m_list.splice(m_list.end(), holder, holder.begin());
		++m_numslots;
		lk.unlock();
		m_cv.notify_one();
	}

	public:
	void resize(size_t n) {
		if (m_numslots < n)
			m_numslots = n;
	}
	void clear() { m_list.clear(); }
	size_t available() const { return m_list.size(); }
	size_t capacity() const { return m_numslots; }
	void bump() {
		std::unique_lock lk(m_mtx);
		m_list.clear();
		++m_gen;
	}

	private:
	std::atomic<size_t> m_numslots{0};
	std::mutex m_mtx;
	std::condition_variable m_cv;
	std::list<Tp> m_list;
	unsigned int m_gen = 0;
};

}
