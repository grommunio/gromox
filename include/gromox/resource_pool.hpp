// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH licensing exception
// SPDX-FileCopyrightText: 2020–2026 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <optional>
#include <utility>
#include <gromox/clock.hpp>

namespace gromox {

/*
 * Resource pool with generational support. Because Tp objects may become
 * "outdated" and be purged through the use of bump(), it does not make a lot
 * of sense to construct objects a-priori and stockpile them. Consequentially.
 * this API supports only just-in-time construction. As a result, get_wait()
 * needs to be passed ctor args at all times, in case a new Tp needs
 * construction.
 *
 * @m_numslots: number of remaining tokens the pool will give
 * @m_max:      maximum number of tokens the pool will give
 *              (used to determine whether to putback or retire an object)
 * @m_list:     reusable objects
 */
template<typename Tp> class GX_EXPORT resource_pool {
	protected:
	struct entry {
		template<typename... A> entry(A &&...args) :
			obj(std::forward<A>(args)...)
		{}
		Tp obj;
		gromox::time_point last_use{};
	};

	public:
	class token {
		/* automatically return connection back to pool when going out of scope */
		public:
		token(resource_pool &pool, std::list<entry> &&holder, unsigned int gen) noexcept :
			m_pool(pool), m_holder(std::move(holder)), m_gen(gen)
		{}
		token(token &&o) noexcept :
			m_pool(o.m_pool), m_holder(std::move(o.m_holder)),
			m_gen(o.m_gen)
		{}
		~token() try {
			if (m_holder.size() > 0)
				finish();
		} catch (...) {
		}
		inline bool operator!() const { return !m_holder.front().obj; }
		inline Tp &operator*() { return m_holder.front().obj; }
		inline const Tp &operator*() const { return m_holder.front().obj; }
		inline Tp *operator->() { return &m_holder.front().obj; }
		inline const Tp *operator->() const { return &m_holder.front().obj; }
		void operator=(token &&) noexcept = delete;
		void finish() { m_pool.put(std::move(m_holder), m_gen); }
		protected:
		resource_pool &m_pool;
		std::list<entry> m_holder;
		unsigned int m_gen = 0;
	};

	resource_pool(size_t z = 0) : m_numslots(z), m_max(z) {}
	template<typename... A> std::optional<token> get(A &&...args) {
		std::list<entry> holder;
		std::unique_lock<std::mutex> lk(m_mtx);
		if (m_numslots == 0)
			return {};
		if (m_list.size() > 0)
			holder.splice(holder.end(), m_list, m_list.begin());
		else
			holder.emplace_back(std::forward<A>(args)...);
		std::optional<token> tk{std::in_place_t{}, *this, std::move(holder), m_gen};
		--m_numslots;
		return tk;
	}
	template<typename... A> token get_wait(A &&...args) {
		std::list<entry> holder;
		std::unique_lock<std::mutex> lk(m_mtx);
		m_cv.wait(lk, [this]() { return m_numslots > 0; });
		if (m_list.size() > 0)
			holder.splice(holder.end(), m_list, m_list.begin());
		else
			holder.emplace_back(std::forward<A>(args)...);
		token tk{*this, std::move(holder), m_gen};
		--m_numslots;
		return tk;
	}

	private:
	void put_slot() noexcept {
		if (m_numslots >= m_max)
			return;
		++m_numslots;
		m_cv.notify_one();
	}
	void put(std::list<entry> &&holder, unsigned int gen) {
		if (m_numslots >= m_max) {
			/* Avoid returning object to pool when pool shrank */
			holder.clear();
			return;
		}
		std::list<entry> graveyard;
		{
			std::lock_guard<std::mutex> lk(m_mtx);
			if (m_gen == gen && holder.size() >= 1) {
				/* ..it was used until just before put() */
				holder.front().last_use = tp_now();
				m_list.splice(m_list.begin(), holder, holder.begin());
			}
			/* Defer cleanup until after critical section */
			graveyard = std::move(holder);
			++m_numslots;
		}
		m_cv.notify_one();
	}

	public:
	void resize(size_t n) {
		std::lock_guard lk(m_mtx);
		m_max = m_numslots = n;
		while (m_list.size() > m_numslots)
			m_list.pop_front();
		m_cv.notify_one();
	}
	void clear() {
		std::lock_guard lk(m_mtx);
		m_list.clear();
	}
	/**
	 * Drop objects that have not been used for a while.
	 */
	void drop_idle(time_duration ttl)
	{
		auto cutoff = tp_now() - ttl;
		std::list<entry> graveyard;
		{
			std::lock_guard lk(m_mtx);
			/*
			 * m_list is ordered, so only the partition point needs
			 * to be located, without needing gromox::splice_if.
			 */
			auto it = m_list.begin();
			while (it != m_list.end() && it->last_use < cutoff)
				++it;
			graveyard.splice(graveyard.end(), m_list, m_list.begin(), it);
		}
	}
	size_t capacity() const { return m_max; }
	void bump() {
		std::unique_lock lk(m_mtx);
		m_list.clear();
		++m_gen;
	}

	private:
	std::atomic<size_t> m_numslots{0}, m_max{0};
	std::mutex m_mtx;
	std::condition_variable m_cv;
	std::list<entry> m_list;
	unsigned int m_gen = 0;
};

}
