// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace gromox::EWS
{


/**
 * @brief      Timed object cache
 *
 * Objects are stored for a limited time and automatically removed once they
 * expire.
 *
 * Once stored, only copies of the stored elements can be retrieved to avoid
 * asynchronous deconstruction during access (use std::shared_ptr).
 *
 * @tparam     Key     Key type
 * @tparam     Object  Object type
 */
template<class Key, class Object>
class ObjectCache
{
public:
	using clock_t = std::chrono::steady_clock;

	~ObjectCache();

	void run(std::chrono::milliseconds);
	void stop();

	template<typename KeyArg, typename... Args>
	bool emplace(std::chrono::milliseconds, KeyArg&&, Args&&...);
	Object get(const Key&) const;
	Object get(const Key&, std::chrono::milliseconds);
	void evict(const Key&);

private:
	struct Container
	{
		template<typename... Args>
		Container(clock_t::time_point, Args&&...);

		clock_t::time_point expires;
		Object object;
	};

	mutable std::mutex objectLock; ///< Mutext to protect object map
	std::unordered_map<Key, Container> objects; ///< Stored objects

	std::condition_variable notify; ///< CV to signal stopping
	std::thread scanThread; ///< Thread used for periodic scanning
	bool running = false; ///< Whether the scanner is running

	void scan();
	void periodicScan(std::chrono::milliseconds);

};

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Create new object container
 *
 * @param      exp     Expiration time point
 * @param      args    Arguments for object creation
 */
template<class Key, class Object>
template<typename... Args>
ObjectCache<Key, Object>::Container::Container(clock_t::time_point exp, Args&&... args) :
	expires(exp), object(std::forward<Args...>(args)...)
{}

/**
 * @brief      Clear cache and stop scanner
 */
template<class Key, class Object>
ObjectCache<Key, Object>::~ObjectCache()
{stop();}

/**
 * @brief      Start clean up thread
 *
 * @param      interval  Scan interval
 */
template<class Key, class Object>
void ObjectCache<Key, Object>::run(std::chrono::milliseconds interval)
{
	if(running)
		return;
	running = true;
	scanThread = std::thread([this, interval](){periodicScan(interval);});
}

/**
 * @brief      Stop clean up thread
 */
template<class Key, class Object>
void ObjectCache<Key, Object>::stop()
{
	if(!running)
		return;
	running = false;
	notify.notify_all();
	scanThread.join();
}

/**
 * @brief      Add object to cache
 *
 * @param      lifespan  Object life span
 * @param      key       Object key
 * @param      args      Object constructor arguments
 *
 * @tparam     KeyArg    Type to derive key from
 * @tparam     Args      Object constructor arguments
 *
 * @return     true if emplaced, false if already present
 */
template<class Key, class Object>
template<typename KeyArg, typename... Args>
bool ObjectCache<Key, Object>::emplace(std::chrono::milliseconds lifespan, KeyArg&& key, Args&&... args)
{
	auto guard = std::lock_guard(objectLock);
	auto res = objects.try_emplace(Key(key), clock_t::now()+lifespan, std::forward<Args...>(args)...);
	return res.second;
}

/**
 * @brief      Get cached object
 *
 * Throws std::out_of_range if object does not exist.
 *
 * @param      key     Object key
 *
 * @return     Copy of the cached object
 */
template<class Key, class Object>
Object ObjectCache<Key, Object>::get(const Key& key) const
{
	auto guard = std::lock_guard(objectLock);
	return objects.at(key).object;
}

/**
 * @brief      Get cached object and bump lifespan
 *
 * Throws std::out_of_range if object does not exist.
 *
 * @param      key       Object key
 * @param      lifespan  New lifespan
 * *
 * @return     Copy of the cached object
 */
template<class Key, class Object>
Object ObjectCache<Key, Object>::get(const Key& key, std::chrono::milliseconds lifespan)
{
	auto guard = std::lock_guard(objectLock);
	Container& cont = objects.at(key);
	cont.expires = clock_t::now()+lifespan;
	return cont.object;
}

/**
 * @brief      Remove object from cache
 * *
 * @param      key       Object key
 */
template<class Key, class Object>
void ObjectCache<Key, Object>::evict(const Key& key)
{
	auto guard = std::lock_guard(objectLock);
	objects.erase(key);
}

/**
 * @brief      Scan cache for expired objects
 */
template<class Key, class Object>
void ObjectCache<Key, Object>::scan()
{
	auto guard = std::lock_guard(objectLock);
	auto now = std::chrono::steady_clock::now();
	for(auto it = objects.begin(); it != objects.end();)
		if(it->second.expires < now)
			objects.erase(it++);
		else
			++it;
}

/**
 * @brief      Periodically invoke scan
 *
 * @param sleepTime
 */
template<class Key, class Object>
void ObjectCache<Key, Object>::periodicScan(std::chrono::milliseconds sleepTime)
	{
		std::mutex notifyLock;
		std::unique_lock notifyGuard(notifyLock);
		while(running)
		{
			scan();
			notify.wait_for(notifyGuard, std::chrono::milliseconds(sleepTime));
		}
	}


} //gromox::EWS
