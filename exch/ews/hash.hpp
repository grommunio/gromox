// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#pragma once

#include <cstdint>

/**
 * @brief Basic hash function (Fowler-Noll-Vo hash algortihm)
 *
 * Intended use is to provide base functionality for std::hash
 * template specialization.
 *
 * Shoult *not* be used as a drop-in replacement for std::hash
 * with standard library types.
 */
struct FNV
{
	/**
	 * @brief      Initialize by consecutively hashing all objects
	 *
	 * @param      objs  Objects to hash
	 *
	 * @tparam     Ts    Object types
	 */
	template<typename... Ts>
	constexpr FNV(const Ts&... objs) noexcept
	{(*this << ... << objs);}

	/**
	 * @brief      Hash data block
	 *
	 * Data is hashed byte-wise
	 *
	 * @param      data  Data to hash
	 * @param      len   Length of the data block
	 *
	 * @return     New hash value
	 */
	constexpr uint64_t operator()(const void* data, uint64_t len) noexcept
	{return apply(static_cast<const uint8_t*>(data), len);	}

	/**
	 * @brief      Hash object
	 *
	 * Should only be used if no member is or contains any pointers.
	 * User defined specializations may be provided.
	 *
	 * Hashes memory occupied by the object. Memory is hashed in 8, 4, 2 or 1
	 * byte blocks, depending on type size and alignment.
	 *
	 * @param      obj   Object to hash
	 *
	 * @tparam     T     Object type
	 *
	 * @return     New hash value
	 */
	template<typename T> constexpr uint64_t operator()(const T& obj) noexcept
	{
		if constexpr(!(sizeof(T) % sizeof(uint64_t) || alignof(T) % alignof(uint64_t)))
			return apply(static_cast<const uint64_t*>(&obj), sizeof(T)/sizeof(uint64_t));
		else if constexpr(!(sizeof(T) % sizeof(uint32_t) || alignof(T) % alignof(uint32_t)))
			return apply(static_cast<const uint32_t*>(&obj), sizeof(T)/sizeof(uint32_t));
		else if constexpr(!(sizeof(T) % sizeof(uint16_t) || alignof(T) % alignof(uint16_t)))
			return apply(static_cast<const uint16_t*>(&obj), sizeof(T)/sizeof(uint16_t));
		else
			return apply(static_cast<const uint8_t*>(&obj), sizeof(T));
	}

	/**
	 * @brief      Stream-like object hashing
	 *
	 * @param      obj   Object to hash
	 *
	 * @tparam     T     Object type
	 *
	 * @return     *this
	 */
	template<typename T> constexpr FNV& operator<<(const T& obj) noexcept
	{
		operator()(obj);
		return *this;
	}

	uint64_t value = 0xcbf29ce484222325ULL; ///< Current hash value

private:
	/**
	 * @brief      Update hash
	 *
	 * @param      data   Data to hash
	 * @param      count  Data element count
	 *
	 * @tparam     T      One of uint8_t, uint16_t, uint32_t or uint64_t
	 *
	 * @return     New hash value
	 */
	template<typename T>
	constexpr uint64_t apply(const T* data, uint64_t count) noexcept
	{
		for(const T* ptr = data; ptr < data+count; ++ptr)
			value = (value^uint64_t(*ptr))*0x100000001b3ULL;
		return value;
	}
};

