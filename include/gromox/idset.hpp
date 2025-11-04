#pragma once
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/range_set.hpp>

namespace gromox {

using REPLICA_MAPPING = BOOL (*)(BOOL, void *, uint16_t *, GUID *);
using REPLIST_ENUM = void (*)(void *, uint16_t);
using REPLICA_ENUM = void (*)(void *, uint64_t);

struct GX_EXPORT repl_node {
	repl_node() = default;
	repl_node(uint16_t r) : replid(r) {}
	repl_node(const GUID &g) : replguid(g) {}

	union {
		uint16_t replid;
		GUID replguid{};
	};
	using range_list_t = gromox::range_set<uint64_t>;
	range_list_t range_list; /* GLOBSET */
};

class GX_EXPORT idset {
	public:
	enum class type : uint8_t {
		id_packed   = 0x41, id_loose   = 0x42,
		guid_packed = 0x81, guid_loose = 0x82,
	};

	idset(idset::type t) : repl_type(t) {}
	static std::unique_ptr<idset> create(idset::type);
	bool packed() const { return static_cast<uint8_t>(repl_type) & 0x1; }

	BOOL register_mapping(void *logon_obj, REPLICA_MAPPING);
	void clear() { repl_list.clear(); }
	bool empty() const { return repl_list.empty(); }
	BOOL append(uint64_t eid);
	BOOL append_range(uint16_t replid, uint64_t low_value, uint64_t high_value);
	void remove(uint64_t eid);
	BOOL concatenate(const idset *set_src);
	bool contains(uint64_t eid) const;
	BINARY *serialize();
	BINARY *serialize_replid() const;
	BINARY *serialize_replguid();
	BOOL deserialize(const BINARY &);
	/* convert from deserialize idset into serialize idset */
	BOOL convert();
	/* get maximum of first range in idset for specified replid */
	BOOL get_repl_first_max(uint16_t replid, uint64_t *eid);
	BOOL enum_replist(void *param, REPLIST_ENUM);
	BOOL enum_repl(uint16_t replid, void *param, REPLICA_ENUM);
	inline const std::vector<repl_node> &get_repl_list() const { return repl_list; }
	void dump(FILE * = nullptr) const;
#ifdef COMPILE_DIAG
	inline size_t nelem() const {
		size_t x = 0;
		for (const auto &i : repl_list)
			x += i.range_list.nelem();
		return x;
	}
#endif

	private:
	std::pair<bool, repl_node::range_list_t *> get_range_by_id(uint16_t);

	void *pparam = nullptr;
	REPLICA_MAPPING mapping = nullptr;
	idset::type repl_type = idset::type::id_packed;
	/* If @repl_type is guid_packed, repl_nodes are REPLGUID_NODE. */
	std::vector<repl_node> repl_list;
};

}
