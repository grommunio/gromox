#pragma once
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <shared_mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/clock.hpp>

namespace gromox::ab_tree {

struct minid;

}

template<> struct std::hash<gromox::ab_tree::minid> {
	inline size_t operator()(gromox::ab_tree::minid minid) const;
};

namespace gromox::ab_tree {

class ab_base;

static constexpr uint32_t CF_RECIPIENTS = 0x1;
static constexpr uint32_t CF_SUBCONTAINERS = 0x2;
static constexpr uint32_t CF_UNMODIFIABLE = 0x8;
static constexpr uint32_t CF_ALL = CF_RECIPIENTS | CF_SUBCONTAINERS | CF_UNMODIFIABLE;

enum class abnode_type : uint8_t {
	remote = 0,
	user = 1, /* person, room, equipment */
	mlist = 2,
	domain = 0x81,
	containers = 0x81, /* for >= */
};

enum class userinfo {
	mail_address,
	real_name,
	job_title,
	comment,
	mobile_tel,
	business_tel,
	nick_name,
	home_address,
	store_path,
};

/**
 * @brief      Minimal entry ID of address book entries
 *
 * Wrapper for 32-bit unsigned integer to encode type information (high bits)
 * and ID (low bits) of an entry.
 * The ID of the (user or domain) object is used with an offset of 0x10, since
 * the lower minid values are reserved for special purposes.
 */
struct GX_EXPORT minid {
	enum Type : uint32_t {
		address = 0,
		domain = 1,
	};

	static constexpr uint32_t TYPEMASK = 0x80000000; ///< Bits used for minid type information
	static constexpr uint32_t VALMASK = 0x7FFFFFFF; ///< Bits used for minid value information
	static constexpr uint32_t TYPEOFFSET = 31; ///< Offset for type information bits
	static constexpr uint32_t MAXVAL = VALMASK - 0x10; ///< Maximum value that can be stored in a minid

	// Positioning ID as per MS-OXNSPI 2.2.1.8
	static constexpr uint32_t BEGINNING_OF_TABLE = STREAM_SEEK_SET;
	static constexpr uint32_t CURRENT = STREAM_SEEK_CUR;
	static constexpr uint32_t END_OF_TABLE = STREAM_SEEK_END;

	// Ambiguous name resolution IDs, as per MS-OXNSPI 2.2.1.9
	static constexpr uint32_t UNRESOLVED = 0x00000000;
	static constexpr uint32_t AMBIGUOUS = 0x0000001;
	static constexpr uint32_t RESOLVED = 0x0000002;

	/* minids we have set aside for zcore special containers */
	static constexpr uint32_t SC_ROOT = 0xC;
	static constexpr uint32_t SC_EMPTY = 0xD;
	static constexpr uint32_t SC_PROVIDER = 0xE;
	static constexpr uint32_t SC_GAL = 0xF;

	constexpr minid(uint32_t i = 0) : id(i) {}
	constexpr explicit minid(const GUID &guid) : id(guid.time_low) {}

	/**
	 * @brief      Construct minid from type and ID
	 *
	 * @param      t     Minid type
	 * @param      v     Object ID (offset is applied automatically)
	 */
	constexpr minid(Type t, uint32_t v) : id((uint32_t(t) << TYPEOFFSET) | ((v + 0x10) & VALMASK)) {}
	constexpr operator uint32_t() const { return id; }
	constexpr GUID to_guid() const { return GUID{id, 0, 0, {0, 0}, {0, 0, 0, 0, 0, 0}}; }

	constexpr Type type() const { return Type(id >> TYPEOFFSET); } ///< Extract type from minid
	constexpr uint32_t value() const { return (id & VALMASK) - 0x10; } ///< Extract object ID from minid

	constexpr bool valid() const { return id >= 0x10; } ///< Check if object ID is valid

	uint32_t id; ///< Minid value
};

/**
 * @brief      Address book domain node
 */
struct GX_EXPORT ab_domain {
	uint32_t id;
	sql_domain info;
	std::vector<minid> userref; ///< List of minids of contained objects
};

/**
 * @brief      Address book base
 *
 * Contains all domain and user nodes from an organization. Provides a common
 * interface to access node properties.
 */
class ab_base {
	public:
	/**
	 * @brief     Address book iterator
	 *
	 * Random access iterator providing read-only access to all minids from
	 * the address book.
	 */
	class iterator {
		public:
		using iterator_category = std::random_access_iterator_tag;
		using difference_type = ssize_t;
		using value_type = const minid;
		using pointer = value_type *;
		using reference = value_type &;

		iterator() = default;

		iterator(const ab_base *b, const std::vector<ab_domain>::const_iterator &i) :
			m_base(b), it(i)
		{
			if (i != m_base->domains.cend())
				mid = minid(minid::domain, i->id);
			else
				mid = 0;
		}

		iterator(const ab_base *b, const std::vector<sql_user>::const_iterator &i) :
			m_base(b), it(i)
		{
			if (i != m_base->m_users.cend())
				mid = minid(minid::address, i->id);
			else
				mid = 0;
		}

		constexpr bool operator==(const iterator &o) const { return m_base == o.m_base && it == o.it; }
		constexpr auto operator<=>(const iterator &o) const {
			auto c = m_base <=> o.m_base;
			if (c != 0)
				return c;
			c = it.index() <=> o.it.index();
			if (c != 0)
				return c;
			if (it.index() == 0)
				return std::get<0>(it).base() <=> std::get<0>(o.it).base();
			else
				return std::get<1>(it).base() <=> std::get<1>(o.it).base();
		}
		inline iterator operator+(difference_type offset) const { return iterator(*this) += offset; }
		inline iterator &operator++() { return *this += 1; }
		inline iterator operator++(int) const { return iterator(*this) + 1; }
		iterator &operator+=(difference_type);

		difference_type operator-(const iterator &other) const { return pos() - other.pos(); }
		inline iterator &operator--() { return *this -= 1; }
		inline iterator operator--(int) const { return iterator(*this) - 1; }
		inline iterator &operator-=(difference_type offset) { return *this += -offset; }

		inline iterator operator-(difference_type offset) const { return iterator(*this) -= offset; }
		inline minid operator[](difference_type offset) const { return *(*this + offset); }

		inline const minid &operator*() const { return mid; }
		inline const minid *operator->() const { return &mid; }

		inline const ab_base *base() const { return m_base; }
		size_t pos() const;

		private:
		using domain_it = std::vector<ab_domain>::const_iterator;
		using user_it = std::vector<sql_user>::const_iterator;

		const ab_base *m_base = nullptr;
		std::variant<domain_it, user_it> it;
		minid mid; ///< cached minid to allow returning references and pointers
	};

	enum class Status : uint8_t { CONSTRUCTING, LIVING };

	explicit ab_base(int32_t id);

	bool await_load() const;
	bool load();
	/// Get time since the base was loaded
	inline std::chrono::seconds age() const { return std::chrono::duration_cast<std::chrono::seconds>(gromox::tp_now() - m_load_time); }

	minid at(uint32_t) const;
	const std::vector<std::string> &aliases(minid) const;
	size_t children(minid) const;
	bool company_info(minid, std::string *, std::string *) const;
	std::string displayname(minid) const;
	bool dn(minid, std::string &) const;
	uint32_t dtyp(minid) const;
	std::optional<uint32_t> dtypx(minid) const;
	void dump() const;
	uint32_t etyp(minid) const;
	bool exists(minid) const;
	const ab_domain *fetch_domain(minid) const;
	ec_error_t fetch_prop(minid, uint32_t, std::string &) const;
	bool fetch_props(minid, const PROPTAG_ARRAY &, std::unordered_map<uint32_t, std::string> &) const;
	const sql_user *fetch_user(minid) const;
	uint32_t get_leaves_num(minid) const;
	inline const GUID &guid() const { return m_guid; }
	size_t hidden() const;
	uint32_t hidden(minid) const;
	ec_error_t mdbdn(minid, std::string &) const;
	bool mlist_info(minid, std::string *, std::string *, int *) const;
	ec_error_t proplist(minid, std::vector<uint32_t> &) const;
	minid resolve(const char *) const;
	inline size_t size() const { return m_users.size() + domains.size(); }
	abnode_type type(minid) const;
	inline size_t users() const { return m_users.size(); }
	const char *user_info(minid, userinfo) const;

	inline iterator begin() const { return iterator(this, domains.cbegin()); } ///< Iterator to beginning of address book
	inline iterator end() const { return iterator(this, m_users.cend()); } ///< Iterator to end of address book
	inline iterator dbegin() const { return iterator(this, domains.cbegin()); } ///< Iterator to beginning of domain list
	inline iterator dend() const { return iterator(this, m_users.cbegin()); } ///< Iterator to end of domain list
	inline iterator ubegin() const { return iterator(this, m_users.cbegin()); } ///< Iterator to beginning of user list
	inline iterator uend() const { return iterator(this, m_users.cend()); } ///< Iterator to end of user list
	iterator find(minid) const;

	static display_type dtypx_to_etyp(display_type);

	private:
	const ab_domain *find_domain(uint32_t) const;

	static const std::vector<std::string> vs_empty; ///< used to return empty alias list in case of invalid minid

	GUID m_guid; ///< GUID of the base
	gromox::time_point m_load_time{}; ///< Load time
	/**
	 * base_id==0: not permitted (contains e.g. the AAPI administrator)
	 * base_id >0: Base is for an organization (multiple domains)
	 * base_id <0: Base is for one domain (base_id == -domain_id);
	 *             @domains will have exactly one entry.
	 */
	int m_base_id = 0;
	std::vector<ab_domain> domains; ///< list of domains belonging to the base
	std::vector<sql_user> m_users; ///< list of users from all those domains, sorted by displayname
	std::unordered_map<minid, uint32_t> minid_idx_map; ///< map from minid to index in domain/user list
	mutable std::mutex m_lock;
	std::atomic<Status> m_status{Status::CONSTRUCTING};
};

/**
 * @brief      Central address book class
 *
 * Manages ab_bases. There should only exist one instance.
 */
class ab {
	public:
	using base_ref = std::shared_ptr<ab_base>;
	using const_base_ref = std::shared_ptr<const ab_base>;

	void init(std::string_view org, int cache_interval);

	const_base_ref get(int32_t base_id);
	inline const_base_ref get(const GUID &guid) { return get(base_id(guid)); }
	void drop(int32_t base_id);

	bool run();
	void stop();
	void invalidate_cache();

	inline const std::string &org_name() const { return m_org_name; }
	inline const std::string &essdn_server_prefix() const { return m_essdn_server_prefix; }
	inline const std::string &essdn_rcpts_prefix() const { return m_essdn_rcpts_prefix; }

	static int32_t base_id(const GUID &guid);

	private:
	std::string m_org_name{};
	std::string m_essdn_server_prefix, m_essdn_rcpts_prefix;
	std::shared_mutex m_lock;
	std::chrono::seconds m_cache_interval;
	std::unordered_map<int32_t, std::shared_ptr<ab_base>> m_base_hash;

	std::thread worker; ///< Worker thread removing expired bases
	std::deque<int> worker_queue; ///< Queue of base IDs to be flushed
	std::condition_variable worker_signal; ///< Wake-up signal for the worker thread
	std::atomic<int> running = 0; ///< Number of plugins that are using the address book

	void work();
};
extern class ab AB;

/**
 * @brief      Node proxy, bundling minid with ab_base
 *
 * Provides easy access to a specific node in an ab_tree.
 */
struct GX_EXPORT ab_node {
	public:
	ab_node() = default;
	ab_node(const ab::const_base_ref &br, minid m) : base(br.get()), mid(m) {}
	ab_node(const ab_base *b, minid m) : base(b), mid(m) {}
	ab_node(const ab_base::iterator &it) : base(it.base()), mid(*it) {}

	const ab_base *base = nullptr;
	minid mid{};

	#define WRAP(FUNC) \
		template<typename... Args> \
		inline auto FUNC(Args &&...args) const \
		{ return base->FUNC(mid, std::forward<Args>(args)...); }

	WRAP(aliases)
	WRAP(children)
	WRAP(company_info)
	WRAP(displayname)
	WRAP(dn)
	WRAP(dtyp)
	WRAP(dtypx)
	WRAP(etyp)
	WRAP(exists)
	WRAP(fetch_prop)
	WRAP(fetch_user)
	WRAP(get_leaves_num)
	WRAP(mdbdn)
	WRAP(mlist_info)
	WRAP(proplist)
	WRAP(type)
	WRAP(user_info)

	#undef WRAP

	inline GUID guid() const { return GUID(mid); }
	inline uint32_t hidden() const { return base->hidden(mid); }
	inline bool valid() const { return base && base->exists(mid); }

	using iterator = decltype(ab_domain::userref)::const_iterator;
	iterator begin() const;
	iterator end() const;
	inline iterator find(minid) const { return mid.type() == minid::address ? std::find(begin(), end(), mid) : end(); }
	inline minid at(uint32_t idx) const { return idx < children() ? this->operator[](idx) : minid(); }
	minid operator[](uint32_t) const;
};

} // namespace gromox::ab_tree

inline size_t std::hash<gromox::ab_tree::minid>::operator()(gromox::ab_tree::minid minid) const { return std::hash<uint32_t>()(minid); }
