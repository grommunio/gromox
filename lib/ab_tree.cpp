// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <fmt/core.h>
#include <gromox/ab_tree.hpp>
#include <gromox/gab.hpp>
#include <gromox/proc_common.h>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include <gromox/process.hpp>

namespace gromox::ab_tree
{

ab AB; ///< Global address book management object

/**
 * @brief      Extract base ID from GUID
 */
int32_t ab::base_id(const GUID& guid)
{
	int32_t id;
	memcpy(&id, guid.node, sizeof(int32_t));
	return id;
}

/**
 * @brief      Remove base from registry, causing it to reload on next access
 */
void ab::drop(int32_t id)
{
	std::unique_lock lock(m_lock);
	m_base_hash.erase(id);
}

/**
 * @brief      Initialize address book
 *
 * Initializes address book with given parameters. Only effective on first
 * call, any further calls will have no effect.
 *
 * @param      org               x500 organization name
 * @param      cache_interval    Lifespan of ab_tree in seconds
 */
void ab::init(std::string_view org, int cache_interval)
{
	m_org_name = org;
	m_cache_interval = std::chrono::seconds(cache_interval);
	m_essdn_server_prefix = fmt::format("/o={}/" EAG_SERVERS "/cn=", m_org_name);
	m_essdn_rcpts_prefix = fmt::format("/o={}/" EAG_RCPTS "/cn=", m_org_name);
}

/**
 * @brief      Drop all loaded address books
 */
void ab::invalidate_cache()
{
	std::unique_lock lock(m_lock);
	m_base_hash.clear();
}

/**
 * @brief      Get base with given ID, load if necessary
 *
 * @param      base_id   Base ID (negative for domains, positive for organizations)
 *
 * @return     Pointer to address book object
 */
ab::const_base_ref ab::get(int32_t base_id)
{
	std::unique_lock lock(m_lock);
	auto it = m_base_hash.find(base_id);
	if (it != m_base_hash.end()) {
		base_ref base = it->second;
		lock.unlock();
		return base->await_load() ? base : nullptr;
	}
	try {
		auto res = m_base_hash.try_emplace(base_id, std::make_shared<ab_base>(base_id));
		if (!res.second)
			return nullptr;
		it = res.first;
	} catch (std::bad_alloc &) {
		return nullptr;
	}
	lock.unlock();
	if (!it->second->load()) {
		lock.lock();
		m_base_hash.erase(it);
		return nullptr;
	}
	return std::const_pointer_cast<const ab_base>(it->second);
}

/**
 * @brief      Register address book consumer
 *
 * @return     true if successful, false on error
 */
bool ab::run() try
{
	if (running++)
		return true;
	worker = std::thread(&ab::work, this);
	return true;
} catch (...) {
	running = 0;
	return false;
}

/**
 * @brief      Unregister address book consumer
 */
void ab::stop()
{
	if (--running)
		return;
	worker_signal.notify_all();
	worker.join();
}

/**
 * @brief      Worker thread
 *
 * Cleans up expired address books
 */
void ab::work()
{
	std::chrono::seconds wait_time;
	std::mutex notify_lock;
	std::unique_lock notify_guard(notify_lock);
	while (running) {
		std::unique_lock lock_guard(m_lock);
		if (worker_queue.empty())
			wait_time = m_cache_interval;
		else {
			auto base = get(worker_queue.front());
			if (!base || base->age() >= m_cache_interval) {
				drop(worker_queue.front());
				worker_queue.pop_front();
				continue;
			}
			wait_time = m_cache_interval-base->age();
		}
		lock_guard.unlock();
		worker_signal.wait_for(notify_guard, wait_time);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// ab_base organizational member functions

const std::vector<std::string> ab_base::vs_empty{};

/**
 * @brief      Initialize base and lock until loaded
 *
 * @param      id    Base ID
 */
ab_base::ab_base(int32_t id) : m_base_id(id)
{
	m_guid = GUID::random_new();
	memcpy(m_guid.node, &m_base_id, sizeof(int32_t));
	m_lock.lock(); // unlocked after load
}

/**
 * @brief      Wait until the base unlocks after loading
 *
 * @return     whether base is ready
 */
bool ab_base::await_load() const
{
	std::lock_guard guard(m_lock);
	return m_status == Status::LIVING;
}

/**
 * @brief       Load address book from database and unlock
 *
 * @return      Whether loading was successful
 */
bool ab_base::load()
{
	std::lock_guard lock(m_lock, std::adopt_lock);
	std::vector<unsigned int> dmemb;
	if (m_base_id <= 0)
		dmemb.emplace_back(-m_base_id);
	else if (!mysql_adaptor_get_org_domains(m_base_id, dmemb))
		return false;
	if (dmemb.size() > minid::MAXVAL) // cannot reference more nodes
		dmemb.resize(minid::MAXVAL);

	std::unordered_map<unsigned int, unsigned int> domid_to_listidx;
	domains.reserve(dmemb.size());
	for (unsigned int domid : dmemb) try {
		/* appends to m_users */
		if (!mysql_adaptor_get_domain_users(domid, m_users))
			return false;
		domid_to_listidx[domid] = uint32_t(domains.size());
		ab_domain &domain = domains.emplace_back();
		domain.id = domid;
		mysql_adaptor_get_domain_info(domid, domain.info);
	} catch (std::exception &) {
		return false;
	}
	if (m_users.size() > minid::MAXVAL)
		m_users.resize(minid::MAXVAL);
	std::sort(m_users.begin(), m_users.end());
	minid_idx_map.reserve(m_users.size() + dmemb.size());
	for (size_t i = 0; i < m_users.size(); ++i) {
		const sql_user &u = m_users[i];
		domains[domid_to_listidx[u.domain_id]].userref.emplace_back(minid(minid::address, u.id));
		minid_idx_map.emplace(minid(minid::address, u.id), i);
	}
	for (size_t i = 0; i < domains.size(); ++i)
		minid_idx_map.emplace(minid(minid::domain, domains[i].id), i);
	m_status = Status::LIVING;
	return true;
}

///////////////////////////////////////////////////////////////////////////////
// ab_base informational member functions

/**
 * @brief      Get list of node aliases
 *
 * @param      mid   Minid of the node
 *
 * @return     List of aliases or empty list if node is not a user
 */
const std::vector<std::string> &ab_base::aliases(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	return user ? user->aliases : vs_empty;
}

/**
 * @brief      Get minid of node by index
 *
 * @param      idx   Index of the node
 *
 * @return     Minid of the node or empty minid on invalid index
 */
minid ab_base::at(uint32_t idx) const
{
	return idx < domains.size() ? minid(minid::domain, domains[idx].id) :
	       idx - domains.size() < m_users.size() ? minid(minid::address, m_users[idx-domains.size()].id) : minid();
}

/**
 * @brief      Write company info to target strings
 *
 * @param      mid           Mid of the node
 * @param      str_name      String to write company name to, or nullptr to ignore
 * @param      str_address   String to write company address to, or nullptr to ignore
 *
 * @return     true if successful, false otherwise
 */
bool ab_base::company_info(minid mid, std::string *str_name, std::string *str_address) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return false;
	const ab_domain *domain = find_domain(user->domain_id);
	if (!domain)
		return false;
	if (str_name != nullptr)
		*str_name = domain->info.title;
	if (str_address != nullptr)
		*str_address = domain->info.address;
	return true;
}

/**
 * @brief      Retrieve displayname
 *
 * For domain nodes, return domain name.
 * For user nodes, try to fetch the display name property, if it not exists,
 * default to the base part of the e-mail address (up to the '@')
 *
 * @param      mid   Mid of the node
 *
 * @return     Display name of the node
 */
std::string ab_base::displayname(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (user) {
		auto it = user->propvals.find(PR_DISPLAY_NAME);
		if (it != user->propvals.end())
			return it->second.c_str();
		auto at = user->username.find('@');
		return at == std::string::npos ? user->username : user->username.substr(0, at);
	}
	const ab_domain *domain = fetch_domain(mid);
	if (domain)
		return domain->info.name;
	return std::string();
}

/**
 * @brief      Generate essdn for user node
 *
 * @param      mid       Mid of the node
 * @param      essdn     String to write essdn to
 *
 * @return     false if node is not a user node, true otherwise
 */
bool ab_base::dn(minid mid, std::string& essdn) const
{
	const sql_user *user = fetch_user(mid);
	if(!user) {
		char guid_str[33];
		mid.to_guid().to_str(guid_str, std::size(guid_str));
		essdn = "/guid=";
		essdn += guid_str;
		return true;
	}
	auto username = user_info(mid, userinfo::mail_address);
	const ab_domain *domain = find_domain(user->domain_id);
	return cvt_username_to_essdn(username, AB.org_name().c_str(), user->id, domain->id, essdn) == ecSuccess;
}

/**
 * @brief      Get display type of node
 *
 * @param      mid   Mid of the node
 *
 * @return     DT_CONTAINER for domains, display type property for users
 */
uint32_t ab_base::dtyp(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return DT_CONTAINER;
	return user->dtypx & DTE_MASK_LOCAL;
}

/**
 * @brief      Get extended display type of node
 *
 * @param      mid   Mid of the node
 *
 * @return     Empty container if not a user, display type property otherwise
 */
std::optional<uint32_t> ab_base::dtypx(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return {};
	if ((user->dtypx & DTE_MASK_LOCAL) == DT_REMOTE_MAILUSER)
		return DT_REMOTE_MAILUSER;
	/*
	 * In Gromox, (almost) everything with a username is capable of being
	 * used in an ACL (and usernames are mandatory currently).
	 */
	return (user->dtypx & DTE_MASK_LOCAL) | DTE_FLAG_ACL_CAPABLE;
}

/**
 * @brief      Print address book to stderr
 */
void ab_base::dump() const
{
	fmt::print(stderr, "AB Base {}#{}\n", m_base_id < 0? "D" : "O", abs(m_base_id));
	fmt::print(stderr, "  Domains ({}):\n", domains.size());
	for (auto it = dbegin(); it != dend(); ++it) {
		const ab_domain *domain = fetch_domain(*it);
		if (domain == nullptr) {
			fmt::print(stderr, "    [INVALID DOMAIN MINID {:#010x}]\n", uint32_t(*it));
			continue;
		}
		fmt::print(stderr, "    {:#010x}: '{}'/{}, {} users:\n",
		           uint32_t(*it), domain->info.name, domain->id, domain->userref.size());
		for (minid mid : domain->userref) {
			const sql_user *user = fetch_user(mid);
			if (user == nullptr)
				fmt::print(stderr, "      [INVALID USER MINID {:#010x}]\n", uint32_t(mid));
			else
				fmt::print(stderr, "      {:#010x}: {}/{} (\"{}\")\n",
				           uint32_t(mid), user->username, user->id, displayname(mid));
		}
	}
	fmt::print(stderr, "  Complete node list ({}):\n", size());
	for (minid mid : *this) {
		const sql_user *user = fetch_user(mid);
		const ab_domain *domain = fetch_domain(mid);
		std::string dispname = displayname(mid);
		if (domain)
			fmt::print(stderr, "    {:#010x}: {}/{} (\"{}\")\n", uint32_t(mid), domain->info.name, domain->id, dispname);
		else if (user)
			fmt::print(stderr, "    {:#010x}: {}/{} (\"{}\")\n", uint32_t(mid), user->username, user->id, dispname);
		else
			fmt::print(stderr, "    [INVALID MINID {:#010x}]\n", uint32_t(mid));
	}
}

/**
 * @brief      Convert display type to entry ID type
 *
 * @param      dt    Display type
 *
 * @return     Entry ID type
 */
display_type ab_base::dtypx_to_etyp(display_type dt)
{
	dt = static_cast<display_type>(dt & DTE_MASK_LOCAL);
	switch (dt) {
	case DT_MAILUSER:
	case DT_ROOM:
	case DT_EQUIPMENT:
	case DT_SEC_DISTLIST:
		return DT_MAILUSER;
	default:
		return dt;
	}
}

/**
 * @brief      Get entry ID type of node
 *
 * @param      mid   Mid of the node
 *
 * @return     Entry ID type of the node
 */
uint32_t ab_base::etyp(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return DT_CONTAINER;
	return dtypx_to_etyp(user->dtypx);
}

/**
 * @brief      Check whether node exists
 *
 * @param      mid   Mid of the node
 *
 * @return     true if the minid is valid and points to an object, false otherwise
 */
bool ab_base::exists(minid mid) const
{
	return mid.valid() && (fetch_user(mid) || fetch_domain(mid));
}

/**
 * @brief      Fetch property of user node
 *
 * @param      mid   Mid of the node
 * @param      tag   Property tag ID to fetch
 * @param      prop  String to write the property value to
 *
 * @return     Exchange error code indicating success or failure
 */
ec_error_t ab_base::fetch_prop(minid mid, uint32_t tag, std::string &prop) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return ecNotFound;
	auto it = user->propvals.find(tag);
	if (it == user->propvals.cend())
		return ecNotFound;
	prop = it->second;
	return ecSuccess;
}

/**
 * @brief      Fetch list of properties of user node
 *
 * @param      mid       Mid of the node
 * @param      tags      List of property tag IDs to fetch
 * @param      props     Tag ID to value mapping for found properties
 *
 * @return     true if user object was found, false otherwise
 */
bool ab_base::fetch_props(minid mid, const PROPTAG_ARRAY &tags, std::unordered_map<uint32_t, std::string> &props) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return false;
	for (auto tag  : tags) {
		auto it = user->propvals.find(tag);
		if (it == user->propvals.end())
			continue;
		props.emplace(tag, it->second);
	}
	return true;
}

/**
 * @brief      Get total number of children of the node
 *
 * Equivalent to children(), since the maximum tree depth is currently 1.
 *
 * @param      mid   Mid of the node
 *
 * @return     Number of users of a domain node, ot 0 for user nodes
 */
uint32_t ab_base::get_leaves_num(minid mid) const
{
	auto domain = fetch_domain(mid);
	return domain ? uint32_t(domain->userref.size()) : 0;
}

/**
 * @brief      Get the number of direct child nodes
 *
 * @param      mid   Mid of the node
 *
 * @return     Number of users of a domain node or 0 for user nodes
 */
size_t ab_base::children_count(minid mid) const
{
	const ab_domain *domain = fetch_domain(mid);
	return domain ? domain->userref.size() : 0;
}

/**
 * @brief      Count number of users hidden from GAL
 *
 * @return     Number of users with AB_HIDE_FROM_GAL flag set
 */
size_t ab_base::hidden_count() const
{
	return std::count_if(m_users.cbegin(), m_users.cend(),
	       [](const sql_user &u) { return u.cloak_bits & AB_HIDE_FROM_GAL; });
}

/**
 * @brief      Get the hidden property of a node
 *
 * @param      mid   Mid of the node
 *
 * @return    Bitmask of hidden flags for user nodes or 0 for domain nodes
 */
uint32_t ab_base::hidden(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	return user != nullptr ? user->cloak_bits : 0;
}

/**
 * @brief      Get node mdbdn
 *
 * @param      mid   Mid of the node
 * @param      dn    String to write the dn to
 *
 * @return     Exchange error code indicating success or failure
 */
ec_error_t ab_base::mdbdn(minid mid, std::string &dn) const
{
	auto username = znul(user_info(mid, userinfo::mail_address));
	return cvt_username_to_mdbdn(username, AB.org_name().c_str(), mid.value(), dn);
}

/**
 * @brief      Get mailing list info
 *
 * @param      mid           Mid of the node
 * @param      mail_address  String to write mail address to, or nullptr to ignore
 * @param      create_day    String to write create day to, or nullptr to ignore
 * @param      privilege     Integer to store list privilege in, or nullptr to ignore
 *
 * @return     true if user was found, false otherwise
 */
bool ab_base::mlist_info(minid mid, std::string *mail_address, std::string *create_day, int *privilege) const
{
	const sql_user *user = fetch_user(mid);
	if (!user) {
		if (mail_address != nullptr)
			*mail_address = '\0';
		if (privilege != nullptr)
			*privilege = 0;
		return false;
	}
	if (mail_address != nullptr)
		*mail_address = user->username;
	if (create_day != nullptr)
		*create_day = '\0';
	if (privilege != nullptr)
		*privilege = user->list_priv;
	return true;
}

/**
 * @brief      Get list of properties of a user
 *
 * @param      mid   Mid of the node
 * @param      tags  Integer list to write tag IDs to
 *
 * @return     Exchange error code indicating success or failure
 */
ec_error_t ab_base::proplist(minid mid, std::vector<uint32_t> &tags) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return ecNotFound;
	for (auto &entry : user->propvals)
		tags.push_back(entry.first);
	return ecSuccess;
}

/**
 * @brief      Retrieve minid from dn
 *
 * No checks are performed whether the resulting minid is valid.
 * Use exists() to check whether the minid is usable.
 *
 * @param      dn    Dn of the user
 *
 * @return     Minid of the user node
 */
minid ab_base::resolve(const char* dn) const
{
	auto z = strlen(dn);
	const std::string &server_prefix = AB.essdn_server_prefix();
	if (strncasecmp(dn, server_prefix.c_str(), server_prefix.size()) == 0 &&
	    z >= server_prefix.size() + 60) {
		/* Reason for 60: see DN format in ab_tree_get_mdbdn */
		auto id = decode_hex_int(dn + server_prefix.size() + 60);
		return minid(minid::address, id);
	}
	const std::string &rcpts_prefix = AB.essdn_rcpts_prefix();
	if (strncasecmp(dn, rcpts_prefix.c_str(), rcpts_prefix.size()) != 0 ||
	    z < rcpts_prefix.size() + 8)
		return {};
	auto id = decode_hex_int(dn + rcpts_prefix.size() + 8);
	return minid(minid::address, id);
}

/**
 * @brief      Get address book node type
 *
 * @param      mid   Mid of the node
 *
 * @return     Node type
 */
abnode_type ab_base::type(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (user)
		return (user->dtypx & DTE_MASK_LOCAL) == DT_DISTLIST ?
		       abnode_type::mlist : abnode_type::user;
	const ab_domain *domain = fetch_domain(mid);
	if (domain)
		return abnode_type::domain;
	return abnode_type::remote;
}

/**
 * @brief     Get user info of the node
 *
 * @param      mid   Mid of the node
 * @param      ui    Type of user info to query
 *
 * @return     nullptr if not a user node, empty string if not found, info otherwise
 */
const char *ab_base::user_info(minid mid, userinfo ui) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return nullptr;
	uint32_t tag = 0;
	switch (ui) {
	case userinfo::mail_address:
		if ((user->dtypx & DTE_MASK_LOCAL) != DT_REMOTE_MAILUSER)
			return user->username.c_str();
		tag = PR_SMTP_ADDRESS;
		break;
	case userinfo::real_name: tag = PR_DISPLAY_NAME; break;
	case userinfo::job_title: tag = PR_TITLE; break;
	case userinfo::comment: tag = PR_COMMENT; break;
	case userinfo::mobile_tel: tag = PR_MOBILE_TELEPHONE_NUMBER; break;
	case userinfo::business_tel: tag = PR_PRIMARY_TELEPHONE_NUMBER; break;
	case userinfo::nick_name: tag = PR_NICKNAME; break;
	case userinfo::home_address: tag = PR_HOME_ADDRESS_STREET; break;
	case userinfo::store_path: return user->maildir.c_str();
	default: return "";
	}
	auto it = user->propvals.find(tag);
	return it != user->propvals.cend() ? it->second.c_str() : "";
}

///////////////////////////////////////////////////////////////////////////////
// ab_base private helper member functions

/**
 * @brief      Get domain object from minid
 *
 * @param      mid   Mid of the node
 *
 * @return     Domain object or nullptr if not found
 */
const ab_domain *ab_base::fetch_domain(minid mid) const
{
	if (mid.type() != minid::domain)
		return nullptr;
	auto it = minid_idx_map.find(mid);
	if (it == minid_idx_map.end())
		return nullptr;
	size_t idx = it->second;
	return idx >= domains.size() ? nullptr : &domains[idx];
}

/**
 * @brief      Get user object from minid
 *
 * @param      mid   Mid of the node
 *
 * @return     User object or nullptr if not found
 */
const sql_user *ab_base::fetch_user(minid mid) const
{
	if (mid.type() != minid::address)
		return nullptr;
	auto it = minid_idx_map.find(mid);
	if (it == minid_idx_map.end())
		return nullptr;
	size_t idx = it->second;
	return idx >= m_users.size() ? nullptr : &m_users[idx];
}

/**
 * @brief      Get iterator to node
 *
 * @param      mid   Mid of the node
 *
 * @return     Iterator to node or end() if not found
 */
ab_base::iterator ab_base::find(minid mid) const
{
	auto it = minid_idx_map.find(mid);
	if (it == minid_idx_map.end())
		return end();
	return mid.type() == minid::domain ? iterator(this, domains.begin() + it->second) :
	       iterator(this, m_users.begin() + it->second);
}

/**
 * @brief      Find domain by id
 *
 * @param      id    Domain ID
 *
 * @return     Domain object or nullptr if not found
 */
const ab_domain *ab_base::find_domain(uint32_t id) const
{
	for (auto &domain : domains)
		if (domain.id == id)
			return &domain;
	return nullptr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// ab_base::iterator member functions

/**
 * @brief      Move iterator
 *
 * @param      offset    Distance to move the iterator
 *
 * @return     *this
 */
ab_base::iterator &ab_base::iterator::operator+=(difference_type offset)
{
	if (offset == 0)
		return *this;

	if (it.index() == 0) {
		auto &i = std::get<0>(it);
		ssize_t dist = std::distance(i, m_base->domains.cend());
		if (offset < 0 || offset < dist) {
			i += offset;
			mid = minid(minid::domain, i->id);
			return *this;
		}
		/* Wrap forwards over to users */
		auto i2 = m_base->m_users.cbegin() + (offset - dist);
		it = i2;
		if (i2 != m_base->m_users.cend())
			mid = minid(minid::address, i2->id);
		else
			mid = 0;
		return *this;
	} else if (it.index() == 1) {
		auto &i = std::get<1>(it);
		ssize_t dist = std::distance(m_base->m_users.cbegin(), i);
		if (offset > 0 || -offset <= dist) {
			i += offset;
			if (i != m_base->m_users.cend())
				mid = minid(minid::address, i->id);
			else
				mid = 0;
			return *this;
		}
		/* Wrap backwards over to domains */
		auto i2 = m_base->domains.cend() + (dist + offset);
		it = i2;
		if (i2 != m_base->domains.cend())
			mid = minid(minid::domain, i2->id);
		else
			mid = 0;
		return *this;
	}
	return *this;
}

/**
 * @brief      Get absolute iterator position
 *
 * @return     Distance to begin()
 */
size_t ab_base::iterator::pos() const
{
	return it.index() == 0 ? std::distance(m_base->domains.cbegin(), std::get<0>(it)) :
	                         std::distance(m_base->m_users.cbegin(), std::get<1>(it)) + m_base->domains.size();
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// ab_node member functions

ab_node::iterator ab_node::begin() const
{
	const ab_domain *domain = base->fetch_domain(mid);
	return domain ? domain->userref.cbegin() : iterator();
}

ab_node::iterator ab_node::end() const
{
	const ab_domain *domain = base->fetch_domain(mid);
	return domain ? domain->userref.cend() : iterator();
}

minid ab_node::operator[](uint32_t idx) const
{
	const ab_domain *domain = base->fetch_domain(mid);
	return domain && idx < domain->userref.size() ? domain->userref[idx] : minid();
}

} // namespace gromox::ab_tree
