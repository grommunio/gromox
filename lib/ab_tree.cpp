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

namespace gromox::ab_tree
{

ab AB;

int32_t ab::base_id(const GUID& guid)
{
	int32_t id;
	memcpy(&id, guid.node, sizeof(int32_t));
	return id;
}

void ab::drop(int32_t id)
{
	std::unique_lock lock(m_lock);
	m_base_hash.erase(id);
}

void ab::init(std::string_view org, int cache_interval)
{
	std::unique_lock ul(m_lock);
	if (m_initialized)
		return;
	m_org_name = org;
	m_cache_interval = std::chrono::seconds(cache_interval);
	m_essdn_server_prefix = fmt::format("/o={}/" EAG_SERVERS "/cn=", m_org_name);
	m_essdn_rcpts_prefix = fmt::format("/o={}/" EAG_RCPTS "/cn=", m_org_name);
}

void ab::invalidate_cache()
{
	std::unique_lock lock(m_lock);
	m_base_hash.clear();
}

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

void ab::stop()
{
	if (--running)
		return;
	worker_signal.notify_all();
	worker.join();
}

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
// ab_base organistational member functions

const std::vector<std::string> ab_base::vs_empty{};

ab_base::ab_base(int32_t id) : m_base_id(id)
{
	m_guid = GUID::random_new();
	memcpy(m_guid.node, &m_base_id, sizeof(int32_t));
	m_lock.lock(); // unlocked after load
}

bool ab_base::await_load() const
{
	std::lock_guard guard(m_lock);
	return m_status == Status::LIVING;
}

bool ab_base::load()
{
	std::lock_guard lock(m_lock, std::adopt_lock);
	std::vector<unsigned int> domain_ids;
	if (m_base_id <= 0)
		domain_ids.emplace_back(-m_base_id);
	else if (!mysql_adaptor_get_org_domains(m_base_id, domain_ids))
		return false;
	if (domain_ids.size() > minid::MAXVAL) // cannot reference more nodes
		domain_ids.resize(minid::MAXVAL);
	std::unordered_map<unsigned int, unsigned int> domain_map;
	domains.reserve(domain_ids.size());
	sql_domain domain;
	for (unsigned int domain_id : domain_ids) try {
		if (!mysql_adaptor_get_domain_users(domain_id, m_users))
			return false;
		domain_map[domain_id] = uint32_t(domains.size());
		ab_domain &domain = domains.emplace_back();
		domain.id = domain_id;
		mysql_adaptor_get_domain_info(domain_id, domain.info);
	} catch (std::exception &) {
		return false;
	}
	if (m_users.size() > minid::MAXVAL)
		m_users.resize(minid::MAXVAL);
	std::sort(m_users.begin(), m_users.end());
	minid_idx_map.reserve(m_users.size() + domain_ids.size());
	std::unordered_map<unsigned int, unsigned int> domainMap;
	for (size_t i = 0; i < m_users.size(); ++i) {
		const sql_user &u = m_users[i];
		domains[domain_map[u.domain_id]].userref.emplace_back(minid(minid::address, u.id));
		minid_idx_map.emplace(minid(minid::address, u.id), i);
	}
	for (size_t i = 0; i < domains.size(); ++i)
		minid_idx_map.emplace(minid(minid::domain, domains[i].id), i);
	m_status = Status::LIVING;
	return true;
}

///////////////////////////////////////////////////////////////////////////////
// ab_base informational member functions

const std::vector<std::string> &ab_base::aliases(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	return user ? user->aliases : vs_empty;
}

minid ab_base::at(uint32_t idx) const
{
	return idx < domains.size() ? minid(minid::domain, domains[idx].id) :
	       idx - domains.size() < m_users.size() ? minid(minid::address, m_users[idx-domains.size()].id) : minid();
}

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

bool ab_base::dn(minid mid, std::string& essdn) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return false;
	auto username = user_info(mid, userinfo::mail_address);
	const ab_domain *domain = find_domain(user->domain_id);
	return cvt_username_to_essdn(username, AB.org_name().c_str(), user->id, domain->id, essdn) == ecSuccess;
}

uint32_t ab_base::dtyp(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return DT_CONTAINER;
	return user->dtypx;
}

std::optional<uint32_t> ab_base::dtypx(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return {};
	if (user->dtypx == DT_REMOTE_MAILUSER)
		return DT_REMOTE_MAILUSER;
	/*
	 * In Gromox, (almost) everything with a username is capable of being
	 * used in an ACL (and usernames are mandatory currently).
	 */
	return (user->dtypx & DTE_MASK_LOCAL) | DTE_FLAG_ACL_CAPABLE;
}

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

uint32_t ab_base::etyp(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return DT_CONTAINER;
	return dtypx_to_etyp(user->dtypx);
}

bool ab_base::exists(minid mid) const
{
	return mid.valid() && (fetch_user(mid) || fetch_domain(mid));
}

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

minid ab_base::from_guid(const GUID &guid)
{
	return guid.time_low;
}

uint32_t ab_base::get_leaves_num(minid mid) const
{
	auto domain = fetch_domain(mid);
	return domain ? uint32_t(domain->userref.size()) : 0;
}

GUID ab_base::guid(minid mid)
{
	GUID g{};
	g.time_low = mid;
	return g;
}

size_t ab_base::children(minid mid) const
{
	const ab_domain *domain = fetch_domain(mid);
	return domain ? domain->userref.size() : 0;
}

uint32_t ab_base::hidden(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	return user ? user->hidden : 0;
}

ec_error_t ab_base::mdbdn(minid mid, std::string &dn) const
{
	auto username = znul(user_info(mid, userinfo::mail_address));
	return cvt_username_to_mdbdn(username, AB.org_name().c_str(), mid.value(), dn);
}

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

ec_error_t ab_base::proplist(minid mid, std::vector<uint32_t> &tags) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return ecNotFound;
	for (auto &entry : user->propvals)
		tags.push_back(entry.first);
	return ecSuccess;
}

minid ab_base::resolve(const char* dn) const
{
	const std::string &server_prefix = AB.essdn_server_prefix();
	if (strncasecmp(dn, server_prefix.c_str(), AB.essdn_server_prefix().size()) == 0 && strlen(dn) >= server_prefix.size() + 60) {
		/* Reason for 60: see DN format in ab_tree_get_mdbdn */
		auto id = decode_hex_int(dn + server_prefix.size() + 60);
		return minid(minid::address, id);
	}
	const std::string rcpts_prefix = AB.essdn_rcpts_prefix();
	auto id = decode_hex_int(dn + rcpts_prefix.size() + 8);
	return minid(minid::address, id);
}

abnode_type ab_base::type(minid mid) const
{
	const sql_user *user = fetch_user(mid);
	if (user)
		return user->dtypx == DT_DISTLIST ? abnode_type::mlist : abnode_type::user;
	const ab_domain *domain = fetch_domain(mid);
	if (domain)
		return abnode_type::domain;
	return abnode_type::remote;
}

const char *ab_base::user_info(minid mid, userinfo ui) const
{
	const sql_user *user = fetch_user(mid);
	if (!user)
		return nullptr;
	uint32_t tag;
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
	}
	auto it = user->propvals.find(tag);
	return it != user->propvals.cend() ? it->second.c_str() : "";
}

///////////////////////////////////////////////////////////////////////////////
// ab_base private helper member functions

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

ab_base::iterator ab_base::find(minid mid) const
{
	auto it = minid_idx_map.find(mid);
	if (it == minid_idx_map.end())
		return end();
	return mid.type() == minid::domain ? iterator(this, domains.begin() + it->second) :
	       iterator(this, m_users.begin() + it->second);
}

const ab_domain *ab_base::find_domain(uint32_t id) const
{
	for (auto &domain : domains)
		if (domain.id == id)
			return &domain;
	return nullptr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// ab_base::iterator member functions

ab_base::iterator &ab_base::iterator::operator+=(difference_type offset)
{
	if (offset == 0)
		return *this;

	if (it.index() == 0 && offset > 0) {
		auto &i = std::get<0>(it);
		ssize_t dist = std::distance(i, m_base->domains.cend());
		if (offset < dist)
			i += offset;
		else
			it = m_base->m_users.cbegin() + (offset - dist);
	} else if (it.index() == 1 && offset < 0) {
		auto &i = std::get<1>(it);
		ssize_t dist = std::distance(m_base->m_users.cbegin(), i);
		if (-offset <= dist)
			i += offset;
		else
			it = m_base->domains.cend() + (dist + offset);
	} else
		std::visit([=](auto &i) { i += offset; }, it);
	mid = minid(it.index() == 0 ? minid::domain : minid::address, std::visit([](auto &i) { return i->id; }, it));
	return *this;
}

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
