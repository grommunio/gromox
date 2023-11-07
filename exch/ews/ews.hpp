// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once
#include <list>
#include <optional>
#include <unordered_map>
#include <variant>

#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/hpm_common.h>
#include <gromox/http.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/mapi_types.hpp>
#include <include/gromox/pcl.hpp>

#include "ObjectCache.hpp"
#include "exceptions.hpp"
#include "soaputil.hpp"
#include "structures.hpp"

namespace gromox::EWS::detail
{
/**
 * @brief     Generic deleter struct
 *
 * Provides explicit deleters for classes without destructor.
 */
struct Cleaner
{
	void operator()(BINARY*);
	void operator()(MESSAGE_CONTENT*);
};

struct AttachmentInstanceKey {
	std::string dir;
	uint64_t mid;
	uint32_t aid;

	inline bool operator==(const AttachmentInstanceKey& o) const
	{return mid == o.mid && aid == o.aid && dir == o.dir;}
};

struct MessageInstanceKey {
	std::string dir;
	uint64_t mid;

	inline bool operator==(const MessageInstanceKey& o) const
	{return mid == o.mid && dir == o.dir;}
};

using ExmdbSubscriptionKey = std::pair<std::string, uint32_t>;
using SubscriptionKey = uint32_t;
using ContextWakeupKey = int;

struct EmbeddedInstanceKey
{
	std::string dir;
	uint32_t aid;

	inline bool operator==(const EmbeddedInstanceKey& o) const
	{return dir == o.dir && aid == o.aid;}
};

} // namespace gromox::EWS::detail

template<> struct std::hash<gromox::EWS::detail::AttachmentInstanceKey>
{size_t operator()(const gromox::EWS::detail::AttachmentInstanceKey&) const noexcept;};

template<> struct std::hash<gromox::EWS::detail::ExmdbSubscriptionKey>
{size_t operator()(const gromox::EWS::detail::ExmdbSubscriptionKey&) const noexcept;};

template<> struct std::hash<gromox::EWS::detail::MessageInstanceKey>
{size_t operator()(const gromox::EWS::detail::MessageInstanceKey&) const noexcept;};

template<> struct std::hash<gromox::EWS::detail::EmbeddedInstanceKey>
{size_t operator()(const gromox::EWS::detail::EmbeddedInstanceKey&) const noexcept;};

namespace gromox::EWS {

class EWSContext;

/**
 * @brief      Aggregation of plugin data and functions
 */
class EWSPlugin
{
public:
	using Handler = void (*)(const tinyxml2::XMLElement *, tinyxml2::XMLElement *, EWSContext &);

	EWSPlugin();
	~EWSPlugin();
	http_status proc(int, const void*, uint64_t);
	static BOOL preproc(int);

	bool logEnabled(const std::string_view&) const;

	struct _mysql {
		_mysql();

		decltype(mysql_adaptor_get_domain_ids)* get_domain_ids;
		decltype(mysql_adaptor_get_domain_info)* get_domain_info;
		decltype(mysql_adaptor_get_homedir)* get_homedir;
		decltype(mysql_adaptor_get_id_from_homedir)* get_id_from_homedir;
		decltype(mysql_adaptor_get_id_from_maildir)* get_id_from_maildir;
		decltype(mysql_adaptor_get_maildir)* get_maildir;
		decltype(mysql_adaptor_get_user_aliases) *get_user_aliases;
		decltype(mysql_adaptor_get_user_displayname) *get_user_displayname;
		decltype(mysql_adaptor_get_user_ids) *get_user_ids;
		decltype(mysql_adaptor_get_user_properties) *get_user_properties;
		decltype(mysql_adaptor_get_username_from_id)* get_username_from_id;
	} mysql; ///< mysql adaptor function pointers

	struct _exmdb {
		_exmdb();

	#define EXMIDL(n, p) EXMIDL_RETTYPE (*n) p;
	#define IDLOUT
	#include <gromox/exmdb_idef.hpp>
	#undef EXMIDL
	#undef IDLOUT
		bool get_message_property(const char*, const char*, cpid_t, uint64_t, uint32_t, void **ppval) const;
		void (*register_proc)(void*);
	} exmdb;

	struct ExmdbInstance {
		const EWSPlugin& plugin; ///< Plugin used to release the instance
		std::string dir; ///< Home directory of domain or user
		uint32_t instanceId; ///< Instance ID

		ExmdbInstance(const EWSPlugin&, const std::string&, uint32_t);
		ExmdbInstance(const ExmdbInstance&) = delete;
		ExmdbInstance& operator=(const ExmdbInstance&) = delete;
		~ExmdbInstance();
	};

	/**
	 * @brief      Subscription management struct
	 */
	struct Subscription
	{
		Subscription(const char*, const EWSPlugin&);
		Subscription(const Subscription&) = delete;
		Subscription(Subscription&&) = delete;

		Subscription& operator=(const Subscription&) = delete;
		Subscription& operator=(Subscription&&) = delete;

		const EWSPlugin& ews; ///< Parent plugin
		std::string username; ///< Name of the user who created the subscription
		Structures::sMailboxInfo mailboxInfo; ///< Target mailbox metadata
		std::mutex lock; ///< I/O mutex
		std::vector<detail::ExmdbSubscriptionKey> subscriptions; ///< Exmdb subscription keys
		std::list<Structures::sNotificationEvent> events; ///< Events that occured since last check
		std::optional<int> waitingContext; ///< ID of context waiting for events

		~Subscription();
	};

	void event(const char*, BOOL, uint32_t, const DB_NOTIFY*) const;
	bool linkSubscription(const Structures::tSubscriptionId&, const EWSContext&) const;
	std::shared_ptr<ExmdbInstance> loadAttachmentInstance(const std::string&, uint64_t, uint64_t, uint32_t) const;
	std::shared_ptr<ExmdbInstance> loadEmbeddedInstance(const std::string&, uint32_t) const;
	std::shared_ptr<ExmdbInstance> loadMessageInstance(const std::string&, uint64_t, uint64_t) const;
	Structures::sFolderEntryId mkFolderEntryId(const Structures::sMailboxInfo&, uint64_t) const;
	Structures::sMessageEntryId mkMessageEntryId(const Structures::sMailboxInfo&, uint64_t, uint64_t) const;
	std::shared_ptr<Subscription> mksub(const Structures::tSubscriptionId&, const char*) const;
	detail::ExmdbSubscriptionKey subscribe(const std::string&, uint16_t, bool, uint64_t, detail::SubscriptionKey) const;
	std::shared_ptr<Subscription> subscription(detail::SubscriptionKey, uint32_t) const;
	void unlinkSubscription(int) const;
	bool unsubscribe(detail::SubscriptionKey, const char*) const;
	void unsubscribe(const detail::ExmdbSubscriptionKey&) const;
	void wakeContext(int, std::chrono::milliseconds) const;

	std::string x500_org_name; ///< organization name or empty string if not configured
	std::string smtp_server_ip = "::1"; ///< Host to send mail to, default `"::1"`
	uint16_t smtp_server_port = 25; ///< Port to send mail to, default `"25"`
	int request_logging = 0; ///< 0 = none, 1 = request names, 2 = request data
	int response_logging = 0; ///< 0 = none, 1 = response names, 2 = response data
	int pretty_response = 0; ///< 0 = compact output, 1 = pretty printed response
	int experimental = 0; ///< Enable experimental requests, 0 = disabled
	size_t max_user_photo_size = 5*1024*1024; ///< Maximum user photo file size (5 MiB)
	std::chrono::milliseconds cache_interval{5'000}; ///< Interval for cache cleanup
	std::chrono::milliseconds cache_attachment_instance_lifetime{30'000}; ///< Lifetime of attachment instances
	std::chrono::milliseconds cache_embedded_instance_lifetime{30'000}; /// Lifetime of embedded instances
	std::chrono::milliseconds cache_message_instance_lifetime{30'000}; ///< Lifetime of message instances
	std::chrono::milliseconds event_stream_interval{45'000}; ///< How often to send updates for GetStreamingEvents

	int retr(int);
	void term(int);

private:
	template<typename T> using sptr = std::shared_ptr<T>;

	struct DebugCtx;

	struct WakeupNotify
	{
		inline explicit WakeupNotify(int id) : ID(id) {}
		int ID;
		~WakeupNotify();
	};

	using CacheKey = std::variant<detail::AttachmentInstanceKey, detail::MessageInstanceKey, detail::SubscriptionKey, detail::ContextWakeupKey, detail::EmbeddedInstanceKey>;
	using CacheObj = std::variant<sptr<ExmdbInstance>, sptr<Subscription>, sptr<WakeupNotify>>;

	static const std::unordered_map<std::string, Handler> requestMap;

	static http_status fault(int, http_status, const std::string_view&);

	mutable std::mutex subscriptionLock;
	mutable std::unordered_map<detail::ExmdbSubscriptionKey, detail::SubscriptionKey> subscriptions;

	std::vector<std::unique_ptr<EWSContext>> contexts;
	mutable ObjectCache<CacheKey, CacheObj> cache;

	std::unique_ptr<DebugCtx> debug;
	std::vector<std::string> logFilters;
	bool invertFilter = true;
	bool teardown = false;

	http_status dispatch(int, HTTP_AUTH_INFO&, const void*, uint64_t);
	void loadConfig();
};

/**
 * @brief      EWS request context
 */
class EWSContext
{
public:
	enum State : uint8_t {S_DEFAULT, S_WRITE, S_DONE, S_STREAM_NOTIFY};

	inline EWSContext(int id, HTTP_AUTH_INFO ai, const char *data, uint64_t length, EWSPlugin &p) :
		m_ID(id), m_orig(*get_request(id)), m_auth_info(ai), m_request(data, length), m_plugin(p)
	{}

	EWSContext(const EWSContext&) = delete;
	EWSContext(EWSContext&&) = delete;

	Structures::sFolder create(const std::string&, const Structures::sFolderSpec&, const Structures::sFolder&) const;
	Structures::sItem create(const std::string&, const Structures::sFolderSpec&, const MESSAGE_CONTENT&) const;
	void disableEventStream();
	void enableEventStream(int);
	std::string essdn_to_username(const std::string&) const;
	std::string get_maildir(const Structures::tMailbox&) const;
	std::string get_maildir(const std::string&) const;
	uint32_t getAccountId(const std::string&, bool) const;
	std::string getDir(const Structures::sFolderSpec&) const;
	TAGGED_PROPVAL getFolderEntryId(const std::string&, uint64_t) const;
	template<typename T> const T* getFolderProp(const std::string&, uint64_t, uint32_t) const;
	TPROPVAL_ARRAY getFolderProps(const std::string&, uint64_t, const PROPTAG_ARRAY&) const;
	std::pair<std::list<Structures::sNotificationEvent>, bool> getEvents(const Structures::tSubscriptionId&) const;
	TAGGED_PROPVAL getFolderEntryId(const Structures::sFolderSpec&) const;
	TPROPVAL_ARRAY getFolderProps(const Structures::sFolderSpec&, const PROPTAG_ARRAY&) const;
	TAGGED_PROPVAL getItemEntryId(const std::string&, uint64_t) const;
	template<typename T> const T* getItemProp(const std::string&, uint64_t, uint32_t) const;
	TPROPVAL_ARRAY getItemProps(const std::string&, uint64_t, const PROPTAG_ARRAY&) const;
	GUID getMailboxGuid(const std::string&) const;
	Structures::sMailboxInfo getMailboxInfo(const std::string&, bool) const;
	PROPID_ARRAY getNamedPropIds(const std::string&, const PROPNAME_ARRAY&, bool=false) const;
	void getNamedTags(const std::string&, Structures::sShape&, bool=false) const;
	Structures::sAttachment loadAttachment(const std::string&,const Structures::sAttachmentId&) const;
	Structures::sFolder loadFolder(const std::string&, uint64_t, Structures::sShape&) const;
	Structures::sItem loadItem(const std::string&, uint64_t, uint64_t, Structures::sShape&) const;
	Structures::sItem loadOccurrence(const std::string&, uint64_t, uint64_t, uint32_t, Structures::sShape&) const;
	std::unique_ptr<BINARY, detail::Cleaner> mkPCL(const XID&, PCL=PCL()) const;
	uint64_t moveCopyFolder(const std::string&, const Structures::sFolderSpec&, uint64_t, uint32_t, bool) const;
	uint64_t moveCopyItem(const std::string&, const Structures::sMessageEntryId&, uint64_t, bool) const;
	void normalize(Structures::tEmailAddressType&) const;
	void normalize(Structures::tMailbox&) const;
	int notify();
	uint32_t permissions(const char*, const Structures::sFolderSpec&, const char* = nullptr) const;
	Structures::sFolderSpec resolveFolder(const Structures::tDistinguishedFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::tFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::sFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::sMessageEntryId&) const;
	void send(const std::string&, const MESSAGE_CONTENT&) const;
	BINARY serialize(const XID&) const;
	bool streamEvents(const Structures::tSubscriptionId&) const;
	MESSAGE_CONTENT toContent(const std::string&, const Structures::sFolderSpec&, Structures::sItem&, bool) const;
	void updated(const std::string&, const Structures::sFolderSpec&) const;
	Structures::tSubscriptionId subscribe(const Structures::tPullSubscriptionRequest&) const;
	Structures::tSubscriptionId subscribe(const Structures::tStreamingSubscriptionRequest&) const;
	bool unsubscribe(const Structures::tSubscriptionId&) const;
	void updated(const std::string&, const Structures::sMessageEntryId&) const;
	std::string username_to_essdn(const std::string&) const;
	void validate(const std::string&, const Structures::sMessageEntryId&) const;

	double age() const;
	void experimental() const;

	inline int ID() const {return m_ID;}
	inline const HTTP_AUTH_INFO& auth_info() const {return m_auth_info;}
	inline const EWSPlugin& plugin() const {return m_plugin;}
	inline const SOAP::Envelope& request() const {return m_request;}
	inline SOAP::Envelope& response() {return m_response;}

	inline http_status code() const {return m_code;}
	inline void code(http_status c) {m_code = c;}
	inline bool log() const {return m_log;}
	inline void log(bool l) {m_log = l;}
	inline State state() const {return m_state;}
	inline void state(State s) {m_state = s;}

	static void* alloc(size_t);
	template<typename T> static T* alloc(size_t=1);
	template<typename T, typename... Args> static T* construct(Args&&...);

	static void assertIdType(Structures::tBaseItemId::IdType, Structures::tBaseItemId::IdType);
	static void ext_error(pack_result, const char* = nullptr, const char* = nullptr);

private:
	const void* getFolderProp(const std::string&, uint64_t, uint32_t) const;
	const void* getItemProp(const std::string&, uint64_t, uint32_t) const;

	struct NotificationContext
	{
		enum State : uint8_t {
			S_INIT, ///< Just initalized, flush data and wait
			S_SLEEP, ///< Waiting for next wakeup
			S_WRITE, ///< Just wrote data, proceed with sleeping
			S_CLOSING, ///< All subscriptions died so we might as well
			S_CLOSED ///< isded
		};

		inline explicit NotificationContext(gromox::time_point e) : state(S_INIT), expire(e) {}

		State state;
		std::vector<Structures::tSubscriptionId> subscriptions;
		gromox::time_point expire;
	};

	void loadSpecial(const std::string&, uint64_t, uint64_t, Structures::tItem&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, uint64_t, Structures::tMessage&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, uint64_t, Structures::tCalendarItem&, uint64_t) const;
	Structures::tSubscriptionId subscribe(const std::vector<Structures::sFolderId>&, uint16_t, bool, uint32_t) const;

	void toContent(const std::string&, Structures::tCalendarItem&, Structures::sShape&, MESSAGE_CONTENT&) const;
	void toContent(const std::string&, Structures::tContact&, Structures::sShape&, MESSAGE_CONTENT&) const;
	void toContent(const std::string&, Structures::tItem&, Structures::sShape&, MESSAGE_CONTENT&) const;
	void toContent(const std::string&, Structures::tMessage&, Structures::sShape&, MESSAGE_CONTENT&) const;

	void updateProps(Structures::tItem&, Structures::sShape&, const TPROPVAL_ARRAY&) const {};
	void updateProps(Structures::tCalendarItem&, Structures::sShape&, const TPROPVAL_ARRAY&) const;

	PROPERTY_NAME* getPropertyName(const std::string&, uint16_t) const;

	int m_ID = 0;
	HTTP_REQUEST& m_orig;
	HTTP_AUTH_INFO m_auth_info{};
	SOAP::Envelope m_request;
	SOAP::Envelope m_response;
	EWSPlugin& m_plugin;
	std::chrono::high_resolution_clock::time_point m_created = std::chrono::high_resolution_clock::now();
	http_status m_code = http_status::ok;
	State m_state = S_DEFAULT;
	bool m_log = false;
	std::unique_ptr<NotificationContext> m_notify;
};

/**
 * @brief      Get single folder property
 *
 * @param      dir   Store directory
 * @param      mid   Folder ID
 * @param      tag   Tag ID
 *
 * @tparam     T     Type to return
 *
 * @return     Pointer to property or nullptr if not found.
 */
template<typename T>
const T* EWSContext::getFolderProp(const std::string& dir, uint64_t mid, uint32_t tag) const
{return static_cast<const T*>(getFolderProp(dir, mid, tag));}

/**
 * @brief      Get single item property
 *
 * @param      dir   Store directory
 * @param      mid   Message ID
 * @param      tag   Tag ID
 *
 * @tparam     T     Type to return
 *
 * @return     Pointer to property or nullptr if not found.
 */
template<typename T>
const T* EWSContext::getItemProp(const std::string& dir, uint64_t mid, uint32_t tag) const
{return static_cast<const T*>(getItemProp(dir, mid, tag));}

/**
 * @brief      Throwing convenience wrapper for alloc
 *
 * @param      count  Number of elements to allocate memory for
 *
 * @tparam     T      Type to allocate memory for
 *
 * @return     Pointer to allocated memory
 */
template<typename T>
inline T* EWSContext::alloc(size_t count)
{
	T* res = static_cast<T*>(alloc(sizeof(T)*count));
	if(!res)
		throw Exceptions::EWSError::NotEnoughMemory(Exceptions::E3129);
	return res;
}

/**
 * @brief      Throwing convenience wrapper for alloc
 *
 * @param      count  Number of elements to allocate memory for
 *
 * @tparam     T      Type to allocate memory for
 *
 * @return     Pointer to allocated memory
 */
template<typename T, typename... Args>
inline T* EWSContext::construct(Args&&... args)
{
	static_assert(std::is_trivially_destructible_v<T>, "Can only construct trivially destructible types");
	return new(alloc<T>()) T(std::forward<Args...>(args...));
}

}
