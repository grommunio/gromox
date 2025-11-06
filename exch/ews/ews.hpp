// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once
#include <cstdint>
#include <list>
#include <optional>
#include <unordered_map>
#include <variant>
#include <vector>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/hpm_common.h>
#include <gromox/http.hpp>
#include <gromox/mapi_types.hpp>
#include <include/gromox/pcl.hpp>

#include "ObjectCache.hpp"
#include "exceptions.hpp"
#include "soaputil.hpp"
#include "structures.hpp"

namespace gromox::EWS::detail {

/**
 * @brief     Generic deleter struct
 *
 * Provides explicit deleters for classes without destructor.
 */
struct Cleaner {
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
using ContextKey = int;

struct EmbeddedInstanceKey {
	std::string dir;
	uint32_t aid;

	inline bool operator==(const EmbeddedInstanceKey& o) const
	{return dir == o.dir && aid == o.aid;}
};

} // namespace gromox::EWS::detail

template<> struct std::hash<gromox::EWS::detail::AttachmentInstanceKey> {
	size_t operator()(const gromox::EWS::detail::AttachmentInstanceKey &) const noexcept;
};

template<> struct std::hash<gromox::EWS::detail::ExmdbSubscriptionKey> {
	size_t operator()(const gromox::EWS::detail::ExmdbSubscriptionKey &) const noexcept;
};

template<> struct std::hash<gromox::EWS::detail::MessageInstanceKey> {
	size_t operator()(const gromox::EWS::detail::MessageInstanceKey &) const noexcept;
};

template<> struct std::hash<gromox::EWS::detail::EmbeddedInstanceKey> {
	size_t operator()(const gromox::EWS::detail::EmbeddedInstanceKey &) const noexcept;
};

namespace gromox::EWS {

class EWSContext;

/**
 * @brief      Aggregation of plugin data and functions
 */
class EWSPlugin {
	public:
	using Handler = void (*)(const tinyxml2::XMLElement *, tinyxml2::XMLElement *, EWSContext &);

	EWSPlugin();
	~EWSPlugin();
	http_status proc(detail::ContextKey, const void*, uint64_t);
	static BOOL preproc(detail::ContextKey);
	bool logEnabled(const std::string_view) const;

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
	struct SubManager {
		SubManager(const char *, const EWSPlugin &);
		~SubManager();
		NOMOVE(SubManager);

		const EWSPlugin& ews; ///< Parent plugin
		std::string username; ///< Name of the user who created the subscription
		Structures::sMailboxInfo mailboxInfo; ///< Target mailbox metadata
		std::mutex lock; ///< I/O mutex
		std::vector<detail::ExmdbSubscriptionKey> inner_subs; ///< Exmdb subscription keys
		std::list<Structures::sNotificationEvent> events; ///< Events that occured since last check
		std::optional<detail::ContextKey> waitingContext; ///< ID of context waiting for events
	};

	void event(const char*, BOOL, uint32_t, const DB_NOTIFY*) const;
	bool linkSubscription(const Structures::tSubscriptionId&, const EWSContext&) const;
	std::shared_ptr<ExmdbInstance> loadAttachmentInstance(const std::string&, uint64_t, uint64_t, uint32_t) const;
	std::shared_ptr<ExmdbInstance> loadEmbeddedInstance(const std::string&, uint32_t) const;
	std::shared_ptr<ExmdbInstance> loadMessageInstance(const std::string&, uint64_t, uint64_t) const;
	Structures::sFolderEntryId mkFolderEntryId(const Structures::sMailboxInfo&, uint64_t) const;
	Structures::sMessageEntryId mkMessageEntryId(const Structures::sMailboxInfo&, uint64_t, uint64_t) const;
	std::shared_ptr<SubManager> make_submgr(const Structures::tSubscriptionId &, const char *) const;
	detail::ExmdbSubscriptionKey subscribe(const std::string&, uint16_t, bool, uint64_t, detail::SubscriptionKey) const;
	std::shared_ptr<SubManager> get_submgr(detail::SubscriptionKey, uint32_t) const;
	std::string timestamp() const;
	void unlinkSubscription(detail::ContextKey) const;
	bool unsubscribe(detail::SubscriptionKey, const char*) const;
	void unsubscribe(const detail::ExmdbSubscriptionKey&) const;
	void wakeContext(int, std::chrono::milliseconds) const;

	inline const SOAP::VersionInfo& server_version() const {return m_server_version;}

	std::string x500_org_name; ///< organization name or empty string if not configured
	std::string smtp_url;
	std::string timestampFormat = " "; ///< format specification for log timestamps or empty to disable timestamps
	int request_logging = 0; ///< 0 = none, 1 = request names, 2 = request data
	int response_logging = 0; ///< 0 = none, 1 = response names, 2 = response data
	int pretty_response = 0; ///< 0 = compact output, 1 = pretty printed response
	int experimental = 0; ///< Enable experimental requests, 0 = disabled
	size_t max_user_photo_size = 5 << 20; ///< Maximum user photo file size (5 MiB)
	std::chrono::milliseconds cache_interval{5'000}; ///< Interval for cache cleanup
	std::chrono::milliseconds cache_attachment_instance_lifetime{30'000}; ///< Lifetime of attachment instances
	std::chrono::milliseconds cache_embedded_instance_lifetime{30'000}; /// Lifetime of embedded instances
	std::chrono::milliseconds cache_message_instance_lifetime{30'000}; ///< Lifetime of message instances
	std::chrono::milliseconds event_stream_interval{45'000}; ///< How often to send updates for GetStreamingEvents

	int retr(detail::ContextKey);
	void term(detail::ContextKey);

	private:
	template<typename T> using sptr = std::shared_ptr<T>;

	struct DebugCtx;

	struct WakeupNotify {
		inline explicit WakeupNotify(detail::ContextKey id) : ctx_id(id) {}
		detail::ContextKey ctx_id;
		~WakeupNotify();
	};

	using CacheKey = std::variant<detail::AttachmentInstanceKey, detail::MessageInstanceKey, detail::SubscriptionKey, detail::ContextKey, detail::EmbeddedInstanceKey>;
	using CacheObj = std::variant<sptr<ExmdbInstance>, sptr<SubManager>, sptr<WakeupNotify>>;

	static const std::unordered_map<std::string, Handler> requestMap;

	static http_status fault(detail::ContextKey, http_status, const std::string_view);

	mutable std::mutex subscriptionLock;
	mutable std::unordered_map<detail::ExmdbSubscriptionKey, detail::SubscriptionKey> subscriptions;

	std::vector<std::unique_ptr<EWSContext>> contexts;
	mutable ObjectCache<CacheKey, CacheObj> cache;

	std::unique_ptr<DebugCtx> debug;
	std::vector<std::string> logFilters;
	SOAP::VersionInfo m_server_version;
	bool invertFilter = true;
	bool teardown = false;

	http_status dispatch(detail::ContextKey, HTTP_AUTH_INFO &, const void *, uint64_t);
	void loadConfig();
};

/**
 * @brief      EWS request context
 */
class EWSContext {
	public:
	using MCONT_PTR = std::unique_ptr<MESSAGE_CONTENT, detail::Cleaner>; ///< Unique pointer to MESSAGE_CONTENT

	enum State : uint8_t {S_DEFAULT, S_WRITE, S_DONE, S_STREAM_NOTIFY};

	EWSContext(detail::ContextKey, const HTTP_AUTH_INFO &, const char *, uint64_t, EWSPlugin &);
	~EWSContext();

	EWSContext(const EWSContext&) = delete;
	EWSContext(EWSContext&&) = delete;

	Structures::sFolder create(const std::string&, const Structures::sFolderSpec&, const Structures::sFolder&) const;
	Structures::sItem create(const std::string&, const Structures::sFolderSpec&, const MESSAGE_CONTENT&) const;
	void createCalendarItemFromMeetingRequest(const Structures::tItemId&, uint32_t) const;
	void disableEventStream();
	const char* effectiveUser(const Structures::sFolderSpec&) const;
	void enableEventStream(int);
	std::string essdn_to_username(const std::string&) const;
	std::string exportContent(const std::string&, const MESSAGE_CONTENT&, const std::string&) const;
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
	uint16_t getNamedPropId(const std::string&, const PROPERTY_NAME&, bool=false) const;
	PROPID_ARRAY getNamedPropIds(const std::string&, const PROPNAME_ARRAY&, bool=false) const;
	void getNamedTags(const std::string&, Structures::sShape&, bool=false) const;
	Structures::sAttachment loadAttachment(const std::string&,const Structures::sAttachmentId&) const;
	Structures::sFolder loadFolder(const std::string&, uint64_t, Structures::sShape&) const;
	Structures::sItem loadItem(const std::string&, uint64_t, uint64_t, Structures::sShape&) const;
	TARRAY_SET loadPermissions(const std::string&, uint64_t) const;
	Structures::sItem loadOccurrence(const std::string&, uint64_t, uint64_t, uint32_t, Structures::sShape&) const;
	void loadSpecial(const std::string&, uint64_t, Structures::tBaseFolderType&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, Structures::tCalendarFolderType&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, Structures::tContactsFolderType&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, Structures::tFolderType&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, uint64_t, Structures::tItem&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, uint64_t, Structures::tMessage&, uint64_t) const;
	void loadSpecial(const std::string&, uint64_t, uint64_t, Structures::tCalendarItem&, uint64_t) const;
	std::unique_ptr<BINARY, detail::Cleaner> mkPCL(const XID&, PCL=PCL()) const;
	uint64_t moveCopyFolder(const std::string&, const Structures::sFolderSpec&, uint64_t, uint32_t, bool) const;
	uint64_t moveCopyItem(const std::string&, const Structures::sMessageEntryId&, uint64_t, bool) const;
	void normalize(Structures::tEmailAddressType&) const;
	void normalize(Structures::tMailbox&) const;
	int notify();
	uint32_t permissions(const std::string&, uint64_t) const;
	Structures::sFolderSpec resolveFolder(const Structures::tDistinguishedFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::tFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::sFolderId&) const;
	Structures::sFolderSpec resolveFolder(const Structures::sMessageEntryId&) const;
	void send(const std::string &dir, uint64_t log_msg_id, const MESSAGE_CONTENT &) const;
	BINARY serialize(const XID&) const;
	bool streamEvents(const Structures::tSubscriptionId&) const;
	MCONT_PTR toContent(const std::string&, std::string&) const;
	MCONT_PTR toContent(const std::string&, const Structures::sFolderSpec&, Structures::sItem&, bool) const;
	Structures::tSubscriptionId subscribe(const Structures::tPullSubscriptionRequest&) const;
	Structures::tSubscriptionId subscribe(const Structures::tPushSubscriptionRequest &) const;
	Structures::tSubscriptionId subscribe(const Structures::tStreamingSubscriptionRequest&) const;
	bool unsubscribe(const Structures::tSubscriptionId&) const;
	void updated(const std::string&, const Structures::sFolderSpec&) const;
	void updated(const std::string&, const Structures::sMessageEntryId&, Structures::sShape&) const;
	void validate(const std::string&, const Structures::sMessageEntryId&) const;
	void writePermissions(const std::string&, uint64_t, const std::vector<PERMISSION_DATA>&) const;

	gromox::time_duration age() const { return tp_now() - m_created; }
	void experimental(const char*) const;

	inline detail::ContextKey context_id() const { return m_ctx_id; }
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
	static char *cpystr(const std::string_view);

	static void assertIdType(Structures::tBaseItemId::IdType, Structures::tBaseItemId::IdType);
	static void ext_error(pack_result, const char* = nullptr, const char* = nullptr);

private:
	const void* getFolderProp(const std::string&, uint64_t, uint32_t) const;
	const void* getItemProp(const std::string&, uint64_t, uint32_t) const;

	struct NotificationContext {
		enum State : uint8_t {
			S_INIT, ///< Just initalized, flush data and wait
			S_SLEEP, ///< Waiting for next wakeup
			S_WRITE, ///< Just wrote data, proceed with sleeping
			S_CLOSING, ///< All subscriptions died so we might as well
			S_CLOSED ///< isded
		};

		inline explicit NotificationContext(gromox::time_point e) : state(S_INIT), expire(e) {}

		State state;
		std::vector<Structures::tSubscriptionId> nct_subs;
		gromox::time_point expire;
	};

	void impersonate(const char*, const char*);

	Structures::tSubscriptionId subscribe(const std::vector<Structures::sFolderId>&, uint16_t, bool, uint32_t) const;

	void toContent(const std::string&, Structures::tCalendarItem&, Structures::sShape&, MCONT_PTR&) const;
	void toContent(const std::string&, Structures::tContact&, Structures::sShape&, MCONT_PTR&) const;
	void toContent(const std::string&, Structures::tItem&, Structures::sShape&, MCONT_PTR&) const;
	void toContent(const std::string&, Structures::tMessage&, Structures::sShape&, MCONT_PTR&) const;
	void toContent(const std::string &, Structures::tAcceptItem &, Structures::sShape &, MCONT_PTR &) const;
	void toContent(const std::string &, Structures::tTentativelyAcceptItem &, Structures::sShape &, MCONT_PTR &) const;
	void toContent(const std::string &, Structures::tDeclineItem &, Structures::sShape &, MCONT_PTR &) const;
	std::optional<uint64_t> findExistingByGoid(const Structures::sFolderSpec&, const std::string&, const MESSAGE_CONTENT&) const;

	inline void updateProps(Structures::tItem&, Structures::sShape&, const TPROPVAL_ARRAY&) const {}
	void updateProps(Structures::tCalendarItem&, Structures::sShape&, const TPROPVAL_ARRAY&) const;

	PROPERTY_NAME* getPropertyName(const std::string&, uint16_t) const;

	detail::ContextKey m_ctx_id = -1;
	http_status m_code = http_status::ok;
	State m_state = S_DEFAULT;
	bool m_log = false;
	HTTP_REQUEST& m_orig;
	HTTP_AUTH_INFO m_auth_info{};
	SOAP::Envelope m_request;
	SOAP::Envelope m_response;
	EWSPlugin& m_plugin;
	std::string impersonationUser; ///< Buffer to hold username of impersonated user
	std::string impersonationMaildir; ///< Buffer to hold maildir of impersonated user
	gromox::time_point m_created{};
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
{
	return static_cast<const T *>(getFolderProp(dir, mid, tag));
}

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
{
	return static_cast<const T*>(getItemProp(dir, mid, tag));
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
template<typename T>
inline T* EWSContext::alloc(size_t count)
{
	T* res = static_cast<T*>(alloc(sizeof(T)*count));
	if (!res)
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
	return new(alloc<T>()) T(std::forward<Args>(args)...);
}

}
