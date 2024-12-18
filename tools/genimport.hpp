#pragma once
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>

enum {
	GXMT_FOLDER = static_cast<unsigned int>(MAPI_FOLDER),
	GXMT_MESSAGE = static_cast<unsigned int>(MAPI_MESSAGE),
	GXMT_NAMEDPROP = 250,
};

struct PERMISSION_DATA;
class YError final : public std::exception {
	public:
	YError(const std::string &);
	YError(std::string &&);
	YError(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
	virtual const char *what() const noexcept { return m_str.c_str(); }

	protected:
	std::string m_str;
};

struct gi_delete : public gromox::stdlib_delete {
	using gromox::stdlib_delete::operator();
	inline void operator()(ATTACHMENT_CONTENT *x) const { attachment_content_free(x); }
	inline void operator()(BINARY *x) const { rop_util_free_binary(x); }
	inline void operator()(TARRAY_SET *x) const { tarray_set_free(x); }
};

using gi_name_map = std::unordered_map<gromox::proptag_t, PROPERTY_XNAME>;
struct namedprop_bimap;

struct parent_desc {
	/* Here, MAPI_STORE is used to mean "unset" */
	enum mapi_object_type type = MAPI_STORE;
	union {
		void *unknown = nullptr;
		uint64_t folder_id;
		MESSAGE_CONTENT *message;
		ATTACHMENT_CONTENT *attach;
	};
	namedprop_bimap *names = nullptr;

	static inline parent_desc as_msg(MESSAGE_CONTENT *m)
	{
		parent_desc d{MAPI_MESSAGE};
		d.message = m;
		return d;
	}
	static inline parent_desc as_attach(ATTACHMENT_CONTENT *a)
	{
		parent_desc d{MAPI_ATTACH};
		d.attach = a;
		return d;
	}
	static inline parent_desc as_folder(uint64_t id)
	{
		parent_desc d{MAPI_FOLDER};
		d.folder_id = id;
		return d;
	}
};

struct tgt_folder {
	bool create = false;
	uint64_t fid_to = 0;
	std::string create_name;
};

using attachment_content_ptr = std::unique_ptr<ATTACHMENT_CONTENT, gi_delete>;
using gi_folder_map_t = std::unordered_map<uint32_t, tgt_folder>;
using message_content_ptr = std::unique_ptr<MESSAGE_CONTENT, gromox::mc_delete>;
using propname_array_ptr = std::unique_ptr<PROPNAME_ARRAY, gi_delete>;
using tarray_set_ptr = std::unique_ptr<TARRAY_SET, gi_delete>;

enum {
	DELIVERY_TWOSTEP = 0x8000U,
	DELIVERY_MRAUTOPROC = 0x10000U,
};

extern std::string g_dstuser, g_storedir_s;
extern const char *g_storedir;
extern unsigned int g_user_id, g_wet_run;
extern unsigned int g_public_folder, g_verbose_create;

extern void gi_dump_folder_map(const gi_folder_map_t &);
extern void gi_dump_name_map(const gi_name_map &);
extern void gi_folder_map_read(const void *, size_t, gi_folder_map_t &);
extern void gi_folder_map_write(const gi_folder_map_t &);
extern void gi_name_map_read(const void *, size_t, gi_name_map &);
extern void gi_name_map_write(const gi_name_map &);
extern gromox::propid_t gi_resolve_namedprop(const PROPERTY_XNAME &);
extern int exm_set_change_keys(TPROPVAL_ARRAY *props, eid_t cn);
extern int exm_create_folder(uint64_t parent_fld, TPROPVAL_ARRAY *props, bool o_excl, uint64_t *new_fld_id);
extern int exm_permissions(eid_t, const std::vector<PERMISSION_DATA> &);
extern int exm_deliver_msg(const char *target, MESSAGE_CONTENT *, unsigned int flags = 0);
extern int exm_create_msg(uint64_t parent_fld, MESSAGE_CONTENT *);
extern int gi_setup_from_user(const char *);
extern int gi_setup_from_dir(const char *);
extern int gi_startup_client(unsigned int maxconn = 1);
extern eid_t gi_lookup_eid_by_name(const char *dir, const char *name);
extern void gi_shutdown();
