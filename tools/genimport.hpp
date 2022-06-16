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
	inline void operator()(MESSAGE_CONTENT *x) const { message_content_free(x); }
	inline void operator()(TARRAY_SET *x) const { tarray_set_free(x); }
};

using gi_name_map = std::unordered_map<uint32_t, PROPERTY_XNAME>;

struct parent_desc {
	/* Here, MAPI_STORE is used to mean "unset" */
	enum mapi_object_type type = MAPI_STORE;
	union {
		void *unknown = nullptr;
		uint64_t folder_id;
		MESSAGE_CONTENT *message;
		ATTACHMENT_CONTENT *attach;
	};

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
using message_content_ptr = std::unique_ptr<MESSAGE_CONTENT, gi_delete>;
using propname_array_ptr = std::unique_ptr<PROPNAME_ARRAY, gi_delete>;
using tarray_set_ptr = std::unique_ptr<TARRAY_SET, gi_delete>;

extern const char *g_storedir;
extern unsigned int g_user_id, g_show_tree, g_show_props, g_wet_run, g_public_folder;

extern void tree(unsigned int d);
extern void tlog(const char *f, ...) __attribute__((format(printf, 1, 2)));
extern void gi_dump_tpropval_a(unsigned int depth, const TPROPVAL_ARRAY &);
extern void gi_dump_tarray_set(unsigned int depth, const tarray_set &);
extern void gi_dump_msgctnt(unsigned int depth, const MESSAGE_CONTENT &);
extern void gi_dump_folder_map(const gi_folder_map_t &);
extern void gi_dump_name_map(const gi_name_map &);
extern void gi_folder_map_read(const void *, size_t, gi_folder_map_t &);
extern void gi_folder_map_write(const gi_folder_map_t &);
extern void gi_name_map_read(const void *, size_t, gi_name_map &);
extern void gi_name_map_write(const gi_name_map &);
extern uint16_t gi_resolve_namedprop(const PROPERTY_XNAME &);
extern int exm_set_change_keys(TPROPVAL_ARRAY *props, uint64_t cn);
extern int exm_create_folder(uint64_t parent_fld, TPROPVAL_ARRAY *props, bool o_excl, uint64_t *new_fld_id);
extern int exm_permissions(eid_t, const std::vector<PERMISSION_DATA> &);
extern int exm_deliver_msg(const char *target, MESSAGE_CONTENT *);
extern int exm_create_msg(uint64_t parent_fld, MESSAGE_CONTENT *);
extern void gi_setup_early(const char *dstmbox);
extern int gi_setup();
extern void gi_shutdown();
