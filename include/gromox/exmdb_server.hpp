#pragma once 
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>

enum { /* exmdb_server_build_env flags */
	EM_LOCAL = 0x1,
	EM_PRIVATE = 0x2,
};

struct message_content;

namespace exmdb_server {

extern void build_env(unsigned int flags, const char *dir);
extern void free_env();
extern void set_remote_id(const char *);
extern const char *get_remote_id();
extern void set_public_username(const char *);
extern const char *get_public_username();
extern ALLOC_CONTEXT *get_alloc_context();
extern bool is_private();
extern const char *get_dir();
extern void set_dir(const char *);
extern unsigned int get_account_id();
extern const GUID *get_handle();

/*
 * presently using void* to silence
 *
 * service: type mismatch on dlname "exmdb_client_register_proc" (FvPFvPKcljPK9DB_NOTIFYEE VS FvPvE)
 */
extern void register_proc(void *);
extern void event_proc(const char *dir, BOOL is_table, uint32_t notify_id, const DB_NOTIFY *);

#define IDLOUT
#define EXMIDL(n, p) extern EXMIDL_RETTYPE n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT

}

extern void *instance_read_cid_content(const char *cid, uint32_t *plen, uint32_t tag);
extern int instance_get_message_body(message_content *, unsigned int tag, cpid_t, TPROPVAL_ARRAY *);

extern unsigned int g_dbg_synth_content;
extern unsigned int exmdb_body_autosynthesis;
extern unsigned int exmdb_pf_read_per_user, exmdb_pf_read_states;
