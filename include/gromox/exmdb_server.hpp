#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>

enum { /* exmdb_server_build_env flags */
	EM_LOCAL = 0x1,
	EM_PRIVATE = 0x2,
};

extern void (*exmdb_server_event_proc)(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify);

extern int exmdb_server_run();
extern void exmdb_server_build_env(unsigned int flags, const char *dir);
extern void exmdb_server_free_environment();
void exmdb_server_set_remote_id(const char *remote_id);
extern const char *exmdb_server_get_remote_id();
void exmdb_server_set_public_username(const char *username);
extern const char *exmdb_server_get_public_username();
extern ALLOC_CONTEXT *exmdb_server_get_alloc_context();
extern bool exmdb_server_is_private();
extern const char *exmdb_server_get_dir();
void exmdb_server_set_dir(const char *dir);
extern int exmdb_server_get_account_id();
extern const GUID *exmdb_server_get_handle();
void exmdb_server_register_proc(void *pproc);

#define IDLOUT
#define EXMIDL(n, p) extern BOOL exmdb_server_ ## n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT

extern void *instance_read_cid_content(uint64_t cid, uint32_t *plen, uint32_t tag);
extern int instance_get_message_body(MESSAGE_CONTENT *, unsigned int tag, unsigned int cpid, TPROPVAL_ARRAY *);

extern unsigned int g_dbg_synth_content;
extern unsigned int exmdb_body_autosynthesis;
extern unsigned int exmdb_pf_read_per_user, exmdb_pf_read_states;
