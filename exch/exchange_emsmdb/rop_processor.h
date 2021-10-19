#pragma once
#include <cstdint>
#include <ctime>
#include "logon_object.h"
#include <gromox/mapi_types.hpp>
#define OBJECT_TYPE_NONE					0
#define OBJECT_TYPE_LOGON					1
#define OBJECT_TYPE_FOLDER					2
#define OBJECT_TYPE_MESSAGE					3
#define OBJECT_TYPE_ATTACHMENT				4
#define OBJECT_TYPE_TABLE					5
#define OBJECT_TYPE_STREAM					6
#define OBJECT_TYPE_FASTDOWNCTX				7
#define OBJECT_TYPE_FASTUPCTX				8
#define OBJECT_TYPE_ICSDOWNCTX				9
#define OBJECT_TYPE_ICSUPCTX				10
#define OBJECT_TYPE_SUBSCRIPTION			11

extern void *rop_processor_create_logmap();
void rop_processor_release_logmap(void *plogmap);
void rop_processor_init(int average_handles, int scan_interval);
extern int rop_processor_run();
extern void rop_processor_stop();
extern uint32_t rop_processor_proc(uint32_t flags, const uint8_t *in, uint32_t cb_in, uint8_t *out, uint32_t *cb_out);
int rop_processor_create_logon_item(void *plogmap,
	uint8_t logon_id, logon_object *plogon);
int rop_processor_add_object_handle(void *plogmap, uint8_t logon_id,
	int parent_handle, int type, void *pobject);
void* rop_processor_get_object(void *plogmap,
	uint8_t logon_id, uint32_t obj_handle, int *ptype);
template<typename T> T *rop_proc_get_obj(void *l, uint8_t id, uint32_t oh, int *ty) {
	return static_cast<T *>(rop_processor_get_object(l, id, oh, ty));
}
void rop_processor_release_object_handle(void *plogmap,
	uint8_t logon_id, uint32_t obj_handle);
extern logon_object *rop_processor_get_logon_object(void *logmap, uint8_t logon_id);
