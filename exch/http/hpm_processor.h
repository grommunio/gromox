#pragma once
#include <gromox/plugin.hpp>
#include <gromox/double_list.hpp>
#include <gromox/common_types.hpp>

#define HPM_RETRIEVE_ERROR					0
#define HPM_RETRIEVE_WRITE					1
#define HPM_RETRIEVE_NONE					2
#define HPM_RETRIEVE_WAIT					3
#define HPM_RETRIEVE_DONE					4
#define HPM_RETRIEVE_SOCKET					5

struct HTTP_CONTEXT;

struct HPM_INTERFACE {
	BOOL (*preproc)(int);
	BOOL (*proc)(int, const void*, uint64_t);
	int (*retr)(int);
	BOOL (*send)(int, const void*, int);
	int (*receive)(int, void*, int length);
	void (*term)(int);
};

struct HPM_PLUGIN {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST list_reference;
	HPM_INTERFACE interface;
	void *handle;
	PLUGIN_MAIN lib_main;
	TALK_MAIN talk_main;
	char file_name[256];
	bool completed_init;
};

extern void hpm_processor_init(int context_num, const char *plugins_path, const char *const *names, uint64_t cache_size, uint64_t max_size, bool ignerr);
extern int hpm_processor_run();
extern int hpm_processor_stop();
extern void hpm_processor_free();
int hpm_processor_console_talk(int argc, char **argv, char *result, int length);
BOOL hpm_processor_get_context(HTTP_CONTEXT *phttp);

void hpm_processor_put_context(HTTP_CONTEXT *phttp);

BOOL hpm_processor_check_context(HTTP_CONTEXT *phttp);

BOOL hpm_processor_write_request(HTTP_CONTEXT *phttp);

BOOL hpm_processor_check_end_of_request(HTTP_CONTEXT *phttp);

BOOL hpm_processor_proc(HTTP_CONTEXT *phttp);

int hpm_processor_retrieve_response(HTTP_CONTEXT *phttp);

BOOL hpm_processor_send(HTTP_CONTEXT *phttp,
	const void *pbuff, int length);

int hpm_processor_receive(HTTP_CONTEXT *phttp,
	char *pbuff, int length);
