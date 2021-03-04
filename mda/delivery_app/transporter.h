#pragma once
#include "message_dequeue.h"
#include <gromox/plugin.hpp>
#include <gromox/mail.hpp>

enum{
	TRANSPORTER_MIN_THREADS,
	TRANSPORTER_MAX_THREADS,
	TRANSPORTER_CREATED_THREADS
};

extern void transporter_init(const char *path, const char *const *names,
	int threads_min, int threads_max, int free_num, int mime_ratio, BOOL dm_valid,
	bool ignerr);
extern int transporter_run();
extern int transporter_stop();
extern void transporter_free();
extern void transporter_wakeup_one_thread();
int transporter_unload_library(const char* path);

int transporter_load_library(const char* path);

int transporter_console_talk(int argc, char** argv, char *result, int length);
int transporter_get_param(int param);

void transporter_validate_domainlist(BOOL b_valid);
extern BOOL transporter_domainlist_valid();
