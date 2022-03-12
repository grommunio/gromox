#pragma once
#include <gromox/mail.hpp>
#include <gromox/plugin.hpp>
#include "message_dequeue.h"

extern void transporter_init(const char *path, const char *const *names, unsigned int threads_min, unsigned int threads_max, unsigned int free_num, unsigned int mime_ratio, bool ignerr);
extern int transporter_run();
extern void transporter_stop();
extern void transporter_wakeup_one_thread();
int transporter_unload_library(const char* path);
int transporter_load_library(const char* path);
