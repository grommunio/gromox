#pragma once
#include <memory>
#include <string>
#include <vector>
#include <gromox/single_list.hpp>

enum {
	MESSAGE_MESS = 2,
};

enum {
	MESSAGE_DEQUEUE_HOLDING,
};

struct CONFIG_FILE;

/* message struct for dequeuing from mail queue */
struct MESSAGE {
	int flush_ID = 0; /* flush_ID by smtp server */
	int bound_type = 0; /* BOUND_IN, BOUND_OUT, BOUND_RELAY ... */
	BOOL is_spam = false; /* is this a spam mail */
	int message_option = 0; /* tape message or mess message */
	int message_data = 0; /* tape position or mess ID*/
	char *begin_address = nullptr; /* message buffer address */
	size_t size = 0; /* size of allocated buffer */
	void *mail_begin = nullptr; /* mail begin address */
	size_t mail_length = 0; /* mail length */
	char *envelope_from = nullptr, *envelope_rcpt = nullptr;
};

extern void message_dequeue_init(const char *path, size_t max_memory);
extern int message_dequeue_run();
extern void message_dequeue_stop();
extern MESSAGE *message_dequeue_get();
extern void message_dequeue_put(MESSAGE *);
extern int message_dequeue_get_param(int param);
extern void message_dequeue_save(MESSAGE *);

extern void resource_init();
extern void resource_free();
extern int resource_run();
extern void resource_stop();

extern int system_services_run();
extern void system_services_stop();

extern void transporter_init(const char *path, std::vector<std::string> &&names, unsigned int threads_min, unsigned int threads_max, unsigned int free_num, unsigned int mime_ratio, bool ignerr);
extern int transporter_run();
extern void transporter_stop();
extern void transporter_wakeup_one_thread();
extern int transporter_unload_library(const char *);
extern int transporter_load_library(const char *);

extern std::shared_ptr<CONFIG_FILE> g_config_file;
