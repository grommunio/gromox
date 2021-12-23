// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <string>
#include <gromox/atomic.hpp>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include "engine.h"
#include "file_operation.h"
#include <gromox/gateway_control.h>
#include "data_source.h"
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std::string_literals;
using namespace gromox;

static gromox::atomic_bool g_notify_stop;
static pthread_t g_thread_id1;
static char g_domainlist_path[256];
static char g_aliasaddress_path[256];

static void *adap_thrwork(void *);

void engine_init(const char *domainlist_path, const char *aliasaddress_path)
{
	gx_strlcpy(g_domainlist_path, domainlist_path, arsizeof(g_domainlist_path));
	gx_strlcpy(g_aliasaddress_path, aliasaddress_path, arsizeof(g_aliasaddress_path));
}


int engine_run()
{
	g_notify_stop = false;
	auto ret = pthread_create(&g_thread_id1, nullptr, adap_thrwork, nullptr);
	if (ret != 0) {
		g_notify_stop = true;
		printf("[engine]: failed to create work thread: %s\n", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_thread_id1, "work/1");
	return 0;
}

void engine_trig()
{
	pthread_kill(g_thread_id1, SIGALRM);
}

void engine_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		pthread_kill(g_thread_id1, SIGALRM);
		pthread_join(g_thread_id1, NULL);
	}
}

static void *adap_thrwork(void *param)
{
	int fd, len;
	char temp_domain[257];
	char temp_line[1024];

	for (; !g_notify_stop; sleep(30)) {
		fprintf(stderr, "[engine]: starting data collection\n");
		std::vector<DOMAIN_ITEM> domain_list;
		std::vector<ALIAS_ITEM> alias_map;
		std::string temp_path;
	
		if (!data_source_get_domain_list(domain_list)) {
			continue;
		}
		try {
			temp_path = g_domainlist_path + ".tmp"s;
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1523: ENOMEM\n");
			continue;
		}
		fd = open(temp_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			continue;
		}
	
		for (const auto &e : domain_list) {
			len = gx_snprintf(temp_domain, arsizeof(temp_domain),
			      "%s\n", e.domainname.c_str());
			write(fd, temp_domain, len);
		}
		close(fd);

		if ( file_operation_compare(temp_path.c_str(), g_domainlist_path) != 0) {
			if (rename(temp_path.c_str(), g_domainlist_path) < 0)
				fprintf(stderr, "E-1402: rename %s %s: %s\n",
				        temp_path.c_str(), g_domainlist_path, strerror(errno));
			gateway_control_notify("libgxs_domain_list.so reload",
				NOTIFY_SMTP|NOTIFY_DELIVERY);
		}
		if (!data_source_get_alias_list(alias_map)) {
			continue;
		}
		
		try {
			temp_path = g_aliasaddress_path + ".tmp"s;
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1524: ENOMEM\n");
			continue;
		}
		fd = open(temp_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, DEF_MODE);
		if (-1 == fd) {
			continue;
		}
		
		for (const auto &e : alias_map) {
			len = gx_snprintf(temp_line, arsizeof(temp_line),
			      "%s\t%s\n", e.aliasname.c_str(), e.mainname.c_str());
			if (e.aliasname.find('@') != std::string::npos)
				write(fd, temp_line, len);
		}
		close(fd);
		if (file_operation_compare(temp_path.c_str(), g_aliasaddress_path) != 0) {
			if (rename(temp_path.c_str(), g_aliasaddress_path) < 0)
				fprintf(stderr, "E-1423: rename %s %s: %s\n",
				        temp_path.c_str(), g_aliasaddress_path, strerror(errno));
			gateway_control_notify("libgxm_alias_translator.so reload addresses",
				NOTIFY_DELIVERY);
		}
	}
	return NULL;
}
