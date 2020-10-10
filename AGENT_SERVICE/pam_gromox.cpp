/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#define PAM_SM_AUTH 1
#include <cstring>
#include <memory>
#include <mutex>
#include <libHX/misc.h>
#include <security/pam_modules.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/tie.hpp>
#include "config_file.h"
#include "util.h"
#include "../EXCHANGE_SYSTEM/http/service.h"
#ifndef PAM_EXTERN
#	define PAM_EXTERN
#endif

using namespace gromox;

extern CONFIG_FILE *g_config_file;
CONFIG_FILE *g_config_file;
static std::mutex g_svc_once;
static const char *const g_dfl_svc_plugins[] = {
	"libgxsvc_ldap_adaptor.so",
	"libgxsvc_mysql_adaptor.so",
	"libgxsvc_authmgr.so",
	nullptr,
};

static int converse(pam_handle_t *pamh, int nargs,
    const struct pam_message **message, struct pam_response **resp)
{
	*resp = nullptr;
	struct pam_conv *conv;
	auto ret = pam_get_item(pamh, PAM_CONV, const_cast<const void **>(reinterpret_cast<void **>(&conv)));

	if (ret == PAM_SUCCESS && conv != nullptr && conv->conv != nullptr)
		ret = conv->conv(nargs, message, resp, conv->appdata_ptr);
	if (resp == nullptr || *resp == nullptr || (*resp)->resp == nullptr)
		ret = PAM_AUTH_ERR;
	return ret;
}

static int read_password(pam_handle_t *pamh, const char *prompt, char **pass)
{
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = nullptr;

	*pass = nullptr;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt != nullptr ? prompt : "Password: ";
	auto ret = converse(pamh, 1, &pmsg, &resp);
	if (ret == PAM_SUCCESS)
		*pass = strdup(resp->resp);
	return ret;
}

PAM_EXTERN GX_EXPORT int pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	auto cfg = config_file_init2(nullptr, PKGSYSCONFDIR "/pam.cfg");
	if (cfg == nullptr)
		return PAM_AUTH_ERR;
	auto cleanup_0 = make_scope_exit([&]() { config_file_free(cfg); });

	const char *username = nullptr;
	auto ret = pam_get_user(pamh, &username, nullptr);
	if (ret != PAM_SUCCESS || username == nullptr)
		return PAM_AUTH_ERR;

	const void *authtok_v = nullptr;
	ret = pam_get_item(pamh, PAM_AUTHTOK, &authtok_v);
	if (ret != PAM_SUCCESS) {
		printf("USUC\n");
		return PAM_AUTH_ERR;
	}
	struct stdlib_free { void operator()(void *p) { free(p); } };
	std::unique_ptr<char, stdlib_free> authtok;
	if (authtok_v != nullptr) {
		authtok.reset(strdup(static_cast<const char *>(authtok_v)));
	} else {
		printf("RP\n");
		ret = read_password(pamh, config_file_get_value(cfg, "pam_prompt"), &unique_tie(authtok));
		if (ret != PAM_SUCCESS)
			return ret;
	}

	const char *svc_plugin_path = config_file_get_value(cfg, "service_plugin_path");
	if (svc_plugin_path == nullptr)
		svc_plugin_path = PKGLIBDIR;
	struct strvecfree { void operator()(char **s) { HX_zvecfree(s); } };
	std::unique_ptr<char *[], strvecfree> pluglistbuf;
	const char *const *svc_plugin_list = nullptr;
	auto val = config_file_get_value(cfg, "service_plugin_list");
	if (val == nullptr) {
		svc_plugin_list = g_dfl_svc_plugins;
	} else {
		pluglistbuf.reset(read_file_by_line(val));
		if (pluglistbuf == nullptr)
			return PAM_AUTH_ERR;
		svc_plugin_list = pluglistbuf.get();
	}

	bool svcplug_ignerr = parse_bool(config_file_get_value(cfg, "service_plugin_ignore_errors"));
	const char *config_dir = val = config_file_get_value(cfg, "config_file_path");
	if (val == nullptr)
		config_dir = PKGSYSCONFDIR "/pam";

	std::lock_guard<std::mutex> holder(g_svc_once);
	service_init({"pam", svc_plugin_path, config_dir, "", "",
		svc_plugin_list, svcplug_ignerr, 1});
	if (service_run() != 0)
		return PAM_AUTH_ERR;
	auto cleanup_1 = make_scope_exit(service_stop);

	using login_t = BOOL (*)(const char *, const char *, char *, int);
	auto fptr_login = reinterpret_cast<login_t>(service_query("auth_login_smtp", "system"));
	if (fptr_login == nullptr)
		return PAM_AUTH_ERR;
	char reason[256];
	printf("%s, %s\n", username, authtok.get());
	return fptr_login(username, authtok.get(), reason, sizeof(reason)) != FALSE ?
	       PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN GX_EXPORT int pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	return PAM_SUCCESS;
}
