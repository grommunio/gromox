// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <libHX/option.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/plugin.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static char *g_username, *g_domain;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'd', HXTYPE_STRING, &g_domain, nullptr, nullptr, 0, "Domain to operate on", "NAME"},
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username to operate on", "EMAILADDR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};
static constexpr static_module g_dfl_svc_plugins[] =
	{{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor}};

#define E(name, symbol) \
	auto fp_ ## name = reinterpret_cast<decltype(&mysql_adaptor_ ## name)>(service_query((symbol), "system", typeid(mysql_adaptor_ ## name))); \
	if ((fp_ ## name) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (symbol)); \
		return -1; \
	} \
	auto cl_ ## name = make_scope_exit([&]() { service_release((symbol), "system"); });

static int t_private()
{
	E(meta, "mysql_auth_meta");
	sql_meta_result mres;
	auto err = fp_meta(g_username, 0, mres);
	printf("meta: %s\n", err == 0 ? "OK" : strerror(errno));

	E(login2, "mysql_auth_login2");
	auto pass = znul(getenv("PASS"));
	std::string errstr;
	if (fp_login2(g_username, pass, mres.enc_passwd, errstr))
		printf("login2: OK\n");
	else
		printf("login2: %s\n", errstr.c_str());

	E(setpasswd, "set_password");
	printf("setpasswd: %s\n", fp_setpasswd(g_username, pass, pass) ? "OK" : "failed");

	E(get_username_from_id, "get_username_from_id");
	char buf[UADDR_SIZE];
	if (!fp_get_username_from_id(mres.user_id, buf, std::size(buf)))
		printf("get_username_from_id: failed\n");
	else
		printf("get_username_from_id: OK %s\n", buf);

	E(get_id_from_maildir, "get_id_from_maildir");
	unsigned int id = 0;
	if (!fp_get_id_from_maildir(mres.maildir.c_str(), &id))
		printf("get_id_from_maildir: failed\n");
	else if (id != mres.user_id)
		printf("get_id_from_maildir: userid switch %u->%u\n", mres.user_id, id);
	else
		printf("get_id_from_maildir: OK\n");

	E(get_user_ids, "get_user_ids");
	unsigned int orgid = 0;
	enum display_type dtypx{};
	if (!fp_get_user_ids(g_username, &id, &orgid, &dtypx))
		printf("get_user_ids: failed\n");
	else if (id != mres.user_id)
		printf("get_user_ids: exp %u got %u\n", mres.user_id, id);
	else
		printf("get_user_ids: OK\n");

	E(get_user_displayname, "get_user_displayname");
	if (fp_get_user_displayname(g_username, buf, std::size(buf)))
		printf("get_user_displayname: OK %s\n", buf);
	else
		printf("get_user_displayname: failed\n");

	E(get_user_privilege_bits, "get_user_privilege_bits");
	uint32_t priv = 0;
	if (fp_get_user_privilege_bits(g_username, &priv))
		printf("get_user_priv: OK 0x%x\n", priv);
	else
		printf("get_user_priv: failed\n");

	E(set_user_lang, "set_user_lang");
	printf("set_user_lang: %s\n", fp_set_user_lang(g_username, "en") ? "OK" : "failed");

	E(set_timezone, "set_timezone");
	printf("set_timezone: %s\n", fp_set_timezone(g_username, GROMOX_FALLBACK_TIMEZONE) ? "OK" : "failed");

	E(check_mlist_include, "check_mlist_include");
	printf("check_mlist_include: %s\n", fp_check_mlist_include(g_username, g_username) ? "self-ref" : "not incl");

	E(get_mlist_memb, "get_mlist_memb");
	int result = 0;
	std::vector<std::string> vs;
	if (!fp_get_mlist_memb(g_username, g_username, &result, vs))
		printf("get_mlist_memb: failed\n");
	else
		printf("get_mlist_memb: OK (result code %u) (%zu entries)\n", result, vs.size());

	E(get_user_aliases, "get_user_aliases");
	if (!fp_get_user_aliases(g_username, vs))
		printf("get_user_aliases: failed\n");
	else
		printf("get_user_aliases: OK (%zu aliases)\n", vs.size());

	E(get_user_properties, "get_user_properties");
	TPROPVAL_ARRAY tpa{};
	if (!fp_get_user_properties(g_username, tpa))
		printf("get_user_properties: failed\n");
	else
		printf("get_user_properties: OK (%u props)\n", tpa.count);

	E(scndstore_hints, "scndstore_hints");
	std::vector<sql_user> vu;
	err = fp_scndstore_hints(mres.user_id, vu);
	if (err != 0)
		printf("scndstore_hints: %s\n", strerror(err));
	else
		printf("scndstore_hints: OK (%zu stores)\n", vu.size());

	E(get_homeserver, "get_homeserver");
	std::pair<std::string, std::string> pairing;
	err = fp_get_homeserver(g_username, true, pairing);
	if (err != 0)
		printf("get_homeserver: %s\n", strerror(err));
	else
		printf("get_homeserver: OK, %s, public: %s\n",
			pairing.first.c_str(), pairing.second.c_str());

	return 0;
}

static int t_public()
{
	char buf[UDOM_SIZE];

	E(get_homedir, "get_homedir");
	if (!fp_get_homedir(g_domain, buf, std::size(buf)))
		printf("get_homedir: failed\n");
	else
		printf("get_homedir: OK %s\n", buf);

	E(get_domain_ids, "get_domain_ids");
	unsigned int domid = 0, orgid = 0;
	if (!fp_get_domain_ids(g_domain, &domid, &orgid))
		printf("get_domain_ids: failed\n");
	else
		printf("get_domain_ids: OK %u\n", domid);

	E(get_homedir_by_id, "get_homedir_by_id");
	if (!fp_get_homedir_by_id(domid, buf, std::size(buf)))
		printf("get_homedir_by_id: failed\n");
	else
		printf("get_homedir_by_id: OK %s\n", buf);

	E(get_id_from_homedir, "get_id_from_homedir");
	unsigned int id = 0;
	if (!fp_get_id_from_homedir(buf, &id))
		printf("get_id_from_homedir: failed\n");
	else if (id != domid)
		printf("get_id_from_homedir: exp %u got %u\n", domid, id);
	else
		printf("get_id_from_homedir: OK\n");

	E(get_org_domains, "get_org_domains");
	std::vector<unsigned int> vi;
	if (!fp_get_org_domains(orgid, vi))
		printf("get_org_domains: failed\n");
	else
		printf("get_org_domains: OK (%zu domains)\n", vi.size());

	E(get_domain_info, "get_domain_info");
	sql_domain dominfo;
	printf("get_domain_info: %s\n", fp_get_domain_info(domid, dominfo) ? "OK" : "failed");

	E(check_same_org, "check_same_org");
	printf("check_same_org: %s\n", fp_check_same_org(orgid, orgid) ? "OK" : "failed");

	E(get_domain_groups, "get_domain_groups");
	std::vector<sql_group> vg;
	if (!fp_get_domain_groups(domid, vg))
		printf("get_domain_groups: failed\n");
	else
		printf("get_domain_groups: OK (%zu groupd)\n", vg.size());

	E(get_group_users, "get_group_users");
	std::vector<sql_user> vu;
	if (!fp_get_group_users(1, vu))
		printf("get_group_users (grp 1): failed\n");
	else
		printf("get_group_users (grp 1): OK (%zu users)\n", vu.size());

	E(get_domain_users, "get_domain_users");
	if (!fp_get_domain_users(domid, vu))
		printf("get_domain_users: failed\n");
	else
		printf("get_domain_users: OK (%zu users)\n", vu.size());

	E(check_same_org2, "check_same_org2");
	printf("check_same_org2: %s\n", fp_check_same_org2(g_domain, g_domain) ? "OK" : "failed");

	E(domain_list_query, "domain_list_query"); // "is locally handled?"
	printf("domain_list_query: %s\n", fp_domain_list_query(g_domain) ? "OK" : "no");
	return -1;
}
/*
*/
#undef E

int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	service_init({nullptr, g_dfl_svc_plugins, 1});
	auto cl_1 = make_scope_exit(service_stop);
	if (service_run_early() != 0 || service_run() != 0) {
		fprintf(stderr, "service_run failed\n");
		return EXIT_FAILURE;
	}

	mlog_init("udb", nullptr, LV_DEBUG);
	if (g_username != nullptr && t_private() != 0)
		return EXIT_FAILURE;
	if (g_domain != nullptr && t_public() != 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
