// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/plugin.hpp>
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

static int t_private()
{
	sql_meta_result mres;
	auto err = mysql_adaptor_meta(g_username, 0, mres);
	printf("meta: %s\n", err == 0 ? "OK" : strerror(errno));

	auto pass = znul(getenv("PASS"));
	std::string errstr;
	if (mysql_adaptor_login2(g_username, pass, mres.enc_passwd, errstr))
		printf("login2: OK\n");
	else
		printf("login2: %s\n", errstr.c_str());

	printf("setpasswd: %s\n", mysql_adaptor_setpasswd(g_username, pass, pass) ? "OK" : "failed");

	std::string ubuf;
	auto ret = mysql_adaptor_userid_to_name(mres.user_id, ubuf);
	if (ret != ecSuccess)
		printf("get_username_from_id: %s\n", mapi_strerror(ret));
	else
		printf("get_username_from_id: OK %s\n", ubuf.c_str());

	unsigned int id = 0;
	if (!mysql_adaptor_get_id_from_maildir(mres.maildir.c_str(), &id))
		printf("get_id_from_maildir: failed\n");
	else if (id != mres.user_id)
		printf("get_id_from_maildir: userid switch %u->%u\n", mres.user_id, id);
	else
		printf("get_id_from_maildir: OK\n");

	unsigned int orgid = 0;
	enum display_type dtypx{};
	if (!mysql_adaptor_get_user_ids(g_username, &id, &orgid, &dtypx))
		printf("get_user_ids: failed\n");
	else if (id != mres.user_id)
		printf("get_user_ids: exp %u got %u\n", mres.user_id, id);
	else
		printf("get_user_ids: OK\n");

	char buf[UADDR_SIZE];
	if (mysql_adaptor_get_user_displayname(g_username, buf, std::size(buf)))
		printf("get_user_displayname: OK %s\n", buf);
	else
		printf("get_user_displayname: failed\n");

	uint32_t priv = 0;
	if (mysql_adaptor_get_user_privilege_bits(g_username, &priv))
		printf("get_user_priv: OK 0x%x\n", priv);
	else
		printf("get_user_priv: failed\n");

	printf("set_user_lang: %s\n", mysql_adaptor_set_user_lang(g_username, "en") ? "OK" : "failed");

	printf("set_timezone: %s\n", mysql_adaptor_set_timezone(g_username, GROMOX_FALLBACK_TIMEZONE) ? "OK" : "failed");

	printf("check_mlist_include: %s\n", mysql_adaptor_check_mlist_include(g_username, g_username) ? "self-ref" : "not incl");

	int result = 0;
	std::vector<std::string> vs;
	if (!mysql_adaptor_get_mlist_memb(g_username, g_username, &result, vs))
		printf("get_mlist_memb: failed\n");
	else
		printf("get_mlist_memb: OK (result code %u) (%zu entries)\n", result, vs.size());

	if (!mysql_adaptor_get_user_aliases(g_username, vs))
		printf("get_user_aliases: failed\n");
	else
		printf("get_user_aliases: OK (%zu aliases)\n", vs.size());

	TPROPVAL_ARRAY tpa{};
	if (!mysql_adaptor_get_user_properties(g_username, tpa))
		printf("get_user_properties: failed\n");
	else
		printf("get_user_properties: OK (%u props)\n", tpa.count);

	std::vector<sql_user> vu;
	err = mysql_adaptor_scndstore_hints(mres.user_id, vu);
	if (err != 0)
		printf("scndstore_hints: %s\n", strerror(err));
	else
		printf("scndstore_hints: OK (%zu stores)\n", vu.size());

	std::pair<std::string, std::string> pairing;
	err = mysql_adaptor_get_homeserver(g_username, true, pairing);
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

	if (!mysql_adaptor_get_homedir(g_domain, buf, std::size(buf)))
		printf("get_homedir: failed\n");
	else
		printf("get_homedir: OK %s\n", buf);

	unsigned int domid = 0, orgid = 0;
	if (!mysql_adaptor_get_domain_ids(g_domain, &domid, &orgid))
		printf("get_domain_ids: failed\n");
	else
		printf("get_domain_ids: OK %u\n", domid);

	if (!mysql_adaptor_get_homedir_by_id(domid, buf, std::size(buf)))
		printf("get_homedir_by_id: failed\n");
	else
		printf("get_homedir_by_id: OK %s\n", buf);

	unsigned int id = 0;
	if (!mysql_adaptor_get_id_from_homedir(buf, &id))
		printf("get_id_from_homedir: failed\n");
	else if (id != domid)
		printf("get_id_from_homedir: exp %u got %u\n", domid, id);
	else
		printf("get_id_from_homedir: OK\n");

	std::vector<unsigned int> vi;
	if (!mysql_adaptor_get_org_domains(orgid, vi))
		printf("get_org_domains: failed\n");
	else
		printf("get_org_domains: OK (%zu domains)\n", vi.size());

	sql_domain dominfo;
	printf("get_domain_info: %s\n", mysql_adaptor_get_domain_info(domid, dominfo) ? "OK" : "failed");

	printf("check_same_org: %s\n", mysql_adaptor_check_same_org(orgid, orgid) ? "OK" : "failed");

	std::vector<sql_group> vg;
	if (!mysql_adaptor_get_domain_groups(domid, vg))
		printf("get_domain_groups: failed\n");
	else
		printf("get_domain_groups: OK (%zu groupd)\n", vg.size());

	std::vector<sql_user> vu;
	if (!mysql_adaptor_get_group_users(1, vu))
		printf("get_group_users (grp 1): failed\n");
	else
		printf("get_group_users (grp 1): OK (%zu users)\n", vu.size());

	if (!mysql_adaptor_get_domain_users(domid, vu))
		printf("get_domain_users: failed\n");
	else
		printf("get_domain_users: OK (%zu users)\n", vu.size());

	printf("check_same_org2: %s\n", mysql_adaptor_check_same_org2(g_domain, g_domain) ? "OK" : "failed");

	printf("domain_list_query: %s\n", mysql_adaptor_domain_list_query(g_domain) ? "OK" : "no");
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
	auto cl_1 = HX::make_scope_exit(service_stop);
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
