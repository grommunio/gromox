// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <cstring>
#include <string>
#include <libHX/string.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>

using namespace std::string_literals;

namespace gromox {

ec_error_t cvt_essdn_to_username(const char *idn, const char *org,
    cvt_id2user id2user, std::string &username) try
{
	auto prefix = "/o="s + org + "/" + EAG_RCPTS "/cn=";
	if (strncasecmp(idn, prefix.c_str(), prefix.size()) != 0)
		return ecUnknownUser;
	auto len = strlen(idn);
	if (len < prefix.size() + 16 || idn[prefix.size()+16] != '-')
		return ecUnknownUser;
	auto local_part = &idn[prefix.size()+17];
	auto user_id = decode_hex_int(&idn[prefix.size()+8]);
	auto ret = id2user(user_id, username);
	if (ret != ecSuccess)
		return ret;
	auto pos = username.find('@');
	if (pos == username.npos ||
	    strncasecmp(username.c_str(), local_part, pos) != 0)
		return ecUnknownUser;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-5208: ENOMEM");
	return ecServerOOM;
}

ec_error_t cvt_essdn_to_username(const char *idn, const char *org,
    cvt_id2user id2user, char *username, size_t ulen)
{
	std::string es_result;
	auto ret = cvt_essdn_to_username(idn, org, id2user, es_result);
	if (ret == ecSuccess)
		gx_strlcpy(username, es_result.c_str(), ulen);
	return ret;
}

/**
 * ecNullObject is returned to signify that a situation was encountered that is
 * equivalent to addrtype not having been present in the first place.
 */
ec_error_t cvt_genaddr_to_smtpaddr(const char *addrtype, const char *emaddr,
    const char *org, cvt_id2user id2user, std::string &smtpaddr)
{
	if (strcasecmp(addrtype, "SMTP") == 0) {
		if (emaddr != nullptr)
			smtpaddr = emaddr;
		return emaddr != nullptr ? ecSuccess : ecNullObject;
	} else if (strcasecmp(addrtype, "EX") == 0) {
		if (emaddr == nullptr)
			return ecNullObject;
		return cvt_essdn_to_username(emaddr, org, id2user, smtpaddr);
	} else if (strcmp(addrtype, "0") == 0) {
		/*
		 * When MFCMAPI 21.2.21207.01 imports a .msg file, PR_SENT_*
		 * gets reset to this odd combo.
		 */
		return ecNullObject;
	}
	return ecUnknownUser;
}

ec_error_t cvt_genaddr_to_smtpaddr(const char *addrtype, const char *emaddr,
    const char *org, cvt_id2user id2user, char *smtpaddr, size_t slen)
{
	std::string es_result;
	auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr, org,
	           id2user, es_result);
	if (ret == ecSuccess)
		gx_strlcpy(smtpaddr, es_result.c_str(), slen);
	return ret;
}

bool emsab_to_email(EXT_PULL &ser, const char *org, cvt_id2user id2user,
    char *addr, size_t asize)
{
	EMSAB_ENTRYID eid;
	if (ser.g_abk_eid(&eid) != pack_result::success || eid.type != DT_MAILUSER)
		return false;
	return cvt_essdn_to_username(eid.px500dn, org, id2user, addr, asize) == ecSuccess;
}

}
