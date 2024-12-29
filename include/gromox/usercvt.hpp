#pragma once
#include <functional>
#include <string>
#include <gromox/common_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/mapi_types.hpp>

struct BINARY;
struct EXT_PULL;

namespace gromox {

using cvt_id2user = ec_error_t (*)(unsigned int, std::string &);
extern GX_EXPORT ec_error_t cvt_essdn_to_username(const char *emaddr, const char *org, cvt_id2user, std::string &);
extern GX_EXPORT ec_error_t cvt_essdn_to_username(const char *emaddr, const char *org, cvt_id2user, char *, size_t);
extern GX_EXPORT ec_error_t cvt_genaddr_to_smtpaddr(const char *atype, const char *emaddr, const char *org, cvt_id2user, std::string &);
extern GX_EXPORT ec_error_t cvt_genaddr_to_smtpaddr(const char *atype, const char *emaddr, const char *org, cvt_id2user, char *, size_t);
/* Only muidEMSAB entryids */
extern GX_EXPORT ec_error_t cvt_emsab_to_essdn(const BINARY *, std::string &);
/* Multiple types of entryids */
extern GX_EXPORT ec_error_t cvt_entryid_to_smtpaddr(const BINARY *, const char *org, cvt_id2user, std::string &);
extern GX_EXPORT ec_error_t cvt_username_to_essdn(const char *username, const char *org, unsigned int uid, unsigned int domid, std::string &);
extern GX_EXPORT ec_error_t cvt_username_to_essdn(const char *username, const char *org, GET_USER_IDS, GET_DOMAIN_IDS, std::string &);
extern GX_EXPORT ec_error_t cvt_username_to_abkeid(const char *username, const char *org, enum display_type, GET_USER_IDS, GET_DOMAIN_IDS, std::string &);
extern GX_EXPORT ec_error_t cvt_username_to_mailboxid(const char *username, unsigned int id, std::string &);
extern GX_EXPORT ec_error_t cvt_username_to_serverdn(const char *username, const char *org, unsigned int id, std::string &);
extern GX_EXPORT ec_error_t cvt_username_to_mdbdn(const char *username, const char *org, unsigned int id, std::string &);
extern GX_EXPORT const char *cvt_serverdn_to_domain(const char *essdn, const char *org);

}
