#pragma once
#include <string>
#include <gromox/mysql_adaptor.hpp>

namespace gromox::oxdisco {
class OxdiscoPlugin {
	public:
	OxdiscoPlugin();

	BOOL proc(int, const void*, uint64_t);
	static BOOL preproc(int);

	struct _mysql {
		_mysql();

		decltype(mysql_adaptor_get_user_displayname) *get_user_displayname;
		decltype(mysql_adaptor_get_user_ids) *get_user_ids;
	} mysql; // mysql adaptor function pointers

	private:
	tinyxml2::XMLDocument respdoc;
	std::string x500_org_name;
	uint server_id; // Hash of the name of the mail server
	std::string RedirectAddr; // Domain to perform Autodiscover
	std::string RedirectUrl; // URL for a subsequent Autodiscover request
	int user_id;
	int domain_id;
	int request_logging = 0; // 0 = none, 1 = request data
	int response_logging = 0; // 0 = none, 1 = response data
	int pretty_response = 0; // 0 = compact output, 1 = pretty printed response

	void loadConfig();
	void writeheader(int, int, size_t);
	BOOL die(int, const char *, const char *);
	BOOL resp(int, const char *, const char *);
	void resp_pub(tinyxml2::XMLElement *, const char *);
	void resp_web(tinyxml2::XMLElement *, const char *);
	void resp_eas(tinyxml2::XMLElement *, const char *);
	tinyxml2::XMLElement *add_child(tinyxml2::XMLElement *, const char *, const char *);
	tinyxml2::XMLElement *add_child(tinyxml2::XMLElement *, const char *, const std::string &);
	const char *gtx(tinyxml2::XMLElement &, const char *);
	const char *get_redirect_addr(const char *);
	BOOL username_to_essdn(const char *username, char *dn, size_t);

};

}
