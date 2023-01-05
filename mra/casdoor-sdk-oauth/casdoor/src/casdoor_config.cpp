/*
 * Copyright 2022 The Casdoor Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CASDOOR_CONFIG_CPP
#define CASDOOR_CONFIG_CPP
//#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <iostream>
#include <vector>
#include "httplib/httplib.h"
#include "json/json.h"
#include "jwt-cpp/jwt.h"
#include "casdoor_user.h"
#include "casdoor_config.h"

/**
 * CasdoorConfig initializes a CasdoorConfig with a model file and a policy file.
 *
 * @param endpoint the URL of the Casdoor server.
 * @param client_id the Client ID for the Casdoor application.
 * @param client_secret the Client secret for the Casdoor application.
 * @param certificate the public key for the Casdoor application's cert.
 * @param org_name the name for the Casdoor organization.
 */
CasdoorConfig::CasdoorConfig(std::string endpoint, std::string client_id, std::string client_secret, std::string certificate, std::string org_name) : m_endpoint(endpoint), m_client_id(client_id), m_client_secret(client_secret), m_certificate(certificate), m_org_name(org_name) {};

std::string CasdoorConfig::GetOAuthLink(const std::string& redirect_uri, const std::string& state, const std::string& response_type="code", const std::string& scope="read") {
	Json::Value* p_root = new Json::Value("");

	std::string path = "/login/oauth/authorize?";
	path += "client_id=" + m_client_id;
	path += "&response_type=" + response_type;
	path += "&redirect_uri=" + redirect_uri;
	path += "&scope=" + scope;
	path += "&state=" + state;

	httplib::Client cli(m_endpoint.substr(7, m_endpoint.length() - 7));
	auto res = cli.Get(path.c_str());
	if (res->status != 200) {
		return "";
	}

	Json::Reader* p_reader = new Json::Reader();
	p_reader->parse(res->body, *p_root);

	return (* p_root)["url"].asString();
};

std::string CasdoorConfig::GetOAuthToken(const std::string& code) {
	Json::Value* p_root = new Json::Value("");

	std::string path = "/api/login/oauth/access_token?";
	path += "grant_type=" + m_grant_type;
	path += "&client_id=" + m_client_id;
	path += "&client_secret=" + m_client_secret;
	path += "&code=" + code;

	httplib::Client cli(m_endpoint.substr(7, m_endpoint.length() - 7));
	auto res = cli.Post(path.c_str());
	if (res->status != 200) {
		return "";
	}

	Json::Reader* p_reader = new Json::Reader();
	p_reader->parse(res->body, *p_root);

	return (*p_root)["access_token"].asString();
};

jwt::decoded_jwt<jwt::traits::kazuho_picojson> CasdoorConfig::ParseJwtToken(const std::string& token) {
    return jwt::decode(token);
};

Json::Value* CasdoorConfig::GetUsers() {
	Json::Value* p_root = new Json::Value("");

	std::string path = "/api/get-users?";
	path += "owner=" + m_org_name;
	path += "&clientId=" + m_client_id;
	path += "&clientSecret=" + m_client_secret;

	httplib::Client cli(m_endpoint.substr(7, m_endpoint.length()-7));
	auto res = cli.Get(path.c_str());
	if (res->status != 200) {
		return p_root;
	}

	Json::Reader* p_reader = new Json::Reader();
	p_reader->parse(res->body, *p_root);
	return p_root;
};

Json::Value* CasdoorConfig::GetUser(const std::string user_id) {
	Json::Value* p_root = new Json::Value("");

	std::string path = "/api/get-user?";
	path += "id=" + m_org_name + "/" + user_id;
	path += "&clientId=" + m_client_id;
	path += "&clientSecret=" + m_client_secret;

	httplib::Client cli(m_endpoint.substr(7, m_endpoint.length() - 7));
	auto res = cli.Get(path.c_str());
	if (res->status != 200) {
		return p_root;
	}

	Json::Reader* p_reader = new Json::Reader();
	p_reader->parse(res->body, *p_root);
	return p_root;
};

Json::Value* CasdoorConfig::ModifyUser(const std::string method, CasdoorUser user) {
	Json::Value* p_root = new Json::Value("");

	std::string path = "/api/" + method + "?";
	user.set_owner(m_org_name);
	path += "id=" + user.get_owner() + "/" + user.get_name();
	path += "&clientId=" + m_client_id;
	path += "&clientSecret=" + m_client_secret;

	httplib::Client cli(m_endpoint.substr(7, m_endpoint.length() - 7));
	auto res = cli.Post(path.c_str(), user.to_json_str(), "text/plain");
	if (res->status != 200) {
		return p_root;
	}

	Json::Reader* p_reader = new Json::Reader();
	p_reader->parse(res->body, *p_root);
	return p_root;
};

Json::Value* CasdoorConfig::AddUser(CasdoorUser user) {
	return ModifyUser("add-user", user);
};

Json::Value* CasdoorConfig::UpdateUser(CasdoorUser user) {
	return ModifyUser("update-user", user);
};

Json::Value* CasdoorConfig::DeleteUser(CasdoorUser user) {
	return ModifyUser("delete-user", user);
};

#endif
