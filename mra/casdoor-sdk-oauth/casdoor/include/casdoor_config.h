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

#ifndef CASDOOR_CPP_SDK_CASDOOR_CONFIG
#define CASDOOR_CPP_SDK_CASDOOR_CONFIG
//#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <iostream>
#include <vector>
#include "json/json.h"
#include "jwt-cpp/jwt.h"
#include "casdoor_user.h"

class CasdoorConfig {
private:
	std::string m_endpoint;
	std::string m_client_id;
	std::string m_client_secret;
	std::string m_certificate;
	std::string m_org_name;
	std::string m_app_name;
	std::string m_grant_type = "authorization_code";

public:
	/**
	 * CasdoorConfig initializes a CasdoorConfig with a model file and a policy file.
	 *
	 * @param endpoint the URL of the Casdoor server.
	 * @param client_id the Client ID for the Casdoor application.
	 * @param client_secret the Client secret for the Casdoor application.
	 * @param certificate the public key for the Casdoor application's cert.
	 * @param org_name the name for the Casdoor organization.
	 */
	CasdoorConfig(std::string endpoint, std::string client_id, std::string client_secret, std::string certificate, std::string org_name);

    std::string GetOAuthLink(const std::string& redirect_uri, const std::string& state, const std::string& response_type, const std::string& scope);

	std::string GetOAuthToken(const std::string& code);

    jwt::decoded_jwt<jwt::traits::kazuho_picojson> ParseJwtToken(const std::string& token);

	Json::Value* GetUsers();

	Json::Value* GetUser(const std::string user_id);

	Json::Value* ModifyUser(const std::string method, CasdoorUser user);

	Json::Value* AddUser(CasdoorUser user);

	Json::Value* UpdateUser(CasdoorUser user);

	Json::Value* DeleteUser(CasdoorUser user);

    inline std::string getEndPoint() {return m_endpoint;}

    inline std::string getClientId() {return m_client_id;}

    inline std::string getCertificate() {return m_certificate;}

    inline std::string getOrgName() {return m_org_name;}

    inline std::string getAppName() {return m_app_name;}

    inline std::string getGrantType() {return m_grant_type;}
};

#endif
