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

#ifndef CASDOOR_USER_CPP
#define CASDOOR_USER_CPP

#include <iostream>
#include <string>
#include <vector>
#include "casdoor_user.h"

CasdoorUser::CasdoorUser() {
    m_address = { "string" };
    m_affiliation = "string";
    m_avatar = "string";
    m_createdTime = "string";
    m_dingtalk = "string";
    m_displayName = "string";
    m_email = "string";
    m_facebook = "string";
    m_gitee = "string";
    m_github = "string";
    m_google = "string";
    m_hash = "string";
    m_id = "string";
    m_isAdmin = true;
    m_isForbidden = true;
    m_isGlobalAdmin = true;
    m_language = "string";
    m_name = "string";
    m_owner = "string";
    m_password = "string";
    m_phone = "string";
    m_preHash = "string";
    m_qq = "string";
    m_score = 0;
    m_signupApplication = "string";
    m_tag = "string";
    m_type = "string";
    m_updatedTime = "string";
    m_wechat = "string";
    m_weibo = "string";
};

std::string CasdoorUser::to_json_str() {
    std::string str_address = "[";
    for (int i = 0; i < m_address.size(); i++) {
        if (i > 0) {
            str_address += R"(", )";
        }
        str_address += '"' + m_address[i] + '"';
    }
    str_address += "]";

    std::string str_isAdmin = m_isAdmin ? "true" : "false";
    std::string str_isForbidden = m_isForbidden ? "true" : "false";
    std::string str_isGlobalAdmin = m_isGlobalAdmin ? "true" : "false";

    std::string str_json = "{";
    str_json += R"("address": )" + str_address + R"(, )";
    str_json += R"("affiliation": ")" + m_affiliation + R"(", )";
    str_json += R"("avatar": ")" + m_avatar + R"(", )";
    str_json += R"("createdTime": ")" + m_createdTime + R"(", )";
    str_json += R"("dingtalk": ")" + m_dingtalk + R"(", )";
    str_json += R"("displayName": ")" + m_displayName + R"(", )";
    str_json += R"("email": ")" + m_email + R"(", )";
    str_json += R"("facebook": ")" + m_facebook + R"(", )";
    str_json += R"("gitee": ")" + m_gitee + R"(", )";
    str_json += R"("github": ")" + m_github + R"(", )";
    str_json += R"("google": ")" + m_google + R"(", )";
    str_json += R"("hash": ")" + m_hash + R"(", )";
    str_json += R"("id": ")" + m_id + R"(", )";
    str_json += R"("isAdmin": )" + str_isAdmin + R"(, )";
    str_json += R"("isForbidden": )" + str_isForbidden + R"(, )";
    str_json += R"("isGlobalAdmin": )" + str_isGlobalAdmin + R"(, )";
    str_json += R"("language": ")" + m_language + R"(", )";
    str_json += R"("name": ")" + m_name + R"(", )";
    str_json += R"("owner": ")" + m_owner + R"(", )";
    str_json += R"("password": ")" + m_password + R"(", )";
    str_json += R"("phone": ")" + m_phone + R"(", )";
    str_json += R"("preHash": ")" + m_preHash + R"(", )";
    str_json += R"("qq": ")" + m_qq + R"(", )";
    str_json += R"("score": )" + std::to_string(m_score) + R"(, )";
    str_json += R"("signupApplication": ")" + m_signupApplication + R"(", )";
    str_json += R"("tag": ")" + m_tag + R"(", )";
    str_json += R"("type": ")" + m_type + R"(", )";
    str_json += R"("updatedTime": ")" + m_updatedTime + R"(", )";
    str_json += R"("wechat": ")" + m_wechat + R"(", )";
    str_json += R"("weibo": ")" + m_weibo + R"("})";

    return str_json;
};

#endif
