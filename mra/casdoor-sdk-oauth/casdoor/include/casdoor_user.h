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

#ifndef CASDOOR_CPP_SDK_CASDOOR_USER
#define CASDOOR_CPP_SDK_CASDOOR_USER

#include <iostream>
#include <vector>

class CasdoorUser {
private:
    std::vector<std::string> m_address;
    std::string m_affiliation;
    std::string m_avatar;
    std::string m_createdTime;
    std::string m_dingtalk;
    std::string m_displayName;
    std::string m_email;
    std::string m_facebook;
    std::string m_gitee;
    std::string m_github;
    std::string m_google;
    std::string m_hash;
    std::string m_id;
    bool m_isAdmin;
    bool m_isForbidden;
    bool m_isGlobalAdmin;
    std::string m_language;
    std::string m_name;
    std::string m_owner;
    std::string m_password;
    std::string m_phone;
    std::string m_preHash;
    std::string m_qq;
    int m_score;
    std::string m_signupApplication;
    std::string m_tag;
    std::string m_type;
    std::string m_updatedTime;
    std::string m_wechat;
    std::string m_weibo;
public:
    CasdoorUser();

    inline std::string get_owner() { return m_owner; };
    inline void set_owner(const std::string& owner) { m_owner = owner; };
    inline std::string get_name() { return m_name; };
    inline void set_name(const std::string& name) { m_name = name; };

    std::string to_json_str();
};

#endif
