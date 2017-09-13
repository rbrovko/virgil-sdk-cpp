/**
 * Copyright (C) 2017 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <catch.hpp>

#include <TestConst.h>
#include <fstream>
#include <nlohman/json.hpp>

using virgil::sdk::test::TestConst;
using json = nlohmann::json;

TestConst::TestConst(const std::string &fileName, bool enableStg) {
    std::ifstream input(fileName);

    std::string str((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());

    if (str.empty())
        std::cout << "asdasdasd" << std::endl;
    else {
        auto j = json::parse(str);

        json dict = enableStg ? j["staging"] : j["prod"];

        cardsServiceURL_               = dict["cardsServiceURL"];
        cardsServiceROURL_             = dict["cardsServiceROURL"];
        applicationToken_              = dict["applicationToken"];
        applicationPublicKeyBase64_    = dict["applicationPublicKeyBase64"];
        applicationPrivateKeyBase64_   = dict["applicationPrivateKeyBase64"];
        applicationPrivateKeyPassword_ = dict["applicationPrivateKeyPassword"];
        applicationIdentityType_       = dict["applicationIdentityType"];
        applicationId_                 = dict["applicationId"];
    }
    input.close();
}

const std::string& TestConst::cardsServiceURL() const { return cardsServiceURL_; }

const std::string& TestConst::cardsServiceROURL() const { return cardsServiceROURL_; }

const std::string& TestConst::applicationToken() const { return applicationToken_; }

const std::string& TestConst::applicationPrivateKeyBase64() const { return applicationPrivateKeyBase64_; }

const std::string& TestConst::applicationPrivateKeyPassword() const { return applicationPrivateKeyPassword_; }

const std::string& TestConst::applicationIdentityType() const { return applicationIdentityType_; }

const std::string& TestConst::applicationId() const { return applicationId_; }

const std::string& TestConst::applicationPublicKeyBase64() const {
    /*  Getting Public appkey from private one
     crypto::Crypto crypto_;

     auto privateAppKeyData = VirgilBase64::decode(this->applicationPrivateKeyBase64());
     auto appPrivateKey = crypto_.importPrivateKey(privateAppKeyData, this->applicationPrivateKeyPassword());

     auto appPublicKey = crypto_.extractPublicKeyFromPrivateKey(appPrivateKey);
     return VirgilBase64::encode(crypto_.exportPublicKey(appPublicKey));
     */
    return applicationPublicKeyBase64_;
}
