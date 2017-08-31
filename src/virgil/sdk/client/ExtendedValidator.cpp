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

#include <virgil/sdk/client/ExtendedValidator.h>
#include <virgil/sdk/client/models/validation_rules/SelfValidationRule.h>
#include <virgil/sdk/client/models/validation_rules/VirgilValidationRule.h>
#include <virgil/sdk/client/models/validation_rules/WhitelistValidationRule.h>
#include <string>
using virgil::sdk::client::ExtendedValidator;
using virgil::sdk::client::models::validation_rules::SelfValidationRule;
using virgil::sdk::client::models::validation_rules::VirgilValidationRule;
using virgil::sdk::client::models::validation_rules::WhitelistValidationRule;

static_assert(!std::is_abstract<virgil::sdk::client::ExtendedValidator>(), "ExtendedValidator must not be abstract.");

static const std::string kServiceCardId = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";
static const std::string kServicePublicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAxa1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=";

ExtendedValidator::ExtendedValidator(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                     const std::list<SignerInfo> &whitelist,
                                     const bool &ignoreSelfSignature,
                                     const bool &ignoreVirgilSignature)
: whitelist_(whitelist), ignoreSelfSignature_(ignoreSelfSignature), ignoreVirgilSignature_(ignoreVirgilSignature) {}

void ExtendedValidator::initialize(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto) {
    rules_.clear();

    if (!ignoreSelfSignature_)
        rules_.push_back(std::make_shared<SelfValidationRule>());

    if (!ignoreVirgilSignature_) {
        auto virgilPublickey = crypto->importPublicKey(VirgilBase64::decode(kServicePublicKey));
        rules_.push_back(std::make_shared<VirgilValidationRule>(std::make_pair(kServiceCardId, virgilPublickey)));
    }

    if (whitelist_.size() > 0){
        std::unordered_map<std::string, PublicKeyInterface*> registeredVerifiers_;

        for (const auto& verifier : whitelist_)
            registeredVerifiers_[verifier.cardId()] = crypto->importPublicKey(VirgilBase64::decode(verifier.publicKey()));

        rules_.push_back(std::make_shared<WhitelistValidationRule>(registeredVerifiers_));
    }
}

bool ExtendedValidator::validateCard(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                     const interfaces::CardInterface &card) const {
    for (auto const& rule : rules_)
        if (!rule->check(crypto, card))
            return false;
    return true;
}
