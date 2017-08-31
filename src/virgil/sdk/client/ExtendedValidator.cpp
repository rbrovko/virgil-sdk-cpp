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
#include <virgil/sdk/client/models/policies/SelfIntegrityPolicy.h>
#include <virgil/sdk/client/models/policies/VirgilIntegrityPolicy.h>
#include <virgil/sdk/client/models/policies/ApplicationIntegrityPolicy.h>
#include <string>
using virgil::sdk::client::ExtendedValidator;
using virgil::sdk::client::models::policies::SelfIntegrityPolicy;
using virgil::sdk::client::models::policies::VirgilIntegrityPolicy;
using virgil::sdk::client::models::policies::ApplicationIntegrityPolicy;

static_assert(!std::is_abstract<virgil::sdk::client::ExtendedValidator>(), "ExtendedValidator must not be abstract.");

static const std::string kServiceCardId = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";
static const std::string kServicePublicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAxa1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=";

ExtendedValidator::ExtendedValidator(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                     const std::unordered_map<std::string, std::string> &whitelist,
                                     const bool &ignoreSelfSignature,
                                     const bool &ignoreVirgilSignature) {
    if (!ignoreSelfSignature)
        rules_.push_back(std::make_shared<SelfIntegrityPolicy>());

    if (!ignoreVirgilSignature) {
        rules_.push_back(std::make_shared<VirgilIntegrityPolicy>());
        registeredVerifiers_[kServiceCardId] = crypto->importPublicKey(VirgilBase64::decode(kServicePublicKey));
    }

    if (whitelist.size() > 0){
        rules_.push_back(std::make_shared<ApplicationIntegrityPolicy>(whitelist));

        for (const auto& verifier : whitelist)
            registeredVerifiers_[verifier.first] = crypto->importPublicKey(VirgilBase64::decode(verifier.second));
    }
}

bool ExtendedValidator::validateCard(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                     const interfaces::CardInterface &card) {
    registeredVerifiers_[card.identifier()] = card.publicKey().get();
    bool result = true;
    for (auto const& rule : rules_)
        if (!rule->diagnose(crypto, card, *this)) {
            result = false;
            break;
        }
    registeredVerifiers_.erase(card.identifier());
    return result;
}

bool ExtendedValidator::checkVerifier(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                      const interfaces::CardInterface &card,
                                      const std::string &verifierId) const {
    try {
        auto signature = card.signatures().at(verifierId);

        auto isVerified = crypto->verify(card.fingerprint(), signature, *(registeredVerifiers_.at(verifierId)));

        if (!isVerified) {
            return false;
        }
    }
    catch (...) {
        return false;
    }
    return true;
}