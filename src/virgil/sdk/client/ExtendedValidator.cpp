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
#include <virgil/sdk/client/models/policies/AllValidPolicy.h>
#include <string>
using virgil::sdk::client::ExtendedValidator;
using virgil::sdk::client::models::policies::SelfIntegrityPolicy;
using virgil::sdk::client::models::policies::VirgilIntegrityPolicy;
using virgil::sdk::client::models::policies::ApplicationIntegrityPolicy;
using virgil::sdk::client::models::policies::AllValidPolicy;

ExtendedValidator::ExtendedValidator(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                     const IntegrityPolicy &policy)
    : crypto_(crypto) {

    rules_ = std::move(policy.getRules(*this));
}

bool ExtendedValidator::validateCard(const interfaces::CardInterface &card) {
    registeredVerifiers_[card.identifier()] = card.publicKey().get();
    for (auto const& rule : rules_)
        if (!rule->diagnose(card, *this))
            return false;
    return true;
}

void ExtendedValidator::registerVerifiers(const std::unordered_map<std::string, VirgilByteArray> &verifiers) {
    for (const auto& verifier : verifiers)
        registeredVerifiers_[verifier.first] = crypto_->importPublicKey(verifier.second);
}

bool ExtendedValidator::checkVerifier(const interfaces::CardInterface &card,
                                      const std::string &verifierId) const {
    try {
        auto signature = card.signatures().at(verifierId);

        auto isVerified = crypto_->verify(card.fingerprint(), signature, *(registeredVerifiers_.at(verifierId)));

        if (!isVerified) {
            return false;
        }
    }
    catch (...) {
        return false;
    }
    return true;
}