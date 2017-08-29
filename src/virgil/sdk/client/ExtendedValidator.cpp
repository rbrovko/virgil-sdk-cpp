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

using virgil::sdk::client::ExtendedValidator;
using virgil::sdk::client::models::policies::SelfIntegrityPolicy;
using virgil::sdk::client::models::policies::VirgilIntegrityPolicy;
using virgil::sdk::client::models::policies::ApplicationIntegrityPolicy;
using virgil::sdk::client::models::policies::AllValidPolicy;

ExtendedValidator::ExtendedValidator(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                     const ValidationRules &rules)
    : crypto_(crypto) {

    if (!rules.ignoreSelfSignatures())
        policy_.push_back(std::make_shared<SelfIntegrityPolicy>(crypto));

    if (!rules.ignoreVirgilSignatures())
        policy_.push_back(std::make_shared<VirgilIntegrityPolicy>());

    if (rules.verifiers().size() > 0)
        policy_.push_back(std::make_shared<ApplicationIntegrityPolicy>(
                rules.verifiers(),
                rules.behavior()
        ));
}


bool ExtendedValidator::validateCard(const interfaces::CardInterface &card) const {
    for (auto const& policy : policy_)
        if (!policy->diagnose(card, *this))
            return false;
    return true;
}

bool ExtendedValidator::checkVerifier(const interfaces::CardInterface &card,
                                      const std::pair<std::string, VirgilByteArray> &verifier) const {
    try {
        auto fingerprint = crypto_->calculateFingerprint(card.snapshot());

        auto signature = card.signatures().at(verifier.first);
        auto publicKeyPointer = crypto_->importPublicKey(verifier.second);

        auto isVerified = crypto_->verify(fingerprint, signature, *publicKeyPointer);

        if (!isVerified) {
            return false;
        }
    }
    catch (...) {
        return false;
    }
    return true;
}