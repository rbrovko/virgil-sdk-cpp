/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/CardValidator.h>
#include <virgil/sdk/client/models/CardIdGenerator.h>
using virgil::sdk::client::models::Card;
static_assert(!std::is_abstract<virgil::sdk::client::CardValidator>(), "CardValidator must not be abstract.");

using virgil::sdk::client::CardValidator;
using virgil::cryptointerfaces::CryptoInterface;
using virgil::sdk::VirgilBase64;
using virgil::cryptointerfaces::PublicKeyInterface;
using virgil::sdk::client::models::CardIdGenerator;

static const std::string kServiceCardId = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";
static const std::string kServicePublicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAxa1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=";


CardValidator::CardValidator(const std::shared_ptr<CryptoInterface> &crypto)
        : crypto_(crypto) {
    auto servicePublicKeyData = VirgilBase64::decode(kServicePublicKey);
    verifiers_[kServiceCardId] = servicePublicKeyData;
}

void CardValidator::addVerifier(std::string verifierId, VirgilByteArray publicKeyData) {
    verifiers_[std::move(verifierId)] = std::move(publicKeyData);
}

bool CardValidator::validateCard(const Card &card) const {
    if (card.cardVersion() == "3.0")
        return true;

    auto fingerprint = crypto_->calculateFingerprint(card.snapshot());
    auto CardId = CardIdGenerator::generate(crypto_, fingerprint);

    if (card.identifier() != CardId)
        return false;

    auto verifiers = verifiers_;

    verifiers[CardId] = crypto_->exportPublicKey(*card.publicKey().get());

    for (const auto& verifier : verifiers) {
        try {
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
    }

    return true;
}

