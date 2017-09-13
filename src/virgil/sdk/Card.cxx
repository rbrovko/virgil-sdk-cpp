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

#include <virgil/sdk/Card.h>
#include <virgil/sdk/Common.h>
#include <virgil/sdk/serialization/JsonSerializer.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/sdk/serialization/CanonicalSerializer.h>
#include <virgil/sdk/web/CSRSnapshotModel.h>
#include <virgil/sdk/util/JsonUtils.h>

static_assert(!std::is_abstract<virgil::sdk::Card>(), "Card must not be abstract.");

using virgil::sdk::Card;
using virgil::sdk::serialization::JsonDeserializer;
using virgil::sdk::serialization::JsonSerializer;
using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::util::JsonUtils;
using virgil::sdk::serialization::CanonicalSerializer;

using virgil::cryptointerfaces::PublicKeyInterface;


Card Card::parse(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto, const web::RawCard &cardRaw) {
    auto model =
            CanonicalSerializer<web::CSRSnapshotModel>::fromCanonicalForm(cardRaw.contentSnapshot());

    std::shared_ptr<PublicKeyInterface> publicKey(crypto->importPublicKey(model.publicKeyData()));

    auto fingerprint = crypto->calculateFingerprint(cardRaw.contentSnapshot());

    std::unordered_map<std::string, CardSignatureInfo> signatures;
    for (const auto& signature : cardRaw.signatures()) {

        auto extraData = JsonUtils::jsonToUnorderedMap((VirgilByteArrayUtils::bytesToString(signature.second.extraData())));
        CardSignatureInfo signatureInfo(
                signature.second.sign(),
                signature.second.signType(),
                extraData
        );
        signatures[signature.first] = signatureInfo;
    }

    return Card(cardRaw, fingerprint, cardRaw.contentSnapshot(), model.identity(), publicKey,
                cardRaw.createdAt(), cardRaw.cardVersion(), signatures);
}

Card::Card(web::RawCard cardRaw, VirgilByteArray fingerprint, VirgilByteArray snapshot, std::string identity,
           std::shared_ptr<cryptointerfaces::PublicKeyInterface> publicKey,
           std::string createdAt, std::string cardVersion, std::unordered_map<std::string, CardSignatureInfo> signatures)
        : cardRaw_(cardRaw), fingerprint_(fingerprint), snapshot_(std::move(snapshot)), identity_(std::move(identity)),
          publicKey_(std::move(publicKey)), createdAt_(std::move(createdAt)),
          cardVersion_(std::move(cardVersion)), signatures_(signatures) {
}

std::string Card::exportAsString() const {
    auto json = JsonSerializer<web::RawCard>::toJson(cardRaw_);
    return VirgilBase64::encode(VirgilByteArrayUtils::stringToBytes(json));
}

Card Card::importFromString(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto, const std::string &data) {
    auto jsonStr = VirgilByteArrayUtils::bytesToString(VirgilBase64::decode(data));
    auto cardRaw = JsonDeserializer<web::RawCard>::fromJsonString(jsonStr);

    return Card::parse(crypto, cardRaw);
}