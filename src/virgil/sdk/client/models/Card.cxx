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

#include <virgil/sdk/client/models/Card.h>
#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>
#include <virgil/sdk/client/models/serialization/JsonDeserializer.h>
#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>
#include <virgil/sdk/client/models/snapshotmodels/CreateCardSnapshotModel.h>

static_assert(!std::is_abstract<virgil::sdk::client::models::Card>(), "Card must not be abstract.");

using virgil::sdk::client::models::Card;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::client::models::serialization::JsonDeserializer;
using virgil::sdk::client::models::serialization::JsonSerializer;
using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::client::models::serialization::CanonicalSerializer;

using virgil::cryptointerfaces::PublicKeyInterface;


Card Card::ImportRaw(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto, const responses::CardRaw &cardRaw) {
    auto model =
            CanonicalSerializer<snapshotmodels::CreateCardSnapshotModel>::fromCanonicalForm(cardRaw.ContentSnapshot());

    std::shared_ptr<PublicKeyInterface> publicKey(crypto->importPublicKey(model.publicKeyData()));

    return Card(cardRaw, cardRaw.ContentSnapshot(), cardRaw.Identifier(), model.identity(), model.identityType(), publicKey,
                model.data(), model.scope(), cardRaw.Meta().createdAt(), cardRaw.Meta().cardVersion(), cardRaw.Meta().signatures());
}

Card::Card(responses::CardRaw cardRaw, VirgilByteArray snapshot, std::string identifier, std::string identity, std::string identityType,
           std::shared_ptr<cryptointerfaces::PublicKeyInterface> publicKey, std::unordered_map<std::string, std::string> data, CardScope scope,
           std::string createdAt, std::string cardVersion, std::unordered_map<std::string, VirgilByteArray> signatures)
        : cardRaw_(cardRaw), snapshot_(std::move(snapshot)), identifier_(std::move(identifier)), identity_(std::move(identity)),
          identityType_(std::move(identityType)), publicKey_(std::move(publicKey)), data_(std::move(data)),
          scope_(scope), createdAt_(std::move(createdAt)),
          cardVersion_(std::move(cardVersion)), signatures_(signatures) {
}

std::string Card::exportAsString() const {
    auto json = JsonSerializer<responses::CardRaw>::toJson(cardRaw_);
    return VirgilBase64::encode(VirgilByteArrayUtils::stringToBytes(json));
}

Card Card::importFromString(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto, const std::string &data) {
    auto jsonStr = VirgilByteArrayUtils::bytesToString(VirgilBase64::decode(data));
    auto cardRaw = JsonDeserializer<responses::CardRaw>::fromJsonString(jsonStr);

    return Card::ImportRaw(crypto, cardRaw);
}