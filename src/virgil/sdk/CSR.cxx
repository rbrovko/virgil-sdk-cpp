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

#include <virgil/sdk/CSR.h>
#include <virgil/sdk/CardIdGenerator.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/interfaces/SignableRequestInterface.h>
#include <virgil/sdk/serialization/JsonSerializer.h>

using virgil::sdk::CSR;
using virgil::sdk::util::JsonUtils;
using virgil::sdk::serialization::JsonSerializer;
using virgil::sdk::interfaces::SignableRequestInterface;
using virgil::sdk::web::CSRSnapshotModel;
using virgil::sdk::serialization::CanonicalSerializer;
using virgil::sdk::CardIdGenerator;
using virgil::sdk::web::RawCardSignatureInfo;
using virgil::sdk::web::SignType;

CSR CSR::generate(
        const std::string &identity,
        const VirgilByteArray &publicKeyData)
{ return CSR(web::CSRSnapshotModel::createModel(identity, publicKeyData)); }

CSR::CSR(const web::CSRSnapshotModel &snapshotModel,
         const std::unordered_map<std::string, RawCardSignatureInfo> &signatures)
        : CSR(serialization::CanonicalSerializer<web::CSRSnapshotModel>::toCanonicalForm(snapshotModel),
              snapshotModel, signatures) { };

CSR::CSR(const VirgilByteArray &snapshot,
         const std::unordered_map<std::string, RawCardSignatureInfo> &signatures)
        : CSR(snapshot,
              serialization::CanonicalSerializer<web::CSRSnapshotModel>::fromCanonicalForm(snapshot),
              signatures) {}

CSR::CSR(VirgilByteArray snapshot, web::CSRSnapshotModel snapshotModel,
         std::unordered_map<std::string, RawCardSignatureInfo> signatures)
: snapshot_(std::move(snapshot)), snapshotModel_(std::move(snapshotModel)), signatures_(std::move(signatures)) { };


void CSR::addSignature(RawCardSignatureInfo signature, std::string fingerprint) {
    signatures_[std::move(fingerprint)] = std::move(signature);
}

void CSR::sign(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto,
               const cryptointerfaces::PrivateKeyInterface &privateKey) {
    auto fingerprint = crypto->calculateFingerprint(snapshot());
    auto cardId = CardIdGenerator::generate(fingerprint);

    auto signatureInfo = web::RawCardSignatureInfo(
            crypto->generateSignature(fingerprint, privateKey),
            SignType::self
    );

    addSignature(signatureInfo, cardId);
}

void CSR::sign(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto,
               const CardSigner &cardSigner,
               const SignType &signType) {

    auto extraDataSnapshot = (!cardSigner.extraData().empty()) ? VirgilByteArrayUtils::stringToBytes(JsonUtils::unorderedMapToJson(cardSigner.extraData()).dump()) : std::vector<unsigned char>();

    auto combinedSnapshot = snapshot();
    VirgilByteArrayUtils::append(combinedSnapshot, extraDataSnapshot);

    auto fingerprint = crypto->calculateFingerprint(combinedSnapshot);
    auto signatureInfo = RawCardSignatureInfo(
            crypto->generateSignature(fingerprint, cardSigner.privateKey()),
            signType,
            extraDataSnapshot
    );

    addSignature(signatureInfo, cardSigner.cardId());
}

std::string CSR::exportAsString() const {
    auto json = serialization::JsonSerializer<SignableRequestInterface>::toJson(*this);

    return VirgilBase64::encode(VirgilByteArrayUtils::stringToBytes(json));
}

