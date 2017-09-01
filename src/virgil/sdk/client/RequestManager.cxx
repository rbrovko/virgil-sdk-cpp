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

#include <virgil/sdk/client/RequestManager.h>
#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>
#include <virgil/sdk/client/RequestSigner.h>
#include <virgil/sdk/VirgilSdkError.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::client::RequestManager;
using virgil::sdk::client::models::snapshotmodels::CreateCardSnapshotModel;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::client::models::serialization::CanonicalSerializer;
using virgil::sdk::client::RequestSigner;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::CardRevocationReason;
using virgil::sdk::make_error;

RequestManager::RequestManager(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto)
        :crypto_(crypto){}

const CreateCardRequest RequestManager::createCardRequest(const models::CardInfo &cardInfo,
                                          const cryptointerfaces::PrivateKeyInterface &privateKey) const {
    if (cardInfo.identity().empty()) {
        throw make_error(VirgilSdkError::CreateRequestManagerFailed, "Identity property is mandatory");
    }

    auto PublicKey = crypto_->exportPublicKey(cardInfo.publicKey());
    auto request = CreateCardRequest::createRequest(
            cardInfo.identity(),
            cardInfo.identityType(),
            PublicKey
    );

    auto signer = RequestSigner(crypto_);

    if (cardInfo.generateSelfSignature())
        signer.selfSign(request, privateKey);

    return request;
}

const RevokeCardRequest RequestManager::revokeCardRequest(const std::string &identifier,
                                                          const std::list<models::CardSigner> &signers) const {

    if (identifier.empty()) {
        throw make_error(VirgilSdkError::CreateRequestManagerFailed, "Id property is mandatory");
    }
    auto request = RevokeCardRequest::createRequest(
            identifier,
            CardRevocationReason::unspecified
    );

    auto signer = RequestSigner(crypto_);

    for (const auto& elem : signers)
        signer.authoritySign(request, elem.cardId(), elem.privateKey());

    return request;
}

void RequestManager::signRequest(CreateCardRequest &request, const std::list<models::CardSigner> &signers) const {

    auto signer = RequestSigner(crypto_);

    for (const auto& elem : signers)
        signer.authoritySign(request, elem.cardId(), elem.privateKey());
}