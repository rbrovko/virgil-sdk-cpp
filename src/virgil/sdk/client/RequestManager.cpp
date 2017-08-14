//
// Created by Eugen Pivovarov on 8/10/17.
//

#include <virgil/sdk/client/RequestManager.h>
#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>
#include <virgil/sdk/client/RequestSigner.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::client::RequestManager;
using virgil::sdk::client::models::snapshotmodels::CreateCardSnapshotModel;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::client::models::serialization::CanonicalSerializer;
using virgil::sdk::client::CreateCardParams;
using virgil::sdk::client::RequestSigner;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::CardRevocationReason;

RequestManager::RequestManager(const std::shared_ptr<CryptoInterface> crypto_)
        :crypto_(crypto_){}

CreateCardRequest RequestManager::CreateCardRequest(CreateCardParams parameters) {

    auto PublicKey = crypto_->exportPublicKey(parameters.keyPair.publicKey());
    auto request = CreateCardRequest::createRequest(
            parameters.Identity,
            parameters.IdentityType,
            PublicKey
    );

    auto signer = RequestSigner(crypto_);

    if (parameters.GenerateSelfSignature)
        signer.selfSign(request, parameters.keyPair.privateKey());

    for (const auto& elem : parameters.RequestSigners)
        signer.authoritySign(request, elem.first, elem.second);

    return request;
}

RevokeCardRequest RequestManager::RevokeCardRequest(RevokeCardParams parameters) {

    auto request = RevokeCardRequest::createRequest(
            parameters.identifier,
            CardRevocationReason::unspecified
    );

    auto signer = RequestSigner(crypto_);

    for (const auto& elem : parameters.RequestSigners)
        signer.authoritySign(request, elem.first, elem.second);

    return request;
}