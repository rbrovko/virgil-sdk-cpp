//
// Created by Eugen Pivovarov on 8/29/17.
//


#include <catch.hpp>
#include <virgil/sdk/client/CardManager.h>
#include <virgil/sdk/crypto/Crypto.h>
#include <TestConst.h>
#include <TestUtils.h>
#include <virgil/sdk/client/ValidationRules.h>
#include <virgil/sdk/client/models/CardSigner.h>
#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/ExtendedValidator.h>


using virgil::sdk::client::CardManager;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::client::ValidationRules;
using virgil::sdk::client::models::CardSigner;
using virgil::sdk::VirgilByteArray;
using virgil::sdk::client::ExtendedValidator;
using virgil::sdk::VirgilBase64;


TEST_CASE("test_001_FreeTest", "[FreeTests]") {
    TestConst consts;
    auto crypto = std::make_shared<Crypto>();
    TestUtils utils(consts);

    std::unordered_map<std::string, VirgilByteArray> verifiers = {
            {consts.applicationId(), VirgilBase64::decode(consts.applicationPublicKeyBase64())}
    };

    ValidationRules rules(
            verifiers
    );

    CardManagerParams cardManagerParams(
            crypto,
            consts.applicationToken(),
            rules
    );

    CardManager manager(cardManagerParams);
    auto request = utils.instantiateCreateCardRequest();

    auto future = manager.createCard(request);
    auto card = future.get();

    REQUIRE(utils.checkCardEquality(card, request));

    auto revokeRequest = utils.instantiateRevokeCardRequest(card);
    auto revokeFuture = manager.revokeCard(revokeRequest);

    revokeFuture.get();
}
