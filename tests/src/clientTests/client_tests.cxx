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

#include <catch.hpp>

#include <thread>
#include <memory>

#include <TestConst.h>
#include <TestUtils.h>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/CardValidator.h>

#include <virgil/sdk/util/Memory.h>
#include <virgil/sdk/client/RequestSigner.h>
#include <virgil/sdk/client/RequestManager.h>

#include <virgil/sdk/client/ExtendedValidator.h>

using virgil::sdk::client::Client;
using virgil::sdk::client::ServiceConfig;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::SearchCardsCriteria;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::client::CardValidator;
using virgil::sdk::VirgilBase64;
using virgil::sdk::client::interfaces::CardValidatorInterface;

using virgil::sdk::client::RequestSigner;
using virgil::sdk::client::models::parameters::CreateCardParams;
using virgil::sdk::client::models::parameters::RevokeCardParams;
using virgil::sdk::client::RequestManager;

using virgil::sdk::client::ExtendedValidator;

TEST_CASE("test001_CreateCardTest", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto crypto = std::make_shared<Crypto>();                           //making crypto

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());

    Client client(std::move(serviceConfig));                            //creating client

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(CreateCardRequest);
    auto cardRaw = future.get();

    auto card = Card::ImportRaw(crypto, cardRaw);

    auto validator = ExtendedValidator(
            {{consts.applicationId(), consts.applicationPublicKeyBase64()}}
    );
    validator.initialize(crypto);
    auto isValid = validator.validateCard(crypto, card).isValid();

    REQUIRE(isValid);
    REQUIRE(utils.checkCardEquality(card, CreateCardRequest));
}

TEST_CASE("test002_CreateCardWithCustomData", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());

    Client client(std::move(serviceConfig));

    std::unordered_map<std::string, std::string> CustomData;
    CustomData["some_random_key1"] = "some_random_data1";
    CustomData["some_random_key2"] = "some_random_data2";

    auto createCardRequest = utils.instantiateCreateCardRequest(CustomData);

    auto future = client.createCard(createCardRequest);

    auto cardRaw = future.get();

    auto card = Card::ImportRaw(utils.crypto(), cardRaw);

    REQUIRE(utils.checkCardEquality(card, createCardRequest));
}


TEST_CASE("test003_SearchCards", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());

    Client client(std::move(serviceConfig));

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto cardRaw = future.get();

    auto card = Card::ImportRaw(utils.crypto(), cardRaw);

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future2 = client.searchCards(
            SearchCardsCriteria::createCriteria({ card.identity() }, CardScope::application, card.identityType()));

    auto list = future2.get();

    auto foundCards = Card::ImportRaw(utils.crypto(), list[0]);

    REQUIRE(list.size() == 1);
    REQUIRE(utils.checkCardEquality(card, foundCards));
}

TEST_CASE("test004_GetCard", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());

    Client client(std::move(serviceConfig));

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto cardRaw = future.get();

    auto card = Card::ImportRaw(utils.crypto(), cardRaw);

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future2 = client.getCard(card.identifier());

    auto foundCardRaw = future2.get();

    auto card2 = Card::ImportRaw(utils.crypto(), foundCardRaw);

    REQUIRE(utils.checkCardEquality(card, card2));
}


TEST_CASE("test006_RevokeCardTest", "[client]") {
    TestConst consts;
    TestUtils utils((TestConst()));

    auto crypto = std::make_shared<Crypto>();                           //making crypto

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());

    Client client(std::move(serviceConfig));                            //creating client

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(CreateCardRequest);
    auto cardRaw = future.get();

    auto card = Card::ImportRaw(utils.crypto(), cardRaw);


    //Revoking
    auto RevokeCardRequest = utils.instantiateRevokeCardRequest(card);

    auto future_1 = client.revokeCard(RevokeCardRequest);
    future_1.get();

    auto future_2 = client.getCard(card.identifier());

    bool errorWasThrown = false;
    try {
        future_2.get();
    }
    catch (...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}

TEST_CASE("test007_CreateCardRequest_Should_ThrowExeption_IfIdentityIsEmpty", "[client]") {

    TestConst consts;
    TestUtils utils(consts);

    auto crypto = std::make_shared<Crypto>();                           //making crypto

    RequestManager manager(crypto);                                     //creating RequestManager
    auto keyPair = crypto->generateKeyPair();                           //making KeyPair

    auto privateAppKeyData = VirgilBase64::decode(consts.applicationPrivateKeyBase64());
    auto appPrivateKey = crypto->importPrivateKey(privateAppKeyData, consts.applicationPrivateKeyPassword());

    //making CardParams
    CreateCardParams parameters(
            "",                                          //Identity
            consts.applicationIdentityType(),            //IdentityType
            keyPair,                                     //keyPair
            {{consts.applicationId(), appPrivateKey}}    //RequestSigners
    );

    bool errorWasThrown = false;
    try {
        auto CreateCardRequest = manager.createCardRequest(parameters);
    }
    catch(...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}

TEST_CASE("test008_Free_Test", "[client]") {

}