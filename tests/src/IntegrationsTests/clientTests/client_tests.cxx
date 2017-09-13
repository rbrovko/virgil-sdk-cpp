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
/*
#include <catch.hpp>

#include <thread>
#include <memory>

#include <TestConst.h>
#include <TestUtils.h>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/web/Client.h>

#include <virgil/sdk/util/Memory.h>
#include <virgil/sdk/web/RequestSigner.h>
#include <virgil/sdk/web/RequestManager.h>
#include <PrivateKeyInterface.h>

#include <virgil/sdk/web/ExtendedValidator.h>
using virgil::sdk::crypto::keys::PrivateKey;

using virgil::sdk::web::models::CardInfo;
using virgil::sdk::web::Client;
using virgil::sdk::web::ServiceConfig;
using virgil::sdk::web::models::requests::CSR;
using virgil::sdk::web::models::SearchCardsCriteria;
using virgil::sdk::web::models::CardScope;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::VirgilBase64;
using virgil::sdk::web::interfaces::CardValidatorInterface;

using virgil::sdk::web::RequestSigner;
using virgil::sdk::web::RequestManager;
using virgil::cryptointerfaces::PrivateKeyInterface;
using virgil::sdk::web::ExtendedValidator;
using virgil::sdk::web::models::CardIdGenerator;

TEST_CASE("test001_CreateCardTest", "[web]") {
    TestConst consts;
    TestUtils utils(consts);

    auto crypto = std::make_shared<Crypto>();

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    serviceConfig.cardsServiceURL(consts.cardsServiceURL());
    serviceConfig.cardsServiceROURL(consts.cardsServiceROURL());

    Client web(std::move(serviceConfig));

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = web.createCard(CreateCardRequest);
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

TEST_CASE("test002_CreateCardWithCustomData", "[web]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    serviceConfig.cardsServiceURL(consts.cardsServiceURL());
    serviceConfig.cardsServiceROURL(consts.cardsServiceROURL());

    Client web(std::move(serviceConfig));

    std::unordered_map<std::string, std::string> CustomData;
    CustomData["some_random_key1"] = "some_random_data1";
    CustomData["some_random_key2"] = "some_random_data2";

    auto createCardRequest = utils.instantiateCreateCardRequest(CustomData);

    auto future = web.createCard(createCardRequest);

    auto cardRaw = future.get();

    auto card = Card::ImportRaw(utils.crypto(), cardRaw);

    REQUIRE(utils.checkCardEquality(card, createCardRequest));
}


TEST_CASE("test003_SearchCardsTest", "[web]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    serviceConfig.cardsServiceURL(consts.cardsServiceURL());
    serviceConfig.cardsServiceROURL(consts.cardsServiceROURL());

    Client web(std::move(serviceConfig));

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = web.createCard(createCardRequest);

    auto cardRaw = future.get();

    auto card = Card::ImportRaw(utils.crypto(), cardRaw);

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future2 = web.searchCards(
            SearchCardsCriteria::createCriteria({ card.identity() }, CardScope::application, card.identityType()));

    auto list = future2.get();

    auto foundCards = Card::ImportRaw(utils.crypto(), list[0]);

    REQUIRE(list.size() == 1);
    REQUIRE(utils.checkCardEquality(card, foundCards));
}

TEST_CASE("test004_GetCardTest", "[web]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    serviceConfig.cardsServiceURL(consts.cardsServiceURL());
    serviceConfig.cardsServiceROURL(consts.cardsServiceROURL());

    Client web(std::move(serviceConfig));

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = web.createCard(createCardRequest);

    auto cardRaw = future.get();

    auto card = Card::ImportRaw(utils.crypto(), cardRaw);

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future2 = web.getCard(CardIdGenerator::generate(card.fingerprint()));

    auto foundCardRaw = future2.get();

    auto card2 = Card::ImportRaw(utils.crypto(), foundCardRaw);

    REQUIRE(utils.checkCardEquality(card, card2));
}


TEST_CASE("test006_RevokeCardTest", "[web]") {
    TestConst consts;
    TestUtils utils((TestConst()));

    auto crypto = std::make_shared<Crypto>();

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    serviceConfig.cardsServiceURL(consts.cardsServiceURL());
    serviceConfig.cardsServiceROURL(consts.cardsServiceROURL());

    Client web(std::move(serviceConfig));

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = web.createCard(CreateCardRequest);
    auto cardRaw = future.get();

    auto card = Card::ImportRaw(utils.crypto(), cardRaw);

    //Revoking
    auto RevokeCardRequest = utils.instantiateRevokeCardRequest(card);

    auto future_1 = web.revokeCard(RevokeCardRequest);
    future_1.get();

    auto future_2 = web.getCard(CardIdGenerator::generate(card.fingerprint()));

    bool errorWasThrown = false;
    try {
        future_2.get();
    }
    catch (...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}

TEST_CASE("test007_CreateCardRequest_Should_ThrowExeption_IfIdentityIsEmpty", "[web]") {

    TestConst consts;
    TestUtils utils(consts);

    auto crypto = std::make_shared<Crypto>();

    RequestManager manager(crypto);
    auto keyPair = crypto->generateKeyPair();

    auto privateAppKeyData = VirgilBase64::decode(consts.applicationPrivateKeyBase64());
    auto appPrivateKey = crypto->importPrivateKey(privateAppKeyData, consts.applicationPrivateKeyPassword());

    CardInfo cardInfo(
            "",                                          //Identity
            keyPair.publicKey(),                         //keyPair
            consts.applicationIdentityType()             //IdentityType
    );

    bool errorWasThrown = false;
    try {
        auto request = manager.createCardRequest(cardInfo, std::make_shared<PrivateKey>(keyPair.privateKey()));
    }
    catch(...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}*/