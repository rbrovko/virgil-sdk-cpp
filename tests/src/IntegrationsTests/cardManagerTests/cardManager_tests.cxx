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
#include <virgil/sdk/util/Memory.h>
#include <virgil/sdk/CardManager.h>
#include <virgil/sdk/validation/ExtendedValidator.h>
#include <virgil/sdk/CardIdGenerator.h>
#include <helpers.h>
#include <virgil/sdk/CSRParams.h>

using virgil::sdk::CSRParams;
using virgil::sdk::web::ServiceConfig;
using virgil::sdk::validation::SignerInfo;
using virgil::sdk::web::CardsClient;
using virgil::sdk::CardManager;
using virgil::sdk::web::SearchCardsCriteria;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::CardSigner;
using virgil::sdk::test::Utils;
using virgil::sdk::VirgilBase64;
using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::CardIdGenerator;
using virgil::sdk::web::SignType;

using virgil::sdk::validation::ExtendedValidator;


TEST_CASE("test000_Create_and_Sign_CSR", "[CardManager]") {
    TestConst consts;
    TestUtils utils(consts);

    auto crypto = std::make_shared<Crypto>();
    auto keyPair = crypto->generateKeyPair();

    CardManagerParams managerParams(
            crypto,
            consts.applicationToken()
    );
    CardManager manager(managerParams);

    auto privateAppKeyData = VirgilBase64::decode(consts.applicationPrivateKeyBase64());
    auto appPrivateKey = crypto->importPrivateKey(privateAppKeyData, consts.applicationPrivateKeyPassword());
    auto identity = Utils::generateRandomStr(40);

    CSRParams csrParams(
            identity,
            keyPair.publicKey(),
            std::make_shared<PrivateKey>(keyPair.privateKey())
    );

    auto csr = manager.generateCSR(csrParams);

    std::unordered_map<std::string, std::string> extraData;
    extraData["some_random_key1"] = "some_random_data1";
    extraData["some_random_key2"] = "some_random_data2";

    std::list<CardSigner> requestSigners;
    requestSigners.push_back(
            CardSigner(
                    consts.applicationId(),
                    appPrivateKey,
                    extraData
            )
    );

    //csr.sign(crypto, cardSigner);
    //csr.sign(crypto, keyPair.privateKey());

    manager.signCSR(csr, requestSigners);


    auto fingerprint = crypto->calculateFingerprint(csr.snapshot());
    auto cardId = CardIdGenerator::generate(fingerprint);

    auto signatures = csr.signatures();
    REQUIRE(signatures.size() == 2);
    REQUIRE(signatures[cardId].signType() == SignType::self);
    REQUIRE(signatures[consts.applicationId()].signType() == SignType::application);
}

/*
TEST_CASE("test001_CreateCard", "[CardManager]") {
    TestConst consts;
    TestUtils utils(consts);

    auto crypto = std::make_shared<Crypto>();

    std::list<SignerInfo> whitelist;
    whitelist.push_back(SignerInfo(consts.applicationId(), consts.applicationPublicKeyBase64()));

    auto validator = std::make_shared<ExtendedValidator>(
            whitelist
    );

    CardManagerParams managerParams(
            crypto,
            consts.applicationToken(),
            validator,
            consts.cardsServiceURL(),
            consts.cardsServiceROURL()
    );

    CardManager manager(managerParams);

    auto keyPair = crypto->generateKeyPair();

    auto privateAppKeyData = VirgilBase64::decode(consts.applicationPrivateKeyBase64());
    auto appPrivateKey = crypto->importPrivateKey(privateAppKeyData, consts.applicationPrivateKeyPassword());

    std::list<CardSigner> requestSigners;
    requestSigners.push_back(
            CardSigner(consts.applicationId(), appPrivateKey)
    );

    auto identity = Utils::generateRandomStr(40);

    auto csr = manager.generateCSR(
            identity,
            keyPair.publicKey(),
            std::make_shared<PrivateKey>(keyPair.privateKey())
    );

    manager.signCSR(csr, requestSigners);

    auto future = manager.createCard(csr);
    auto card = future.get();

    REQUIRE(utils.checkCardEquality(card, csr));
}

TEST_CASE("test003_SearchCards", "[CardManager]") {
    TestConst consts;
    TestUtils utils(consts);

    auto crypto = std::make_shared<Crypto>();

    std::list<SignerInfo> whitelist;
    whitelist.push_back(SignerInfo(consts.applicationId(), consts.applicationPublicKeyBase64()));

    auto validator = std::make_shared<ExtendedValidator>(
            whitelist
    );

    CardManagerParams managerParams(
            crypto,
            consts.applicationToken(),
            validator,
            consts.cardsServiceURL(),
            consts.cardsServiceROURL()
    );

    CardManager manager(managerParams);

    auto csr = utils.instantiateCreateCardRequest();

    auto future = manager.createCard(csr);
    auto card = future.get();

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future_ = manager.searchCards(
            SearchCardsCriteria::createCriteria({ card.identity() }));

    auto foundCards = future_.get();

    REQUIRE(foundCards.size() == 1);
    REQUIRE(utils.checkCardEquality(card, foundCards.front()));
}

TEST_CASE("test005_GetCard", "[CardManager]") {
    TestConst consts;
    TestUtils utils(consts);

    auto crypto = std::make_shared<Crypto>();

    std::list<SignerInfo> whitelist;
    whitelist.push_back(SignerInfo(consts.applicationId(), consts.applicationPublicKeyBase64()));

    auto validator = std::make_shared<ExtendedValidator>(
            whitelist
    );

    CardManagerParams managerParams(
            crypto,
            consts.applicationToken(),
            validator,
            consts.cardsServiceURL(),
            consts.cardsServiceROURL()
    );

    CardManager manager(managerParams);

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = manager.createCard(CreateCardRequest);
    auto card = future.get();

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future_ = manager.getCard(CardIdGenerator::generate(card.fingerprint()));
    auto foundCard = future_.get();

    REQUIRE(utils.checkCardEquality(card, foundCard));
}*/