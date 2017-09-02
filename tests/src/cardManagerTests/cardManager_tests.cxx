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
#include <virgil/sdk/util/Memory.h>
#include <virgil/sdk/client/CardManager.h>
#include <virgil/sdk/client/ExtendedValidator.h>

using virgil::sdk::client::models::SignerInfo;
using virgil::sdk::client::Client;
using virgil::sdk::client::CardManager;
using virgil::sdk::client::models::SearchCardsCriteria;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;

using virgil::sdk::client::ExtendedValidator;

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
            validator
    );

    CardManager manager(managerParams);

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = manager.createCard(CreateCardRequest);
    auto card = future.get();

    REQUIRE(utils.checkCardEquality(card, CreateCardRequest));
}

TEST_CASE("test002_RevokeCard", "[CardManager]") {
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
            validator
    );

    CardManager manager(managerParams);

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = manager.createCard(CreateCardRequest);
    auto card = future.get();

    auto RevokeCardRequest = utils.instantiateRevokeCardRequest(card);

    auto future_1 = manager.revokeCard(RevokeCardRequest);
    future_1.get();

    auto future_2 = manager.getCard(card.identifier());

    bool errorWasThrown = false;
    try {
        future_2.get();
    }
    catch (...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
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
            validator
    );

    CardManager manager(managerParams);

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = manager.createCard(CreateCardRequest);
    auto card = future.get();

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future_ = manager.searchCards(
            SearchCardsCriteria::createCriteria({ card.identity() }, CardScope::application, card.identityType()));

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
            validator
    );

    CardManager manager(managerParams);

    auto CreateCardRequest = utils.instantiateCreateCardRequest();

    auto future = manager.createCard(CreateCardRequest);
    auto card = future.get();

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future_ = manager.getCard(card.identifier());
    auto foundCard = future_.get();

    REQUIRE(utils.checkCardEquality(card, foundCard));
}
