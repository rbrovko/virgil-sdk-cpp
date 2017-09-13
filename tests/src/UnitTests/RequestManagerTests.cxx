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
#include <virgil/sdk/web/RequestManager.h>

#include <Mocks/KeysTest.h>
#include <Mocks/CryptoTest.h>

using virgil::sdk::web::models::CardInfo;
using virgil::cryptointerfaces::PublicKeyInterface;
using VirgilByteArrayUtils = virgil::crypto::VirgilByteArrayUtils;
using VirgilBase64 = virgil::crypto::foundation::VirgilBase64;
using virgil::sdk::test::CryptoTest;
using virgil::sdk::test::KeyPairTest;
using virgil::sdk::test::PrivateKeyTest;

using virgil::sdk::web::RequestManager;
using virgil::sdk::web::models::SignType;


TEST_CASE("test001_CreateCardRequest", "[RequestManager]") {

    auto crypto = std::make_shared<CryptoTest>();

    RequestManager manager(crypto);

    KeyPairTest keyPair;
    auto privateKey = keyPair.privateKey();

    std::string appId = "Random appId";

    CardInfo cardInfo(
            "Alice",                                     //Identity
            keyPair.publicKey(),                         //keyPair
            "test"                                       //IdentityType
    );

    auto request = manager.createCardRequest(cardInfo, std::make_shared<PrivateKeyTest>(keyPair.privateKey()));

    manager.signRequest(request, {{appId, privateKey}});

    auto snap = "{\"identity\":\"Alice\",\"identity_type\":\"test\",\"public_key\":\"dGVzdA==\",\"scope\":\"application\"}";

    REQUIRE(VirgilByteArrayUtils::bytesToString(request.snapshot()) == snap);
    REQUIRE(request.signatures().size() == 2);
    auto m = request.signatures();
    REQUIRE(m[appId].sign() == VirgilByteArrayUtils::stringToBytes("signature"));
    REQUIRE(m[appId].signType() == SignType::application);
    auto Cardid = VirgilByteArrayUtils::bytesToHex(crypto->calculateFingerprint(request.snapshot()));
    REQUIRE(m[Cardid].sign() == VirgilByteArrayUtils::stringToBytes("signature"));
    REQUIRE(m[Cardid].signType() == SignType::self);
}


TEST_CASE("test002_CreateCardRequest_withCustomData", "[RequestManager]") {

    auto crypto = std::make_shared<CryptoTest>();

    RequestManager manager(crypto);

    KeyPairTest keyPair;
    auto privateKey = keyPair.privateKey();

    std::string appId = "Random appId";

    std::unordered_map<std::string, std::string> CustomData;
    CustomData["some_random_key1"] = "some_random_data1";
    CustomData["some_random_key2"] = "some_random_data2";

    CardInfo cardInfo(
            "Alice",                                     //Identity
            keyPair.publicKey(),                         //keyPair
            "test",                                      //IdentityType
            CustomData                                   //CustomFields
    );

    auto request = manager.createCardRequest(cardInfo, std::make_shared<PrivateKeyTest>(keyPair.privateKey()));

    manager.signRequest(request, {{appId, privateKey}});

    auto snap = "{\"identity\":\"Alice\",\"identity_type\":\"test\",\"public_key\":\"dGVzdA==\",\"scope\":\"application\"}";

    REQUIRE(VirgilByteArrayUtils::bytesToString(request.snapshot()) == snap);

    REQUIRE(request.signatures().size() == 2);
    auto m = request.signatures();
    REQUIRE(m[appId].sign() == VirgilByteArrayUtils::stringToBytes("signature"));
    auto Cardid = VirgilByteArrayUtils::bytesToHex(crypto->calculateFingerprint(request.snapshot()));
    REQUIRE(m[Cardid].sign() == VirgilByteArrayUtils::stringToBytes("signature"));
}

TEST_CASE("test003_CreateCardRequest_withoutSelfSign", "[RequestManager]") {

    auto crypto = std::make_shared<CryptoTest>();

    RequestManager manager(crypto);

    KeyPairTest keyPair;
    auto privateKey = keyPair.privateKey();

    std::string appId = "Random appId";

    CardInfo cardInfo(
            "Alice",                                     //Identity
            keyPair.publicKey(),                         //keyPair
            "test"                                       //IdentityType
    );

    auto request = manager.createCardRequest(cardInfo);

    manager.signRequest(request, {{appId, privateKey}});

    auto snap = "{\"identity\":\"Alice\",\"identity_type\":\"test\",\"public_key\":\"dGVzdA==\",\"scope\":\"application\"}";

    REQUIRE(VirgilByteArrayUtils::bytesToString(request.snapshot()) == snap);
    REQUIRE(request.signatures().size() == 1);
    auto m = request.signatures();
    REQUIRE(m[appId].sign() == VirgilByteArrayUtils::stringToBytes("signature"));
}

TEST_CASE("test004_RevokeCardRequest", "[RequestManager]") {

    auto crypto = std::make_shared<CryptoTest>();

    RequestManager manager(crypto);

    KeyPairTest keyPair;
    auto privateKey = keyPair.privateKey();

    std::string appId = "Random appId";

    auto request = manager.revokeCardRequest("CardId",  {{appId, privateKey}});

    auto snap = VirgilByteArrayUtils::stringToBytes("{\"card_id\":\"CardId\",\"revocation_reason\":\"unspecified\"}");

    REQUIRE(request.snapshot() == snap);
    REQUIRE(request.signatures().size() == 1);
    auto m = request.signatures();
    REQUIRE(m[appId].sign() == VirgilByteArrayUtils::stringToBytes("signature"));
}

TEST_CASE("test005_CreateCardRequest_ShouldThrowExeption", "[RequestManager]") {

    auto crypto = std::make_shared<CryptoTest>();

    RequestManager manager(crypto);

    KeyPairTest keyPair;
    auto privateKey = keyPair.privateKey();

    std::string appId = "Random appId";

    CardInfo cardInfo(
            "",                                          //Identity
            keyPair.publicKey(),                          //keyPair
            "test"                                      //IdentityType
    );

    bool errorWasThrown = false;
    try {
        auto request = manager.createCardRequest(cardInfo, std::make_shared<PrivateKeyTest>(keyPair.privateKey()));
    }
    catch(...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}
*/