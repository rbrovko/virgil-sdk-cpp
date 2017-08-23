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
#include <virgil/sdk/client/CardValidator.h>
#include <UnitTests/CryptoTest.h>

#include <UnitTests/CardTest.h>

#include <virgil/sdk/client/models/CardIdGenerator.h>

using virgil::sdk::client::models::CardIdGenerator;

static const std::string kServiceCardId = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";
static const std::string kServicePublicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAxa1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=";

using virgil::sdk::client::CardValidator;
using VirgilBase64 = virgil::crypto::foundation::VirgilBase64;
using VirgilByteArrayUtils = virgil::crypto::VirgilByteArrayUtils;
using virgil::sdk::test::CryptoTest;
using virgil::sdk::test::KeyPairTest;
using virgil::sdk::test::PublicKeyTest;
using virgil::sdk::test::CardTest;

TEST_CASE("test_001_CreateValidator", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    REQUIRE(validator->verifiers().size() == 1);
    auto verifiers = validator->verifiers();
    REQUIRE(verifiers[kServiceCardId] == VirgilBase64::decode(kServicePublicKey));
}

TEST_CASE("test_002_addVerifier", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    std::string appId = "Random appId";
    auto publicKeyData = VirgilByteArrayUtils::stringToBytes("publicKey");

    validator->addVerifier(appId, publicKeyData);
    REQUIRE(validator->verifiers().size() == 2);
    auto verifiers = validator->verifiers();
    REQUIRE(verifiers[kServiceCardId] == VirgilBase64::decode(kServicePublicKey));
    REQUIRE(verifiers[appId] == publicKeyData);
}

TEST_CASE("test_003_addSameVerifier", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    validator->addVerifier(kServiceCardId, VirgilBase64::decode(kServicePublicKey));
    REQUIRE(validator->verifiers().size() == 1);
    auto verifiers = validator->verifiers();
    REQUIRE(verifiers[kServiceCardId] == VirgilBase64::decode(kServicePublicKey));
}

TEST_CASE("test_004_addVarifierWithSameName_SouldReplaceOldOne", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    auto publicKeyData = VirgilByteArrayUtils::stringToBytes("publicKey");

    validator->addVerifier(kServiceCardId, publicKeyData);
    REQUIRE(validator->verifiers().size() == 1);
    auto verifiers = validator->verifiers();
    REQUIRE(verifiers[kServiceCardId] == publicKeyData);
}

TEST_CASE("test_005_addEmptyVerifier_ShouldThrowExeption", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    auto publicKeyData = VirgilByteArrayUtils::stringToBytes("");

    bool errorWasThrown = false;
    try {
        validator->addVerifier("", publicKeyData);
    }
    catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);
}


TEST_CASE("test_006_validateCard_ShouldBeTrue", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    KeyPairTest keyPair;
    auto publicKey = std::make_shared<PublicKeyTest>(keyPair.publicKey());

    auto validIdentifier = "66696e6765727072696e74";

    CardTest card;
    card.snapshot_ = VirgilByteArrayUtils::stringToBytes("snapshot");
    card.identifier_ = validIdentifier;
    card.publicKey_ = publicKey;
    card.cardVersion_ = "3.1";
    card.data_ = {{}};
    card.signatures_ = {{kServiceCardId, VirgilBase64::decode(kServicePublicKey)},{validIdentifier, crypto->exportPublicKey(*publicKey.get())}};

    auto isValid = validator->validateCard(card);

    REQUIRE(isValid);
}

TEST_CASE("test_007_validateCardWithoutSignatures_ShouldBeFalse", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    KeyPairTest keyPair;
    auto publicKey = std::make_shared<PublicKeyTest>(keyPair.publicKey());

    auto validIdentifier = "66696e6765727072696e74";

    CardTest card;
    card.snapshot_ = VirgilByteArrayUtils::stringToBytes("snapshot");
    card.identifier_ = validIdentifier;
    card.publicKey_ = publicKey;
    card.cardVersion_ = "3.1";
    card.data_ = {{}};
    card.signatures_ = {{}};

    auto isValid = validator->validateCard(card);

    REQUIRE(!isValid);
}

TEST_CASE("test_008_validateCardWithWrongId_ShouldBeFalse", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    KeyPairTest keyPair;
    auto publicKey = std::make_shared<PublicKeyTest>(keyPair.publicKey());

    auto validIdentifier = "66696e6765727072696e74";

    CardTest card;
    card.snapshot_ = VirgilByteArrayUtils::stringToBytes("snapshot");
    card.identifier_ = "id";
    card.publicKey_ = publicKey;
    card.cardVersion_ = "3.1";
    card.data_ = {{}};
    card.signatures_ = {{kServiceCardId, VirgilBase64::decode(kServicePublicKey)},{validIdentifier, crypto->exportPublicKey(*publicKey.get())}};

    auto isValid = validator->validateCard(card);

    REQUIRE(!isValid);
}

TEST_CASE("test_009_validateCardWithWrongParams_ButVersion3.0_ShouldBeTrue", "[CardValidator]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = std::make_shared<CardValidator>(crypto);

    KeyPairTest keyPair;
    auto publicKey = std::make_shared<PublicKeyTest>(keyPair.publicKey());

    CardTest card;
    card.snapshot_ = VirgilByteArrayUtils::stringToBytes("snapshot");
    card.identifier_ = "id";
    card.publicKey_ = publicKey;
    card.cardVersion_ = "3.0";
    card.data_ = {{}};
    card.signatures_ = {{}};

    auto isValid = validator->validateCard(card);

    REQUIRE(isValid);
}


