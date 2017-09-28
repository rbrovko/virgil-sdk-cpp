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
#include <iostream>

#include <virgil/sdk/validation/ExtendedValidator.h>

#include <TestConst.h>
#include <Mocks/CryptoTest.h>
#include <Mocks/CardTest.h>
#include <virgil/sdk/util/ByteArrayUtils.h>

using virgil::sdk::util::ByteArrayUtils;

using virgil::sdk::validation::ExtendedValidator;
using virgil::sdk::CardSignatureInfo;
using virgil::sdk::crypto::Crypto;

using virgil::sdk::test::TestConst;

using virgil::sdk::test::CryptoTest;
using virgil::sdk::test::KeyPairTest;
using virgil::sdk::test::PublicKeyTest;
using virgil::sdk::test::CardTest;

static const std::string kServiceCardId = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";
static const std::string kServicePublicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAxa1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=";

TEST_CASE("test_001_CreateValidator_With_Default_Parameters", "[ExtendedValidator]") {
    auto validator = std::make_shared<ExtendedValidator>();

    REQUIRE(!validator->ignoreSelfSignature());
    REQUIRE(!validator->ignoreVirgilSignature());
    REQUIRE(validator->whitelist().size() == 0);
    REQUIRE(validator->rules().size() == 0);
}

TEST_CASE("test_002_CreateValidator_With_Whitelist", "[ExtendedValidator]") {
    TestConst consts;
    auto validator = ExtendedValidator(
            {{consts.applicationId(), consts.applicationPublicKeyBase64()}}
    );

    REQUIRE(!validator.ignoreSelfSignature());
    REQUIRE(!validator.ignoreVirgilSignature());
    REQUIRE(validator.whitelist().size() == 1);
    REQUIRE(validator.rules().size() == 0);
}

TEST_CASE("test_003_CreateEmptyValidator", "[ExtendedValidator]") {
    ExtendedValidator validator(
            {},         //Whitelist
            true,       //ignoreSelfSignature
            true        //ignoreVirgilSignature
    );

    REQUIRE(validator.ignoreSelfSignature());
    REQUIRE(validator.ignoreVirgilSignature());
    REQUIRE(validator.whitelist().size() == 0);
    REQUIRE(validator.rules().size() == 0);
}

TEST_CASE("test_004_InitializingValidator_Should_makeRules", "[ExtendedValidator]") {
    TestConst consts;
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = ExtendedValidator(
            {{consts.applicationId(), consts.applicationPublicKeyBase64()}}
    );

    REQUIRE(validator.rules().size() == 0);
    validator.initialize(crypto);

    REQUIRE(validator.rules().size() == 3);
}

TEST_CASE("test_005_Card_ShouldBe_Valid", "[CardValidator]") {
    TestConst consts;
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = ExtendedValidator(
            {{consts.applicationId(), consts.applicationPublicKeyBase64()}},
            true,
            false
    );
    validator.initialize(crypto);

    CardTest card;

    card.signatures_ =
            {{kServiceCardId, ByteArrayUtils::stringToBytes(kServicePublicKey)},
             {consts.applicationId(), ByteArrayUtils::stringToBytes(consts.applicationPublicKeyBase64())}};

    auto result = validator.validateCard(crypto, card);

    REQUIRE(result.errors().size() == 0);
    REQUIRE(result.isValid());
}


TEST_CASE("test_006_Card_ShouldNotBe_Valid_without_Signature", "[CardValidator]") {
    TestConst consts;
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = ExtendedValidator(
            {{consts.applicationId(), consts.applicationPublicKeyBase64()}},
            true,
            false
    );
    validator.initialize(crypto);

    CardTest card;

    card.signatures_ = {};

    auto result = validator.validateCard(crypto, card);

    REQUIRE(result.errors().size() == 2);
    REQUIRE(!result.isValid());
}

TEST_CASE("test_007_Card_ShouldNotBe_Valid", "[CardValidator]") {
    TestConst consts;
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = ExtendedValidator(
            {{consts.applicationId(), consts.applicationPublicKeyBase64()}},
            true,
            true
    );
    validator.initialize(crypto);

    CardTest card;

    card.signatures_ = {};

    auto result = validator.validateCard(crypto, card);

    REQUIRE(result.errors().size() == 1);
    REQUIRE(!result.isValid());
}

TEST_CASE("test_008_UnValidCard_ButVersion3.0_ShouldValidate", "[CardValidator]") {
    TestConst consts;
    auto crypto = std::make_shared<CryptoTest>();
    auto validator = ExtendedValidator(
            {{consts.applicationId(), consts.applicationPublicKeyBase64()}},
            true,
            false
    );
    validator.initialize(crypto);

    CardTest card;

    card.signatures_ = {};
    card.cardVersion_ = "3.0";

    auto result = validator.validateCard(crypto, card);

    REQUIRE(result.errors().size() == 0);
    REQUIRE(result.isValid());
}

