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
#include <virgil/sdk/CSR.h>
#include <Mocks/CryptoTest.h>

//using virgil::sdk::util::Base64;

using virgil::sdk::util::ByteArrayUtils;
using virgil::sdk::CSR;
using virgil::sdk::CSRParams;
using virgil::sdk::test::CryptoTest;
using virgil::sdk::test::KeyPairTest;
using virgil::sdk::test::PrivateKeyTest;
using virgil::sdk::web::SignType;
using virgil::sdk::CardSigner;

TEST_CASE("test001_CreateCSR", "[CSR]") {
    auto crypto = std::make_shared<CryptoTest>();

    KeyPairTest keyPair;
    auto csrParams = CSRParams(
            "id",
            keyPair.publicKey()
    );

    auto csr = CSR::generate(crypto, csrParams);

    auto validCSR = "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkltbGtJaXdpY0hWaWJHbGpYMnRsZVNJNkltUkhWbnBrUVQwOUluMD0iLCJtZXRhIjp7InNpZ25zIjpudWxsfX0=";
    auto snap = "{\"identity\":\"id\",\"public_key\":\"dGVzdA==\"}";

    REQUIRE(ByteArrayUtils::bytesToString(csr.snapshot()) == snap);
    REQUIRE(csr.exportAsString() == validCSR);
    REQUIRE(csr.signatures().size() == 0);
}

TEST_CASE("test002_CreateCSR_ShouldBe_SelfSigned", "[CSR]") {
    auto crypto = std::make_shared<CryptoTest>();

    KeyPairTest keyPair;
    auto csrParams = CSRParams(
            "id",
            keyPair.publicKey(),
            std::make_shared<PrivateKeyTest>(keyPair.privateKey())
    );

    auto csr = CSR::generate(crypto, csrParams);

    auto validCSR = "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkltbGtJaXdpY0hWaWJHbGpYMnRsZ"
                    "VNJNkltUkhWbnBrUVQwOUluMD0iLCJtZXRhIjp7InNpZ25zIjp7IjY2Njk2ZTY3NjU3MjcwNzI2OTZl"
                    "NzQiOnsiZXh0cmFEYXRhIjoiIiwic2lnbiI6ImMybG5ibUYwZFhKbCIsInNpZ25UeXBlIjoic2VsZiJ9fX19";

    auto snap = "{\"identity\":\"id\",\"public_key\":\"dGVzdA==\"}";

    REQUIRE(ByteArrayUtils::bytesToString(csr.snapshot()) == snap);
    REQUIRE(csr.exportAsString() == validCSR);
    REQUIRE(csr.signatures().size() == 1);


    auto signatures = csr.signatures();
    auto Cardid = ByteArrayUtils::bytesToHex(crypto->calculateFingerprint(csr.snapshot()));
    REQUIRE(signatures[Cardid].sign() == ByteArrayUtils::stringToBytes("signature"));
    REQUIRE(signatures[Cardid].signType() == SignType::self);
}

TEST_CASE("test003_SignCSR_with_App", "[CSR]") {
    auto crypto = std::make_shared<CryptoTest>();

    KeyPairTest keyPair;
    auto csrParams = CSRParams(
            "id",
            keyPair.publicKey()
    );

    auto csr = CSR::generate(crypto, csrParams);

    std::string appId = "Random appId";

    auto cardSigner = CardSigner(
            appId,
            keyPair.privateKey()
    );

    csr.sign(crypto, cardSigner);

    auto signatures = csr.signatures();
    REQUIRE(csr.signatures().size() == 1);
    REQUIRE(signatures[appId].sign() == ByteArrayUtils::stringToBytes("signature"));
    REQUIRE(signatures[appId].signType() == SignType::application);
}

TEST_CASE("test004_CreatingCSR_withoutIdentity_ShouldThrowExeption", "[CSR]") {
    auto crypto = std::make_shared<CryptoTest>();

    KeyPairTest keyPair;
    auto csrParams = CSRParams(
            "",
            keyPair.publicKey()
    );

    bool errorWasThrown = false;
    try {
        auto csr = CSR::generate(crypto, csrParams);
    }
    catch(...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}