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
#include <UnitTests/SignableTest.h>

#include <virgil/sdk/client/RequestSigner.h>
#include <UnitTests/CryptoTest.h>

using virgil::sdk::client::RequestSigner;
using virgil::sdk::test::CryptoTest;
using virgil::sdk::test::SignableTest;
using virgil::sdk::test::KeyPairTest;

TEST_CASE("test_001_AutoritySign", "[RequestSigner]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto signer = RequestSigner(crypto);

    KeyPairTest keyPair;
    SignableTest request;
    auto appId = "appId";

    signer.authoritySign(
            request,
            appId,
            keyPair.privateKey()
    );

    auto signatures = request.signatures();
    REQUIRE(signatures.size() == 1);
    REQUIRE(signatures[appId] == VirgilByteArrayUtils::stringToBytes("signature"));
}

TEST_CASE("test_002_SelfSign", "[RequestSigner]") {
    auto crypto = std::make_shared<CryptoTest>();
    auto signer = RequestSigner(crypto);

    KeyPairTest keyPair;
    SignableTest request;
    auto randData = VirgilByteArrayUtils::stringToBytes("data");
    auto cardId = VirgilByteArrayUtils::bytesToHex(crypto->calculateFingerprint(randData));

    signer.selfSign(
            request,
            keyPair.privateKey()
    );

    auto signatures = request.signatures();
    REQUIRE(signatures.size() == 1);
    REQUIRE(signatures[cardId] == VirgilByteArrayUtils::stringToBytes("signature"));
}