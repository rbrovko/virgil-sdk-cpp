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
#include <TestConst.h>
#include <virgil/sdk/client/Client.h>
#include <TestUtils.h>
#include <virgil/sdk/client/RequestSigner.h>
#include <virgil/sdk/client/models/serialization/JsonTemplatedDeserializer.h>

using virgil::sdk::client::models::interfaces::SignableRequestInterface;


using virgil::sdk::client::Client;
using virgil::sdk::test::TestConst;
using VirgilByteArrayUtils = virgil::crypto::VirgilByteArrayUtils;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::requests::RevokeCardRequest;
using virgil::sdk::client::models::CardRevocationReason;

using virgil::sdk::client::models::serialization::JsonTemplatedDeserializer;

static std::string id;

std::string TestCreateRequest = "{\"content_snapshot\":\"eyJpZGVudGl0eSI6Im5ldmVyIiwiaWRlbnRpdHlfdHlwZSI6InRlc3QiLCJwdWJsaWNfa2V5IjoiTUNvd0JRWURLMlZ3QXlFQVIraXB4ZHo2bDMrMm91d1NXaVVUU2hIN21TdEh3NDBjQ1hEelFBbVZDZkk9Iiwic2NvcGUiOiJhcHBsaWNhdGlvbiJ9\",\"meta\":{\"signs\":{\"9756e6de48e77554c49a8335c8fbbb7eeb3a9dc7b9e112226f222ab10a55ade2\":\"MFEwDQYJYIZIAWUDBAICBQAEQEmmJSbZsmtnc9jroJQHHuB97zdvb2d1ltQVGiYIUbyllhzxX8o1OXhPEFFTCjxdYgfYmsWRV/nbvKwEUM4qtwg=\",\"e683aa8ad95095d8baa86760892722189a534c76617ad1cddd041829fd055390\":\"MFEwDQYJYIZIAWUDBAICBQAEQMxNreKsQDdrZvX26EH3wYZsNoNgo0xK/UMludS4G8IqEf9mxvMMWuhwHtVR0rw0Lr+sGwjLSou1EF9s0WgTFwo=\"}}}";
std::string TestRevokeRequest;


TEST_CASE("test_001_CreateCard", "[client]") {
/*
    auto request = JsonTemplatedDeserializer<SignableRequestInterface>::fromJson<CreateCardRequest>(TestCreateRequest);

    TestConst consts;
    Client client(consts.applicationToken());

    auto future = client.createCard(request);
    auto cardRaw = future.get();
    */
}

TEST_CASE("test_002_RevokeCard", "[client]") {

}



/*
void doTheThing() {

    TestConst consts;

    auto crypto_ = std::make_shared<Crypto>();
    RequestManager manager(crypto_);                                     //creating RequestManager
    auto keyPair = crypto_->generateKeyPair();                           //making KeyPair

    auto privateAppKeyData = VirgilBase64::decode(consts.applicationPrivateKeyBase64());
    auto appPrivateKey = crypto_->importPrivateKey(privateAppKeyData, consts.applicationPrivateKeyPassword());

    auto identity = "never";

    std::list<CardSigner> RequestSigners;
    RequestSigners.push_back(
            CardSigner(consts.applicationId(), appPrivateKey)
    );

    std::unordered_map<std::string, std::string> CustomData;
    CustomData["some_random_key1"] = "some_random_data1";
    CustomData["some_random_key2"] = "some_random_data2";

    //making CardParams
    CreateCardParams parameters(
            identity,                                    //Identity
            "test",                                      //IdentityType
            keyPair,                                     //keyPair
            RequestSigners,                               //RequestSigners
            true,                                        //GenerateSignature
            CustomData                                         //CustomFields
    );

    auto CreateCardRequest = manager.createCardRequest(parameters);
}
 */