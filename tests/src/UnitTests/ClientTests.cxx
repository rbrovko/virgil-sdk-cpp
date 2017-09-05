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
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>
#include <virgil/sdk/client/models/CardIdGenerator.h>
#include <virgil/sdk/crypto/keys/PrivateKey.h>


#include <virgil/sdk/client/models/CardSigner.h>
#include <virgil/sdk/client/RequestManager.h>
#include <virgil/sdk/client/models/CardInfo.h>
#include <UnitTests/KeysTest.h>
#include <virgil/sdk/client/models/requests/SignableRequest.h>
using virgil::sdk::client::RequestManager;
using virgil::sdk::VirgilBase64;
using virgil::sdk::client::models::CardSigner;
using virgil::sdk::client::models::CardInfo;
using virgil::sdk::test::PrivateKeyTest;
using virgil::sdk::client::models::CardIdGenerator;
using virgil::sdk::crypto::keys::PrivateKey;

using virgil::sdk::client::models::interfaces::SignableRequestInterface;
using virgil::sdk::client::Client;
using virgil::sdk::test::TestConst;
using VirgilByteArrayUtils = virgil::crypto::VirgilByteArrayUtils;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::requests::RevokeCardRequest;
using virgil::sdk::client::models::CardRevocationReason;
using virgil::sdk::client::models::requests::SignableRequest;

using virgil::sdk::client::models::serialization::JsonTemplatedDeserializer;
using virgil::sdk::client::models::serialization::JsonSerializer;

//static std::string id = "e1b42a28ab36232b2e6543853b3724bc260bd1248800dc07b32868f2a85450c9";

//std::string testCreateRequest = "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkltNWxkbVZ5SWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW5SbGMzUWlMQ0p3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVRSYWR6RTBjak5XVEZBcmNWVkNObXhqVGxGbWEyazBPSGxVUTNGRlJraHdSekpsTVVkUlptOVhiV3M5SWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSjkiLCJtZXRhIjp7InNpZ25zIjp7ImUxYjQyYTI4YWIzNjIzMmIyZTY1NDM4NTNiMzcyNGJjMjYwYmQxMjQ4ODAwZGMwN2IzMjg2OGYyYTg1NDUwYzkiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRRllSUitEVnk5UVZCbjZsR2FlRjcrTlNYT1o5NExVWkxxOXJpMS9wRE5UVHgzUlZ3SzBHSGh3S1hkTVBaVWxFMVoxYnhaZkRXNUdyYVBRTlZUeHVIZ289IiwiZjRhZjYxYmFlM2ViNGQzMmUzYjFjODBhYTg5NmUyMDZiMjNlNjgwNDEwMDlkZWE1ZjNmODMwMmNjZTE4MWI0OSI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFQbUQ3dWd3TG1ZQmQrbm1iNlorR0l4Z1g5YmpHamNvalN6SVFCa0tXMmxwMWthdVBIY1ZvVkdkRmd0ekg3MTRMMlZ1UWg3cFdQL3Q3RlBHY1NwNEV3ST0ifX19";
//std::string testRevokeRequest = "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKallYSmtYMmxrSWpvaVpURmlOREpoTWpoaFlqTTJNak15WWpKbE5qVTBNemcxTTJJek56STBZbU15TmpCaVpERXlORGc0TURCa1l6QTNZak15T0RZNFpqSmhPRFUwTlRCak9TSXNJbkpsZG05allYUnBiMjVmY21WaGMyOXVJam9pZFc1emNHVmphV1pwWldRaWZRPT0iLCJtZXRhIjp7InNpZ25zIjp7ImY0YWY2MWJhZTNlYjRkMzJlM2IxYzgwYWE4OTZlMjA2YjIzZTY4MDQxMDA5ZGVhNWYzZjgzMDJjY2UxODFiNDkiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRQjlwV2FvWXl6SnhvZkxsZnhwTmdtVmVMMWs0bXY1QjZrRTVuZ1NIazhlTEhIMEJsbjBOeHgySGVPVEMxTzNXRUFwRjE3WldCVDQ5R3RwU2t3NmlVUUk9In19fQ==";

static std::string id = "94054cd4eacd7d9a515ab9be7dc449d54953b14ed1856da06e5b810d8c221497";

std::string testCreateRequest = "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkltNWxkbVZ5SWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW5SbGMzUWlMQ0p3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVROQlkwSkVOMU42UVhwb1JFZ3laRzVpZGs1TVZtUkRXVUpHYVV0WVQzcGxWVkl6V1hBeWJYVmlLMGs5SWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSjkiLCJtZXRhIjp7InNpZ25zIjp7Ijk0MDU0Y2Q0ZWFjZDdkOWE1MTVhYjliZTdkYzQ0OWQ1NDk1M2IxNGVkMTg1NmRhMDZlNWI4MTBkOGMyMjE0OTciOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRSVRNTVBtaE9XVHYwaGdGMjNLRFhXM1VRb0c5Z0wvMkRMU1E4U001WDB2ODlSM2tiN2g0VGo5UURQenVJS3I0dFBxSGVrMnZaVHlCUUlYZmxuZDFsUTg9IiwiZTY4M2FhOGFkOTUwOTVkOGJhYTg2NzYwODkyNzIyMTg5YTUzNGM3NjYxN2FkMWNkZGQwNDE4MjlmZDA1NTM5MCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFDWk5uSTQ2RlRkZ1RnbmlONjZyNkZDbnI5WHFLRkJXRG9IZjVidCt0a3FKZFAwV040dEtXTVN3aVhMVDdOWllNODZORzQwZFRNc3k5TFFRcStlOWdRST0ifX19";
std::string testRevokeRequest = "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKallYSmtYMmxrSWpvaU9UUXdOVFJqWkRSbFlXTmtOMlE1WVRVeE5XRmlPV0psTjJSak5EUTVaRFUwT1RVellqRTBaV1F4T0RVMlpHRXdObVUxWWpneE1HUTRZekl5TVRRNU55SXNJbkpsZG05allYUnBiMjVmY21WaGMyOXVJam9pZFc1emNHVmphV1pwWldRaWZRPT0iLCJtZXRhIjp7InNpZ25zIjp7ImU2ODNhYThhZDk1MDk1ZDhiYWE4Njc2MDg5MjcyMjE4OWE1MzRjNzY2MTdhZDFjZGRkMDQxODI5ZmQwNTUzOTAiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRQjNZUnJ3T0xNYzZlbkR5enlrN2JkWG4vazFNUjlmNTBaVlY1NjZzOEJ6eFk5UVdwTU5wMHZ5QnBDM1ljSTdBMmF4K21HSVVGTytUTGpQamNUbHVNUUU9In19fQ==";

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

    CardInfo parameters(
            identity,
            keyPair.publicKey(),
            "test",
            CustomData
    );

    auto createCardRequest = manager.createCardRequest(parameters, std::make_shared<PrivateKey>(keyPair.privateKey()));
    manager.signRequest(createCardRequest, RequestSigners);

    auto testCreate = createCardRequest.exportAsString();

    std::cout << testCreate << std::endl;

    auto id = CardIdGenerator::generate(crypto_, CreateCardRequest::importFromString(testCreate).snapshot());

    std::cout << id << std::endl;

    auto revokeCardRequest = manager.revokeCardRequest(id, RequestSigners);

    std::cout << revokeCardRequest.exportAsString() << std::endl;
}


TEST_CASE("test_001_CreateCard", "[client]") {

    auto createRequest = CreateCardRequest::importFromString(testCreateRequest);

    TestConst consts;
    Client client(consts.applicationToken());

    auto future = client.createCard(createRequest);
    auto cardRaw = future.get();

    REQUIRE(cardRaw.contentSnapshot() == createRequest.snapshot());
    REQUIRE(cardRaw.identifier() == id);
    REQUIRE(cardRaw.meta().signatures().size() == 3);
}


TEST_CASE("test_002_RevokeCard", "[client]") {

    auto request = RevokeCardRequest::importFromString(testRevokeRequest);

    TestConst consts;
    Client client(consts.applicationToken());

    auto future = client.revokeCard(request);
    future.get();
}*/