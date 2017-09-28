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

#include <list>
#include <TestUtils.h>
#include <helpers.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>

#include <virgil/sdk/web/CardsClient.h>
#include <virgil/sdk/crypto/keys/PublicKey.h>
#include <virgil/sdk/CardSigner.h>

using virgil::sdk::CSRParams;
using virgil::sdk::CardManagerParams;
using virgil::sdk::crypto::keys::PublicKey;

using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::test::Utils;
using virgil::sdk::test::TestUtils;
using virgil::sdk::serialization::JsonDeserializer;
using virgil::sdk::CardIdGenerator;

using virgil::sdk::web::CardsClient;
using virgil::sdk::interfaces::SignableRequestInterface;
using virgil::sdk::serialization::JsonSerializer;
using virgil::sdk::web::RawCard;
using virgil::sdk::CardSigner;
using virgil::cryptointerfaces::PrivateKeyInterface;

CSR TestUtils::instantiateCreateCardRequest(
        const std::unordered_map<std::string, std::string> &data) const {

    CardManagerParams managerParams(
            crypto_,
            consts.applicationToken()
    );

    CardManager manager(managerParams);

    auto keyPair = crypto_->generateKeyPair();

    auto privateAppKeyData = Base64::decode(consts.applicationPrivateKeyBase64());
    auto appPrivateKey = crypto_->importPrivateKey(privateAppKeyData, consts.applicationPrivateKeyPassword());

    auto identity = Utils::generateRandomStr(40);

    CSRParams csrParams(
            identity,
            keyPair.publicKey(),
            std::make_shared<PrivateKey>(keyPair.privateKey())
    );

    auto csr = manager.generateCSR(csrParams);

    std::list<CardSigner> requestSigners;
    requestSigners.push_back(
            CardSigner(consts.applicationId(), appPrivateKey)
    );

    manager.signCSR(csr, requestSigners);

    return csr;
}


Card TestUtils::instantiateCard() const {
    CardsClient client(consts.applicationToken());

    auto createCardRequest = instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);
    auto cardRaw = future.get();

    auto card = Card::parse(crypto_, cardRaw);

    return card;
}

bool TestUtils::checkCardEquality(const Card &card, const CSR &request) {
    auto equals = card.identity() == request.snapshotModel().identity();
        //&& card.publicKey() == request.snapshotModel().publicKeyData()

    return equals;
}

bool TestUtils::checkCardEquality(const Card &card1, const Card &card2) {
    auto equals = card1.identity() == card2.identity()
                  && CardIdGenerator::generate(card1.fingerprint()) == CardIdGenerator::generate(card2.fingerprint())
                  && card1.createdAt() == card2.createdAt()
                  && card1.cardVersion() == card2.cardVersion()
                  && card1.publicKey()->key() == card2.publicKey()->key();

    return equals;
}

bool TestUtils::checkCreateCardRequestEquality(const CSR &request1, const CSR &request2) {
    auto equals = request1.snapshot() == request2.snapshot()
                  //&& request1.signatures() == request2.signatures()
                  && request1.snapshotModel().identity() == request2.snapshotModel().identity()
                  && request1.snapshotModel().publicKeyData() == request2.snapshotModel().publicKeyData();

    return equals;
}
