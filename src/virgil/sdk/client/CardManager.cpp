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

#include <virgil/sdk/client/CardManager.h>
#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/ExtendedValidator.h>
#include <virgil/sdk/VirgilSdkError.h>
#include <virgil/sdk/client/models/errors/VirgilError.h>
#include <thread>

using virgil::sdk::make_error;
using virgil::sdk::client::Client;
using virgil::sdk::client::CardManager;
using virgil::cryptointerfaces::CryptoInterface;
using virgil::sdk::client::ExtendedValidator;
using virgil::sdk::client::models::Card;

CardManager::CardManager(const CardManagerParams &cardManagerParams)
        : client_(Client(cardManagerParams.apiToken())),
          crypto_(cardManagerParams.crypto()),
          validator_(cardManagerParams.validator()) {
    validator_->initialize(crypto_);
}

std::future<Card> CardManager::getCard(const std::string &cardId) const {
    auto future = std::async([=]{
        auto cardRaw = client_.getCard(cardId);
        auto card = Card::ImportRaw(crypto_, cardRaw.get());

        auto validationResult = validator_->validateCard(crypto_, card);
        if (!validationResult.isValid()) {
            throw make_error(VirgilSdkError::VerificationFailed, validationResult.errors().front());
        }

        return card;
    });

    return future;
}


std::future<Card> CardManager::createCard(const models::requests::CreateCardRequest &request) const {
    auto future = std::async([=]{
        auto cardRaw = client_.createCard(request);
        auto card = Card::ImportRaw(crypto_, cardRaw.get());

        auto validationResult = validator_->validateCard(crypto_, card);
        if (!validationResult.isValid()) {
            throw make_error(VirgilSdkError::VerificationFailed, validationResult.errors().front());
        }

        return card;
    });

    return future;
}

std::future<std::vector<Card>> CardManager::searchCards(const models::SearchCardsCriteria &criteria) const {
    auto future = std::async([=]{
        auto futureCardsRaw = client_.searchCards(criteria);
        auto cardsRaw = futureCardsRaw.get();

        std::vector<Card> cards;

        for (const auto& cardRaw : cardsRaw)
            cards.push_back(Card::ImportRaw(crypto_, cardRaw));


        for (const auto& card : cards) {
            auto validationResult = validator_->validateCard(crypto_, card);
            if (!validationResult.isValid()) {
                throw make_error(VirgilSdkError::VerificationFailed, validationResult.errors().front());
            }
        }

        return cards;
    });

    return future;
}

std::future<void> CardManager::revokeCard(const models::requests::RevokeCardRequest &request) const {
    auto future = std::async([=]{
        auto cardRaw = client_.revokeCard(request);
        cardRaw.get();

        return;
    });

    return future;
}