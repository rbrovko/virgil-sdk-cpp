/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <virgil/sdk/web/CardsClient.h>
#include <virgil/sdk/web/http/ClientRequest.h>
#include <virgil/sdk/web/http/Response.h>
#include <virgil/sdk/web/endpoints/CardEndpointUri.h>
#include <virgil/sdk/serialization/JsonSerializer.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/sdk/web/http/Connection.h>
#include <virgil/sdk/VirgilSdkError.h>
#include <virgil/sdk/web/errors/VirgilError.h>

#include <virgil/sdk/web/RawCard.h>

static_assert(!std::is_abstract<virgil::sdk::web::CardsClient>(), "Client must not be abstract.");

using virgil::sdk::make_error;
using virgil::sdk::web::CardsClient;
using virgil::sdk::web::http::Connection;
using virgil::sdk::web::http::ClientRequest;
using virgil::sdk::web::http::Response;
using virgil::sdk::web::endpoints::CardEndpointUri;
using virgil::sdk::serialization::JsonSerializer;
using virgil::sdk::serialization::JsonDeserializer;
using virgil::sdk::interfaces::SignableRequestInterface;
using virgil::sdk::CSR;
using virgil::sdk::Card;
using virgil::sdk::web::SearchCardsCriteria;
using virgil::sdk::web::ServiceConfig;
using virgil::sdk::web::errors::Error;
using virgil::sdk::web::errors::VirgilError;

using virgil::sdk::web::RawCard;

CardsClient::CardsClient(std::string accessToken)
        : CardsClient(ServiceConfig::createConfig(std::move(accessToken))) {
}

CardsClient::CardsClient(ServiceConfig serviceConfig)
        : serviceConfig_(std::move(serviceConfig)) {
}

Error CardsClient::parseError(const Response &response) const {
    try {
        auto virgilError = JsonDeserializer<VirgilError>::fromJsonString(response.body());
        return Error(response.statusCodeRaw(), virgilError);
    }
    catch (...) {
        return Error(response.statusCodeRaw(), VirgilError(0));
    }
}

std::future<RawCard> CardsClient::createCard(const CSR &request) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->serviceConfig_.token());
        httpRequest
                .post()
                .baseAddress(this->serviceConfig_.cardsServiceURL())
                .endpoint(CardEndpointUri::create())
                .body(JsonSerializer<SignableRequestInterface>::toJson(request));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto cardRaw = JsonDeserializer<RawCard>::fromJsonString(response.body());

        return cardRaw;
    });

    return future;
}

std::future<RawCard> CardsClient::getCard(const std::string &cardId) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->serviceConfig_.token());
        httpRequest
                .get()
                .baseAddress(this->serviceConfig_.cardsServiceROURL())
                .endpoint(CardEndpointUri::get(cardId));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto cardRaw = JsonDeserializer<RawCard>::fromJsonString(response.body());

        return cardRaw;
    });

    return future;
}

std::future<std::vector<RawCard>> CardsClient::searchCards(const SearchCardsCriteria &criteria) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->serviceConfig_.token());
        httpRequest
                .post()
                .baseAddress(this->serviceConfig_.cardsServiceROURL())
                .endpoint(CardEndpointUri::search())
                .body(JsonSerializer<SearchCardsCriteria>::toJson(criteria));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto cardsRaw = JsonDeserializer<std::vector<RawCard>>::fromJsonString(response.body());

        return cardsRaw;
    });

    return future;
}
