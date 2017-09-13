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

#ifndef VIRGIL_SDK_CLIENT_H
#define VIRGIL_SDK_CLIENT_H

#include <virgil/sdk/web/http/Response.h>
#include <virgil/sdk/web/ServiceConfig.h>
#include <virgil/sdk/interfaces/ClientInterface.h>
#include <virgil/sdk/web/errors/Error.h>


namespace virgil {
    namespace sdk {
        namespace web {
            /*!
             * @brief Default implementation of Client.
             */
            class CardsClient : public interfaces::ClientInterface {
            public:
                /*!
                 * @brief Constructor.
                 * @note For advanced setup see ServiceConfig
                 * @param accessToken std::string with access token generated from Virgil dashboard
                 */

                CardsClient(std::string accessToken);

                /*!
                 * @brief Constructor.
                 * @see ServiceConfig
                 * @param serviceConfig ServiceConfig instance with all data needed to initialize Client
                 */
                CardsClient(ServiceConfig serviceConfig);

                /*!
                 * @brief Getter.
                 * @return ServiceConfig instance used to setup Client
                 */
                const ServiceConfig& serviceConfig() const { return serviceConfig_; }

                std::future<RawCard> createCard(const CSR &request) const override;

                std::future<RawCard> getCard(const std::string &cardId) const override;

                std::future<std::vector<RawCard>> searchCards(
                        const SearchCardsCriteria &criteria) const override;

            private:
                errors::Error parseError(const http::Response &response) const;

                std::string accessToken_;
                ServiceConfig serviceConfig_;
            };
        }
    }
}

#endif //VIRGIL_SDK_CLIENT_H
