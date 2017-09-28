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

#ifndef VIRGIL_SDK_CARDMANAGER_H
#define VIRGIL_SDK_CARDMANAGER_H

#include <CryptoInterface.h>
#include <virgil/sdk/web/CardsClient.h>
#include <virgil/sdk/CardManagerParams.h>
#include <virgil/sdk/interfaces/CardValidatorInterface.h>
#include <virgil/sdk/Card.h>
#include <virgil/sdk/CSR.h>
#include <virgil/sdk/CardSigner.h>
#include <virgil/sdk/web/ClientCommon.h>
#include <virgil/sdk/CSRParams.h>

using virgil::sdk::CSRParams;
using virgil::sdk::CSR;
using virgil::sdk::CardManagerParams;

namespace virgil {
    namespace sdk {
        /*!
         * @brief manager for card manipulating with validation
         */
        class CardManager {
        public:
            /*!
             * @brief constructor
             */
            CardManager(const CardManagerParams &cardManagerParams);

            /*!
             * @brief Creating signed CreateCardRequest
             * @param cardInfo information of card to create request
             * @params privateKey private key implementation for self signing
             * @return CreateCardRequest for creating card
             */
            const CSR generateCSR(const CSRParams &csrParams) const;

            /*!
             * @brief signing CreateCardRequest with addition signs
             * @param request request to sign
             * @param signers std::list with CardSigners for signing request
             */
            void signCSR(CSR &request, const std::list<CardSigner> &signers,
                         const web::SignType &signType = web::SignType::application) const;

            /*!
            * @brief Returns Virgil Card from the Virgil Cards Service with given ID, if exists, and validates it.
            * @param cardId std::string with card ID
            * @return std::future with Card
            */
            std::future<Card> getCard(const std::string &cardId) const;

            /*!
            * @brief Creates Virgil Card instance on the Virgil Cards Service and validates it
            * Creates Virgil Card instance on the Virgil Cards Service and associates it with unique identifier.
            * Also makes the Card accessible for search/get/revoke queries from other users.
            * @see Card
            * @param request CreateCardRequest instance with Card data and signatures
            * @return std::future with validated Card
            */
            std::future<Card> createCard(const CSR &request) const;

            /*!
             * @brief Performs search of Virgil Cards using search criteria on the Virgil Cards Service and validates result
             * @param criteria SearchCardsCriteria instance with criteria for desired cards
             * @return std::future with std::vector which contains found cards in Card form
             */
            std::future<std::vector<Card>> searchCards(const web::SearchCardsCriteria &criteria) const;


        private:

            std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> crypto_;
            std::shared_ptr<interfaces::CardValidatorInterface> validator_;
            std::shared_ptr<web::CardsClient> client_;
        };
    }
}

#endif //VIRGIL_SDK_CARDMANAGER_H