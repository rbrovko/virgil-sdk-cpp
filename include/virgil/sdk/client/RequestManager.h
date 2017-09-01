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

#ifndef VIRGIL_SDK_REQUESTMANAGER_H
#define VIRGIL_SDK_REQUESTMANAGER_H

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/client/models/Card.h>
#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/client/models/requests/RevokeCardRequest.h>
#include <virgil/sdk/client/models/CardInfo.h>
#include <virgil/sdk/client/models/CardSigner.h>
#include <list>

using virgil::cryptointerfaces::CryptoInterface;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::requests::RevokeCardRequest;

namespace virgil {
    namespace sdk {
        namespace client {
            /*!
             * @brief Manager for creating and signing requests.
             */
            class RequestManager {
            public:

                /*!
                 * @brief Constructor
                 * @param crypto Custom instance of crypto which implements CryptoInterface
                 */
                RequestManager(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto);

                /*!
                 * @brief Creating signed CreateCardRequest
                 * @param cardInfo information of card to create request
                 * @params privateKey private key implementation for self signing
                 * @return CreateCardRequest for creating card
                 */
                const CreateCardRequest createCardRequest(const models::CardInfo &cardInfo,
                                                          const cryptointerfaces::PrivateKeyInterface &privateKey) const;

                /*!
                 * @brief Creating signed RevokeCardRequest
                 * @param identifier std::string with card id
                 * @param signers std::list with CardSigners for signing request
                 * @return RevokeCardRequest for revoking card
                 */
                const RevokeCardRequest revokeCardRequest(const std::string &identifier,
                                                          const std::list<models::CardSigner> &signers) const;

                /*!
                 * @brief signing CreateCardRequest with addition signs
                 * @param request request to sign
                 * @param signers std::list with CardSigners for signing request
                 */
                void signRequest(CreateCardRequest &request, const std::list<models::CardSigner> &signers) const;

            private:
                const std::shared_ptr<CryptoInterface> crypto_;
            };
        }
    }
}

#endif //VIRGIL_SDK_REQUESTMANAGER_H
