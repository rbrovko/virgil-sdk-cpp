//
// Created by Eugen Pivovarov on 8/11/17.
//

#ifndef VIRGIL_SDK_REQUESTMANAGER_H
#define VIRGIL_SDK_REQUESTMANAGER_H

#include "../../../../ext/CryptoInterfaces/CryptoInterface.h"
#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/client/models/parameters/CreateCardParams.h>
#include <virgil/sdk/client/models/parameters/RevokeCardParams.h>
#include <virgil/sdk/client/models/Card.h>
#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/client/models/requests/RevokeCardRequest.h>

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
                 * @param parameters all needed parameters for Creating Card
                 * @return CreateCardRequest for creating card
                 */
                CreateCardRequest CreateCardRequest(CreateCardParams &parameters);

                /*!
                 * @brief Creating signed RevokeCardRequest
                 * @param parameters all needed parameters for Revoking Card
                 * @return RevokeCardRequest for revoking card
                 */
                RevokeCardRequest RevokeCardRequest(RevokeCardParams &parameters);
            private:
                const std::shared_ptr<CryptoInterface> crypto_;
            };
        }
    }
}

#endif //VIRGIL_SDK_REQUESTMANAGER_H
