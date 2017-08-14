//
// Created by Eugen Pivovarov on 8/11/17.
//

#ifndef VIRGIL_SDK_REQUESTMANAGER_H
#define VIRGIL_SDK_REQUESTMANAGER_H

#include <virgil/sdk/crypto/CryptoInterface.h>
#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/client/CreateCardParams.h>
#include <virgil/sdk/client/RevokeCardParams.h>
#include <virgil/sdk/client/models/Card.h>
#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/client/models/requests/RevokeCardRequest.h>

using virgil::sdk::crypto::CryptoInterface;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::requests::RevokeCardRequest;

namespace virgil {
    namespace sdk {
        namespace client {
            class RequestManager {
            public:
                RequestManager(const std::shared_ptr<CryptoInterface> crypto_);

                CreateCardRequest CreateCardRequest(CreateCardParams parameters);
                RevokeCardRequest RevokeCardRequest(RevokeCardParams parameters);
            private:
                const std::shared_ptr<CryptoInterface> crypto_;
            };
        }
    }
}

#endif //VIRGIL_SDK_REQUESTMANAGER_H
