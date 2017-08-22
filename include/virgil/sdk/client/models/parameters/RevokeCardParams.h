//
// Created by Eugen Pivovarov on 8/11/17.
//

#ifndef VIRGIL_SDK_REVOKECARDPARAMS_H
#define VIRGIL_SDK_REVOKECARDPARAMS_H

#include <string>
#include <virgil/sdk/crypto/keys/KeyPair.h>
#include <unordered_map>
#include <map>
#include <virgil/sdk/crypto/keys/PrivateKey.h>
#include <virgil/sdk/client/models/CardSigner.h>
#include <list>

using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::client::models::CardSigner;

namespace virgil {
    namespace sdk {
        namespace client {
            namespace models {
                namespace parameters {
                    /*!
                     * @brief container for parameters needed to create Card
                     */
                    class RevokeCardParams {
                    public:
                        /*!
                         * @brief Constructor
                         * @param identifier Card ID
                         * @param RequestSigners map of request signers
                         */
                        RevokeCardParams(
                                std::string identifier,
                                std::list<CardSigner> RequestSigners
                        );

                        std::string identifier;
                        std::list<CardSigner> RequestSigners;
                    };
                }
            }
        }
    }
}


#endif //VIRGIL_SDK_REVOKECARDPARAMS_H
