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

using virgil::sdk::crypto::keys::PrivateKey;

namespace virgil {
    namespace sdk {
        namespace client {
            class RevokeCardParams {
            public:
                RevokeCardParams(
                        std::string identifier,
                        std::map<std::string, PrivateKey> RequestSigners
                );

                std::string identifier;
                std::map<std::string, PrivateKey> RequestSigners;
            };
        }
    }
}


#endif //VIRGIL_SDK_REVOKECARDPARAMS_H
