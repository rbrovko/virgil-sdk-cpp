//
// Created by Eugen Pivovarov on 8/11/17.
//

#ifndef VIRGIL_SDK_CREATECARDPARAMS_H
#define VIRGIL_SDK_CREATECARDPARAMS_H

#include <string>
#include <virgil/sdk/crypto/keys/KeyPair.h>
#include <unordered_map>
#include <map>
#include <virgil/sdk/crypto/keys/PrivateKey.h>

using virgil::sdk::crypto::keys::KeyPair;
using virgil::sdk::crypto::keys::PrivateKey;

namespace virgil {
    namespace sdk {
        namespace client {
            class CreateCardParams {
            public:
                CreateCardParams(
                        std::string Identity,
                        std::string IdentityType,
                        KeyPair keyPair,
                        std::map<std::string, PrivateKey> RequestSigners,
                        bool GenerateSelfSignature = true,
                        std::unordered_map<std::string, std::string> customFields
                        = std::unordered_map<std::string, std::string>()
                );

                std::string Identity;
                std::string IdentityType;
                KeyPair keyPair;
                std::map<std::string, PrivateKey> RequestSigners;
                std::unordered_map<std::string, std::string> customFields;
                bool GenerateSelfSignature;
            };
        }
    }
}

#endif //VIRGIL_SDK_CREATECARDPARAMS_H
