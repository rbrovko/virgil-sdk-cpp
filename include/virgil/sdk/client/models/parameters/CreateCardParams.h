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

using virgil::cryptointerfaces::KeyPairInterface;
using virgil::cryptointerfaces::PrivateKeyInterface;

namespace virgil {
    namespace sdk {
        namespace client {
            namespace parameters {
                /*!
                 * @brief container for parameters needed to create Card
                 */
                class CreateCardParams {
                public:
                    /*!
                     * @brief Constructor
                     * @param Identity                  identity field
                     * @param IdentityType              type of identity
                     * @param keyPair                   key pair generated by custom crypto
                     * @param RequestSigners            map of RequestSingers
                     * @param GenerateSelfSignature     whether ot not you want selfSignature
                     * @param customFields              custom data fields
                     */
                    CreateCardParams(
                            std::string Identity,
                            std::string IdentityType,
                            KeyPairInterface &keyPair,
                            std::map<std::string, PrivateKeyInterface &> RequestSigners,
                            bool GenerateSelfSignature = true,
                            std::unordered_map<std::string, std::string> customFields
                            = std::unordered_map<std::string, std::string>()
                    );

                    std::string Identity;
                    std::string IdentityType;
                    KeyPairInterface &keyPair;
                    std::map<std::string, PrivateKeyInterface &> RequestSigners;
                    std::unordered_map<std::string, std::string> customFields;
                    bool GenerateSelfSignature;
                };
            }
        }
    }
}

#endif //VIRGIL_SDK_CREATECARDPARAMS_H
