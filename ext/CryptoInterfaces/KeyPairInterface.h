//
// Created by Eugen Pivovarov on 8/14/17.
//

#ifndef VIRGIL_SDK_KEYPAIRINTERFACE_H
#define VIRGIL_SDK_KEYPAIRINTERFACE_H

#include "PrivateKeyInterface.h"
#include "PublicKeyInterface.h"

namespace virgil {
    namespace cryptointerfaces {
        class KeyPairInterface {
        public:
            virtual ~KeyPairInterface() = default;

            /*!
            * @brief Getter.
            * @return Public Key
            */
            virtual const PublicKeyInterface& publicKey() const = 0;

            /*!
             * @brief Getter.
             * @return Private Key
             */
            virtual const PrivateKeyInterface& privateKey() const = 0;
        };
    }
}

#endif //VIRGIL_SDK_KEYPAIRINTERFACE_H
