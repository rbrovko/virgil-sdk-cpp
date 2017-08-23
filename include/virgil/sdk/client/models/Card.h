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


#ifndef VIRGIL_SDK_CARD_H
#define VIRGIL_SDK_CARD_H

#include <unordered_map>
#include <string>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/ClientCommon.h>
#include <virgil/sdk/client/models/interfaces/Exportable.h>
#include <virgil/sdk/client/models/interfaces/Importable.h>
#include <virgil/sdk/client/interfaces/CardInterface.h>

#include <virgil/sdk/client/models/responses/CardRaw.h>
#include <virgil/sdk/crypto/Crypto.h>

namespace virgil {
namespace sdk {
namespace client {
    namespace models {
        /*!
         * @brief Model that represents identities on the Virgil Cards Service.
         *
         * Each card has assigned identity of identityType, publicKey (and owner has corresponding private key),
         * info about device on which Card was created, custom payload, version,
         * creation date and scope (global or application)
         */
        class Card: public virgil::sdk::client::interfaces::CardInterface {
        public:
            /*!
             * @brief Required within std::future
             */
            Card() = default;

            /*!
             * @brief Creates Card instance from CardRaw with response form Virgil Service.
             * @param cardRaw CardRaw instance
             * @return instantiated Card instance
             */
            static Card ImportRaw(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto,
                                  const responses::CardRaw &cardRaw);

            std::string exportAsString() const override;

            /// WARNING: Calling side is responsible for validating cardResponse using CardValidator after this import!
            static Card importFromString(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto, const std::string &data);

            /*!
             * @brief Getter.
             * @return byteArray with snapshot
             */
            const VirgilByteArray& snapshot() const override { return snapshot_; }

            /*!
             * @brief Getter.
             * @return std::string with card ID
             */
            const std::string& identifier() const override { return identifier_; }

            /*!
             * @brief Getter.
             * @return std::string with card identity
             */
            const std::string& identity() const override { return identity_; }

            /*!
             * @brief Getter.
             * @return std::string with card identity type
             */
            const std::string& identityType() const override { return identityType_; }

            /*!
             * @brief Getter.
             * @return raw representation of Public Key which corresponds to this Card
             */
            const std::shared_ptr<cryptointerfaces::PublicKeyInterface>& publicKey() const override { return publicKey_; }

            /*!
             * @brief Getter.
             * @return std::unordered_map with custom user payload
             */
            const std::unordered_map<std::string, std::string>& data() const override { return data_; }

            /*!
             * @brief Getter.
             * @return CardScope (application or global)
             */
            CardScope scope() const override { return scope_; }

            /*!
             * @brief Getter.
             * @return std::string with date of Card creation (format is yyyy-MM-dd'T'HH:mm:ssZ)
             */
            const std::string& createdAt() const override { return createdAt_; }

            /*!
             * @brief Getter.
             * @return std::string with card version
             */
            const std::string& cardVersion() const override { return cardVersion_; }

            /*!
            * @brief Getter.
            * @return unordered map with signatures
            */
            const std::unordered_map<std::string, VirgilByteArray>& signatures() const override { return signatures_; }

        private:
            Card(responses::CardRaw cardRaw, VirgilByteArray snapshot, std::string identifier, std::string identity,
                 std::string identityType, std::shared_ptr<cryptointerfaces::PublicKeyInterface> publicKey,
                 std::unordered_map<std::string, std::string> data, CardScope scope,
                 std::string createdAt, std::string cardVersion,
                 std::unordered_map<std::string, VirgilByteArray> signatures);

            responses::CardRaw cardRaw_;
            VirgilByteArray snapshot_;
            std::string identifier_;
            std::string identity_;
            std::string identityType_;
            std::shared_ptr<cryptointerfaces::PublicKeyInterface> publicKey_;
            std::unordered_map<std::string, std::string> data_;
            CardScope scope_;
            std::string createdAt_;
            std::string cardVersion_;
            std::unordered_map<std::string, VirgilByteArray> signatures_;
        };
    }
}
}
}

#endif //VIRGIL_SDK_CARD_H
