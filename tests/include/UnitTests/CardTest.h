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

#ifndef VIRGIL_SDK_CARDTEST_H
#define VIRGIL_SDK_CARDTEST_H

#include <unordered_map>
#include <string>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/ClientCommon.h>
#include <virgil/sdk/client/models/interfaces/Exportable.h>
#include <virgil/sdk/client/models/interfaces/Importable.h>
#include <virgil/sdk/client/interfaces/CardInterface.h>

#include <virgil/sdk/client/models/responses/RawCard.h>
#include <virgil/sdk/crypto/Crypto.h>
#include <vector>
#include <virgil/sdk/client/models/ClientCommon.h>

using byteArray = std::vector<unsigned char>;
using virgil::sdk::client::models::CardScope;

namespace virgil {
    namespace sdk {
        namespace test {
            /*!
             * @brief implementation of CardInterface created for tests
             */
            class CardTest : public virgil::sdk::client::interfaces::CardInterface {
            public:
                CardTest() = default;

                /*!
                 * @brief Getter.
                 * @return byteArray with snapshot
                 */
                const byteArray &snapshot() const override { return snapshot_; }

                /*!
                 * @brief Getter.
                 * @return byteArray with fingerprint
                 */
                const VirgilByteArray& fingerprint() const override { return fingerprint_; }

                /*!
                 * @brief Getter.
                 * @return std::string with card ID
                 */
                const std::string &identifier() const override { return identifier_; }

                /*!
                 * @brief Getter.
                 * @return std::string with card identity
                 */
                const std::string &identity() const override { return identity_; }

                /*!
                 * @brief Getter.
                 * @return std::string with card identity type
                 */
                const std::string &identityType() const override { return identityType_; }

                /*!
                 * @brief Getter.
                 * @return raw representation of Public Key which corresponds to this Card
                 */
                const std::shared_ptr<virgil::cryptointerfaces::PublicKeyInterface> &
                publicKey() const override { return publicKey_; }

                /*!
                 * @brief Getter.
                 * @return std::unordered_map with custom user payload
                 */
                const std::unordered_map<std::string, std::string> &data() const override { return data_; }

                /*!
                 * @brief Getter.
                 * @return CardScope (application or global)
                 */
                CardScope scope() const override { return scope_; }

                /*!
                 * @brief Getter.
                 * @return std::string with date of Card creation (format is yyyy-MM-dd'T'HH:mm:ssZ)
                 */
                const std::string &createdAt() const override { return createdAt_; }

                /*!
                 * @brief Getter.
                 * @return std::string with card version
                 */
                const std::string &cardVersion() const override { return cardVersion_; }

                /*!
                * @brief Getter.
                * @return unordered map with signatures
                */
                const std::unordered_map<std::string, byteArray> &signatures() const override { return signatures_; }

            public:
                byteArray snapshot_;
                byteArray fingerprint_;
                std::string identifier_;
                std::string identity_;
                std::string identityType_;
                std::shared_ptr<virgil::cryptointerfaces::PublicKeyInterface> publicKey_;
                std::unordered_map<std::string, std::string> data_;
                std::string createdAt_;
                std::string cardVersion_;
                CardScope scope_;
                std::unordered_map<std::string, byteArray> signatures_;
            };
        }
    }
}

#endif //VIRGIL_SDK_CARDTEST_H
