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

#ifndef VIRGIL_SDK_CARDINFO_H
#define VIRGIL_SDK_CARDINFO_H

#include <string>
#include <unordered_map>
#include <PublicKeyInterface.h>

using virgil::cryptointerfaces::PublicKeyInterface;

namespace virgil {
    namespace sdk {
        namespace client {
            namespace models {
                /*!
                 * @brief card information representation
                 */
                class CardInfo {
                public:
                    /*!
                     * @brief constructor
                     * @param identity std::string with card identity
                     * @param publicKey implementation of PublicKeyInterface
                     * @param identityType std::string with identity type
                     * @param customFields unordered map with custom strings
                     */
                    CardInfo(
                            const std::string &identity,
                            const PublicKeyInterface &publicKey,
                            const std::string &identityType = "unknown",
                            std::unordered_map<std::string, std::string> customFields
                            = std::unordered_map<std::string, std::string>())
                    : identity_(identity),
                      identityType_(identityType),
                      publicKey_(publicKey),
                      customFields_(customFields) {}

                    /*!
                    * @brief Getter.
                    * @return std::string with card identity
                    */
                    const std::string& identity() const { return identity_; }

                    /*!
                    * @brief Getter.
                    * @return std::string with card identity type
                    */
                    const std::string& identityType() const { return identityType_; }

                    /*!
                    * @brief Getter.
                    * @return reference to stored Public Key
                    */
                    const PublicKeyInterface& publicKey() const { return publicKey_; }

                    /*!
                    * @brief Getter.
                    * @return std::unordered_map with card string custom fields
                    */
                    const std::unordered_map<std::string, std::string>& customFields() const { return customFields_; }

                private:
                    const std::string identity_;
                    const std::string identityType_;
                    const PublicKeyInterface &publicKey_;
                    std::unordered_map<std::string, std::string> customFields_;
                };

            }
        }
    }
}

#endif //VIRGIL_SDK_CARDINFO_H
