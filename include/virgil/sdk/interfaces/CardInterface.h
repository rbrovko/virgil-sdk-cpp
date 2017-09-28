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

#ifndef VIRGIL_SDK_CARDINTERFACE_H
#define VIRGIL_SDK_CARDINTERFACE_H

#include <unordered_map>
#include <string>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/web/ClientCommon.h>
#include <virgil/sdk/interfaces/Exportable.h>
#include <virgil/sdk/interfaces/Importable.h>
#include <CryptoInterface.h>

#include <virgil/sdk/web/RawCard.h>
#include <virgil/sdk/CardSignatureInfo.h>

namespace virgil {
    namespace sdk {
        namespace interfaces {
            /*!
             * @brief Interface for custom implemented Card
             */
            class CardInterface {
            public:

                /*!
                 * @brief Virtual destructor.
                 */
                virtual ~CardInterface() = default;

                /*!
                 * @brief Getter.
                 * @return byteArray with snapshot
                 */
                virtual const ByteArray &snapshot() const = 0;

                /*!
                 * @brief Getter.
                 * @return byteArray with fingerprint
                 */
                virtual const ByteArray &fingerprint() const = 0;

                /*!
                 * @brief Getter.
                 * @return std::string with card identity
                 */
                virtual const std::string &identity() const = 0;

                /*!
                 * @brief Getter.
                 * @return raw representation of Public Key which corresponds to this Card
                 */
                virtual const std::shared_ptr<cryptointerfaces::PublicKeyInterface> &
                publicKey() const = 0;

                /*!
                 * @brief Getter.
                 * @return std::string with date of Card creation (format is yyyy-MM-dd'T'HH:mm:ssZ)
                 */
                virtual const std::string &createdAt() const = 0;

                /*!
                 * @brief Getter.
                 * @return std::string with card version
                 */
                virtual const std::string &cardVersion() const = 0;

                /*!
                * @brief Getter.
                * @return unordered map with signatures
                */
                virtual const std::unordered_map<std::string, CardSignatureInfo> &signatures() const = 0;
            };
        }
    }
}

#endif //VIRGIL_SDK_CARDINTERFACE_H
