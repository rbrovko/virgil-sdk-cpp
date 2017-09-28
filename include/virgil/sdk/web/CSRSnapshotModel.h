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

#ifndef VIRGIL_SDK_CREATECARDSNAPSHOTMODEL_H
#define VIRGIL_SDK_CREATECARDSNAPSHOTMODEL_H

#include <string>
#include <unordered_map>

#include <virgil/sdk/web/ClientCommon.h>
#include <virgil/sdk/serialization/JsonSerializer.h>
#include <virgil/sdk/util/ByteArrayUtils.h>

namespace virgil {
    namespace sdk {
        namespace web {
            /*!
             * @brief Model which contains basic Virgil Card data needed for Card Creation.
             */
            class CSRSnapshotModel {
            public:
                /*!
                 * @brief Required within std::future
                 */
                CSRSnapshotModel() = default;

                /*!
                 * @brief Creates CSRSnapshotModel instance and initializes with given parameters.
                 * @param identity std::string with Card identity
                 * @param publicKeyData raw representation of Card's public key
                 * @return initialized CSRSnapshotModel instance
                 */
                static CSRSnapshotModel createModel(const std::string &identity,
                                                    const util::ByteArray &publicKeyData);

                /*!
                 * @brief Getter.
                 * @return std::string with Card identity
                 */
                const std::string& identity() const { return identity_; }

                /*!
                 * @brief Getter.
                 * @return raw representation of Card's public key
                 */
                const util::ByteArray & publicKeyData() const { return publicKeyData_; }


            private:
                CSRSnapshotModel(std::string identity, util::ByteArray publicKeyData);

                std::string identity_;
                util::ByteArray publicKeyData_;
            };
        }
    }
}

#endif //VIRGIL_SDK_CREATECARDSNAPSHOTMODEL_H
