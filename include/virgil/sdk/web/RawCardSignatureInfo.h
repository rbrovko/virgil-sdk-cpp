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


#ifndef VIRGIL_SDK_SIGNATURE_H
#define VIRGIL_SDK_SIGNATURE_H

#include <string>
#include <virgil/sdk/web/ClientCommon.h>
#include <virgil/sdk/Common.h>

namespace virgil {
    namespace sdk {
        namespace web {
            /*!
             * @brief represents signature info's structure for RawCard - with extra data in byte array
             */
            class RawCardSignatureInfo {
            public:
                RawCardSignatureInfo() = default;

                /*!
                 * @brief constructor
                 * @param sign VirgilByteArray with sign
                 * @param signType enum SignType with type of signature
                 * @param extraData VirgilByteArray with extra data
                 */
                RawCardSignatureInfo(const util::ByteArray& sign,
                              const SignType& signType = SignType::application,
                              const util::ByteArray& extraData = std::vector<unsigned char>())
                        : sign_(sign), signType_(signType), extraData_(extraData) {};

                /*!
                 * @brief Getter.
                 * @return VirgilByteArray with sign
                 */
                const ByteArray& sign() const { return sign_; }

                /*!
                 * @brief Getter.
                 * @return enum SignType with type of signature
                 */
                const SignType& signType() const { return signType_; }

                /*!
                 * @brief Getter.
                 * @return extraData VirgilByteArray with extra data
                 */
                const ByteArray& extraData() const { return extraData_; }

            private:
                ByteArray sign_;
                SignType signType_;
                ByteArray extraData_;
            };

        }
    }
}

#endif //VIRGIL_SDK_SIGNATURE_H
