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

#ifndef VIRGIL_SDK_SIGNABLEREQUESTTEST_H
#define VIRGIL_SDK_SIGNABLEREQUESTTEST_H

#include <virgil/sdk/client/models/interfaces/SignableRequestInterface.h>
#include <unordered_map>
#include <virgil/sdk/client/models/SignatureInfo.h>
#include <virgil/sdk/util/ByteArrayUtils.h>

using virgil::sdk::util::ByteArrayUtils;
using virgil::sdk::client::models::SignatureInfo;
using virgil::sdk::client::models::interfaces::SignableRequestInterface;

namespace virgil {
    namespace sdk {
        namespace test {
            /*!
             * @brief signable request implementation
             */
            class SignableTest : public SignableRequestInterface {
            public:
                /*!
                 * @brief default constructor
                 */
                SignableTest() = default;

                const ByteArray& snapshot() const override { return snapshot_; }

                const std::unordered_map<std::string, SignatureInfo>& signatures() const override
                { return signatures_; };

                void addSignature(SignatureInfo signature, std::string fingerprint) override {
                    signatures_[std::move(fingerprint)] = std::move(signature);
                };

            private:
                std::unordered_map<std::string, SignatureInfo> signatures_;
                ByteArray snapshot_;
            };
        }
    }
}

#endif //VIRGIL_SDK_SIGNABLEREQUESTTEST_H