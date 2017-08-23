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

#ifndef VIRGIL_SDK_TESTCRYPTO_H
#define VIRGIL_SDK_TESTCRYPTO_H

#include <vector>
#include "KeysTest.h"

using byteArray = std::vector<unsigned char>;
using virgil::cryptointerfaces::CryptoInterface;
using virgil::cryptointerfaces::PrivateKeyInterface;
using virgil::cryptointerfaces::PublicKeyInterface;
using VirgilByteArrayUtils = virgil::crypto::VirgilByteArrayUtils;

namespace virgil {
    namespace sdk {
        namespace test {
            /*!
             * @brief implementation of CryptoInterface created for tests
             */
            class CryptoTest : public CryptoInterface {
            public:
                CryptoTest() = default;

                /// Implementation of CryptoInterface member functions

                byteArray exportPublicKey(const PublicKeyInterface &privateKey) const override {
                    return VirgilByteArrayUtils::stringToBytes("test");
                }

                byteArray generateSignature(const byteArray &data,
                                            const PrivateKeyInterface &privateKey) const override {
                    return VirgilByteArrayUtils::stringToBytes("ƕ���Lą�o�鏆lR}\u001D�\u001E�\u0005");
                }

                bool verify(const byteArray &data, const byteArray &signature,
                            const PublicKeyInterface &signerPublicKey) const override { return true; }

                byteArray calculateFingerprint(const byteArray &data) const override {
                    return VirgilByteArrayUtils::stringToBytes("fingerprint");
                }

                PublicKeyInterface *
                importPublicKey(const byteArray &data) const override { return new PublicKeyTest(); }


                //NOT USED YET
                byteArray exportPrivateKey(const PrivateKeyInterface &privateKey,
                                           const std::string &password = "") const override {
                    return VirgilByteArrayUtils::stringToBytes("smth");
                }


                bool verify(std::istream &istream, const byteArray &signature,
                            const PublicKeyInterface &signerPublicKey) const override { return false; }


                byteArray generateSignature(std::istream &istream, const
                PrivateKeyInterface &privateKey) const override { return VirgilByteArrayUtils::stringToBytes("smth"); }
            };
        }
    }
}

#endif //VIRGIL_SDK_TESTCRYPTO_H