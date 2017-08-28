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

#ifndef VIRGIL_SDK_TESTKEYS_H
#define VIRGIL_SDK_TESTKEYS_H
#include <KeyPairInterface.h>
#include <virgil/sdk/Common.h>

using virgil::cryptointerfaces::PublicKeyInterface;
using virgil::cryptointerfaces::PrivateKeyInterface;
using virgil::cryptointerfaces::KeyPairInterface;

using VirgilByteArrayUtils = virgil::crypto::VirgilByteArrayUtils;

namespace virgil {
    namespace sdk {
        namespace test {

            class KeyPairTest;

            /*!
             * @brief implementation of PublicKeyInterface created for tests
             */
            class PublicKeyTest : public PublicKeyInterface {
            public:
                /// Implementation of CryptoInterface member functions\

                const byteArray &key() const override { return key_; }

                const byteArray &identifier() const override { return identifier_; }

                /*!
                 * @brief constructor which creates same key each time it called
                 */
                PublicKeyTest()
                        : key_(VirgilByteArrayUtils::stringToBytes("-----BEGIN PUBLIC KEY-----\n"
                                                                           "MCowBQYDK2VwAyEAedVKLoHYlzZBGhsR3I9TlI8pXwAYCDnRRs7d+j3vKxk=\n"
                                                                           "-----END PUBLIC KEY-----\n")),
                          identifier_(VirgilByteArrayUtils::stringToBytes(
                                  "\u0018\u0003��i�\u001D�Ǻtj+��Ɣ��Z ��$���p}E��")) {}

            private:

                byteArray key_;
                byteArray identifier_;

                friend KeyPairTest;
            };

            /*!
             * @brief implementation of PrivateKeyInterface created for tests
             */
            class PrivateKeyTest : public PrivateKeyInterface {
            public:

                /// Implementation of CryptoInterface member functions

                const byteArray &key() const override { return key_; }

                const byteArray &identifier() const override { return identifier_; }

                /*!
                 * @brief constructor which creates same key each time it called
                 */
                PrivateKeyTest()
                        : key_(VirgilByteArrayUtils::stringToBytes("-----BEGIN PRIVATE KEY-----\n"
                                                                           "MC4CAQAwBQYDK2VwBCIEIJTTFL3mtd5HXMCzJYG/WmLbey9LsOfqGFkoGV/QzbdI\n"
                                                                           "-----END PRIVATE KEY-----\n")),
                          identifier_(VirgilByteArrayUtils::stringToBytes(
                                  "\u0018\u0003��i�\u001D�Ǻtj+��Ɣ��Z ��$���p}E��")) {}

            private:
                byteArray key_;
                byteArray identifier_;

                friend KeyPairTest;
            };

            /*!
             * @brief implementation of KeyPairInterface created for tests
             */
            class KeyPairTest : public KeyPairInterface {
            public:

                /// Implementation of CryptoInterface member functions

                const PublicKeyTest &publicKey() const override { return publicKey_; }

                const PrivateKeyTest &privateKey() const override { return privateKey_; }

                /*!
                 * @brief constructor which creates key pair with test keys
                 */
                KeyPairTest()
                        : privateKey_(PrivateKeyTest()), publicKey_(PublicKeyTest()) {}

            private:

                PrivateKeyTest privateKey_;
                PublicKeyTest publicKey_;
            };
        }
    }
}

#endif //VIRGIL_SDK_TESTKEYS_H
