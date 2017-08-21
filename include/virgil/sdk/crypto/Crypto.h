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

#ifndef VIRGIL_SDK_CRYPTO_H
#define VIRGIL_SDK_CRYPTO_H

#include <virgil/sdk/Common.h>
#include <CryptoInterface.h>
#include <virgil/sdk/crypto/keys/KeyPair.h>

namespace virgil {
namespace sdk {
    namespace crypto {
        /*!
         * @brief Default implementation of CryptoInterface using VirgilCrypto lib
         */
        class Crypto: public cryptointerfaces::CryptoInterface {
        public:
            /// Implementation of CryptoInterface member functions

            VirgilByteArray exportPrivateKey(const cryptointerfaces::PrivateKeyInterface &privateKey,
                                             const std::string &password = "") const override;

            VirgilByteArray exportPublicKey(const cryptointerfaces::PublicKeyInterface &publicKey) const override;

            bool verify(std::istream &istream, const VirgilByteArray &signature,
                        const cryptointerfaces::PublicKeyInterface &signerPublicKey) const override;\

            bool verify(const VirgilByteArray &data, const VirgilByteArray &signature,
                        const cryptointerfaces::PublicKeyInterface &signerPublicKey) const override;

            VirgilByteArray generateSignature(const VirgilByteArray &data,
                                              const cryptointerfaces::PrivateKeyInterface &privateKey) const override;

            VirgilByteArray generateSignature(std::istream &istream, const cryptointerfaces::PrivateKeyInterface &privateKey) const override;

            byteArray calculateFingerprint(const VirgilByteArray &data) const override;

            keys::PublicKey* importPublicKey(const VirgilByteArray &data) const override;

            /*!
             * @brief Generates key pair using ed25519 algorithm.
             * @see KeyPair
             * @return generated KeyPair instance
             */
            keys::KeyPair generateKeyPair() const;

            /*!
             * @brief Imports Private Key with password from raw representation.
             * @param data Raw representation of Private Key
             * @param password std::string password for Private Key
             * @return imported PrivateKey instance
             */
            keys::PrivateKey importPrivateKey(const VirgilByteArray &data,
                                              const std::string& password = "") const;

            /*!
             * @brief Extracts corresponding Public Key from Private Key.
             * @param privateKey PrivateKey instance
             * @return extracted PublicKey instance with Public Key which corresponds to given Private Key
             */
            keys::PublicKey extractPublicKeyFromPrivateKey(const keys::PrivateKey &privateKey) const ;

            /*!
            * @brief Encrypts data.
            * @note Only those, who have Private Key corresponding to one of Public Keys in recipients vector
            *       will be able to decrypt data.
            * @param data data to be encrypted
            * @param recipients std::vector of PublicKey instances with recipients' Public Keys
            * @return encrypted data
            */
            VirgilByteArray encrypt(const VirgilByteArray &data,
                                    const std::vector<keys::PublicKey> &recipients) const ;

            /*!
             * @brief Encrypts stream.
             * @note Only those, who have Private Key corresponding to one of Public Keys in recipients vector
             *       will be able to decrypt data.
             * @param istream std::istream with data to be encrypted
             * @param ostream std::ostream where encrypted data will be pushed
             * @param recipients std::vector of PublicKey instances with recipients' Public Keys
             */
            void encrypt(std::istream &istream, std::ostream &ostream,
                         const std::vector<keys::PublicKey> &recipients) const ;


            /*!
             * @brief Decrypts data.
             * @param data data to be decrypted
             * @param privateKey Private Key of data recipient
             * @return decrypted data
             */
            VirgilByteArray decrypt(const VirgilByteArray &data, const keys::PrivateKey &privateKey) const ;

            /*!
             * @brief Decrypts stream.
             * @param istream std::istream with data to be decrypted
             * @param ostream std::ostream where decrypted data will be pushed
             * @param privateKey Private Key of data recipient
             */
            void decrypt(std::istream &istream, std::ostream &ostream,
                         const keys::PrivateKey &privateKey) const;

            /*!
             * @brief Signs and encrypts data.
             * @param data data to be signed and encrypted
             * @param privateKey Private Key of signer
             * @param recipients std::vector of PublicKey instances with recipients' Public Keys
             * @return signed and encrypted data
             */
            VirgilByteArray signThenEncrypt(const VirgilByteArray &data, const keys::PrivateKey &privateKey,
                                            const std::vector<keys::PublicKey> &recipients) const;

            /*!
             * @brief Decrypts and verifies data.
             * @param data signed and encrypted data
             * @param privateKey Private Key of recipient
             * @param signerPublicKey signer's Public Key
             * @return decrypted and verified data
             */
            VirgilByteArray decryptThenVerify(const VirgilByteArray &data, const keys::PrivateKey &privateKey,
                                              const keys::PublicKey &signerPublicKey) const;


            /// Additional functionality

            /*!
             * @brief Computes hash of data using selected algorithm.
             * @param data data of which hash is computed
             * @param algorithm hash algorithm
             * @return hash
             */
            VirgilByteArray computeHash(const VirgilByteArray &data, VirgilHashAlgorithm algorithm) const;

        private:
            VirgilByteArray computeHashForPublicKey(const VirgilByteArray &publicKey) const;
        };
    }
}
}

#endif //VIRGIL_SDK_CRYPTO_H
