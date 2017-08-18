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

#ifndef VIRGIL_SDK_CRYPTOINTERFACE_H
#define VIRGIL_SDK_CRYPTOINTERFACE_H

#include <string>

#include "KeyPairInterface.h"
#include "PrivateKeyInterface.h"
#include "PublicKeyInterface.h"

using byteArray = std::vector<unsigned char>;

namespace virgil {
    namespace cryptointerfaces {
        /*!
         * @brief Interface for all cryptographic operations.
         */
        class CryptoInterface {
        public:

        /*!
         * @brief Imports Public Key from raw representation.
         * @param data raw representation of Public Key
         * @return pointer to implementation instance of PublicKeyInterface
         */
        virtual PublicKeyInterface* importPublicKey(const byteArray &data) = 0;

        /*!
         * @brief Exports Private Key to raw representation.
         * @param privateKey PrivateKey instance
         * @param password std::string password for Private Key export (required for further import)
         * @return raw representation of Private Key
         */
         virtual byteArray exportPrivateKey(const PrivateKeyInterface &privateKey,
                                                   const std::string &password = "") const = 0;

         /*!
          * @brief Exports Public Key to raw representation.
          * @param publicKey PublicKey instance
          * @return raw representation of Public Key
          */
          virtual byteArray exportPublicKey(const PublicKeyInterface &publicKey) const = 0;

           /*!
           * @brief Verifies data for genuineness.
           * @param data data to be verified
           * @param signature Signature
           * @param signerPublicKeyData PublicKeyData instance with signer's Public Key Data
           * @return true if data was successfully verified, false otherwise
           */
           virtual bool verify(const byteArray &data, const byteArray &signature,
                                    const PublicKeyInterface &signerPublicKey) const = 0;

           /*!
            * @brief Verifies stream for genuineness.
            * @param istream std::istream with data to be verified
            * @param signature Signatue
            * @param signerPublicKey PublicKey instance with signer's Public Keys
            * @return true if data was successfully verified, false otherwise
            */
           virtual bool verify(std::istream &istream, const byteArray &signature,
                                    const cryptointerfaces::PublicKeyInterface &signerPublicKey) const = 0;

            /*!
             * @brief Generates signature for data.
             * @param data data from which signature will be generated
             * @param privateKey signer's Private Key
             * @return Signature for data
             */
            virtual byteArray generateSignature(const byteArray &data,
                                                    const cryptointerfaces::PrivateKeyInterface &privateKey) const = 0;

            /*!
             * @brief Generates signature for stream.
             * @param istream std::istream with data from which signature will be generated
             * @param privateKey signer's Private Key
             * @return Signature for stream
             */
            virtual byteArray generateSignature(std::istream &istream, const
                                            cryptointerfaces::PrivateKeyInterface &privateKey) const = 0;

            /*!
             * @brief Calculates Fingerprint for data.
             * @param data data from which Fingerprint will be calculated
             * @return Fingerprint
             */
            virtual byteArray calculateFingerprint(const byteArray &data) const = 0;

            /*!
             * @brief Virtual destructor.
             */
            virtual ~CryptoInterface() = default;
            };
    }
}

#endif //VIRGIL_SDK_CRYPTOINTERFACE_H
