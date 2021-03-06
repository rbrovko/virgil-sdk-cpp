/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#ifndef VIRGIL_SDK_CREDENTIALS_H
#define VIRGIL_SDK_CREDENTIALS_H

#include <string>

#include <virgil/crypto/VirgilByteArray.h>

namespace virgil {
namespace sdk {
    /**
     * @brief Describe data object that stores user's credentials
     */
    class Credentials {
    public:
        /**
         * @brief Create object with invalid credentials
         * @see isValid()
         */
        Credentials() = default;
        /**
         * @brief Initialize credentials
         * @param privateKey - user's private key
         * @param privateKeyPassword - (optional) private key password if private key is encrypted
         */
        Credentials(const virgil::crypto::VirgilByteArray& privateKey,
                    const virgil::crypto::VirgilByteArray& privateKeyPassword = virgil::crypto::VirgilByteArray());
        /**
         * @brief Perform cleanup first
         * @see cleanup()
         */
        ~Credentials() noexcept;
        /**
         * @brief Check whether credentials are valid
         */
        bool isValid() const;
        /**
         * @brief Perform safe cleanup for all sensitive data
         * @note Credentials become invalid after perform this operation
         * @see isValid()
         */
        void cleanup() noexcept;
        /**
         * @brief Return private key
         * @note For security reason pass it by reference only
         */
        const virgil::crypto::VirgilByteArray& privateKey() const;
        /**
         * @brief Return private key password
         * @note For security reason pass it by reference only
         */
        const virgil::crypto::VirgilByteArray& privateKeyPassword() const;

    private:
        virgil::crypto::VirgilByteArray privateKey_;
        virgil::crypto::VirgilByteArray privateKeyPassword_;
    };
}
}

#endif /* VIRGIL_SDK_CREDENTIALS_H */
