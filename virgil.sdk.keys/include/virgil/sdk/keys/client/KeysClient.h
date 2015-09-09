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

#ifndef VIRGIL_SDK_KEYS_KEYS_CLIENT_H
#define VIRGIL_SDK_KEYS_KEYS_CLIENT_H

#include <memory>

#include <virgil/sdk/keys/client/KeysClientBase.h>
#include <virgil/sdk/keys/client/KeysClientConnection.h>

namespace virgil { namespace sdk { namespace keys { namespace client {
    /**
     * @name Forward declaration
     */
    //@{
    class KeysClientImpl;
    //@}
    /**
     * @brief Default implementation of KeysClientBase.
     */
    class KeysClient final : public KeysClientBase {
    public:
        /**
         * @brief Default API base address URI, i.e. https://keys.virgilsecurity.com/
         */
        static const std::string kBaseAddressDefault;
        /**
         * @brief Initialize with appropriate connection.
         */
        explicit KeysClient(const std::shared_ptr<KeysClientConnection>& connection);
        /**
         * @brief Initialize with application specific token and srevice base address.
         * @param appToken - application specific token.
         * @param baseAddress - service API base address.
         */
        explicit KeysClient(const std::string& appToken, const std::string& baseAddress = kBaseAddressDefault);
        /**
         * @name Default class implementation
         */
        //@{
        PublicKeyClientBase& publicKey() override;
        UserDataClientBase& userData() override;
        //@}
    private:
        std::shared_ptr<KeysClientImpl> impl_;
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_KEYS_CLIENT_H */