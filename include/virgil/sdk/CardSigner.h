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

#ifndef VIRGIL_SDK_CARDSIGNER_H
#define VIRGIL_SDK_CARDSIGNER_H

#include <PrivateKeyInterface.h>
#include <string>
#include <unordered_map>

namespace virgil {
    namespace sdk {
        /*!
         * @brief class for card signers representation
         */
        class CardSigner {
        public:
            CardSigner(const std::string &cardId, const cryptointerfaces::PrivateKeyInterface &privateKey,
                       const std::unordered_map<std::string, std::string> &extraData
                       = std::unordered_map<std::string, std::string>())
                    : cardId_(cardId), privateKey_(privateKey), extraData_(extraData) {};

            /*!
            * @brief Getter.
            * @return string with Card Id
            */
            const std::string& cardId() const { return cardId_; }

            /*!
            * @brief Getter.
            * @return instance of custom implemented Private Key class
            */
            const cryptointerfaces::PrivateKeyInterface& privateKey() const { return privateKey_; }

            /*!
            * @brief Getter.
            * @return std::unordered_map with extra data in strings
            */
            const std::unordered_map<std::string, std::string>& extraData() const { return extraData_; }

        private:
            std::string cardId_;
            const cryptointerfaces::PrivateKeyInterface &privateKey_;
            std::unordered_map<std::string, std::string> extraData_;
        };
    }
}

#endif //VIRGIL_SDK_CARDSIGNER_H
