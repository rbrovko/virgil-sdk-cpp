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

#ifndef VIRGIL_SDK_EXTENDEDVALIDATOR_H
#define VIRGIL_SDK_EXTENDEDVALIDATOR_H

#include <virgil/sdk/client/interfaces/CardValidatorInterface.h>
#include <virgil/sdk/client/interfaces/IntegrityPolicy.h>
#include <list>
#include <virgil/sdk/client/ValidationRules.h>

using virgil::sdk::client::interfaces::IntegrityPolicy;
using virgil::sdk::client::ValidationRules;

namespace virgil {
    namespace sdk {
        namespace client {
            /*!
             * Default implementation of CardValidatorInterface
             */
            class ExtendedValidator : public interfaces::CardValidatorInterface {
            public:
                /*!
                 * @brief constructor
                 * @param crypto Crypto instance
                 * @param rules rules for validation
                 */
                ExtendedValidator(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                  const ValidationRules &rules);

                bool validateCard(const interfaces::CardInterface &card) const override;

                bool checkVerifier(const interfaces::CardInterface &card,
                               const std::pair<std::string, VirgilByteArray> &verifier) const override;

            private:
                std::list<std::shared_ptr<IntegrityPolicy>> policy_;
                std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> crypto_;
            };
        }
    }
}


#endif //VIRGIL_SDK_EXTENDEDVALIDATOR_H
