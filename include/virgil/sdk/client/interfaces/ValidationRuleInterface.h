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

#ifndef VIRGIL_SDK_INTEGRITYPOLICY_H
#define VIRGIL_SDK_INTEGRITYPOLICY_H

#include <virgil/sdk/client/interfaces/CardInterface.h>
#include <virgil/sdk/client/interfaces/CardValidatorInterface.h>
#include <CryptoInterface.h>
#include <virgil/sdk/client/ValidationResult.h>

using virgil::sdk::client::interfaces::CardInterface;
using virgil::sdk::client::interfaces::CardValidatorInterface;

namespace virgil {
    namespace sdk {
        namespace client {
            namespace interfaces {
                /*!
                 * @brief base class for validation policy implamantations
                 */
                class ValidationRuleInterface {
                public:
                    /*!
                     * validate card in different way depends on policy implementation
                     * @param crypto crypto implementation
                     * @param card card implementation to validate
                     * @return bool whether or not card is valid
                     */
                   virtual void check(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                      const CardInterface &card,
                                      ValidationResult &result) const = 0;

                    virtual ~ValidationRuleInterface() = default;
                };
            }
        }
    }
}

#endif //VIRGIL_SDK_INTEGRITYPOLICY_H
