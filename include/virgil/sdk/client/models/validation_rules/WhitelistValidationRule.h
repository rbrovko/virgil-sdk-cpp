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

#ifndef VIRGIL_SDK_APPLICATIONINTEGRITYPOLICY_H
#define VIRGIL_SDK_APPLICATIONINTEGRITYPOLICY_H


#include <virgil/sdk/client/interfaces/ValidationRuleInterface.h>
#include <virgil/sdk/client/ExtendedValidator.h>

namespace virgil {
    namespace sdk {
        namespace client {
            namespace models {
                namespace validation_rules {
                    /*!
                     * @brief implementation policy to validate application or custom signs
                     */
                    class WhitelistValidationRule : public ValidationRuleInterface {
                    public:

                        friend class ExtendedValidator;
                        /*!
                         * @brief constructor
                         * @param verifiers unordered map of verifiers to validate
                         * @param policy defines behavior of diagnise function
                         */
                        WhitelistValidationRule(const std::unordered_map<std::string, PublicKeyInterface*> &whitelist);

                    private:
                        bool check(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                      const CardInterface &card) const override;

                        std::unordered_map<std::string, PublicKeyInterface*> whitelist_;
                    };
                }
            }
        }
    }
}

#endif //VIRGIL_SDK_APPLICATIONINTEGRITYPOLICY_H
