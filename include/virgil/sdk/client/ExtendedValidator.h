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
#include <virgil/sdk/client/interfaces/ValidationRuleInterface.h>
#include <list>
#include <PublicKeyInterface.h>
#include <virgil/sdk/client/models/SignerInfo.h>

using virgil::sdk::client::interfaces::ValidationRuleInterface;
using virgil::cryptointerfaces::PublicKeyInterface;
using virgil::sdk::client::models::SignerInfo;

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
                ExtendedValidator(const std::list<SignerInfo> &whitelist = {{}},
                                  const bool &ignoreSelfSignature = false,
                                  const bool &ignoreVirgilSignature = false);

                void initialize(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto) override;

                ValidationResult validateCard(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                  const interfaces::CardInterface &card) const override;

                const bool ignoreSelfSignature() const { return ignoreSelfSignature_; }

                const bool ignoreVirgilSignature() const { return ignoreVirgilSignature_; }

                const std::list<SignerInfo> whitelist() const { return whitelist_; }

                const std::list<std::shared_ptr<ValidationRuleInterface>> rules() const { return rules_; }

            private:
                bool ignoreSelfSignature_;
                bool ignoreVirgilSignature_;
                std::list<SignerInfo> whitelist_;
                std::list<std::shared_ptr<ValidationRuleInterface>> rules_;
            };
        }
    }
}


#endif //VIRGIL_SDK_EXTENDEDVALIDATOR_H
