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

#ifndef VIRGIL_SDK_VALIDATIONRULES_H
#define VIRGIL_SDK_VALIDATIONRULES_H
#include <list>
#include <virgil/sdk/client/models/CardSigner.h>
#include <virgil/sdk/client/interfaces/IntegrityPolicy.h>
#include <virgil/sdk/client/models/policies/AllValidPolicy.h>

using virgil::sdk::client::models::CardSigner;
using virgil::sdk::client::interfaces::IntegrityPolicy;
using virgil::sdk::client::models::policies::AllValidPolicy;

namespace virgil {
    namespace sdk {
        namespace client {
            /*!
             * @brief defines rules for validation
             */
            class ValidationRules {
            public:
                /*!
                 * @brief constructor
                 * @param verifiers unordered_map of verifiers to validate with
                 * @param behavior can change behavior of validator to validate at least one or all signs
                 * @param ignoreSelfSignatures whether or not to ignore self sign during validating
                 * @param ignoreVirgilSignatures whether or not to ignore service sign during validating
                 */
                ValidationRules(const std::unordered_map<std::string, VirgilByteArray> &verifiers,
                                const std::shared_ptr<IntegrityPolicy> &behavior = std::make_shared<AllValidPolicy>(),
                                const bool ignoreSelfSignatures = false,
                                const bool ignoreVirgilSignatures = false)
                    : ignoreSelfSignatures_(ignoreSelfSignatures),
                      ignoreVirgilSignatures_(ignoreVirgilSignatures),
                      verifiers_(verifiers),
                      behavior_(behavior) {}

                const bool &ignoreVirgilSignatures() const { return ignoreVirgilSignatures_; }

                const bool &ignoreSelfSignatures() const { return ignoreSelfSignatures_; }

                const std::unordered_map<std::string, VirgilByteArray> &verifiers() const { return verifiers_; }

                const std::shared_ptr<IntegrityPolicy> &behavior() const { return behavior_; }

            private:
                bool ignoreVirgilSignatures_;
                bool ignoreSelfSignatures_;
                std::unordered_map<std::string, VirgilByteArray> verifiers_;
                std::shared_ptr<IntegrityPolicy> behavior_;
            };
        }
    }
}


#endif //VIRGIL_SDK_VALIDATIONRULES_H
