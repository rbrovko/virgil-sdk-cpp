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

#include <virgil/sdk/validation/WhitelistValidationRule.h>
#include <virgil/sdk/util/JsonUtils.h>

using virgil::sdk::validation::WhitelistValidationRule;
using virgil::sdk::util::JsonUtils;

WhitelistValidationRule::WhitelistValidationRule(const std::unordered_map<std::string, PublicKeyInterface*> &whitelist)
        : whitelist_(whitelist) {}

void WhitelistValidationRule::check(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                    const CardInterface &card,
                                    ValidationResult &result) const {
    for (const auto& verifier : whitelist_) {
        try {
            auto exist = card.signatures().find(verifier.first);

            if (exist == card.signatures().end()) {
                result.addError("card doesn't have one of whitelist signatures");
                return;
            }

            auto signature = card.signatures().at(verifier.first);

            auto extraDataSnapshot = (signature.extraData().empty()) ? VirgilByteArrayUtils::stringToBytes(JsonUtils::unorderedMapToJson(signature.extraData()).dump()) : std::vector<unsigned char>();
            auto combinedSnapshot = card.snapshot();
            VirgilByteArrayUtils::append(combinedSnapshot, extraDataSnapshot);

            auto fingerprint = crypto->calculateFingerprint(combinedSnapshot);

            auto isVerified = crypto->verify(fingerprint, signature.sign(), *verifier.second);

            if (!isVerified) {
                result.addError("one of whitelist signatures wasn't verified");
                return;
            }
        }
        catch (...) {
            result.addError("one of whitelist signatures verification failed");
        }
    }
}

