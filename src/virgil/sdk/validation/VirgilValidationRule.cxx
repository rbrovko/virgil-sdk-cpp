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

#include <virgil/sdk/validation/VirgilValidationRule.h>

using virgil::sdk::validation::VirgilValidationRule;

VirgilValidationRule::VirgilValidationRule(const std::pair<std::string, PublicKeyInterface*> &virgilVerifier)
: virgilVerifier_(virgilVerifier) {}

void VirgilValidationRule::check(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                 const CardInterface &card,
                                 ValidationResult &result) const {
    try {
        auto exist = card.signatures().find(virgilVerifier_.first);

        if (exist == card.signatures().end()) {
            result.addError("card doesn't have virgil signature");
            return;
        }
        auto signature = card.signatures().at(virgilVerifier_.first);

        auto isVerified = crypto->verify(card.fingerprint(), signature.sign(), *virgilVerifier_.second);

        if (!isVerified) {
            result.addError("virgil signature wasn't verified");
            return;
        }
    }
    catch (...) {
        result.addError("virgil signature verification failed");
    }
}