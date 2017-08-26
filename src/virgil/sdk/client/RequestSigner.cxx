/**
 * Copyright (C) 2016 Virgil Security Inc.
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


#include <virgil/sdk/client/RequestSigner.h>
#include <virgil/sdk/client/models/CardIdGenerator.h>

static_assert(!std::is_abstract<virgil::sdk::client::RequestSigner>(), "RequestSigner must not be abstract.");

using virgil::sdk::client::RequestSigner;
using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::client::models::interfaces::SignableInterface;
using virgil::cryptointerfaces::CryptoInterface;
using virgil::cryptointerfaces::PrivateKeyInterface;
using virgil::sdk::client::models::CardIdGenerator;

RequestSigner::RequestSigner(const std::shared_ptr<CryptoInterface> &crypto)
        : crypto_(crypto) {
}

void RequestSigner::selfSign(SignableInterface &request, const PrivateKeyInterface &privateKey) const {
    auto fingerprint = crypto_->calculateFingerprint(request.snapshot());
    auto CardId = CardIdGenerator::generate(fingerprint);

    request.addSignature(crypto_->generateSignature(fingerprint, privateKey), CardId);
}

void RequestSigner::authoritySign(SignableInterface &request,
                                  const std::string &appId,
                                  const PrivateKeyInterface &privateKey) const {
    auto fingerprint = crypto_->calculateFingerprint(request.snapshot());
    request.addSignature(crypto_->generateSignature(fingerprint, privateKey), appId);
}
