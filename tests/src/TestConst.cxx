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


#include <TestConst.h>

using virgil::sdk::test::TestConst;

std::string TestConst::applicationToken() const {
    return "AT.89cce2fac2fc9260cafb6d5dd2c6f12e7b992c1f85798ca5b3048f9b559d9a2f";
}

std::string TestConst::applicationPublicKeyBase64() const {
    /*  Getting Public appkey from private one
     crypto::Crypto crypto_;

     auto privateAppKeyData = VirgilBase64::decode(this->applicationPrivateKeyBase64());
     auto appPrivateKey = crypto_.importPrivateKey(privateAppKeyData, this->applicationPrivateKeyPassword());

     auto appPublicKey = crypto_.extractPublicKeyFromPrivateKey(appPrivateKey);
     return VirgilBase64::encode(crypto_.exportPublicKey(appPublicKey));
     */
    return "MCowBQYDK2VwAyEAAf7npot3FHPrp1j7AarKFVP6ABFbatF3IfOum1magqU=";
}

std::string TestConst::applicationPrivateKeyBase64() const {
    return "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBB/r4nA7LSZdSRdKiQCnknkAgINljAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEGizST9TJBV1O43/z+VSw80EQPWRUCGGFQ97yK9Cn0uDA8pRsJ3BN16nyke1LS2maFY/xnn/e//nhJDpnAQPHJPDNKusygYex5Ta5Ky+2TgoD1U=";
}

std::string TestConst::applicationPrivateKeyPassword() const {
    return "test";
}

std::string TestConst::applicationIdentityType() const {
    return "test";
}

std::string TestConst::applicationId() const {
    return "e683aa8ad95095d8baa86760892722189a534c76617ad1cddd041829fd055390";
}
