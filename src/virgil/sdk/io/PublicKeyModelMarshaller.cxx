/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#include <nlohman/json.hpp>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/models/PublicKeyModel.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::util::JsonKey;
using virgil::sdk::models::PublicKeyModel;

namespace virgil {
namespace sdk {
    namespace io {
        /**
         * @brief Marshaller<PublicKeyModel> specialization.
         */
        template <> class Marshaller<PublicKeyModel> {
        public:
            template <int INDENT = -1> static std::string toJson(const PublicKeyModel& publicKey) {
                json jsonPublicKey = {{JsonKey::id, publicKey.getId()},
                                      {JsonKey::createdAt, publicKey.getCreatedAt()},
                                      {JsonKey::publicKey, VirgilBase64::encode(publicKey.getKey())}};
                return jsonPublicKey.dump(INDENT);
            }

            template <int FAKE = 0> static PublicKeyModel fromJson(const std::string& jsonString) {
                json jsonPublicKey = json::parse(jsonString);
                std::string id = jsonPublicKey[JsonKey::id];
                std::string createdAt = jsonPublicKey[JsonKey::createdAt];
                std::string publicKey = jsonPublicKey[JsonKey::publicKey];
                return PublicKeyModel(id, createdAt, VirgilBase64::decode(publicKey));
            }

        private:
            Marshaller(){};
        };
    }
}
}

/**
 * Explicit methods instantiation
 */
template std::string
virgil::sdk::io::Marshaller<PublicKeyModel>::toJson(const PublicKeyModel&);

template std::string
virgil::sdk::io::Marshaller<PublicKeyModel>::toJson<2>(const PublicKeyModel&);

template std::string
virgil::sdk::io::Marshaller<PublicKeyModel>::toJson<4>(const PublicKeyModel&);

template PublicKeyModel
virgil::sdk::io::Marshaller<PublicKeyModel>::fromJson(const std::string&);
