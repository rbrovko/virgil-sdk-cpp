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

#include <string>

#include <nlohman/json.hpp>

#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/client/models/serialization/JsonDeserializer.h>
#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>

#include <virgil/sdk/client/models/responses/CardRaw.h>
#include <virgil/sdk/client/models/responses/CardRawMeta.h>

using json = nlohmann::json;

using virgil::sdk::client::models::responses::CardRaw;
using virgil::sdk::client::models::responses::CardRawMeta;

using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;

namespace virgil {
namespace sdk {
namespace client {
namespace models {
    namespace serialization {

        /**
         * @brief JSONSerializer<CardRaw> specialization.
         */
        template<>
        class JsonDeserializer<CardRaw> {
        public:
            template<int FAKE = 0>
            static CardRaw fromJson(const json &j) {
                try {
                    std::string snapshotStr = j[JsonKey::ContentSnapshot];

                    VirgilByteArray snapshot = VirgilBase64::decode(snapshotStr);

                    std::string identifier = j[JsonKey::Id];

                    json meta = j[JsonKey::Meta];

                    auto signatures = JsonUtils::jsonToUnorderedBinaryMap(meta[JsonKey::Signs]);

                    std::string createdAt = meta[JsonKey::CreatedAt];

                    std::string cardVersion = meta[JsonKey::CardVersion];

                    auto cardRaw = CardRaw(
                            snapshot,
                            identifier,
                            CardRawMeta(
                                    signatures,
                                    createdAt,
                                    cardVersion
                            )
                    );

                    return cardRaw;
                } catch (std::exception &exception) {
                    throw std::logic_error(std::string("virgil-sdk:\n JsonDeserializer<CardRaw>::fromJson ") +
                                           exception.what());
                }
            }

            JsonDeserializer() = delete;
        };



        template<>
        class JsonSerializer<CardRaw> {
        public:
            template<int INDENT = -1>
            static std::string toJson(const CardRaw &cardRaw) {
                try {
                    json j = {
                            {JsonKey::ContentSnapshot, VirgilBase64::encode(cardRaw.ContentSnapshot())}
                    };

                    j[JsonKey::Id] = cardRaw.Identifier();
                    j[JsonKey::Meta][JsonKey::Signs] = JsonUtils::unorderedBinaryMapToJson(
                            cardRaw.Meta().signatures());
                    j[JsonKey::Meta][JsonKey::CreatedAt] = cardRaw.Meta().createdAt();
                    j[JsonKey::Meta][JsonKey::CardVersion] = cardRaw.Meta().cardVersion();

                    return j.dump(INDENT);
                } catch (std::exception &exception) {
                    throw std::logic_error(
                            std::string("virgil-sdk:\n JsonSerializer<CardRaw>::toJson ")
                            + exception.what());
                }
            }

            JsonSerializer() = delete;
        };
    }
}
}
}
}

/**
 * Explicit methods instantiation
 */
template CardRaw
virgil::sdk::client::models::serialization::JsonDeserializer<CardRaw>::fromJson(const json&);

template std::string
virgil::sdk::client::models::serialization::JsonSerializer<CardRaw>::toJson(const CardRaw&);
