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

#include <virgil/sdk/serialization/JsonSerializer.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/sdk/serialization/CanonicalSerializer.h>
#include <virgil/sdk/web/CSRSnapshotModel.h>

#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/JsonUtils.h>


using json = nlohmann::json;

using virgil::sdk::util::ByteArray;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;
using virgil::sdk::web::CSRSnapshotModel;

namespace virgil {
    namespace sdk {
        namespace serialization {
            template<>
            class JsonSerializer<CSRSnapshotModel> {
            public:
                template<int INDENT = -1>
                static std::string toJson(const CSRSnapshotModel &model) {
                    try {
                        json j = {
                                {JsonKey::PublicKey, Base64::encode(model.publicKeyData())},
                                {JsonKey::Identity, model.identity()},
                        };

                        return j.dump(INDENT);
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n JsonSerializer<CreateCardSnapshotModel>::toJson ")
                                + exception.what());
                    }
                }

                JsonSerializer() = delete;
            };

            template<>
            class JsonDeserializer<CSRSnapshotModel> {
            public:
                template<int FAKE = 0>
                static CSRSnapshotModel fromJson(const json &j) {
                    try {
                        std::unordered_map<std::string, std::string> data;

                        return CSRSnapshotModel::createModel(j[JsonKey::Identity],
                                                             Base64::decode(j[JsonKey::PublicKey]));
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n JsonDeserializer<CreateCardSnapshotModel>::fromJson ")
                                + exception.what());
                    }
                }

                JsonDeserializer() = delete;
            };

            template<>
            class CanonicalSerializer<CSRSnapshotModel> {
            public:
                template<int INDENT = -1>
                static ByteArray toCanonicalForm(const CSRSnapshotModel &model) {
                    try {
                        return ByteArrayUtils::stringToBytes(
                                JsonSerializer<CSRSnapshotModel>::toJson<INDENT>(model));
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n CanonicalSerializer<CreateCardSnapshotModel>::toCanonicalForm ")
                                + exception.what());
                    }
                }

                template<int FAKE = 0>
                static CSRSnapshotModel fromCanonicalForm(const ByteArray &data) {
                    try {
                        return JsonDeserializerBase<CSRSnapshotModel>::fromJsonString(
                                ByteArrayUtils::bytesToString(data));
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n CanonicalSerializer<CreateCardSnapshotModel>::fromCanonicalForm ")
                                + exception.what());
                    }
                }

                CanonicalSerializer() = delete;
            };
        }
    }
}

/**
 * Explicit methods instantiation
 */
template std::string
virgil::sdk::serialization::JsonSerializer<CSRSnapshotModel>::toJson(const CSRSnapshotModel&);

template std::string
virgil::sdk::serialization::JsonSerializer<CSRSnapshotModel>::toJson<2>(const CSRSnapshotModel&);

template std::string
virgil::sdk::serialization::JsonSerializer<CSRSnapshotModel>::toJson<4>(const CSRSnapshotModel&);

template CSRSnapshotModel
virgil::sdk::serialization::JsonDeserializer<CSRSnapshotModel>::fromJson(const json&);

template ByteArray
virgil::sdk::serialization::CanonicalSerializer<CSRSnapshotModel>::toCanonicalForm(const CSRSnapshotModel&);

template ByteArray
virgil::sdk::serialization::CanonicalSerializer<CSRSnapshotModel>::toCanonicalForm<2>(const CSRSnapshotModel&);

template ByteArray
virgil::sdk::serialization::CanonicalSerializer<CSRSnapshotModel>::toCanonicalForm<4>(const CSRSnapshotModel&);

template CSRSnapshotModel
virgil::sdk::serialization::CanonicalSerializer<CSRSnapshotModel>::fromCanonicalForm(const ByteArray&);
