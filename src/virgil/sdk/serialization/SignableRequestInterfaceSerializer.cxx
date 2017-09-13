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
#include <virgil/sdk/serialization/JsonTemplatedDeserializer.h>
#include <virgil/sdk/interfaces/SignableRequestInterface.h>
#include <virgil/sdk/CSR.h>

using json = nlohmann::json;

using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;
using virgil::sdk::VirgilBase64;
using virgil::sdk::CSR;
using virgil::sdk::interfaces::SignableRequestInterface;

namespace virgil {
    namespace sdk {
        namespace serialization {
            /**
             * @brief JSONSerializer<SignableRequestInterface> specialization.
             */
            template <>
            class JsonSerializer<SignableRequestInterface> {
            public:
                template<int INDENT = -1>
                static std::string toJson(const SignableRequestInterface &request) {
                    try {
                        json j = {
                                {JsonKey::ContentSnapshot, VirgilBase64::encode(request.snapshot())}
                        };

                        j[JsonKey::Meta][JsonKey::Signs] = JsonUtils::unorderedMapofSignsToJson(
                                request.signatures());

                        return j.dump(INDENT);
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n JsonSerializer<SignableRequestInterface>::toJson ")
                                + exception.what());
                    }
                }

                JsonSerializer() = delete;
            };

            template <>
            class JsonTemplatedDeserializer<SignableRequestInterface> {
            public:
                template<typename ResultType>
                static ResultType fromJson(const json &j) {
                    try {
                        std::string snapshotStr = j[JsonKey::ContentSnapshot];

                        auto snapshot = VirgilBase64::decode(snapshotStr);

                        auto signatures = JsonUtils::jsonToUnorderedBinaryMapOfSigns(j[JsonKey::Meta][JsonKey::Signs]);

                        return ResultType(snapshot, signatures);
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n JsonTemplatedDeserializer<SignableRequestInterface>::fromJson ")
                                + exception.what());
                    }
                }
            };
        }
    }
}

/**
 * Explicit methods instantiation
 */
template std::string
virgil::sdk::serialization::JsonSerializer<SignableRequestInterface>::toJson(const SignableRequestInterface&);

template std::string
virgil::sdk::serialization::JsonSerializer<SignableRequestInterface>::toJson<2>(const SignableRequestInterface&);

template std::string
virgil::sdk::serialization::JsonSerializer<SignableRequestInterface>::toJson<4>(const SignableRequestInterface&);

template CSR
virgil::sdk::serialization::JsonTemplatedDeserializer<SignableRequestInterface>::fromJson<CSR>(const json&);
