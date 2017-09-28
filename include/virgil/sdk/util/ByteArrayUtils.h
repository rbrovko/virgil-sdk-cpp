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

#ifndef VIRGIL_SDK_BYTEARRAYUTILS_H
#define VIRGIL_SDK_BYTEARRAYUTILS_H

#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <iomanip>

namespace virgil {
    namespace sdk {
        namespace util {
            /**
             * @typedef ByteArray
             * @brief This type represents a sequence of bytes.
             */
            typedef std::vector<unsigned char> ByteArray;

        }
    }
}

namespace virgil {
    namespace sdk {
        namespace util {
            /*!
             * @brief This class contains conversion utils for byte sequence.
             */
            class ByteArrayUtils {
            public:
                /*!
                 * @brief Represents given string as byte array.
                 */
                static ByteArray stringToBytes(const std::string &data) {
                    std::vector<unsigned char> newData(data.begin(), data.end());
                    return newData;
                }

                /*!
                 * @brief Represent given byte array as string.
                 */
                static std::string bytesToString(const ByteArray &data) {
                    std::string newData(data.begin(), data.end());
                    return newData;
                }

                /*!
                 * @brief Translate given byte array to the HEX string.
                 */
                static std::string bytesToHex(const ByteArray &data) {
                    std::ostringstream hexStream;
                    hexStream << std::setfill('0');

                    for (size_t i = 0; i < data.size(); ++i)
                        hexStream << std::hex << std::setw(2) << (int) data[i];

                    return hexStream.str();

                }

                /*!
                 * @brief Append given bytes to the existing one.
                 * @param dst - destination.
                 * @param src - source.
                 */
                static void append(ByteArray& dst, const ByteArray& src) {
                    auto str1 = bytesToHex(dst);
                    auto str2 = bytesToHex(src);
                    str1.append(str2);
                    dst = stringToBytes(str1);
                }
            };
        }
    }
}

#endif //VIRGIL_SDK_BYTEARRAYUTILS_H
