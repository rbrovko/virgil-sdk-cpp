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

#ifndef VIRGIL_SDK_DTO_IDENTITY_H
#define VIRGIL_SDK_DTO_IDENTITY_H

#include <string>

namespace virgil {
namespace sdk {
    namespace dto {
        /**
         * @brief Represents unique identifer, i.e. email, application, etc
         */
        class Identity {
        public:
            /**
             * @brief Creates empty not valid identity
             */
            Identity() = default;

            virtual ~Identity() = default;

            /**
             * @brief Creates identity with given values
             *
             * @param value - identity value, i.e. support@virgilsecurity.com
             * @param type - identity type, i.e. email, phone etc
             *
             */
            Identity(const std::string& value, const std::string& type);
            /**
             * @brief Return identity value
             */
            const std::string getValue() const;
            /**
             * @brief Return identity type
             */
            const std::string getType() const;

        private:
            std::string value_;
            std::string type_;
        };

        /**
         * @brief Compare identities for equality
         *
         * @return true if given objects are equal, false - otherwise
         */
        inline bool operator==(const Identity& left, const Identity& right) {
            return left.getType() == right.getType() && left.getValue() == right.getValue();
        }

        /**
         * @brief Compare identities for inequality
         *
         * @return true if given objects are inequal, false - otherwise
         */
        inline bool operator!=(const Identity& left, const Identity& right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_DTO_IDENTITY_H */
