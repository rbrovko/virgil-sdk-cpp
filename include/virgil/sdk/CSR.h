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


#ifndef VIRGIL_SDK_SIGNABLEREQUEST_H
#define VIRGIL_SDK_SIGNABLEREQUEST_H

#include <unordered_map>
#include <string>

#include <virgil/sdk/interfaces/Exportable.h>
#include <virgil/sdk/interfaces/Importable.h>
#include <virgil/sdk/serialization/CanonicalSerializer.h>
#include <virgil/sdk/interfaces/SignableRequestInterface.h>
#include <virgil/sdk/web/CSRSnapshotModel.h>
#include <CryptoInterface.h>
#include <virgil/sdk/CardSigner.h>
#include <virgil/sdk/CSRParams.h>
#include <virgil/sdk/Common.h>

namespace virgil {
    namespace sdk {
        /*!
         * @brief This is base class for all requests to the Virgil Service.
         * @tparam SnapshotModelType template type for Snapshot Model
         * @tparam DerivedClass represents concrete DerivedClass
         */
        class CSR final: public interfaces::SignableRequestInterface,
                                public interfaces::Exportable,
                                public interfaces::Importable<CSR> {
        public:

            static CSR generate(const std::shared_ptr<virgil::cryptointerfaces::CryptoInterface> &crypto,
                                const CSRParams &csrParams);

            /*!
             * @brief Getter.
             * @return Returns snapshot model
             */
            const web::CSRSnapshotModel& snapshotModel() const { return snapshotModel_; }

            /*!
             * @brief Getter.
             * @return Snapshot of data to be signed
             */
            const ByteArray& snapshot() const override { return snapshot_; }

            /*!
             * @brief Getter.
             * @return std::unordered_map of all signatures of this request.
             */
            const std::unordered_map<std::string, web::RawCardSignatureInfo>& signatures() const override { return signatures_; };

            /*!
             * @brief Exports object.
             * @return std::string representation of object
             */
            std::string exportAsString() const override;

            /*!
             * @brief Adds new signature.
             * @param signature raw signature
             * @param fingerprint std::string with related fingerprint
             */
            void addSignature(web::RawCardSignatureInfo signature, std::string fingerprint) override;

            void sign(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto,
                      const cryptointerfaces::PrivateKeyInterface &privateKey);

            void sign(const std::shared_ptr<cryptointerfaces::CryptoInterface> &crypto,
                      const CardSigner &cardSigner, const web::SignType &signType = web::SignType::application);


            //For deserialization reason
            // This is private API
            //! @cond Doxygen_Suppress
            CSR(const ByteArray &snapshot,
                const std::unordered_map<std::string, web::RawCardSignatureInfo> &signatures
                = std::unordered_map<std::string, web::RawCardSignatureInfo>());
            //! @endcond
        private:
            // This is private API
            //! @cond Doxygen_Suppress
            CSR(const web::CSRSnapshotModel &snapshotModel,
                const std::unordered_map<std::string, web::RawCardSignatureInfo> &signatures
                    = std::unordered_map<std::string, web::RawCardSignatureInfo>());

            CSR(ByteArray snapshot,
                web::CSRSnapshotModel snapshotModel,
                std::unordered_map<std::string, web::RawCardSignatureInfo> signatures);
            //! @endcond

            ByteArray snapshot_;
            web::CSRSnapshotModel snapshotModel_;
            std::unordered_map<std::string, web::RawCardSignatureInfo> signatures_;
        };
    }
}

#endif //VIRGIL_SDK_SIGNABLEREQUEST_H
