//
// Created by Eugen Pivovarov on 8/23/17.
//

#ifndef VIRGIL_SDK_CARDTEST_H
#define VIRGIL_SDK_CARDTEST_H

#include <unordered_map>
#include <string>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/ClientCommon.h>
#include <virgil/sdk/client/models/interfaces/Exportable.h>
#include <virgil/sdk/client/models/interfaces/Importable.h>
#include <virgil/sdk/client/interfaces/CardInterface.h>

#include <virgil/sdk/client/models/responses/CardRaw.h>
#include <virgil/sdk/crypto/Crypto.h>
#include <vector>
#include <virgil/sdk/client/models/ClientCommon.h>

using byteArray = std::vector<unsigned char>;
using virgil::sdk::client::models::CardScope;

class CardTest: public virgil::sdk::client::interfaces::CardInterface {
public:
    CardTest() = default;

    std::string exportAsString() const override { return "smth"; }

    /*!
     * @brief Getter.
     * @return byteArray with snapshot
     */
    const byteArray& snapshot() const override { return snapshot_; }

    /*!
     * @brief Getter.
     * @return std::string with card ID
     */
    const std::string& identifier() const override { return identifier_; }

    /*!
     * @brief Getter.
     * @return std::string with card identity
     */
    const std::string& identity() const override { return identity_; }

    /*!
     * @brief Getter.
     * @return std::string with card identity type
     */
    const std::string& identityType() const override { return identityType_; }

    /*!
     * @brief Getter.
     * @return raw representation of Public Key which corresponds to this Card
     */
    const std::shared_ptr<virgil::cryptointerfaces::PublicKeyInterface>& publicKey() const override { return publicKey_; }

    /*!
     * @brief Getter.
     * @return std::unordered_map with custom user payload
     */
    const std::unordered_map<std::string, std::string>& data() const override { return data_; }

    /*!
     * @brief Getter.
     * @return CardScope (application or global)
     */
    CardScope scope() const override { return scope_; }

    /*!
     * @brief Getter.
     * @return std::string with date of Card creation (format is yyyy-MM-dd'T'HH:mm:ssZ)
     */
    const std::string& createdAt() const override { return createdAt_; }

    /*!
     * @brief Getter.
     * @return std::string with card version
     */
    const std::string& cardVersion() const override { return cardVersion_; }

    /*!
    * @brief Getter.
    * @return unordered map with signatures
    */
    const std::unordered_map<std::string, byteArray>& signatures() const override { return signatures_; }

public:
    byteArray snapshot_;
    std::string identifier_;
    std::string identity_;
    std::string identityType_;
    std::shared_ptr<virgil::cryptointerfaces::PublicKeyInterface> publicKey_;
    std::unordered_map<std::string, std::string> data_;
    std::string createdAt_;
    std::string cardVersion_;
    CardScope scope_;
    std::unordered_map<std::string, byteArray> signatures_;
};

#endif //VIRGIL_SDK_CARDTEST_H
