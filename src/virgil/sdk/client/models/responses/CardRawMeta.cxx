//
// Created by Eugen Pivovarov on 8/16/17.
//

#include <virgil/sdk/client/models/responses/CardRawMeta.h>

using virgil::sdk::client::models::responses::CardRawMeta;

CardRawMeta::CardRawMeta(
        std::unordered_map<std::string, VirgilByteArray> signatures,
        std::string createdAt, std::string cardVersion)
        : signatures_(signatures), createdAt_(createdAt), cardVersion_(cardVersion) {}