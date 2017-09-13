//
// Created by Eugen Pivovarov on 8/16/17.
//

#include <virgil/sdk/web/RawCard.h>

using virgil::sdk::web::RawCard;

RawCard::RawCard(VirgilByteArray snapshot,
                 std::unordered_map<std::string, RawCardSignatureInfo> signatures,
                 std::string createdAt,
                 std::string cardVersion)
        :snapshot_(snapshot), signatures_(signatures), createdAt_(createdAt), cardVersion_(cardVersion) {}