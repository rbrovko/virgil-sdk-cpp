//
// Created by Eugen Pivovarov on 8/16/17.
//

#include <virgil/sdk/client/models/responses/RawCard.h>

using virgil::sdk::client::models::responses::RawCard;

RawCard::RawCard(VirgilByteArray snapshot, std::string identifier, RawCardMeta meta)
        :snapshot_(snapshot), identifier_(identifier), meta_(meta) {}