//
// Created by Eugen Pivovarov on 8/16/17.
//

#include <virgil/sdk/client/models/responses/CardRaw.h>

using virgil::sdk::client::models::responses::CardRaw;

CardRaw::CardRaw(VirgilByteArray snapshot, std::string identifier, CardRawMeta meta)
        :snapshot_(snapshot), identifier_(identifier), meta_(meta) {}