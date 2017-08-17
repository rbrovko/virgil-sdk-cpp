//
// Created by Eugen Pivovarov on 8/11/17.
//


#include <virgil/sdk/client/models/parameters/RevokeCardParams.h>
#include <unordered_map>

using virgil::sdk::client::RevokeCardParams;

RevokeCardParams::RevokeCardParams(
        std::string identifier,
        std::map<std::string, PrivateKey> RequestSigners
) : identifier(identifier), RequestSigners(RequestSigners) {}

