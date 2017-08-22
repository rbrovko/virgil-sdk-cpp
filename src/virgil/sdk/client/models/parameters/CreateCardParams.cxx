//
// Created by Eugen Pivovarov on 8/11/17.
//

#include <virgil/sdk/client/models/parameters/CreateCardParams.h>


using virgil::sdk::client::models::parameters::CreateCardParams;

CreateCardParams::CreateCardParams(
        const std::string &Identity,
        const std::string &IdentityType,
        const KeyPairInterface& keyPair,
        const std::list<CardSigner> &RequestSigners,
        bool GenerateSelfSignature,
        std::unordered_map<std::string, std::string> customFields
) : Identity(Identity), IdentityType(IdentityType), keyPair(keyPair), RequestSigners(RequestSigners),
    GenerateSelfSignature(GenerateSelfSignature), customFields(customFields) {}