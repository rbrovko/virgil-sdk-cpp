//
// Created by Eugen Pivovarov on 8/11/17.
//

#include <virgil/sdk/client/models/parameters/CreateCardParams.h>


using virgil::sdk::client::parameters::CreateCardParams;

CreateCardParams::CreateCardParams(
        std::string Identity,
        std::string IdentityType,
        KeyPairInterface& keyPair,
        std::map<std::string, PrivateKeyInterface&> RequestSigners,
        bool GenerateSelfSignature,
        std::unordered_map<std::string, std::string> customFields
) : Identity(Identity), IdentityType(IdentityType), keyPair(keyPair), RequestSigners(RequestSigners),
    GenerateSelfSignature(GenerateSelfSignature), customFields(customFields) {}