//
// Created by Eugen Pivovarov on 8/11/17.
//

#include <virgil/sdk/client/CreateCardParams.h>


using virgil::sdk::client::CreateCardParams;

CreateCardParams::CreateCardParams(
        std::string Identity,
        std::string IdentityType,
        KeyPair keyPair,
        std::map<std::string, PrivateKey> RequestSigners,
        bool GenerateSelfSignature,
        std::unordered_map<std::string, std::string> customFields
) : Identity(Identity), IdentityType(IdentityType), keyPair(keyPair), RequestSigners(RequestSigners),
    GenerateSelfSignature(GenerateSelfSignature), customFields(customFields) {}