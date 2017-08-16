//
// Created by Eugen Pivovarov on 8/14/17.
//

#ifndef VIRGIL_SDK_PUBLICKEYINTERFACE_H
#define VIRGIL_SDK_PUBLICKEYINTERFACE_H

using byteArray = std::vector<unsigned char>;

namespace virgil {
    namespace cryptointerfaces {
        class PublicKeyInterface {
        public:
            virtual ~PublicKeyInterface() = default;

            virtual const byteArray &key() const = 0;
            virtual const byteArray &identifier() const = 0;
        };
    }
}

#endif //VIRGIL_SDK_PUBLICKEYINTERFACE_H
