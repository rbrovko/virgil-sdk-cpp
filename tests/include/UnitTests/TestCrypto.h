//
// Created by Eugen Pivovarov on 8/22/17.
//

#ifndef VIRGIL_SDK_TESTCRYPTO_H
#define VIRGIL_SDK_TESTCRYPTO_H

#include <vector>
#include "TestKeys.h"

using byteArray = std::vector<unsigned char>;
using virgil::cryptointerfaces::CryptoInterface;
using virgil::cryptointerfaces::PrivateKeyInterface;
using virgil::cryptointerfaces::PublicKeyInterface;
using VirgilByteArrayUtils = virgil::crypto::VirgilByteArrayUtils;

class CryptoTest : public CryptoInterface {
public:
    CryptoTest() = default;
    byteArray exportPublicKey(const PublicKeyInterface &privateKey) const override {
        return VirgilByteArrayUtils::stringToBytes("test");
    }

    byteArray generateSignature(const byteArray &data,
                                const PrivateKeyInterface &privateKey) const override {
        return VirgilByteArrayUtils::stringToBytes("ƕ���Lą�o�鏆lR}\u001D�\u001E�\u0005");
    }

    bool verify(const byteArray &data, const byteArray &signature,
                const PublicKeyInterface &signerPublicKey) const override { return true; }

    byteArray calculateFingerprint(const byteArray &data) const override { return VirgilByteArrayUtils::stringToBytes("fingerprint"); }

    PublicKeyInterface* importPublicKey(const byteArray &data) const override { return new PublicKeyTest(); }


    //NOT USED YET
    byteArray exportPrivateKey(const PrivateKeyInterface &privateKey,
                               const std::string &password = "") const override { return VirgilByteArrayUtils::stringToBytes("smth"); }



    bool verify(std::istream &istream, const byteArray &signature,
                const PublicKeyInterface &signerPublicKey) const override { return false; }



    byteArray generateSignature(std::istream &istream, const
    PrivateKeyInterface &privateKey) const override { return VirgilByteArrayUtils::stringToBytes("smth"); }
};

#endif //VIRGIL_SDK_TESTCRYPTO_H
