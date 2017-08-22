//
// Created by Eugen Pivovarov on 8/22/17.
//

#ifndef VIRGIL_SDK_TESTCRYPTO_H
#define VIRGIL_SDK_TESTCRYPTO_H

using byteArray = std::vector<unsigned char>;

class CryptoTest : public CryptoInterface {
public:
    CryptoTest() = default;
    byteArray exportPublicKey(const PublicKeyInterface &privateKey) const override {
        return VirgilByteArrayUtils::stringToBytes("0*0\u0005\u0006\u0003+ep\u0003!0y�J.�ؗ6A\u001A\u001B\u0011\u070FS��)_\u00009�F���=�+\u0019");
    }

    byteArray generateSignature(const byteArray &data,
                                const PrivateKeyInterface &privateKey) const override {
        return VirgilByteArrayUtils::stringToBytes("ƕ���Lą�o�鏆lR}\u001D�\u001E�\u0005");
    }



    //NOT USED YET
    PublicKeyInterface* importPublicKey(const byteArray &data) const override { return NULL; }


    byteArray exportPrivateKey(const PrivateKeyInterface &privateKey,
                               const std::string &password = "") const override { return VirgilByteArrayUtils::stringToBytes("smth"); }



    bool verify(const byteArray &data, const byteArray &signature,
                const PublicKeyInterface &signerPublicKey) const override { return false; }


    bool verify(std::istream &istream, const byteArray &signature,
                const PublicKeyInterface &signerPublicKey) const override { return false; }



    byteArray generateSignature(std::istream &istream, const
    PrivateKeyInterface &privateKey) const override { return VirgilByteArrayUtils::stringToBytes("smth"); }


    byteArray calculateFingerprint(const byteArray &data) const override { return VirgilByteArrayUtils::stringToBytes("fingerprint"); }
};

#endif //VIRGIL_SDK_TESTCRYPTO_H
