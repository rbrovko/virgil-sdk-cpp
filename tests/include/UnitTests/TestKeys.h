//
// Created by Eugen Pivovarov on 8/22/17.
//

#ifndef VIRGIL_SDK_TESTKEYS_H
#define VIRGIL_SDK_TESTKEYS_H
#include <PublicKeyInterface.h>
#include <virgil/sdk/Common.h>

using virgil::cryptointerfaces::PublicKeyInterface;
using virgil::cryptointerfaces::PrivateKeyInterface;
using virgil::cryptointerfaces::KeyPairInterface;

using VirgilByteArrayUtils = virgil::crypto::VirgilByteArrayUtils;

class KeyPairTest;

class PublicKeyTest : public PublicKeyInterface {
public:
    const byteArray &key() const override { return key_; }
    const byteArray &identifier() const override { return identifier_; }

    PublicKeyTest()
            : key_(VirgilByteArrayUtils::stringToBytes("-----BEGIN PUBLIC KEY-----\n"
                                                               "MCowBQYDK2VwAyEAedVKLoHYlzZBGhsR3I9TlI8pXwAYCDnRRs7d+j3vKxk=\n"
                                                               "-----END PUBLIC KEY-----\n")),
              identifier_(VirgilByteArrayUtils::stringToBytes("\u0018\u0003��i�\u001D�Ǻtj+��Ɣ��Z ��$���p}E��")) {}
private:

    byteArray key_;
    byteArray identifier_;

    friend KeyPairTest;
};

class PrivateKeyTest : public PrivateKeyInterface {
public:
    const byteArray &key() const override { return key_; }
    const byteArray &identifier() const override { return identifier_; }

    PrivateKeyTest()
            : key_(VirgilByteArrayUtils::stringToBytes("-----BEGIN PRIVATE KEY-----\n"
                                                               "MC4CAQAwBQYDK2VwBCIEIJTTFL3mtd5HXMCzJYG/WmLbey9LsOfqGFkoGV/QzbdI\n"
                                                               "-----END PRIVATE KEY-----\n")),
              identifier_(VirgilByteArrayUtils::stringToBytes("\u0018\u0003��i�\u001D�Ǻtj+��Ɣ��Z ��$���p}E��")) {}
private:
    byteArray key_;
    byteArray identifier_;

    friend KeyPairTest;
};


class KeyPairTest : public KeyPairInterface {
public:
    const PublicKeyTest& publicKey() const override { return publicKey_; }

    const PrivateKeyTest& privateKey() const override { return privateKey_; }

    KeyPairTest()
            : privateKey_(PrivateKeyTest()), publicKey_(PublicKeyTest()) {}
private:

    PrivateKeyTest privateKey_;
    PublicKeyTest publicKey_;
};

#endif //VIRGIL_SDK_TESTKEYS_H
