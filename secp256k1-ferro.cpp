#include "secp256k1-ferro.hpp"

#include <cassert>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

/**
 * @brief Secp256K1::Secp256K1

 */
Secp256K1::Secp256K1()
    : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN))
{

}

Secp256K1::~Secp256K1()
{
    secp256k1_context_destroy(ctx);
}

/**
 * @brief verifies private key and generates corresponding public key
 * @param privateKey - in hexadecimal
 */
Secp256K1::Secp256K1(const std::string& privateKey)
    : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN))
{
    privKey.assign(privateKey.begin(), privateKey.end());
    createPublicKey();
}

std::vector<uint8_t> Secp256K1::publicKey() const
{
    return pubKey;
}

std::vector<uint8_t> Secp256K1::privateKey() const
{
    return privKey;
}


bool Secp256K1::createPublicKey(bool compressed)
{
    // Calculate public key.
    secp256k1_pubkey pubkey;
    int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, &privKey[0]);
    if (ret != 1) {
        return false;
    }

    // Serialize public key.
    size_t outSize = PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(
        ctx, pubkey_, &outSize, &pubkey,
        compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    // Succeed.
    return true;
}


