#include "secp256k1-cxx.hpp"
#include "sha/sha2.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tuple>
#include <vector>
#include <sstream>
#include <iomanip>

/**
 * @brief Secp256K1::Secp256K1
 * creates pub/priv key pair
 */
Secp256K1::Secp256K1()
    : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN))
{
    //get epoch time
    unsigned seed1 = std::chrono::system_clock::now().time_since_epoch().count();

    //generate random number for priv key
    std::seed_seq seed { seed1 };
    std::mt19937_64 eng(seed);
    std::string randString;
    for (int i = 0; i < 10; ++i) {
        randString += eng();
    }

    //generate SHA-256 (our priv key)
    std::vector<uint8_t> out;
    out.resize(32);
    sha256_Raw(reinterpret_cast<const uint8_t*>(randString.c_str()), randString.length(), &out[0]);

    assert(out.size() == 32);

    privKey = std::move(out);

    std::cout << privKey.data();

    if (!createPublicKey()) {
        throw Secp256K1Exception("Unable to create publick key");
    }
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

    //verify priv key
 //   if (!verifyKey()) {
//        throw Secp256K1Exception("Unable to create and verify key:  ");
//}

//    std::cout << privKey.data();

    if (!createPublicKey()) {
        throw Secp256K1Exception("Unable to create publick key");
    }
}

std::vector<uint8_t> Secp256K1::publicKey() const
{
    return pubKey;
}

std::vector<uint8_t> Secp256K1::privateKey() const
{
    return privKey;
}


const std::string bin2hex(const unsigned char *p, size_t length) ;
bool Secp256K1::createPublicKey(bool compressed)
{
    // Calculate public key.
    secp256k1_pubkey pubkey;
    int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, privKey.data());
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


