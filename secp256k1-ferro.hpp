#ifndef SECP256K1_CPP_H
#define SECP256K1_CPP_H

#include "include/secp256k1.h"

#include <stdexcept>
#include <stdint.h>
#include <vector>

class Secp256K1
{
public:
    Secp256K1();
    ~Secp256K1();
    Secp256K1(const std::string& privateKey);
    std::vector<uint8_t> publicKey() const;
    std::vector<uint8_t> privateKey() const;
    unsigned char  pubkey_[65];

    //    bool Verify(const uint8_t* hash, const std::vector<uint8_t>& sig_in) const;


private:
    secp256k1_context* ctx;
    std::vector<uint8_t> pubKey;
    std::vector<uint8_t> privKey;
    static const size_t PUBLIC_KEY_SIZE = 65;

    /** PRIVATE METHODS **/
    bool createPublicKey(bool compressed = false);
};

#endif
