

#include "src/secp256k1-cxx.hpp"
#include "src/sha/sha2.hpp"

#include <iostream>
#include <tuple>
#include <iostream>
#include "libbase58.h"
#include <cstring>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include "keccak.h"
#include <string>
#include <iomanip>
#include <sstream>


const   std::string bin2hex(const unsigned char *p, size_t length) {
    std::stringstream f;
    f<<std::hex << std::setfill('0');
    for (int i = 0; i < length; i++) f << std::setw(2) << (int)p[i];
    return f.str();
}

size_t hex2bin(unsigned char *p , const char *hexstr, const size_t length) {
    size_t wcount = 0;
    while ( wcount++ < length && *hexstr && *(hexstr + 1)) {    //last condition cause np if check fails on middle one.thats coz of short-circuit evaluation
        sscanf(hexstr, "%2hhx",p++);  //7x slower than tables but doesnt metter 
        hexstr = hexstr+2;
    }
    return  --wcount;     // error check here is a waste  
}   

using namespace std;

int main()
{
    std::string key(32, ' ');
       hex2bin((unsigned char *)&key[0], "bbc32876271effdbb576d5751eede7162aed93a398deec0f7fdb330bc3f49956", 32);
    Secp256K1 p { key };
    std::cout << "Private key: " << p.privateKeyHex() << std::endl;

    std::vector<unsigned char> vh{p.publicKey()};
    vh.erase(vh.begin());
    std::cout << "Public key: " << bin2hex((unsigned char *)&vh[0], 64) << std::endl;

    unsigned char ethashtag[32] = {};
    unsigned char etaddr[20] = {};

    Keccak keccak256(Keccak::Keccak256);
    hex2bin(ethashtag, keccak256((char *)&vh[0], 64).c_str(), 32);
    memcpy(etaddr, ethashtag, 20);
    std::string etaddrstring = "0x" + bin2hex(etaddr, 20);
 //   std::cout << "et pubkey :" << std::endl << "0x" + bin2hex((unsigned char *)vh.c_str(), 64) << std::endl << "et address:" << std::endl << etaddrstring << std::endl;
    std::cout << "et pubkey :" << std::endl <<  bin2hex((unsigned char *)&p.publicKey()[1], 64) << std::endl << "et address:" << std::endl << etaddrstring << std::endl;


    return 0;
 //   std::string x = Secp256K1::base16Decode("de7761f8874d23d4e8f3f26f321ade560556c23c8d7c7c8227bfefaa83f2c485b511d12037bd1e1f9730f5cc031784e895d263f557793215c2f401f3cc5cfe2f");

}
//88D8893C90FD4697E242C8FAD3D514848C789F0C15B4DA74280ECA1037FBF6511928DF756AC48B8B167F599583567759886D161B83ECA4870514E7D602F54F78