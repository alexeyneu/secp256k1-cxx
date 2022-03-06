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

void brough(unsigned long long f);
int main()
{
    std::vector<unsigned long long> a{0x2492, 0x4924, 0x6DB6, 0x9248, 0xB6DA, 0xDB6C, 0x10000};
    std::cout << std::endl;
    std::thread h[7];


    for(auto f : a)
    {
        h[f/0x2492 - 1] = std::thread(&brough, f);
    }
    h[0].join();
    h[1].join();
    h[2].join();
    h[3].join();
    h[4].join();
    h[5].join();
    h[6].join();

    return 0;
}

void brough(unsigned long long f)
{
    unsigned long long t7 = f - 0x2492;
    unsigned long long t = {};
    std::string key(32, ' ');
    hex2bin((unsigned char *)&key[0], "bbc32876271effdbb576d5751eede7162aed93a398deec0f7fdb330bc3f49956", 32);
    do
    {

        key[7] = *((unsigned char *)&t7 + 1);
        key[13] = *((unsigned char *)&t7);
        key[17] = *((unsigned char *)&t + 7);
        key[19] = *((unsigned char *)&t + 6);
        key[23] = *((unsigned char *)&t + 5);
        key[25] = *((unsigned char *)&t + 4);
        key[27] = *((unsigned char *)&t + 3);
        key[29] = *((unsigned char *)&t + 2);
        key[30] = *((unsigned char *)&t + 1);
        key[31] = *((unsigned char *)&t);
        Secp256K1 p { key };
        if(f == 0x4924) std::cout << "Private key: " << bin2hex((const unsigned char*)key.c_str(), 32) << '\r';
 //       std::vector<unsigned char> vh{p.publicKey()};
 //       vh.erase(vh.begin());
//        std::cout << "Public key: " << bin2hex((unsigned char *)&vh[0], 64) << std::endl;
        unsigned char ethashtag[32] = {};
        unsigned char etaddr[20] = {};
        Keccak keccak256(Keccak::Keccak256);
        hex2bin(ethashtag, keccak256((char *)&p.publicKey()[1], 64).c_str(), 32);
        memcpy(etaddr, ethashtag, 20);
        std::string etaddrstring = "0x" + bin2hex(etaddr, 20);
//        std::cout << "et pubkey :" << std::endl <<  bin2hex((unsigned char *)&p.publicKey()[1], 64) << std::endl << "et address:" << std::endl << etaddrstring << std::endl;
        if (etaddrstring.contains("address")) { std::cout << std::endl << "yeah" << std::endl << "Private key: " << bin2hex((const unsigned char*)key.c_str(), 32) << std::endl; break; }
        t++;
        if(t == 0) t7++;
    }while(t7 < f);
}