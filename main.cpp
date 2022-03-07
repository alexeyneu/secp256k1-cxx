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
#include <algorithm>
#include <thread>

const   std::string bin2hex(const unsigned char *p, size_t length) {
    std::stringstream f;
    f << std::hex << std::setfill('0');
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
    std::vector<unsigned long long> a{2, 4, 6, 8, 10, 12, 16};
    std::cout << std::endl;
    std::thread h[7];


    for(auto f : a)
    {
        h[f == 16 ? 6 : f/2 - 1] = std::thread(&brough, f);
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
    unsigned long long t = f == 16 ? 12 : f - 2;
    std::string key(32, ' ');
    std::vector<unsigned char> keyb;
    std::pair<std::vector<unsigned char> , unsigned short> mulligan{{0x6, 0x0}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> derby{{0x9, 0x6, 0x0, 0x8}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> dendra{{0xb, 0xa, 0xc/*remove*/, 0xe}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> remm{{0x2, 0x7}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> alfa{{0x2, 0x1}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> tetra{{0x7, 0x5}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> epsilon{{0x0, 0x9, 0x6}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> omega{{0xb, 0x2, 0x8, 0xe}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> beta{{0xa, 0xe, 0xc}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> zeta{{0x9, 0x0, 0x8}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> magna{{0x6, 0x3, 0x8, 0x0}, 0};
    std::pair<std::vector<unsigned char> , unsigned short> medley{{0xe, 0xc, 0xa}, 0};
    hex2bin((unsigned char *)&key[0], "eeeeeeeeeeeeeeeeee28b69dfb9d611d23435d6fc2e2277c2a145087d95e46e0", 32);
    std::string z = "                                         m dd    {}          r        teo bz   mm            ";
    for(int k = 0; k < 64; k++)
    {
        keyb.insert(keyb.end(), k % 2 == 0 ? key[k / 2] >> 4 : key[k / 2] & 0x0f);
    }
    do
    {
        keyb[31] = *((unsigned char *)&t);

        keyb[24] = mulligan.first[mulligan.second];   // mulligan
        keyb[26] = derby.first[derby.second];   // derby
        keyb[27] = dendra.first[dendra.second];   // dendra
        keyb[43] = remm.first[remm.second];   // remm
        keyb[44] = alfa.first[alfa.second];   // alfa
        keyb[52] = tetra.first[tetra.second];   // tetra
        keyb[53] = epsilon.first[epsilon.second];   //epsilon
        keyb[54] = omega.first[omega.second];       // omega
        keyb[56] = beta.first[beta.second];       // beta
        keyb[57] = zeta.first[zeta.second];       // zeta
        keyb[61] = magna.first[zeta.second];       // magna
        keyb[62] = medley.first[zeta.second];       // magna

        for(int b = 0; b < 32; b++)
        {
            key[b] = (keyb[b * 2] << 4) + keyb[b * 2 + 1];
        }
        medley.second++;       
        if(medley.second > medley.first.size() - 1) { magna.second++; medley.second = 0; }      
        if(magna.second > magna.first.size() - 1) { zeta.second++; magna.second = 0; }      
        if(zeta.second > zeta.first.size() - 1) { beta.second++; zeta.second = 0; }      
        if(beta.second > beta.first.size() - 1) { omega.second++; beta.second = 0; }      
        if(omega.second > omega.first.size() - 1) { epsilon.second++; omega.second = 0; }      
        if(epsilon.second > epsilon.first.size() - 1) { tetra.second++; epsilon.second = 0; }      
        if(tetra.second > tetra.first.size() - 1) { alfa.second++; tetra.second = 0; }      
        if(alfa.second > alfa.first.size() - 1) { remm.second++; alfa.second = 0; }      
        if(remm.second > remm.first.size() - 1) { dendra.second++; remm.second = 0; }      
        if(dendra.second > dendra.first.size() - 1) { derby.second++; dendra.second = 0; }      
        if(derby.second > derby.first.size() - 1) { mulligan.second++; derby.second = 0; }      
        if(mulligan.second > mulligan.first.size() - 1) { t++; mulligan.second = 0; }      
  
        Secp256K1 p { key };
        if(f == 4) std::cout << "Private key: " << bin2hex((const unsigned char*)key.c_str(), 32) << '\r';
        unsigned char ethashtag[32] = {};
        unsigned char etaddr[20] = {};
        Keccak keccak256(Keccak::Keccak256);
        hex2bin(ethashtag, keccak256((char *)p.pubkey_ + 1, 64).c_str(), 32);
        memcpy(etaddr, ethashtag + 12, 20);
        std::string etaddrstring = "0x" + bin2hex(etaddr, 20);
        if (etaddrstring.contains("address")) { std::cout << std::endl << "yeah" << std::endl << "Private key: " << bin2hex((const unsigned char*)key.c_str(), 32) << std::endl; break; }
    }while(t < f);
}