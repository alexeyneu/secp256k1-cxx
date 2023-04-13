CC=cl -c
CFLAGS=/FaWin32\ /FoWin32\ /FdWin32\vc800.pdb /DOPENSSL_SYSNAME_WIN32 -I. /D_WIN32 /MD /Ox /O2 /Ob2 -DOPENSSL_THREADS -DDSO_WIN32 -W3 -Gs0 -GF -Gy -nologo -DOPENSSL_SYSNAME_WIN32 -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -D_CRT_SECURE_NO_DEPRECATE -DOPENSSL_BN_ASM_PART_WORDS -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DRMD160_ASM -DAES_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DOPENSSL_USE_APPLINK -I. -DOPENSSL_NO_RC5 -DOPENSSL_NO_MD2 -DOPENSSL_NO_KRB5 -DOPENSSL_NO_JPAKE -DOPENSSL_NO_STATIC_ENGINE -DOPENSSL_NO_COMP -DFORTB -DOPENSSL_NO_PSK
LINKER=link
LINKBONUS=libeay32.lib ssleay32.lib crypt32.lib
DLLFLAGS=-SUBSYSTEM:windows -DLL
MT=mt
MTSTUFF=/nologo /verbose
CFLAGSBONUSF=-Isrc
CFLAGSF=/FaWin32\ /FoWin32\ /FdWin32\vc800.pdb /EHsc /DOPENSSL_SYSNAME_WIN32 -I. /D_WIN32 /MD /Ox /O2 /Ob2 /DUSE_NUM_NONE /DSECP256K1_WIDEMUL_INT64 /DUSE_FIELD_INV_BUILTIN /DUSE_SCALAR_INV_BUILTIN /DECMULT_WINDOW_SIZE=2 /DECMULT_GEN_PREC_BITS=4

docks : trail Win32\scatteredprivate.exe
	$(MT) $(MTSTUFF) -manifest Win32\scatteredprivate.exe.manifest -outputresource:Win32\scatteredprivate.exe

Win32\scatteredprivate.exe : Win32\base58_c.obj Win32\keccak.obj Win32\secp256k1.obj Win32\secp256k1-ferro.obj Win32\main.obj 
     $(LINKER) /OUT:Win32\scatteredprivate.exe Win32\base58_c.obj Win32\keccak.obj Win32\secp256k1.obj Win32\secp256k1-ferro.obj Win32\main.obj  $(LINKBONUS)

trail:
	-@ if NOT EXIST "Win32" mkdir "Win32"

Win32\base58_c.obj : base58_c.cpp libbase58.h
	 $(CC) base58_c.cpp $(CFLAGSF)

Win32\keccak.obj : keccak.cpp keccak.h
	 $(CC) keccak.cpp $(CFLAGSF)

Win32\secp256k1.obj : src\secp256k1.c
	 $(CC) src/secp256k1.c $(CFLAGSF)  $(CFLAGSBONUSF)

Win32\secp256k1-ferro.obj : secp256k1-ferro.cpp secp256k1-ferro.hpp
	 $(CC) secp256k1-ferro.cpp $(CFLAGSF)

Win32\main.obj : main.cpp
	 $(CC) secp256k1-ferro.cpp $(CFLAGSF)

