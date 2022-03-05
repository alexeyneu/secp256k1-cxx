include_directories(include)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_definitions(-DHAVE_CONFIG_H=1)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_C_FLAGS_RELEASE "-O3")

add_library(libsecp256k1 src/secp256k1.c include/secp256k1.h)
