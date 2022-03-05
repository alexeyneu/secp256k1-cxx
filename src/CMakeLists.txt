include_directories(libsecp256k1/include)

add_subdirectory(libsecp256k1)
add_subdirectory(sha)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

add_library(secp256k1-cxx secp256k1-cxx.cpp)

target_link_libraries(secp256k1-cxx PRIVATE libsecp256k1)
target_link_libraries(secp256k1-cxx PRIVATE sha256)
