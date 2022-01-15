file(GLOB SOURCES "*.cpp")
file(GLOB HEADERS "*.h")

add_library(devcrypto STATIC ${SOURCES} ${HEADERS})
target_include_directories(devcrypto PRIVATE ${UTILS_INCLUDE_DIR})
target_link_libraries(devcrypto secp256k1 libscrypt cryptopp-static devcore ${OPENSSL_LIBRARIES})

target_include_directories(devcrypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../crypto)
target_include_directories(devcrypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

# target_link_libraries(devcrypto PUBLIC devcore Secp256k1 PRIVATE libff::ff cryptopp-static libscrypt::scrypt)

set_target_properties(devcrypto PROPERTIES FOLDER "third_party")
set_target_properties(devcrypto PROPERTIES POSITION_INDEPENDENT_CODE ON)
