add_library(libscrypt STATIC
	crypto_scrypt-nosse.c
	sha256.c
	crypto-mcf.c
	b64.c
	crypto-scrypt-saltgen.c
	crypto_scrypt-check.c
	crypto_scrypt-hash.c
	slowequals.c
)

add_definitions(-D_FORTIFY_SOURCE=2)
target_include_directories(libscrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(libscrypt PROPERTIES FOLDER "third_party")
set_target_properties(libscrypt PROPERTIES POSITION_INDEPENDENT_CODE ON)
