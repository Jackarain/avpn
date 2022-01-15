file(GLOB sources "*.cpp" "*.h")

add_library(ethcore ${sources})

target_include_directories(ethcore PRIVATE "${UTILS_INCLUDE_DIR}")
target_link_libraries(ethcore PUBLIC devcrypto devcore)

set_target_properties(ethcore PROPERTIES FOLDER "third_party")
set_target_properties(ethcore PROPERTIES POSITION_INDEPENDENT_CODE ON)
