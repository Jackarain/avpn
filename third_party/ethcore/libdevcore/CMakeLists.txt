file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

add_library(devcore STATIC ${sources} ${headers})
target_include_directories(devcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Needed to prevent including system-level boost headers:
#target_include_directories(devcore SYSTEM PUBLIC ${Boost_INCLUDE_DIR} PRIVATE ../utils)
target_link_libraries(devcore PUBLIC Boost::filesystem Boost::system Boost::thread Threads::Threads cryptopp-static)

set_target_properties(devcore PROPERTIES FOLDER "third_party")
set_target_properties(devcore PROPERTIES POSITION_INDEPENDENT_CODE ON)
