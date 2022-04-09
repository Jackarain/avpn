cmake_minimum_required(VERSION 3.0)

file(GLOB wintun_SRC
	src/*.*
	include/*.*
)

add_library(wintun STATIC ${wintun_SRC})

target_include_directories(wintun PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/)
set_target_properties(wintun PROPERTIES FOLDER "third_party")
set_target_properties(wintun PROPERTIES POSITION_INDEPENDENT_CODE ON)
