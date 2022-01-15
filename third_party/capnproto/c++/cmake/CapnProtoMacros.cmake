function(CAPNP_GENERATE_CPP SOURCES HEADERS)
	if(WIN32)
		set(SYSTEM_NAME "x86_64-windows")
	elseif(APPLE)
		set(SYSTEM_NAME "x86_64-darwin")
	else()
		if("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "mips64")
			set(SYSTEM_NAME "mips64el-linux")
		elseif("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "aarch64")
			set(SYSTEM_NAME "arm64-linux")
		else()
			set(SYSTEM_NAME "x86_64-linux")
		endif()
	endif()

	if(NOT CAPNPC_CXX_EXECUTABLE)
		set(CAPNPC_CXX_EXECUTABLE "${PROJECT_SOURCE_DIR}/third_party/capnproto/bin/${SYSTEM_NAME}/capnpc-c++")
	endif()
	if(NOT CAPNP_EXECUTABLE)
		set(CAPNP_EXECUTABLE "${PROJECT_SOURCE_DIR}/third_party/capnproto/bin/${SYSTEM_NAME}/capnp")
	endif()

	set(${SOURCES})
	set(${HEADERS})

	message(STATUS "Using ${CAPNPC_CXX_EXECUTABLE} for capnp generate cpp")
	message(STATUS "Using ${CAPNP_EXECUTABLE} for capnp generate cpp")

	set(output_dir ":.")
	foreach(schema_file ${ARGN})
		get_filename_component(output_base "${schema_file}" NAME)
		get_filename_component(file_path "${schema_file}" ABSOLUTE)
		get_filename_component(file_dir "${file_path}" PATH)

		add_custom_command(
			OUTPUT "${output_base}.c++" "${output_base}.h"
			COMMAND "${CAPNP_EXECUTABLE}"
			ARGS compile 
				-o ${CAPNPC_CXX_EXECUTABLE}${output_dir}
				--src-prefix ${file_dir}
				${file_path}
			DEPENDS "${schema_file}"
			COMMENT "Compiling Cap'n Proto schema ${schema_file}"
			VERBATIM
		)
		list(APPEND ${SOURCES} "${output_base}.c++")
		list(APPEND ${HEADERS} "${output_base}.h")
	endforeach()

	set_source_files_properties(${${SOURCES}} ${${HEADERS}} PROPERTIES GENERATED TRUE)

	set(${SOURCES} ${${SOURCES}} PARENT_SCOPE)
	set(${HEADERS} ${${HEADERS}} PARENT_SCOPE)
endfunction()
