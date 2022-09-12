cmake_minimum_required(VERSION 3.10)
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0") 
  cmake_policy(SET CMP0135 NEW) # auto enable DOWNLOAD_EXTRACT_TIMESTAMP in ExternalProject_Add()
endif()
project(libsodium_builder C)
include(ExternalProject)

SET(SMALLER_LIBSODIUM NO)

IF (SMALLER_LIBSODIUM OR CMAKE_SYSTEM_NAME MATCHES "Windows" OR CMAKE_SYSTEM_NAME MATCHES "Android")
	ExternalProject_Add(libsodium_builder
		URL
			"${PACKAGE_MIRROR}/1.0.18-RELEASE.tar.gz"
			https://github.com/jedisct1/libsodium/archive/1.0.18-RELEASE.tar.gz
		URL_HASH SHA1=9ff53da20d9051ab80fea78251b7564efd766a74
		DOWNLOAD_DIR ../../cache
		DOWNLOAD_NO_PROGRESS YES
		PREFIX "${CMAKE_CURRENT_BINARY_DIR}"
		BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src/libsodium_builder"
		PATCH_COMMAND ${CMAKE_COMMAND} -E copy builds/msvc/version.h src/libsodium/include/sodium
		COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/SodiumCMakeLists.txt CMakeLists.txt
		CMAKE_ARGS
		-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
		-DCMAKE_POSITION_INDEPENDENT_CODE=${CMAKE_POSITION_INDEPENDENT_CODE}
		-DCMAKE_C_COMPILER_LAUNCHER=${CMAKE_C_COMPILER_LAUNCHER}
		-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
		-DCMAKE_C_FLAGS=${BASE_C_FLAGS}
    "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
		INSTALL_COMMAND ""
		BUILD_BYPRODUCTS
		"<BINARY_DIR>/${CMAKE_STATIC_LIBRARY_PREFIX}sodium${CMAKE_STATIC_LIBRARY_SUFFIX}"
		)

	# Specify include dir
	ExternalProject_Get_Property(libsodium_builder source_dir)
	set(LIBSODIUM_INCLUDE_DIRS ${source_dir}/builds/msvc ${source_dir}/src/libsodium/include)
	FILE(GLOB_RECURSE DIRS LIST_DIRECTORIES true ${source_dir}/src/libsodium/*/)
	foreach (DIR ${DIRS})
		if (IS_DIRECTORY ${DIR}) # AND NOT DIR MATCHES "\\.")
			set(LIBSODIUM_INCLUDE_DIRS ${LIBSODIUM_INCLUDE_DIRS} ${DIR})
		endif()
	endforeach()

	# Specify MainTest's link libraries
	ExternalProject_Get_Property(libsodium_builder binary_dir)
	set(LIBSODIUM_LIBS_DIR ${binary_dir})
	set(LIBSODIUM_LIBS ${binary_dir}/${CMAKE_STATIC_LIBRARY_PREFIX}sodium${CMAKE_STATIC_LIBRARY_SUFFIX})

else()
	if (CMAKE_CROSSCOMPILING)
		set(HOST "--host=${CMAKE_SYSTEM_PROCESSOR}")
	endif()
	IF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
		set(C_FLAGS "-isysroot ${CMAKE_OSX_SYSROOT}")
	endif()
	ExternalProject_Add(libsodium_builder
		URL
			"${PACKAGE_MIRROR}/1.0.18-RELEASE.tar.gz"
			https://github.com/jedisct1/libsodium/archive/1.0.18-RELEASE.tar.gz
		URL_HASH SHA1=9ff53da20d9051ab80fea78251b7564efd766a74
		DOWNLOAD_DIR ../../cache
		DOWNLOAD_NO_PROGRESS YES
		PREFIX "${CMAKE_CURRENT_BINARY_DIR}"
		BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src/libsodium_builder"
		CONFIGURE_COMMAND "<SOURCE_DIR>/configure" "CC=${CMAKE_C_COMPILER_LAUNCHER} ${CMAKE_C_COMPILER}" "CFLAGS=${BASE_C_FLAGS} ${C_FLAGS}" --with-pic ${HOST}
		BUILD_COMMAND "make" "-j8" 
		# Disable install step
		INSTALL_COMMAND ""
		BUILD_BYPRODUCTS
		"<BINARY_DIR>/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}sodium${CMAKE_STATIC_LIBRARY_SUFFIX}"
		"<BINARY_DIR>/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}aesni${CMAKE_STATIC_LIBRARY_SUFFIX}"
		"<BINARY_DIR>/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}avx2${CMAKE_STATIC_LIBRARY_SUFFIX}"
		"<BINARY_DIR>/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}sse2${CMAKE_STATIC_LIBRARY_SUFFIX}"
		"<BINARY_DIR>/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}sse41${CMAKE_STATIC_LIBRARY_SUFFIX}"
		"<BINARY_DIR>/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}ssse3${CMAKE_STATIC_LIBRARY_SUFFIX}"
		)


	# Specify include dir
	ExternalProject_Get_Property(libsodium_builder source_dir)
	set(LIBSODIUM_INCLUDE_DIRS ${source_dir}/src/libsodium/include)

	# Specify link libraries
	ExternalProject_Get_Property(libsodium_builder binary_dir)
	set(LIBSODIUM_LIBS_DIR ${binary_dir})
	set(LIBSODIUM_LIBS
		${binary_dir}/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}sodium${CMAKE_STATIC_LIBRARY_SUFFIX}
		${binary_dir}/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}aesni${CMAKE_STATIC_LIBRARY_SUFFIX}
		${binary_dir}/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}avx2${CMAKE_STATIC_LIBRARY_SUFFIX}
		${binary_dir}/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}sse2${CMAKE_STATIC_LIBRARY_SUFFIX}
		${binary_dir}/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}sse41${CMAKE_STATIC_LIBRARY_SUFFIX}
		${binary_dir}/src/libsodium/.libs/${CMAKE_STATIC_LIBRARY_PREFIX}ssse3${CMAKE_STATIC_LIBRARY_SUFFIX}
		)
endif()

add_library(libsodium INTERFACE)
add_dependencies(libsodium libsodium_builder)
target_link_libraries(libsodium INTERFACE ${LIBSODIUM_LIBS})
target_include_directories(libsodium INTERFACE
	"$<BUILD_INTERFACE:${LIBSODIUM_INCLUDE_DIRS}>"
	"$<INSTALL_INTERFACE:include>"
)
target_compile_definitions(libsodium INTERFACE -DSODIUM_STATIC -DSODIUM_EXPORT=)
