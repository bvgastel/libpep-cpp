cmake_minimum_required(VERSION 3.10)
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0") 
  cmake_policy(SET CMP0135 NEW) # auto enable DOWNLOAD_EXTRACT_TIMESTAMP in ExternalProject_Add()
endif()
project(catch2_builder C CXX)
include(ExternalProject)

ExternalProject_Add(catch2_builder
    URL
      "${PACKAGE_MIRROR}/Catch2.v2.13.7.tar.gz"
      "https://codeload.github.com/catchorg/Catch2/tar.gz/v2.13.7"
    #URL_HASH SHA1=16621762ee1f8d7d07d29e42322d08ebd071b1fa
    DOWNLOAD_NAME "Catch2.v2.13.7.tar.gz"
    DOWNLOAD_DIR ../../cache
		DOWNLOAD_NO_PROGRESS YES
    PREFIX "${CMAKE_CURRENT_BINARY_DIR}"
    CMAKE_ARGS
    -DCMAKE_CXX_COMPILER_LAUNCHER=${CMAKE_CXX_COMPILER_LAUNCHER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
		-DCMAKE_CXX_FLAGS=${BASE_CXX_FLAGS}
		-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
		-DCATCH_BUILD_TESTING=OFF
		CMAKE_GENERATOR ${CMAKE_GENERATOR}
    INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/install"
    )

# Specify include dir
ExternalProject_Get_Property(catch2_builder install_dir)
set(CATCH2_INCLUDE_DIRS ${install_dir}/include)

add_library(catch2 INTERFACE)
add_dependencies(catch2 catch2_builder)
target_include_directories(catch2 INTERFACE
	$<BUILD_INTERFACE:${CATCH2_INCLUDE_DIRS}>
	$<INSTALL_INTERFACE:include>
)
target_compile_definitions(catch2 INTERFACE -DCATCH_CONFIG_ENABLE_BENCHMARKING)
