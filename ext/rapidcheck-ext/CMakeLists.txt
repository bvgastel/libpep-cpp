cmake_minimum_required(VERSION 3.10)
project(rapidcheck_builder C CXX)
include(ExternalProject)

if ((NOT APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 10.0) OR
	  (APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "AppleClang" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12.0))
	# weird apple naming scheme (different version numbers)
	SET(CXX_FLAGS "${CXX_FLAGS} -Wno-implicit-int-float-conversion -Wno-error")
endif()
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	SET(CXX_FLAGS "${CXX_FLAGS} -Wno-sign-compare -Wno-error") # needed for rapidcheck for GCC 9.1
endif()

# check with git ls-remote https://github.com/emil-e/rapidcheck.git 'heads/*'
ExternalProject_Add(rapidcheck_builder
	#GIT_REPOSITORY https://github.com/emil-e/rapidcheck.git
	#GIT_TAG 7bc7d302191a4f3d0bf005692677126136e02f60
	# for C++20 compatibility on MSVC temporary switching to a MR to be merged in main
	GIT_REPOSITORY https://github.com/bvgastel/rapidcheck.git
	GIT_TAG 639089b5ed49122367fbf30efea9694f651f60bb
	GIT_SUBMODULES ""
	UPDATE_COMMAND ""
	DOWNLOAD_DIR ../../cache
	DOWNLOAD_NO_PROGRESS YES
	CMAKE_ARGS
	-DCMAKE_CXX_COMPILER_LAUNCHER=${CMAKE_CXX_COMPILER_LAUNCHER}
	-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
	"-DCMAKE_CXX_FLAGS=${CXX_FLAGS} ${BASE_CXX_FLAGS}"
	"-DCMAKE_STATIC_LINKER_FLAGS=${GCCLIBATOMIC_INIT}"
	"-DCMAKE_OSX_SYSROOT=${CMAKE_OSX_SYSROOT}"
	-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
	-DCMAKE_POSITION_INDEPENDENT_CODE=${CMAKE_POSITION_INDEPENDENT_CODE}
	-DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
	-DCMAKE_INSTALL_LIBDIR=lib  # some platforms use lib64 as directory
	-DRC_ENABLE_CATCH=ON
	PREFIX ${CMAKE_CURRENT_BINARY_DIR}
	INSTALL_COMMAND ""
	BUILD_BYPRODUCTS "<BINARY_DIR>/${CMAKE_STATIC_LIBRARY_PREFIX}rapidcheck${CMAKE_STATIC_LIBRARY_SUFFIX}"
	)

ExternalProject_Get_Property(rapidcheck_builder source_dir)
ExternalProject_Get_Property(rapidcheck_builder binary_dir)

set(rapidcheck_INCLUDE_DIRS
	${source_dir}/extras/catch/include
	${source_dir}/include
	)
SET(rapidcheck_LIBS
	${binary_dir}/${CMAKE_STATIC_LIBRARY_PREFIX}rapidcheck${CMAKE_STATIC_LIBRARY_SUFFIX}
)

add_library(rapidcheck INTERFACE)
add_dependencies(rapidcheck rapidcheck_builder)
target_link_libraries(rapidcheck INTERFACE ${rapidcheck_LIBS})
target_include_directories(rapidcheck INTERFACE
	"$<BUILD_INTERFACE:${rapidcheck_INCLUDE_DIRS}>"
	"$<INSTALL_INTERFACE:include>"
)
