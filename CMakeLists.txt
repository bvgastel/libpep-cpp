cmake_minimum_required(VERSION 3.10) # 3.14 handles PIC differently
if (APPLE)
  if (CMAKE_BUILD_TYPE EQUAL "Release" OR CMAKE_BUILD_TYPE EQUAL "MinSizeRel")
    set(CMAKE_OSX_ARCHITECTURES arm64 x86_64) # needs to be set before project(), see https://cmake.org/cmake/help/latest/variable/CMAKE_OSX_ARCHITECTURES.html
  endif()
endif()
project (pep LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
if (CMAKE_SYSTEM_NAME MATCHES "Android")
  set(CMAKE_CXX_STANDARD 17)
else()
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

OPTION(ALL_WARNINGS "Enable all possible warnings" ON)
OPTION(TEST "Build the tests" ON)

if(UNIX AND NOT APPLE)
  # reduce binary size, by making it easier to garbage collect redundant/unused binary code.
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections")
endif()

# Set default build type.
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
      "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()

if (CMAKE_POSITION_INDEPENDENT_CODE)
	if(CMAKE_VERSION VERSION_LESS 3.14)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
	else()
		include(CheckPIESupported)
	endif()
endif()


if (NOT MSVC)
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe")
else()
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj")
	# enable C++ exceptions
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_USE_MATH_DEFINES")

	# Allow multi-processor compilation: see https://blogs.msdn.microsoft.com/visualstudio/2010/03/07/tuning-c-build-parallelism-in-vs2010/
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
endif()

SET(SANITIZER "" CACHE STRING "Apply sanitizer")
if (SANITIZER)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=${SANITIZER} -g -fno-optimize-sibling-calls -O1")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -fsanitize=${SANITIZER} -g -fno-optimize-sibling-calls -O1")
	MESSAGE("using sanitizer ${SANITIZER}")
	if (SANITIZER STREQUAL "address")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-address-use-after-scope")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-address-use-after-scope")
	endif()
endif (SANITIZER)

# turn on link time optimisation (LTO) for MinSizeRel builds (helps)
# disabled for now, because it takes a long time
# if(CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
# 	set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
# endif()

# faster linking
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold")
	SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=gold")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang"
		AND (NOT CMAKE_SYSTEM_NAME MATCHES "Darwin"))
		SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")
		SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=lld")
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-parentheses-equality") # stb_image triggers this warning due to macro usage
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-reorder-blocks -fno-reorder-blocks-and-partition")
ENDIF()

# need a copy to prevent warnings ending up in dependencies
SET(BASE_C_FLAGS "${CMAKE_C_FLAGS}")
SET(BASE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

SET(PACKAGE_MIRROR "http://packages.bitpowder.com/external/")
set(EXT_PROJECTS_DIR ${PROJECT_SOURCE_DIR}/ext)

add_library(extlib INTERFACE)

MESSAGE("using ext/ libsodium")
add_subdirectory(${EXT_PROJECTS_DIR}/libsodium)
target_link_libraries(extlib INTERFACE libsodium)

if (TEST)
	add_subdirectory(${EXT_PROJECTS_DIR}/catch2)
	add_subdirectory(${EXT_PROJECTS_DIR}/rapidcheck-ext)
  target_include_directories(catch2 INTERFACE $<BUILD_INTERFACE: ${EXT_PROJECTS_DIR}/rapidcheck/extras/catch/include>)
	set(TEST_LIBS
		catch2
		rapidcheck
		)
endif()

if (ALL_WARNINGS)
	# enable all warnings and disable non relevant stuff
	if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Weverything -Wreorder -Woverloaded-virtual -Wcast-align -Wdeprecated")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-disabled-macro-expansion") # avoid warnings in lua defines such as lua_replace
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-missing-prototypes -Wno-weak-vtables -Wno-zero-length-array -Wno-gnu-anonymous-struct -Wno-reserved-id-macro -Wno-nested-anon-types -Wno-missing-variable-declarations")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-padded")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-exit-time-destructors -Wno-global-constructors")
		# possible fix in the future?
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-thread-safety-analysis -Wno-thread-safety-negative")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-documentation -Wno-documentation-unknown-command")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-over-aligned") # getting weird errors that the default allocator guarantees 4 bytes, and 8 bytes is needed if std::function's are used
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unknown-warning-option -Wno-zero-as-null-pointer-constant") # lots of false positives
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-extra-semi-stmt") # lots of issues with checkAssert(..); (warning there is an additional ; at the end)
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ctad-maybe-unsupported") # disable errors about missing angle brackets
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c99-extensions") # disable warnings about designated initializers are a C99 extensions (as it is allowed in C++20) (needed for macOS Catalina)
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-template") # needed for Catch2 TEMPLATE_LIST_TEST_CASE
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-alloca") # for now disabled, sqlite3 integration (only place alloca is used) is possibly removed anyway
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-undefined-func-template") # goes wrong with Prometheus imports (goes wrong on compile time)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unknown-pragmas -Wno-undef")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-reserved-identifier") # avoid _StartsWithCapital warnings (because that is reserved)
	elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Woverloaded-virtual") # -Weffc++
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unknown-pragmas")
		#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wsuggest-final-methods -Wsuggest-final-types")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-attributes")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-maybe-uninitialized")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-variable") # GCC 7.3 complains wrongfully about "error: unused variable '_'" (code: "for (auto& [_, subscriptionInfo] : subscriptions) {")
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-array-bounds") # false positive in memcpy of NumberToStringObject (see https://bitpowder.com:2443/bitpowder/indigo/-/jobs/47193)
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-redundant-move") # conflicts with clang 7.0; which requires the moves	
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-stringop-overflow") # too many false positives in simplestring.h
		SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror=missing-field-initializers") # needed for HTTPRequestOptions{}
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-mismatched-new-delete") # needed for debug.h InstanceDebug
	endif()
	if (NOT MSVC)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
	endif()
endif (ALL_WARNINGS)

if (MSVC)
    # Get rid of warnings about unsafe standard functions such as _open and _ftime64
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D_CRT_SECURE_NO_WARNINGS")

    # Get rid of warnings about using _close() instead of close() etc, see https://docs.microsoft.com/en-us/previous-versions/ms235384(v=vs.100)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D_CRT_NONSTDC_NO_DEPRECATE")

    # Get rid of warnings about passing "unchecked iterators" such as pointers to standard functions such as std::copy. See https://msdn.microsoft.com/en-us/library/aa985965.aspx and e.g. https://stackoverflow.com/a/1301343
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D_SCL_SECURE_NO_WARNINGS")

    # C4068: unknown pragma
    # C4200: nonstandard extension used: zeo-sized array in struct/union
    # C5030: attribute xxx is not recognized
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4068 /wd4200 /wd5030")

		add_definitions(/D_SILENCE_CXX17_RESULT_OF_DEPRECATION_WARNING) # needed for rapidcheck includes
else()
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-psabi")
    endif()
endif()



add_library(lib${PROJECT_NAME} src/base.cpp src/core.cpp src/zkp.cpp)
target_include_directories(lib${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(lib${PROJECT_NAME} extlib)

if (TEST)
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/ext/catch2/contrib)
    ENABLE_TESTING()
    include(CTest)
    include(Catch)

    # unit test executable
		set (test unit-tests/test.cpp)

		FILE(GLOB_RECURSE UNITTESTS unit-tests/*.test.cpp)
		add_executable (${PROJECT_NAME}test ${test} ${UNITTESTS})
    target_link_libraries(${PROJECT_NAME}test PRIVATE lib${PROJECT_NAME})
		target_link_libraries(${PROJECT_NAME}test PRIVATE ${TEST_LIBS})
		if (NOT CMAKE_CROSSCOMPILING)
		    catch_discover_tests(${PROJECT_NAME}test) # do not enable if gtest is part of this (will execute all the gtest tests)
		endif()
endif(TEST)
