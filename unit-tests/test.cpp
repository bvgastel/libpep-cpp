// Author: Bernard van Gastel

#include "lib-common.h"

IGNORE_WARNINGS_START
#define CATCH_CONFIG_RUNNER
#undef __ANDROID__ // so it compiles on Termux
#include <catch2/catch.hpp>
#include <rapidcheck/catch.h>
IGNORE_WARNINGS_END

#ifndef WIN32
#include <sys/resource.h>
#endif

#include <chrono>
#include <thread>
#include <iostream>
#include <iomanip>

// help on defining 'your own main() for Catch2': https://github.com/catchorg/Catch2/blob/master/docs/own-main.md

#if defined(CATCH_CONFIG_WCHAR) && defined(WIN32) && defined(_UNICODE) && !defined(DO_NOT_USE_WMAIN)
// Standard C/C++ Win32 Unicode wmain entry point
extern "C" int wmain (int argc, wchar_t * argv[], wchar_t * []) {
#else
// Standard C/C++ main entry point
int main (int argc, char * argv[]) {
#endif

	int retval = Catch::Session().run(argc, argv);

	// allows for clean up of resources like server sockets
	//using namespace std::chrono_literals;
	//std::this_thread::sleep_for(250ms);

#if !defined(WIN32)
	struct rusage usage;
	getrusage(RUSAGE_SELF, &usage);

	std::cout << "user time:                    " << usage.ru_utime.tv_sec << "." << std::fixed << std::setw(6) << std::setprecision(6) << std::setfill('0') << usage.ru_utime.tv_usec << " s" << std::endl;
	std::cout << "soft page faults:             " << usage.ru_minflt << std::endl;
	std::cout << "hard page faults:             " << usage.ru_majflt << std::endl;
#ifdef __APPLE__
	std::cout << "max memory:                   " << usage.ru_maxrss/1024 << " KiB" << std::endl;
#else
	std::cout << "max memory:                   " << usage.ru_maxrss << " KiB" << std::endl;
#endif
	std::cout << "voluntary context switches:   " << usage.ru_nvcsw << std::endl;
	std::cout << "involuntary context switches: " << usage.ru_nivcsw << std::endl;
#endif

  return retval;
}
