// Author: Bernard van Gastel

#pragma once

#include "lib-defines.h"

#include <memory>
#include <chrono>
#include <functional>
#include <utility>
#include <type_traits>
#include <algorithm>
#include <tuple>
#include <cinttypes>


// Do not implement this on Clang,
// as it will generate code that messes up
// stack traces of uncaught exceptions.
// It has to do with `nounwind` in LLVM IR.
// Probably it rewinds until the last noexcept
// annotated function/method and calling the
// std::terminate handler only at that moment,
// in effect destroying a huge part of the stack
// trace.
#ifdef __clang__
#define NOEXCEPT
#else
#define NOEXCEPT noexcept
#endif

#if defined(__clang__) || defined(__GNUC__)
#define FORMAT(x, y, z) __attribute__ ((format (x, y, z)))
#define USING(x) ((void)(x))
#define UNREACHABLE_CODE(x) \
      _Pragma("clang diagnostic push") \
      _Pragma("clang diagnostic ignored \"-Wunreachable-code\"") \
      x \
      _Pragma("clang diagnostic pop")
#define FLOAT_EQUAL(x) \
      _Pragma("clang diagnostic push") \
      _Pragma("clang diagnostic ignored \"-Wfloat-equal\"") \
      x \
      _Pragma("clang diagnostic pop")
#define SIGN_CONVERSION(x) \
      _Pragma("clang diagnostic push") \
      _Pragma("clang diagnostic ignored \"-Wsign-conversion\"") \
      x \
      _Pragma("clang diagnostic pop")
#define OLD_STYLE_CAST(x) \
      _Pragma("clang diagnostic push") \
      _Pragma("clang diagnostic ignored \"-Wold-style-cast\"") \
      x \
      _Pragma("clang diagnostic pop")
#define COMMA(x) \
      _Pragma("clang diagnostic push") \
      _Pragma("clang diagnostic ignored \"-Wcomma\"") \
      x \
      _Pragma("clang diagnostic pop")
// specifying every option by hand is needed for Clang 3.8 on Ubuntu 16.04 LTS
#if defined(__clang__)
#define IGNORE_WARNINGS_START \
      _Pragma("clang diagnostic push") \
      _Pragma("clang diagnostic ignored \"-Weverything\"") \
      _Pragma("clang diagnostic ignored \"-Wshift-sign-overflow\"") \
      _Pragma("clang diagnostic ignored \"-Wmissing-noreturn\"") \
      _Pragma("clang diagnostic ignored \"-Wdeprecated\"") \
      _Pragma("clang diagnostic ignored \"-Wused-but-marked-unused\"") \
      _Pragma("clang diagnostic ignored \"-Wextra-semi\"") \
      _Pragma("clang diagnostic ignored \"-Wshorten-64-to-32\"") \
      _Pragma("clang diagnostic ignored \"-Wshadow\"") \
      _Pragma("clang diagnostic ignored \"-Wold-style-cast\"") \
      _Pragma("clang diagnostic ignored \"-Wsign-conversion\"") \
      _Pragma("clang diagnostic ignored \"-Wheader-hygiene\"") \
      _Pragma("clang diagnostic ignored \"-Wnon-virtual-dtor\"") \

#define IGNORE_WARNINGS_END \
      _Pragma("clang diagnostic pop")
#define IGNORE_STRING_OP(x) x
#else
#define IGNORE_WARNINGS_START \
	_Pragma("GCC diagnostic push") \
	_Pragma("GCC diagnostic ignored \"-Wdeprecated\"")
	// ...
#define IGNORE_WARNINGS_END \
	_Pragma("GCC diagnostic pop")
#define IGNORE_STRING_OP(x) \
	_Pragma("GCC diagnostic push") \
	_Pragma("GCC diagnostic ignored \"-Wstringop-overflow\"") \
	x; \
	_Pragma("GCC diagnostic pop") 

#endif

#else

#define FORMAT(x, y, z)
#define USING(x) ((void)(x))
#define UNREACHABLE_CODE(x) x
#define FLOAT_EQUAL(x) x
#define SIGN_CONVERSION(x) x
#define OLD_STYLE_CAST(x) x
#define COMMA(x) x
#define IGNORE_WARNINGS_START
#define IGNORE_WARNINGS_END
#define IGNORE_STRING_OP(x) x
#endif

#if defined(__clang__)
#define FALLTHROUGH [[clang::fallthrough]]
#else
#define FALLTHROUGH [[gnu::fallthrough]]
#endif
#if defined(__GNUC__)
#define UNREACHABLE __builtin_unreachable()
#else
#define UNREACHABLE EXPECT(false)
#endif

#ifdef EXTENDED_DEBUG
#define CRASH {*((int*)0x42) = 1;}
#else
#define CRASH
#endif

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define TSAN_ENABLED
#endif
#endif

#ifdef TSAN_ENABLED
extern "C" void AnnotateThreadName(const char* f, int l, const char* name);
extern "C" void AnnotateHappensBefore(const char* f, int l, void* addr);
extern "C" void AnnotateHappensAfter(const char* f, int l, void* addr);
#define TSAN_ANNOTATE_THREAD_NAME(addr) AnnotateThreadName(__FILE__, __LINE__, addr)
#define TSAN_ANNOTATE_HAPPENS_BEFORE(addr) AnnotateHappensBefore(__FILE__, __LINE__, static_cast<void*>(addr))
#define TSAN_ANNOTATE_HAPPENS_AFTER(addr) AnnotateHappensAfter(__FILE__, __LINE__, static_cast<void*>(addr))
#else
#define TSAN_ANNOTATE_THREAD_NAME(name)
#define TSAN_ANNOTATE_HAPPENS_BEFORE(addr)
#define TSAN_ANNOTATE_HAPPENS_AFTER(addr)
#endif

// Enable thread safety attributes only with clang.
// The attributes can be safely erased when compiling with other compilers.
#if (!defined(THREAD_ANNOTATION_ATTRIBUTE__)) && defined(__clang__) && (!defined(SWIG))
#define THREAD_ANNOTATION_ATTRIBUTE__(x)   __attribute__((x))
#else
#define THREAD_ANNOTATION_ATTRIBUTE__(x)   // no-op
#endif

#define CAPABILITY(x) \
  THREAD_ANNOTATION_ATTRIBUTE__(capability(x))

#define SCOPED_CAPABILITY \
  THREAD_ANNOTATION_ATTRIBUTE__(scoped_lockable)

#define GUARDED_BY(x) \
  THREAD_ANNOTATION_ATTRIBUTE__(guarded_by(x))

#define PT_GUARDED_BY(x) \
  THREAD_ANNOTATION_ATTRIBUTE__(pt_guarded_by(x))

#define ACQUIRED_BEFORE(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(acquired_before(__VA_ARGS__))

#define ACQUIRED_AFTER(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(acquired_after(__VA_ARGS__))

#define REQUIRES(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(requires_capability(__VA_ARGS__))

#define REQUIRES_SHARED(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(requires_shared_capability(__VA_ARGS__))

#define ACQUIRE(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(acquire_capability(__VA_ARGS__))

#define ACQUIRE_SHARED(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(acquire_shared_capability(__VA_ARGS__))

#define RELEASE(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(release_capability(__VA_ARGS__))

#define RELEASE_SHARED(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(release_shared_capability(__VA_ARGS__))

#define TRY_ACQUIRE(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_capability(__VA_ARGS__))

#define TRY_ACQUIRE_SHARED(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_shared_capability(__VA_ARGS__))

#define EXCLUDES(...) \
  THREAD_ANNOTATION_ATTRIBUTE__(locks_excluded(__VA_ARGS__))

#define ASSERT_CAPABILITY(x) \
  THREAD_ANNOTATION_ATTRIBUTE__(assert_capability(x))

#define ASSERT_SHARED_CAPABILITY(x) \
  THREAD_ANNOTATION_ATTRIBUTE__(assert_shared_capability(x))

#define RETURN_CAPABILITY(x) \
  THREAD_ANNOTATION_ATTRIBUTE__(lock_returned(x))

#define NO_THREAD_SAFETY_ANALYSIS \
  THREAD_ANNOTATION_ATTRIBUTE__(no_thread_safety_analysis)

// User code should use macros instead of functions.
#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#define ASAN 1
extern "C" {
// Marks memory region [addr, addr+size) as unaddressable.
// This memory must be previously allocated by the user program. Accessing
// addresses in this region from instrumented code is forbidden until
// this region is unpoisoned. This function is not guaranteed to poison
// the whole region - it may poison only subregion of [addr, addr+size) due
// to ASan alignment restrictions.
// Method is NOT thread-safe in the sense that no two threads can
// (un)poison memory in the same memory region simultaneously.
void __asan_poison_memory_region(void const volatile *addr, size_t size);
// Marks memory region [addr, addr+size) as addressable.
// This memory must be previously allocated by the user program. Accessing
// addresses in this region is allowed until this region is poisoned again.
// This function may unpoison a superregion of [addr, addr+size) due to
// ASan alignment restrictions.
// Method is NOT thread-safe in the sense that no two threads can
// (un)poison memory in the same memory region simultaneously.
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
}

#define ASAN_POISON_MEMORY_REGION(addr, size) \
  __asan_poison_memory_region((addr), (size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
  __asan_unpoison_memory_region((addr), (size))
#else
#define ASAN_POISON_MEMORY_REGION(addr, size) \
  ((void)(addr), (void)(size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
  ((void)(addr), (void)(size))
#endif
