// Author: Bernard van Gastel

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __has_feature         // Optional of course.
  #define __has_feature(x) 0  // Compatibility with non-clang compilers.
#endif

#ifndef __has_extension
  #define __has_extension __has_feature // Compatibility with pre-3.0 compilers.
#endif

#include <stdlib.h>
#include <stdio.h>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOGDI
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#include <sys/uio.h>
#endif
#include <errno.h>
#include <string.h>

#if defined(WIN32)
inline int strncasecmp(const char* s1, const char* s2, size_t n) {
  return _strnicmp(s1, s2, n);
}

inline int link(const char* oldPlace, const char *newPlace) {
  if (CreateHardLinkA(newPlace, oldPlace, NULL))
    return 0;
  return -1;
}
inline void bzero(void* b, size_t len) {
  memset(b, '\0', len);
}
#endif

#if defined(__linux__)
#  include <arpa/inet.h>
#  include <endian.h>
#  include <byteswap.h>
#  define ntohll(x) be64toh(x)
#  define htonll(x) htobe64(x)
#  define bswap16(x) bswap_16(x)
#  define bswap32(x) bswap_32(x)
#  define bswap64(x) bswap_64(x)
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <arpa/inet.h>
#  include <sys/endian.h>
#  define ntohll(x) be64toh(x)
#  define htonll(x) htobe64(x)
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define ntohll(x) betoh64(x)
#  define htonll(x) htobe64(x)
#elif defined(__APPLE__)
#  include <arpa/inet.h>
#include <libkern/OSByteOrder.h>
#define bswap16(x) OSSwapInt16(x)
#define bswap32(x) OSSwapInt32(x)
#define bswap64(x) OSSwapInt64(x)
#elif defined(WIN32) || defined(__CYGWIN__)
#define IS_LITTLE_ENDIAN (((struct { union { unsigned int x; unsigned char c; }}){1}).c)
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#ifdef IS_LITTLE_ENDIAN
#define BYTE_ORDER LITTLE_ENDIAN
#else
#define BYTE_ORDER BIG_ENDIAN
#endif
#  if BYTE_ORDER == LITTLE_ENDIAN
#    define ntohs(x) _byteswap_ushort(x)
#    define htons(x) _byteswap_ushort(x)
#    define ntohl(x) _byteswap_ulong(x)
#    define htonl(x) _byteswap_ulong(x)
#    define ntohll(x) _byteswap_uint64(x)
#    define htonll(x) _byteswap_uint64(x)
#  else
#    define ntohs(x) (x)
#    define htons(x) (x)
#    define ntohl(x) (x)
#    define htonl(x) (x)
#    define ntohll(x) (x)
#    define htonll(x) (x)
#  endif
#  define bswap16(x) _byteswap_ushort(x)
#  define bswap32(x) _byteswap_ulong(x)
#  define bswap64(x) _byteswap_uint64(x)
#else
#  warning "no 64-bits ntoh/hton byte operations"
#endif

// not possible to define as sizeof(long)*8 because "#if __WORDSIZE == 64" is used
#ifndef __WORDSIZE
#if defined(_WIN64)
#define __WORDSIZE 64
#elif defined(_WIN32)
#define __WORDSIZE 32
#elif defined(__linux__)
// needed for Alpine Linux, as it uses uLibC
#include <sys/user.h>
#endif
#endif

#if defined(WIN32)

#define NO_SOCKET INVALID_SOCKET
#define ssize_t int
#define socklen_t int

#define SHUT_WR SD_SEND // for shutdown()
#define SOCK_CLOEXEC 0

#define IOV_MAX 125
struct iovec {
    void  *iov_base;    /* Starting address */
    size_t iov_len;     /* Number of bytes to transfer */
};

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define errnoSocket WSAGetLastError()

#else
#define SOCKET int
#define NO_SOCKET int(-1)
#define closesocket(x) close(x)
#define errnoSocket errno
#endif

#ifdef __cplusplus
}
#endif
