// Author: Bernard van Gastel

#pragma once

#include <optional>
#include <string>

#include "lib-common.h"
#include "sodium/crypto_hash_sha512.h"

#ifndef NDEBUG
#define  EXPECT(e)  ((e) ? (void)0 : CrashAssert(__func__, __FILE__, __LINE__, #e))
#define  EXPECT_TEXT(e, text)  ((e) ? (void)0 : CrashAssert(__func__, __FILE__, __LINE__, #e, text))
#else
#define  EXPECT(e)  ((void)0)
#define  EXPECT_TEXT(e, text)  ((void)0)
#endif
#define  ENSURE(e)  ((e) ? (void)0 : CrashAssert(__func__, __FILE__, __LINE__, #e))
#define  ENSURE_TEXT(e, text)  ((e) ? (void)0 : CrashAssert(__func__, __FILE__, __LINE__, #e, text))
extern "C" [[noreturn]] void CrashAssert(const char* func, const char* file, int line, const char* condition, const char* explanation = nullptr);

namespace radboud {
namespace pep {

struct GroupElement;

struct Scalar {
  static const constexpr size_t BYTES = 32;
  uint8_t value[BYTES];
  Scalar() {
    memset(value, 0, sizeof(value));
  }
  Scalar(const Scalar& rhs) {
    *this = rhs;
  }
  Scalar& operator=(const Scalar& rhs) {
    memcpy(value, rhs.value, sizeof(value));
    return *this;
  }
  std::string_view raw() const {
    return {reinterpret_cast<const char*>(value), sizeof(value)};
  }
  GroupElement base() const;
  Scalar invert() const ; // s * s^-1 = 1
  Scalar complement() const ; // s + comp = 1 (mod L)
  Scalar operator-() const; // negate
  bool zero() const;
  bool valid() const;
  // returns a scalar != 0
  static Scalar Random();
  static Scalar FromHash(uint8_t (&value)[64]);
};

bool operator==(const Scalar& lhs, const Scalar& rhs);
bool operator!=(const Scalar& lhs, const Scalar& rhs);

struct GroupElement {
  static const constexpr size_t BYTES = 32;
  uint8_t value[BYTES];
  GroupElement() {
    memset(value, 0, sizeof(value));
  }
  GroupElement(const GroupElement& rhs) {
    *this = rhs;
  }
  GroupElement& operator=(const GroupElement& rhs) {
    memcpy(value, rhs.value, sizeof(value));
    return *this;
  }
  std::string_view raw() const {
    return {reinterpret_cast<const char*>(value), sizeof(value)};
  }
  bool zero() const;
  bool valid() const;
  static GroupElement Random();
  static GroupElement FromHash(uint8_t (&value)[64]);
};

bool operator==(const GroupElement& lhs, const GroupElement& rhs);
bool operator!=(const GroupElement& lhs, const GroupElement& rhs);

GroupElement operator+(const GroupElement& lhs, const GroupElement& rhs);
GroupElement operator-(const GroupElement& lhs, const GroupElement& rhs);
GroupElement operator*(const Scalar& lhs, const GroupElement& rhs);
GroupElement operator/(const GroupElement& lhs, const Scalar& rhs);

Scalar operator+(const Scalar& lhs, const Scalar& rhs);
Scalar operator-(const Scalar& lhs, const Scalar& rhs);
Scalar operator*(const Scalar& lhs, const Scalar& rhs);
Scalar operator/(const Scalar& lhs, const Scalar& rhs);

struct _G {
};
static _G G;
// convert a scalar to a group element
GroupElement operator*(const Scalar& lhs, const _G& rhs);

// use libsodium version of SHA512, so the corelib has less dependencies.
// drawback is that it is slightly slower (not relevant for the few uses we have for sha512 here)
// SHA512
static const size_t SHA512_DIGEST_LENGTH = 64;
using HashSHA512 = uint8_t[SHA512_DIGEST_LENGTH];

inline void _SHA512Update(crypto_hash_sha512_state*) {
}

template <typename... Args>
void _SHA512Update(crypto_hash_sha512_state* cxt, std::string in, const Args& ... args) {
  crypto_hash_sha512_update(cxt, reinterpret_cast<const unsigned char*>(in.data()), in.length());
  _SHA512Update(cxt, args...);
}

template <typename... Args>
void _SHA512Update(crypto_hash_sha512_state* cxt, std::string_view in, const Args& ... args) {
  crypto_hash_sha512_update(cxt, reinterpret_cast<const unsigned char*>(in.data()), in.length());
  _SHA512Update(cxt, args...);
}

template <typename... Args>
void SHA512(HashSHA512& hash, const Args& ... args) {
  crypto_hash_sha512_state context;
  crypto_hash_sha512_init(&context);
  _SHA512Update(&context, args...);
  crypto_hash_sha512_final(&context, &hash[0]);
  // see http://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html and is slow
}

void RandomBytes(void* ptr, std::size_t length);

template <size_t N>
void RandomBytes(char (&buffer)[N]) {
  RandomBytes(buffer, N);
}
template <size_t N>
void RandomBytes(uint8_t (&buffer)[N]) {
  RandomBytes(buffer, N);
}
template <typename T>
void RandomBytes(T & t, typename std::enable_if<std::is_integral<T>::value, void*>::type = nullptr) {
  RandomBytes(&t, sizeof(T));
}

// KDF = Blake2b

static const size_t KDF_SEEDKEYBYTES = 32;
using KDFSeedKey = uint8_t[KDF_SEEDKEYBYTES];

static const size_t KDF_CONTEXTBYTES = 8;
using KDFContext = char[KDF_SEEDKEYBYTES];

void KDFGenerateSeedKey(KDFSeedKey& seedKey);

void KDF(unsigned char *output, size_t outputLength, uint64_t subkey_id, const KDFContext& context, const KDFSeedKey& seedKey);

}
}

