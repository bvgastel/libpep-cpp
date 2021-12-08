// Author: Bernard van Gastel

#include "base.h"

#include <type_traits>
#include <random>
#include <sstream>

#include "sodium.h"

using namespace radboud::pep;

extern "C" [[noreturn]] void CrashAssert(const char* func, const char* file, int line, const char* condition, const char* explanation) {
  fprintf(stderr, "asserton '%s' violated: %s [%s:%i] %s\n", condition, func, file, line, explanation);
  ::abort();
}

static_assert(crypto_core_ristretto255_SCALARBYTES == Scalar::BYTES);
static_assert(crypto_core_ristretto255_BYTES == GroupElement::BYTES);

// documentation of libsodium primitives: https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto

GroupElement Scalar::base() const {
	GroupElement r;
	ENSURE(crypto_scalarmult_ristretto255_base(r.value, value) == 0);
	return r;
}
Scalar Scalar::invert() const {
	Scalar r;
	crypto_core_ristretto255_scalar_invert(r.value, value);
	return r;
};
Scalar Scalar::operator-() const {
	Scalar r;
	crypto_core_ristretto255_scalar_negate(r.value, value);
	return r;
}
Scalar Scalar::complement() const {
	Scalar r;
	crypto_core_ristretto255_scalar_complement(r.value, value);
	return r;
}
[[maybe_unused]] bool Scalar::zero() const {
  return sodium_is_zero(value, sizeof(value));
}
bool Scalar::valid() const {
	// sc25519_is_canonical() from ed25519_ref10.c

	/* 2^252+27742317777372353535851937790883648493 */
    static const unsigned char L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
        0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    unsigned char c = 0;
    unsigned char n = 1;
    unsigned int  i = 32;

    do {
        i--;
        c |= ((value[i] - L[i]) >> 8) & n;
        n &= ((value[i] ^ L[i]) - 1) >> 8;
    } while (i != 0);

    return (c != 0);
}

std::string Scalar::hex() const {
  return ToHex(raw());
}
Scalar Scalar::FromHex(std::string_view view) {
  if (view.size() != 64)
    throw std::invalid_argument("Scalar::FromHex expected different size");
  Scalar retval;
  ::FromHex(retval.value, view);
  return retval;
}
Scalar Scalar::Random() {
	Scalar r;
	// does random bytes, and check if it is canonical and != zero
	crypto_core_ristretto255_scalar_random(r.value);
	return r;
}
Scalar Scalar::FromHash(uint8_t (&value)[64]) {
	Scalar r;
	crypto_core_ristretto255_scalar_reduce(r.value, value);
	return r;
}
[[maybe_unused]] bool GroupElement::zero() const {
  return sodium_is_zero(value, sizeof(value));
}
bool GroupElement::valid() const {
  return crypto_core_ristretto255_is_valid_point(value);
}
std::string GroupElement::hex() const {
  return ToHex(raw());
}
GroupElement GroupElement::FromHex(std::string_view view) {
  if (view.size() != 64)
    throw std::invalid_argument("GroupElement::FromHex expected different size");
  GroupElement retval;
  ::FromHex(retval.value, view);
  return retval;
}
GroupElement GroupElement::FromHash(uint8_t (&value)[64]) {
	GroupElement r;
	crypto_core_ristretto255_from_hash(r.value, value);
	return r;
}
GroupElement GroupElement::Random() {
	GroupElement r;
	// random bytes and calls *_from_hash(...)
	crypto_core_ristretto255_random(r.value);
	return r;
}
namespace radboud {
namespace pep {

GroupElement operator+(const GroupElement& lhs, const GroupElement& rhs) {
	GroupElement r;
	crypto_core_ristretto255_add(r.value, lhs.value, rhs.value);
	return r;
}
GroupElement operator-(const GroupElement& lhs, const GroupElement& rhs) {
	GroupElement r;
	crypto_core_ristretto255_sub(r.value, lhs.value, rhs.value);
	return r;
}
Scalar operator+(const Scalar& lhs, const Scalar& rhs) {
	Scalar r;
	crypto_core_ristretto255_scalar_add(r.value, lhs.value, rhs.value);
	return r;
}
[[maybe_unused]] Scalar operator-(const Scalar& lhs, const Scalar& rhs) {
	Scalar r;
	crypto_core_ristretto255_scalar_sub(r.value, lhs.value, rhs.value);
	return r;
}
Scalar operator*(const Scalar& lhs, const Scalar& rhs) {
	Scalar r;
	crypto_core_ristretto255_scalar_mul(r.value, lhs.value, rhs.value);
	return r;
}
Scalar operator/(const Scalar& lhs, const Scalar& rhs) {
	Scalar r = rhs.invert();
	crypto_core_ristretto255_scalar_mul(r.value, lhs.value, r.value);
	return r;
}
[[maybe_unused]] bool operator==(const Scalar& lhs, const Scalar& rhs) {
	for (size_t i = 0; i < sizeof(lhs.value); ++i)
		if (lhs.value[i] != rhs.value[i])
			return false;
	return true;
}
[[maybe_unused]] bool operator!=(const Scalar& lhs, const Scalar& rhs) {
	return !operator==(lhs, rhs);
}
GroupElement operator*(const Scalar& lhs, const GroupElement& rhs) {
	GroupElement r;
	ENSURE(0 == crypto_scalarmult_ristretto255(r.value, lhs.value, rhs.value));
	return r;
}
GroupElement operator/(const GroupElement& lhs, const Scalar& rhs) {
	GroupElement r;
	ENSURE(0 == crypto_scalarmult_ristretto255(r.value, rhs.invert().value, lhs.value));
	return r;
}
bool operator==(const GroupElement& lhs, const GroupElement& rhs) {
	for (size_t i = 0; i < sizeof(lhs.value); ++i)
		if (lhs.value[i] != rhs.value[i])
			return false;
	return true;
}
bool operator!=(const GroupElement& lhs, const GroupElement& rhs) {
	return !operator==(lhs, rhs);
}

GroupElement operator*(const Scalar& lhs, const _G&) {
  return lhs.base();
}

void RandomBytes(void* ptr, std::size_t length) {
    ::randombytes(static_cast<unsigned char*>(ptr), length);
}

static_assert(crypto_kdf_KEYBYTES == KDF_SEEDKEYBYTES);
static_assert(crypto_kdf_blake2b_CONTEXTBYTES == KDF_CONTEXTBYTES);

void KDFGenerateSeedKey(KDFSeedKey& seedKey) {
	crypto_kdf_keygen(seedKey);
}

void KDF(unsigned char *output, size_t outputLength, uint64_t subkey_id, const KDFContext& context, const KDFSeedKey& seedKey) {
	ENSURE(0 == crypto_kdf_derive_from_key(output, outputLength, subkey_id, context, seedKey));
}

std::string ToHex(std::string_view in) {
  std::stringstream output;
  output << std::hex;
  for (auto sc : in) {
    auto c = uint8_t(sc);
    output << int(c >> 4) << int(c & 0xF);
  }
  return output.str();
}

uint8_t FromDigit(char _c) {
  uint8_t c = static_cast<uint8_t>(_c);
  if ((c >= '0') && (c <= '9')) {
    return c - '0';
  } else if ((c >= 'a') && (c <= 'f')) {
    return c - 'a' + 10;
  } else if ((c >= 'A') && (c <= 'F')) {
    return c - 'A' + 10;
  }
  throw std::invalid_argument("char " + std::to_string(int(c)) + " is not a hex char.");
}
void FromHex(uint8_t* out, size_t out_len, std::string_view in) {
  if (out_len*2 != in.length())
    throw std::invalid_argument("FromHex expected different size");
  for (const char* it = in.begin(); it < in.end(); it += 2) {
    uint8_t l = FromDigit(*it);
    uint8_t r = FromDigit(*(it+1));
    *(out++) = uint8_t(l<<4) | r;
  }
}

}
}

