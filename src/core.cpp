// Author: Bernard van Gastel

#include "core.h"

using namespace pep;

pep::ElGamal::ElGamal(GroupElement _B, const GroupElement& _C, const GroupElement& _Y) : B(_B), C(_C), Y(_Y) {
}

std::string ElGamal::hex() const {
  return B.hex() + C.hex() + Y.hex();
}

ElGamal ElGamal::FromHex(std::string_view view) {
  if (view.size() != 192)
    throw std::invalid_argument("ElGamal::FromHex expected different size");
  ElGamal retval;
  retval.B = GroupElement::FromHex(view.substr(0, 64));
  retval.C = GroupElement::FromHex(view.substr(64, 64));
  retval.Y = GroupElement::FromHex(view.substr(128, 64));
  return retval;
}
bool pep::ElGamal::operator==(const ElGamal& rhs) const {
  return B == rhs.B && C == rhs.C && Y == rhs.Y;
}

bool pep::ElGamal::operator!=(const ElGamal& rhs) const {
  return B != rhs.B || C != rhs.C || Y != rhs.Y;
}

// encrypt message M using public key Y
ElGamal pep::Encrypt(const GroupElement& M, const GroupElement& Y) {
  auto r = Scalar::Random();
  EXPECT(!r.is_zero()); // Random() does never return a zero scalar
  ENSURE(!Y.is_zero()); // we should not encrypt anything with an empty public key, as this will result in plain text send over the line
  return {r * G, M + r*Y, Y};
}

// decrypt encrypted ElGamal tuple with secret key y
GroupElement pep::Decrypt(const ElGamal& in, const Scalar& y) {
  return in.C - y * in.B;
}

ElGamal RerandomizeY(const ElGamal& in, const Scalar& s) {
  return {in.B - s*G, in.C, in.Y + s*G};
}

// randomize the encryption
ElGamal pep::Rerandomize(const ElGamal& in, const Scalar& s) {
  return {s * G + in.B, s * in.Y + in.C, in.Y};
}

// make it decryptable with another key k*y (with y the original private key)
ElGamal pep::Rekey(const ElGamal& in, const Scalar& k) {
  return {in.B / k, in.C, k * in.Y};
}

// adjust the encrypted cypher text to be n*M (with M the original text being encrypted)
ElGamal pep::Reshuffle(const ElGamal& in, const Scalar& n) {
  return {n * in.B, n * in.C, in.Y};
}

// combination of Rekey(k) and Reshuffle(n)
ElGamal pep::RKS(const ElGamal& in, const Scalar& k, const Scalar& n) {
  return {(n / k) * in.B, n * in.C, k * in.Y};
}
