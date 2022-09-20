// Author: Bernard van Gastel

#pragma once

#include "base.h"

namespace libpep {

struct ElGamal {
  GroupElement B;
  GroupElement C;
  GroupElement Y;
  ElGamal() { }
  ElGamal(GroupElement _B, const GroupElement& _C, const GroupElement& _Y);
  bool operator==(const ElGamal& rhs) const;
  bool operator!=(const ElGamal& rhs) const;
  std::string hex() const;
  static ElGamal FromHex(std::string_view view);
};

// encrypt message M using public key Y
ElGamal Encrypt(const GroupElement& M, const GroupElement& Y);

// decrypt encrypted ElGamal tuple with secret key y
GroupElement Decrypt(const ElGamal& in, const Scalar& y); 

// randomize the encryption
ElGamal Rerandomize(const ElGamal& in, const Scalar& s = Scalar::Random());

// make it decryptable with another key k*y (with y the original private key)
ElGamal Rekey(const ElGamal& in, const Scalar& k);

// adjust the encrypted cypher text to be n*M (with M the original text being encrypted)
ElGamal Reshuffle(const ElGamal& in, const Scalar& n);

// combination of Rekey(k) and Reshuffle(n) and Rerandomize(r)
ElGamal RKS(const ElGamal& in, const Scalar& k, const Scalar& n);

}
