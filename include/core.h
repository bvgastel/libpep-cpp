/**
Copyright 2021 Bernard van Gastel, bvgastel@bitpowder.com.
This file is part of libpep.

libpep is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libpep is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Bit Powder Libraries.  If not, see <http://www.gnu.org/licenses/>.
*/
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
