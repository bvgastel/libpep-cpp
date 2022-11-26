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

#include "core.h"

namespace libpep {

// offline Schnorr proof
// using Fiat-Shamir transform
struct Proof {
  GroupElement N;
  GroupElement C1;
  GroupElement C2;
  Scalar s;

  GroupElement value() const {
    return N;
  }
};

// returns <A=a*G, Proof with a value N = a*M>
std::tuple<GroupElement,Proof> CreateProof(const Scalar& a /*secret*/, const GroupElement& M /*public*/);

[[nodiscard]] bool VerifyProof(const GroupElement& A, const GroupElement& M, const GroupElement& N, const GroupElement& C1, const GroupElement& C2, const Scalar& s);

[[nodiscard]] bool VerifyProof(const GroupElement& A, const GroupElement& M, const Proof& p);

//// SIGNATURES

using Signature = Proof;

Signature Sign(const GroupElement& message, const Scalar& secretKey);
[[nodiscard]] bool Verify(const GroupElement& message, const Signature& p, const GroupElement& publicKey);

//// RERANDOMIZE

// We are re-using some variables from the Proof to reconstruct the Rerandomize operation.
// This way, we only need 1 Proof object (which are fairly large)
using ProvedRerandomize = std::tuple<GroupElement,Proof>;

ProvedRerandomize ProveRerandomize(const ElGamal& in, const Scalar& s = Scalar::Random());

[[nodiscard]] std::optional<ElGamal> VerifyRerandomize(const ElGamal& in, const ProvedRerandomize& p);
[[nodiscard]] std::optional<ElGamal> VerifyRerandomize(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& S, const Proof& p);

//// RESHUFFLE

using ProvedReshuffle = std::tuple<GroupElement,Proof,Proof>;

ProvedReshuffle ProveReshuffle(const ElGamal& in, const Scalar& n);

[[nodiscard]] std::optional<ElGamal> VerifyReshuffle(const ElGamal& in, const ProvedReshuffle& p);
[[nodiscard]] std::optional<ElGamal> VerifyReshuffle(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AB, const Proof& pb, const Proof& pc);

GroupElement ReshuffledBy(const ProvedReshuffle& in);

//// REKEY

using ProvedRekey = std::tuple<GroupElement,Proof,GroupElement,Proof>;
ProvedRekey ProveRekey(const ElGamal& in, const Scalar& k);

[[nodiscard]] std::optional<ElGamal> VerifyRekey(const ElGamal& in, const ProvedRekey& p);
[[nodiscard]] std::optional<ElGamal> VerifyRekey(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AB, const Proof& pb, const GroupElement& AY, const Proof& py);

// return k.base() after ProveRekey(in, k)
GroupElement RekeyBy(const ProvedRekey& in);

//// RKS

using ProvedRKS = std::tuple<GroupElement,Proof,GroupElement,Proof,GroupElement,Proof>;

ProvedRKS ProveRKS(const ElGamal& in, const Scalar& k, const Scalar& n);

[[nodiscard]] std::optional<ElGamal> VerifyRKS(const ElGamal& in, const ProvedRKS& p);
[[nodiscard]] std::optional<ElGamal> VerifyRKS(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AB, const Proof& pb, const GroupElement& AC, const Proof& pc, const GroupElement& AY, const Proof& py);

// return n.base() after ProveRKS(in, k, n)
GroupElement ReshuffledBy(const ProvedRKS& in);
// return k.base() after ProveRKS(in, k, n)
GroupElement RekeyBy(const ProvedRKS& in);

}
