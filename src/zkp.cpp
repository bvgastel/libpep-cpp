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

#include "zkp.h"

using namespace libpep;

std::tuple<GroupElement,Proof> libpep::CreateProof(const Scalar& a /*secret*/, const GroupElement& M /*public*/) {
  Scalar r = Scalar::Random();

  GroupElement A = a * G;
  GroupElement N = a * M;
  GroupElement C1 = r * G;
  GroupElement C2 = r * M;

  HashSHA512 hash;
  SHA512(hash,
      A.raw(),
      M.raw(),
      N.raw(),
      C1.raw(),
      C2.raw());
  Scalar e = Scalar::FromHash(hash);
  Scalar s = a*e + r;
  return {A, {N, C1, C2, s}};
}

[[nodiscard]] bool libpep::VerifyProof(const GroupElement& A, const GroupElement& M, const GroupElement& N, const GroupElement& C1, const GroupElement& C2, const Scalar& s) {
  if (!A.is_valid() || !M.is_valid() || !N.is_valid() || !C1.is_valid() || !C2.is_valid() || !s.is_valid())
    return false;
  HashSHA512 hash;
  SHA512(hash,
      A.raw(),
      M.raw(),
      N.raw(),
      C1.raw(),
      C2.raw());
  Scalar e = Scalar::FromHash(hash);

  return s * G == e*A + C1
    && s * M == e*N + C2;
}

[[nodiscard]] bool libpep::VerifyProof(const GroupElement& A, const GroupElement& M, const Proof& p) {
  return VerifyProof(A, M, p.N, p.C1, p.C2, p.s);
}

Signature libpep::Sign(const GroupElement& message, const Scalar& secretKey) {
  auto p = CreateProof(secretKey, message);
  return std::get<1>(p);
}

[[nodiscard]] bool libpep::Verify(const GroupElement& message, const Signature& p, const GroupElement& publicKey) {
  return VerifyProof(publicKey, message, p.N, p.C1, p.C2, p.s);
}

ProvedRerandomize libpep::ProveRerandomize(const ElGamal& in, const Scalar& s) {
  // Rerandomize is normally {s * G + in.b, s*in.y + in.c, in.y};
  return CreateProof(s, in.Y);
}
[[nodiscard]] std::optional<ElGamal> libpep::VerifyRerandomize(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& S, const Proof& py) {
  // slightly different than the others, as we reuse the structure of a standard proof to reconstruct the Rerandomize operation after sending
  return B.is_valid() && C.is_valid() && VerifyProof(S, Y, py) ?
    ElGamal{S + B, py.value() + C, Y} : std::optional<ElGamal>();
}
[[nodiscard]] std::optional<ElGamal> libpep::VerifyRerandomize(const ElGamal& in, const ProvedRerandomize& p) {
  return VerifyRerandomize(in.B, in.C, in.Y, std::get<0>(p), std::get<1>(p));
}

// adjust the encrypted cypher text to be n*M (with M the original text being encrypted)
ProvedReshuffle libpep::ProveReshuffle(const ElGamal& in, const Scalar& n) {
  // Reshuffle is normally {n * in.b, n * in.c, in.y};
  // NOTE: can be optimised a bit, by fusing the two CreateProofs (because same n is used, saving a n*G operation)
  auto [AB, pb] = CreateProof(n, in.B);
  auto [AC, pc] = CreateProof(n, in.C);
  EXPECT(AB == AB);
  return {AB, pb, pc};
}

[[nodiscard]] std::optional<ElGamal> libpep::VerifyReshuffle(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AB, const Proof& pb, const Proof& pc) {
  return VerifyProof(AB, B, pb) && VerifyProof(AB, C, pc) && Y.is_valid() ?
    ElGamal{pb.value(), pc.value(), Y} : std::optional<ElGamal>();
}
[[nodiscard]] std::optional<ElGamal> libpep::VerifyReshuffle(const ElGamal& in, const ProvedReshuffle& p) {
  return VerifyReshuffle(in.B, in.C, in.Y, std::get<0>(p), std::get<1>(p), std::get<2>(p));
}

GroupElement libpep::ReshuffledBy(const ProvedReshuffle& in) {
  return std::get<0>(in);
}

// adjust the encrypted cypher text to be n*M (with M the original text being encrypted)
ProvedRekey libpep::ProveRekey(const ElGamal& in, const Scalar& k) {
  // Rekey is normmaly {in.b/k, in.c, k*in.y};
  auto [AB, pb] = CreateProof(k.invert(), in.B);
  auto [AY, py] = CreateProof(k, in.Y);
  return {AB, pb, AY, py};
}

[[nodiscard]] std::optional<ElGamal> libpep::VerifyRekey(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AB, const Proof& pb, const GroupElement& AY, const Proof& py) {
  return VerifyProof(AB, B, pb) && C.is_valid() && VerifyProof(AY, Y, py) ?
    ElGamal{pb.value(), C, py.value()} : std::optional<ElGamal>();
}

[[nodiscard]] std::optional<ElGamal> libpep::VerifyRekey(const ElGamal& in, const ProvedRekey& p) {
  return VerifyRekey(in.B, in.C, in.Y, std::get<0>(p), std::get<1>(p), std::get<2>(p), std::get<3>(p));
}

GroupElement libpep::RekeyBy(const ProvedRekey& in) {
  return std::get<2>(in);
}

ProvedRKS libpep::ProveRKS(const ElGamal& in, const Scalar& k, const Scalar& n) {
  // RKS is normally {(n / k) * in.B, n * in.C, k * in.Y};
  // different order (C, Y, B) so that first and second group elements for prove_reshuffle,
  // prove_rekey, prove_rks have the same meaning
  return std::tuple_cat(CreateProof(n, in.C), CreateProof(k, in.Y), CreateProof(n/k, in.B));
}
[[nodiscard]] std::optional<ElGamal> libpep::VerifyRKS(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AC, const Proof& pc, const GroupElement& AY, const Proof& py, const GroupElement& AB, const Proof& pb) {
  return VerifyProof(AB, B, pb) && VerifyProof(AC, C, pc) && VerifyProof(AY, Y, py) ?
    ElGamal{pb.value(), pc.value(), py.value()} : std::optional<ElGamal>();
}
[[nodiscard]] std::optional<ElGamal> libpep::VerifyRKS(const ElGamal& in, const ProvedRKS& p) {
  return VerifyRKS(in.B, in.C, in.Y, std::get<0>(p), std::get<1>(p), std::get<2>(p), std::get<3>(p), std::get<4>(p), std::get<5>(p));
}
GroupElement libpep::ReshuffledBy(const ProvedRKS& in) {
  return std::get<0>(in);
}
GroupElement libpep::RekeyBy(const ProvedRKS& in) {
  return std::get<2>(in);
}
