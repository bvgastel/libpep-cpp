// Author: Bernard van Gastel

#include "zkp.h"

using namespace radboud::pep;

std::tuple<GroupElement,Proof> radboud::pep::CreateProof(const Scalar& a /*secret*/, const GroupElement& M /*public*/) {
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

[[nodiscard]] bool radboud::pep::VerifyProof(const GroupElement& A, const GroupElement& M, const GroupElement& N, const GroupElement& C1, const GroupElement& C2, const Scalar& s) {
  if (!A.valid() || !M.valid() || !N.valid() || !C1.valid() || !C2.valid() || !s.valid())
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

[[nodiscard]] bool radboud::pep::VerifyProof(const GroupElement& A, const GroupElement& M, const Proof& p) {
  return VerifyProof(A, M, p.N, p.C1, p.C2, p.s);
}

Signature radboud::pep::Sign(const GroupElement& message, const Scalar& secretKey) {
  auto p = CreateProof(secretKey, message);
  return std::get<1>(p);
}

[[nodiscard]] bool radboud::pep::Verify(const GroupElement& message, const Signature& p, const GroupElement& publicKey) {
  return VerifyProof(publicKey, message, p.N, p.C1, p.C2, p.s);
}

ProvedRerandomize radboud::pep::ProveRerandomize(const ElGamal& in, const Scalar& s) {
  // Rerandomize is normally {s * G + in.b, s*in.y + in.c, in.y};
  return CreateProof(s, in.Y);
}
[[nodiscard]] std::optional<ElGamal> radboud::pep::VerifyRerandomize(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& S, const Proof& py) {
  // slightly different than the others, as we reuse the structure of a standard proof to reconstruct the Rerandomize operation after sending
  return B.valid() && C.valid() && VerifyProof(S, Y, py) ?
    ElGamal{S + B, py.value() + C, Y} : std::optional<ElGamal>();
}
[[nodiscard]] std::optional<ElGamal> radboud::pep::VerifyRerandomize(const ElGamal& in, const ProvedRerandomize& p) {
  return VerifyRerandomize(in.B, in.C, in.Y, std::get<0>(p), std::get<1>(p));
}

// adjust the encrypted cypher text to be n*M (with M the original text being encrypted)
ProvedReshuffle radboud::pep::ProveReshuffle(const ElGamal& in, const Scalar& n) {
  // Reshuffle is normally {n * in.b, n * in.c, in.y};
  // NOTE: can be optimised a bit, by fusing the two CreateProofs (because same n is used)
  auto [AB, pb] = CreateProof(n, in.B);
  auto [AC, pc] = CreateProof(n, in.C);
  return {AB, pb, AC, pc};
}
[[nodiscard]] std::optional<ElGamal> radboud::pep::VerifyReshuffle(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AB, const Proof& pb, const GroupElement& AC, const Proof& pc) {
  return VerifyProof(AB, B, pb) && VerifyProof(AC, C, pc) && Y.valid() ?
    ElGamal{pb.value(), pc.value(), Y} : std::optional<ElGamal>();
}
[[nodiscard]] std::optional<ElGamal> radboud::pep::VerifyReshuffle(const ElGamal& in, const ProvedReshuffle& p) {
  return VerifyReshuffle(in.B, in.C, in.Y, std::get<0>(p), std::get<1>(p), std::get<2>(p), std::get<3>(p));
}

// adjust the encrypted cypher text to be n*M (with M the original text being encrypted)
ProvedRekey radboud::pep::ProveRekey(const ElGamal& in, const Scalar& k) {
  // Rekey is normmaly {in.b/k, in.c, k*in.y};
  auto [AB, pb] = CreateProof(k.invert(), in.B);
  auto [AY, py] = CreateProof(k, in.Y);
  return {AB, pb, AY, py};
}

[[nodiscard]] std::optional<ElGamal> radboud::pep::VerifyRekey(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AB, const Proof& pb, const GroupElement& AY, const Proof& py) {
  return VerifyProof(AB, B, pb) && C.valid() && VerifyProof(AY, Y, py) ?
    ElGamal{pb.value(), C, py.value()} : std::optional<ElGamal>();
}

[[nodiscard]] std::optional<ElGamal> radboud::pep::VerifyRekey(const ElGamal& in, const ProvedRekey& p) {
  return VerifyRekey(in.B, in.C, in.Y, std::get<0>(p), std::get<1>(p), std::get<2>(p), std::get<3>(p));
}

GroupElement radboud::pep::RekeyByPublicKey(const ProvedRekey& in) {
  return std::get<2>(in);
}

ProvedRKS radboud::pep::ProveRKS(const ElGamal& in, const Scalar& k, const Scalar& n) {
  // RKS is normally {(n / k) * in.B, n * in.C, k * in.Y};
  return std::tuple_cat(CreateProof(n/k, in.B), CreateProof(n, in.C), CreateProof(k, in.Y));
}
[[nodiscard]] std::optional<ElGamal> radboud::pep::VerifyRKS(const GroupElement& B, const GroupElement& C, const GroupElement& Y, const GroupElement& AB, const Proof& pb, const GroupElement& AC, const Proof& pc, const GroupElement& AY, const Proof& py) {
  return VerifyProof(AB, B, pb) && VerifyProof(AC, C, pc) && VerifyProof(AY, Y, py) ?
    ElGamal{pb.value(), pc.value(), py.value()} : std::optional<ElGamal>();
}
[[nodiscard]] std::optional<ElGamal> radboud::pep::VerifyRKS(const ElGamal& in, const ProvedRKS& p) {
  return VerifyRKS(in.B, in.C, in.Y, std::get<0>(p), std::get<1>(p), std::get<2>(p), std::get<3>(p), std::get<4>(p), std::get<5>(p));
}
GroupElement radboud::pep::RekeyByPublicKey(const ProvedRKS& in) {
  return std::get<4>(in);
}
