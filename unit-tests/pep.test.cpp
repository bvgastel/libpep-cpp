// Author: Bernard van Gastel

#include "zkp.h"

#include <limits.h>
#include <optional>

IGNORE_WARNINGS_START
#include <catch2/catch.hpp>
#include <rapidcheck/catch.h>
IGNORE_WARNINGS_END

namespace {
using namespace radboud::pep;
using namespace std::literals;

TEST_CASE("PEP.SecureRemotePassword", "[PEP]") {
	uint8_t salt[4];
	RandomBytes(salt);

	uint8_t hashPassword[64];
	SHA512(hashPassword, std::string_view(reinterpret_cast<const char*>(salt), sizeof(salt)), "foobar"sv);
	auto x = Scalar::FromHash(hashPassword);
	auto V = x * G;

	// server stores identity, V, and salt

	// client
	auto a = Scalar::Random();
	auto A = a * G;

	// client -> server: identity, A

	// server
	auto b = Scalar::Random();
	auto B = b * G + V;

	// server -> client: salt, B

	// both
	uint8_t hashAB[64];
	SHA512(hashAB, A.raw(), B.raw());
	auto u = Scalar::FromHash(hashAB);

	// client
	ENSURE(!B.zero());
	ENSURE(!u.zero());
	CHECK(Scalar() + Scalar() == Scalar()); // test if zero() works
	auto S_C = (a + u*x)*(B - V);

	// server
	ENSURE(!A.zero());
	auto S_S = b*(A + u*V);

	CHECK(S_C == S_S);

	// from S_S an hsalsa key can be derived
	// see 
	// int crypto_box_beforenm(uint8_t* k, const uint8_t* y, const uint8_t* x) {
	// 	uint8_t s[32];
	// 	crypto_scalarmult(s, x, y);
	// 	return crypto_core_hsalsa20(k, _0, s, sigma);
	// }
	// likewise this can be used
}


TEST_CASE("PEP.ElGamalEncryption", "[PEP]") {
	// secret key
	auto s = Scalar::Random();
	// public key
	auto P = s * G;

	// choose a random value to encrypt
	GroupElement value = GroupElement::Random();

	// encrypt/decrypt this value
	auto encrypted = Encrypt(value, P);
	auto decrypted = Decrypt(encrypted, s);

	CHECK(value == decrypted);
}

// this methods encrypts a message M using a randomized public key Y. The public key is randomized by a factor r, which is included as randomizedG. This randomizedG can be generated from r by r * G
ElGamal Encrypt(const GroupElement& M, const GroupElement& randomizedY, const GroupElement& randomizedG) {
	auto r = Scalar::Random();
	return {r*randomizedG, M + r*randomizedY, randomizedY};
}

TEST_CASE("PEP.ElGamalEncryptionrandomizedPublicKey", "[PEP]") {
	// secret key
	auto s = Scalar::Random();
	// public key
	auto P = s * G;

	auto r = Scalar::Random();
	auto PP = r*P;
	auto gg = r * G;

  {
    auto g1 = (s + s.complement()) * G; // == 1
    auto gg2 = r*g1;
    CHECK(r * G == gg2);
  }

	// choose a random value to encrypt
	GroupElement value = GroupElement::Random();

	// encrypt/decrypt this value
	auto encrypted = Encrypt(value, PP, gg);
	auto decrypted = Decrypt(encrypted, s);
	CHECK(value == decrypted);

	auto r2 = Scalar::Random();
	PP = r2*PP;
	gg = r2*gg;
	encrypted = Encrypt(value, PP, gg);
	decrypted = Decrypt(encrypted, s);
	CHECK(value == decrypted);
}


TEST_CASE("PEP.PEPAssumptions", "[PEP]") {
	// secret key of system
	auto y = Scalar::Random();
	// public key of system
	auto Y = y * G;

	// secret key of service provider
	auto sj = Scalar::Random();
	auto yj = sj * y;
	CHECK(yj * G == sj * Y);

	// Lemma 2: RS(RK(..., k), n) == RK(RS(..., n), k)
	GroupElement value = GroupElement::Random();
	auto encrypted = Encrypt(value, Y);
	auto k = Scalar::Random();
	auto n = Scalar::Random();
	CHECK(Reshuffle(Rekey(encrypted, k), n) == Rekey(Reshuffle(encrypted, n), k));
	CHECK(Reshuffle(Rekey(encrypted, k), n) == RKS(encrypted, k, n));
}

TEST_CASE("PEP.PEPDerivedKey", "[PEP]") {
	auto y = Scalar::Random();
	auto Y = y * G;

	auto x = Scalar::Random();

	auto value = GroupElement::Random();

	auto encrypted = Encrypt(value, Y);
	auto morphed = Rekey(encrypted, x);
	auto decrypted = Decrypt(morphed, x*y);
	CHECK(value == decrypted);
}

TEST_CASE("PEP.PEPTotallyDifferentKey", "[PEP]") {
	auto y = Scalar::Random();
	auto Y = y * G;

	auto x = Scalar::Random();

	// encrypt with a different private key (but directly with a private key, not using the public key)
	auto value = GroupElement::Random();

	auto encrypted = Encrypt(value, Y);
	auto morphed = Rekey(encrypted, y.invert()*x);
	auto decrypted = Decrypt(morphed, x);
	CHECK(value == decrypted);
}

TEST_CASE("PEP.PEPWithKeyServer", "[PEP]") {
	// secret key of system
	Scalar y = Scalar::Random();

	// Client: user sends some identification (per group or per user)
	uint64_t pid;
	RandomBytes(pid);
	uint64_t sessionToken;
	RandomBytes(sessionToken);

	// EXAMPLE 0: DERRIVE USER DECRYPTION KEY
	// KeyServer: generate two randoms
	Scalar k_am_p = Scalar::Random();
	Scalar k_t_p = Scalar::Random();

	// send the private key blinded to the client
	Scalar y_p = k_am_p * k_t_p * y;
	// to client x_p

	// KeyServer to access manager: pid, sessionToken, k_am_p
  KDFContext AM_CONTEXT = "PEP-AMAM";
  KDFSeedKey am_seed_key;
  KDFGenerateSeedKey(am_seed_key);

	HashSHA512 am_hash_a;
	KDF(am_hash_a, sizeof(am_hash_a), pid ^ sessionToken, AM_CONTEXT, am_seed_key);
	// generate the factor unique for this user
	Scalar k_am_a = Scalar::FromHash(am_hash_a);
	// send the unblind combined with a secret of the access manager to the user
	Scalar k_a_am_p = k_am_a * k_am_p.invert();

	// KeyServer to transcryptor manager: pid, sessionToken, k_t_p
  KDFContext T_CONTEXT = "PEP-TTTT";
  KDFSeedKey t_seed_key;
  KDFGenerateSeedKey(t_seed_key);

	HashSHA512 t_hash_a;
	KDF(t_hash_a, sizeof(t_hash_a), pid ^ sessionToken, T_CONTEXT, t_seed_key);
	// generate the factor unique for this user
	Scalar k_t_a = Scalar::FromHash(t_hash_a);
	// send the unblind combined with a secret of the transcryptor to the user
	Scalar k_a_t_p = k_t_a * k_t_p.invert();

	// to client: k_a_am_p and k_a_t_p
	// the client can compute a new secret key which is: k_am_a * k_t_a * x
	auto y_a = k_a_am_p * k_a_t_p * y_p;

	// public key of system
	GroupElement Y = y * G;

	// *****************************************
	// EXAMPLE 1: store a value (e.g. AES key) and re-encrypt if for a client

	// we use an extra scalar at the AccessManager to provide additional protection: if the private key of the key server leaks, the values in the database can not be decrypted
	Scalar extraFactor = Scalar::Random();

	// let's encrypt a random value with the public key of the whole system
	GroupElement value = GroupElement::Random();
	auto encrypted = Encrypt(value, Y);
	// before storing the encrypted key, it should be 'blinded' using the extra factor
	encrypted = Reshuffle(encrypted, extraFactor);

	// rekey so that the value can be decrypted using the user private key
	// this step should be done by the access manager (as the secret of the access manager is needed)
	auto rekeyed_am = Rerandomize(RKS(encrypted, k_am_a, extraFactor.invert()));
	// and step should be done by the transcryptor (as the secret of the transcryptor is needed)
	auto rekeyed_am_t = Rerandomize(Rekey(rekeyed_am, k_t_a));

	// let's decrypt the value using the user private key, as the data is now encrypted by a secret key that is k_am_a * k_t_a * x
	auto decrypted = Decrypt(rekeyed_am_t, y_a);
	CHECK(value == decrypted);

	// *****************************************
	// EXAMPLE 2: generate a polymorphic pseudonym and convert it to a local one, and back again
	uint64_t accessGroup;
	RandomBytes(accessGroup);

	// additional factors needed for both AM and Transcryptor, to scramble the pseudonym and make it local
  KDFContext AM_CONTEXT_PSEUDONYM = "AMAM-PEP";
	HashSHA512 am_hash_ap;
	KDF(am_hash_ap, sizeof(am_hash_ap), accessGroup, AM_CONTEXT_PSEUDONYM, am_seed_key);
	Scalar k_am_ap = Scalar::FromHash(am_hash_ap);

  KDFContext T_CONTEXT_PSEUDONYM = "TTTT-PEP";
	HashSHA512 t_hash_ap;
	KDF(t_hash_ap, sizeof(t_hash_ap), accessGroup, T_CONTEXT_PSEUDONYM, t_seed_key);
	Scalar k_t_ap = Scalar::FromHash(t_hash_ap);

	// lets create a polymorphic pseudonym
	HashSHA512 polymorphicPseudonymSource;
	SHA512(polymorphicPseudonymSource, "some-identifier"sv);
	value = GroupElement::FromHash(polymorphicPseudonymSource);
	//INFO("raw pseudonym: " << ToBase64(value.raw()));
	auto polymorphicPseudonym = Encrypt(value, Y);

	// rekey so that the value can be decrypted using the user private key
	// reshuffle to make the value unique for the user
	// this step should be done by the access manager (as the secret of the access manager is needed)
	rekeyed_am = Rerandomize(RKS(polymorphicPseudonym, k_am_a, k_am_ap));
	// and step should be done by the transcryptor (as the secret of the transcryptor is needed)
	rekeyed_am_t = Rerandomize(RKS(rekeyed_am, k_t_a, k_t_ap));

	// let's decrypt the value using the user private key, as the data is now encrypted by a secret key that is k_am_a * k_t_a * x
	auto localPseudonym = Decrypt(rekeyed_am_t, y_a);

	// 44 bytes in base64, 64 bytes in hex
	//INFO("local pseudonym: " << ToBase64(localPseudonym.raw()));

	auto recrypted = Encrypt(localPseudonym, y_a * G);

	auto recryptedTranscryptor = Rerandomize(RKS(recrypted, k_t_a.invert(), k_t_ap.invert()));
	auto recryptedAM = Rerandomize(RKS(recryptedTranscryptor, k_am_a.invert(), k_am_ap.invert()));

	auto decryptedPseudonym = Decrypt(recryptedAM, y);
	CHECK(value == decryptedPseudonym);
	//INFO("raw pseudonym reconstructed " << ToBase64(decryptedPseudonym.raw()));
}

TEST_CASE("PEP.PEPWithoutKeyServer", "[PEP]") {
	// secret key of system, split over access manager
	auto y_am = Scalar::Random();
	auto y_t = Scalar::Random();

	auto Y_am = y_am * G;
	auto Y_t = y_t * G;

	// Client: user sends some identification (per group or per user)
	uint64_t pid;
	RandomBytes(pid);
	uint64_t sessionToken;
	RandomBytes(sessionToken);

	// EXAMPLE 0: DERRIVE USER DECRYPTION KEY

	// client to access manager: pid, sessionToken, k_am_p
  KDFContext AM_CONTEXT = "PEP-AMAM";
  KDFSeedKey am_seed_key;
  KDFGenerateSeedKey(am_seed_key);

	HashSHA512 am_hash_a;
	KDF(am_hash_a, sizeof(am_hash_a), pid ^ sessionToken, AM_CONTEXT, am_seed_key);
	// generate the factor unique for this user
	Scalar k_am_a = Scalar::FromHash(am_hash_a);
	// send the unblind combined with a secret of the access manager to the user
	Scalar k_a_am_p = k_am_a * y_am;

	// client to transcryptor manager: pid, sessionToken
  KDFContext T_CONTEXT = "PEP-TTTT";
  KDFSeedKey t_seed_key;
  KDFGenerateSeedKey(t_seed_key);

	HashSHA512 t_hash_a;
	KDF(t_hash_a, sizeof(t_hash_a), pid ^ sessionToken, T_CONTEXT, t_seed_key);
	// generate the factor unique for this user
	Scalar k_t_a = Scalar::FromHash(t_hash_a);
	// send the unblind combined with a secret of the transcryptor to the user
	Scalar k_a_t_p = k_t_a * y_t;

	// to client: k_a_am_p and k_a_t_p
	// the client can compute a new secret key which is: k_am_a_p * k_t_a_p
	auto x_a = k_a_am_p * k_a_t_p;

	// public key of system as generated by the transcryptor
	GroupElement Y = y_t * Y_am;

	// public key of the system as generated by the access manager
	GroupElement Y2 = y_am * Y_t;
	CHECK(Y2 == Y);

	// *****************************************
	// EXAMPLE 1: store a value (e.g. AES key) and re-encrypt if for a client

	// we use an extra scalar at the AccessManager to provide additional protection: if the private key of the key server leaks, the values in the database can not be decrypted
	Scalar extraFactor = Scalar::Random();

	// let's encrypt a random value with the public key of the whole system
	GroupElement value = GroupElement::Random();
	auto encrypted = Encrypt(value, Y);
	// before storing the encrypted key, it should be 'blinded' using the extra factor
	encrypted = Reshuffle(encrypted, extraFactor);

	// rekey so that the value can be decrypted using the user private key
	// this step should be done by the access manager (as the secret of the access manager is needed)
	auto rekeyed_am = Rerandomize(RKS(encrypted, k_am_a, extraFactor.invert()));
	// and step should be done by the transcryptor (as the secret of the transcryptor is needed)
	auto rekeyed_am_t = Rerandomize(Rekey(rekeyed_am, k_t_a));

	// let's decrypt the value using the user private key, as the data is now encrypted by a secret key that is k_am_a * k_t_a * x
	auto decrypted = Decrypt(rekeyed_am_t, x_a);
	CHECK(value == decrypted);

	// *****************************************
	// EXAMPLE 2: generate a polymorphic pseudonym and convert it to a local one, and back again
	uint64_t accessGroup;
	RandomBytes(accessGroup);

	// additional factors needed for both AM and Transcryptor, to scramble the pseudonym and make it local
  KDFContext AM_CONTEXT_PSEUDONYM = "AMAM-PEP";
	HashSHA512 am_hash_ap;
	KDF(am_hash_ap, sizeof(am_hash_ap), accessGroup, AM_CONTEXT_PSEUDONYM, am_seed_key);
	Scalar k_am_ap = Scalar::FromHash(am_hash_ap);

  KDFContext T_CONTEXT_PSEUDONYM = "TTTT-PEP";
	HashSHA512 t_hash_ap;
	KDF(t_hash_ap, sizeof(t_hash_ap), accessGroup, T_CONTEXT_PSEUDONYM, t_seed_key);
	Scalar k_t_ap = Scalar::FromHash(t_hash_ap);

	// lets create a polymorphic pseudonym
	HashSHA512 polymorphicPseudonymSource;
	SHA512(polymorphicPseudonymSource, "some-identifier"sv);
	value = GroupElement::FromHash(polymorphicPseudonymSource);
	//INFO("raw pseudonym: " << ToBase64(value.raw()));
	auto polymorphicPseudonym = Encrypt(value, Y);

	// rekey so that the value can be decrypted using the user private key
	// reshuffle to make the value unique for the user
	// this step should be done by the access manager (as the secret of the access manager is needed)
	rekeyed_am = Rerandomize(RKS(polymorphicPseudonym, k_am_a, k_am_ap));

	// and step should be done by the transcryptor (as the secret of the transcryptor is needed)
	rekeyed_am_t = Rerandomize(RKS(rekeyed_am, k_t_a, k_t_ap));

	// let's decrypt the value using the user private key, as the data is now encrypted by a secret key that is k_am_a * k_t_a * x
	auto localPseudonym = Decrypt(rekeyed_am_t, x_a);

	// 44 bytes in base64, 64 bytes in hex
	//INFO("local pseudonym: " << ToBase64(localPseudonym.raw()));

	auto recrypted = Encrypt(localPseudonym, x_a * G);

	auto recryptedTranscryptor = Rerandomize(RKS(recrypted, k_t_a.invert(), k_t_ap.invert()));
	auto recryptedAM = Rerandomize(RKS(recryptedTranscryptor, k_am_a.invert(), k_am_ap.invert()));

	// CHECK if it yields the same pseudonym
	auto decryptedPseudonym = Decrypt(recryptedAM, y_am * y_t);
	CHECK(value == decryptedPseudonym);
	//INFO("raw pseudonym reconstructed " << ToBase64(decryptedPseudonym.raw()));
}

TEST_CASE("PEP.PEPSchnorrBasicInteractive", "[PEP]") {
	// given a secret a and public M, proof that a certain triplet (A, M, N) is actually calculated by (a*G, M, a * M)

	// prover
	Scalar a = Scalar::Random();
	Scalar r = Scalar::Random();

	// sending to verifier
	GroupElement A = a * G;
	GroupElement M = GroupElement::Random();
	GroupElement N = a * M;
	GroupElement c1 = r * G;
	GroupElement c2 = r * M;

	// verifier
	Scalar e = Scalar::Random();

	// prover
	Scalar s = a*e + r;

	// verifier
	CHECK(s * G == e*A + c1);
	CHECK(s * M == e*N + c2);

	// proof for a factor r times M
	Scalar r2 = Scalar::Random();
	M = r2 * M;
	N = r2 * N;
	c2 = r2 * c2;

	CHECK(s * G == e*A + c1);
	CHECK(s * M == e*N + c2);
}

TEST_CASE("PEP.ElGamalSignature", "[PEP]") {
	// secret key
	auto s = Scalar::Random();
	auto s2 = Scalar::Random();
	// public key
	auto P = s * G;

	auto v = GroupElement::Random();
	auto signature = Sign(v, s);
	CHECK(Verify(v, signature, P));

	signature = Sign(v, s2);
	CHECK(!Verify(v, signature, P));
}

TEST_CASE("PEP.PEPSchnorrBasicOffline", "[PEP]") {
	// given a secret a and public M, proof that a certain triplet (A, M, N) is actually calculated by (a*G, M, a * M)
	// using Fiat-Shamir transform

	// prover
	Scalar a = Scalar::Random();
	GroupElement Min = GroupElement::Random();

	auto [A, p] = CreateProof(a, Min);
	CHECK(a * Min == p.value());

	// verifier
	CHECK(VerifyProof(A, Min, p));
}

TEST_CASE("PEP.PEPSchnorrRerandomize", "[PEP]") {
	// secret key of system
	auto y = Scalar::Random();
	// public key of system
	auto Y = y * G;

	GroupElement M = GroupElement::Random();
	Scalar s = Scalar::Random();

	ElGamal msg = Encrypt(M, Y);

	auto proved = ProveRerandomize(msg, s);

	auto checked = VerifyRerandomize(msg, proved);

	REQUIRE(checked);
	CHECK(msg != checked.value());
	CHECK(M == Decrypt(checked.value(), y));
	CHECK(Rerandomize(msg, s) == checked.value());
}

TEST_CASE("PEP.PEPSchnorrReshuffle", "[PEP]") {
	// secret key of system
	auto y = Scalar::Random();
	// public key of system
	auto Y = y * G;

	GroupElement M = GroupElement::Random();
	Scalar n = Scalar::Random();

	ElGamal msg = Encrypt(M, Y);

	auto proved = ProveReshuffle(msg, n);

	auto checked = VerifyReshuffle(msg, proved);

	REQUIRE(checked);
	CHECK(msg != checked.value());
	CHECK(n*M == Decrypt(checked.value(), y));
}

TEST_CASE("PEP.PEPSchnorrRekey", "[PEP]") {
	// secret key of system
	auto y = Scalar::Random();
	// public key of system
	auto Y = y * G;

	GroupElement M = GroupElement::Random();
	Scalar k = Scalar::Random();

	ElGamal msg = Encrypt(M, Y);

	auto proved = ProveRekey(msg, k);
	auto checked = VerifyRekey(msg, proved);

	REQUIRE(checked);
	CHECK(msg != checked.value());
	CHECK(RekeyByPublicKey(proved) == k * G);
	CHECK(M == Decrypt(checked.value(), k*y));
}

TEST_CASE("PEP.PEPSchnorrRKS", "[PEP]") {
	// secret key of system
	auto y = Scalar::Random();
	// public key of system
	auto Y = y * G;

	GroupElement M = GroupElement::Random();
	Scalar k = Scalar::Random();
	Scalar n = Scalar::Random();

	ElGamal msg = Encrypt(M, Y);

	auto proved = ProveRKS(msg, k, n);

	auto checked = VerifyRKS(msg, proved);

	REQUIRE(checked);
	CHECK(msg != checked.value());
	CHECK(RekeyByPublicKey(proved) == k * G);
	CHECK(n*M == Decrypt(checked.value(), k*y));
}

TEST_CASE("PEP.PEPSchnorrRKSAlt", "[PEP]") {
	// secret key of system
	auto y = Scalar::Random();
	// public key of system
	auto Y = y * G;

	GroupElement M = GroupElement::Random();
	Scalar r = Scalar::Random();
	Scalar k = Scalar::Random();
	Scalar n = Scalar::Random();

	ElGamal msg1 = Encrypt(M, Y);

	// Rerandomize is normally {s * G + in.b, s*in.y + in.c, in.y};
	// RKS is normally {(n / k) * in.b, n * in.c, k * in.y};
  ElGamal msg2 = RKS(Rerandomize(msg1, r), k, n);

  // If the new Y (k*msg1.Y) is already known, we can use
  // a different way of encoding this operation. This different way
  // combines a rerandomize in the operation, but saves two group
  // elements (= 64 bytes) in the representation of the proof.

  // static verifiers (fixed, known to the verifier)
  auto [verifier1,proof1] = CreateProof(n/k, msg1.B + r*G);
  auto [verifier2,proof2] = CreateProof(n, msg1.C + r*msg1.Y);
  auto [R, proof3] = CreateProof(r, msg1.Y);

  // straightforward proof of 3 GroupElements is normally: 3 * (4ge + 1s) = 12ge + 3s
  
  // transcryptor send back to access manager:
  // - proof1 (3ge + 1s)
  // - proof2 (3ge + 1s)
  // - R (1ge)
  // - proof3 (3ge + 1s)
  // total: 10ge + 3s
  //
  // checked:
  // Check that msg1.Y AND msg2.Y are the right one
  // Check that the first arguments to Verify are the right ones:
  // so that n/k*G and n*G matches.

  CHECK(VerifyProof(verifier1, msg1.B + R,        proof1.N, proof1.C1, proof1.C2, proof1.s));
  CHECK(VerifyProof(verifier2, msg1.C + proof3.N, proof2.N, proof2.C1, proof2.C2, proof2.s));
  CHECK(VerifyProof(R,         msg1.Y,            proof3.N, proof3.C1, proof3.C2, proof3.s));

  CHECK(proof1.N == msg2.B);
  CHECK(proof2.N == msg2.C);
}

TEST_CASE("PEP.RistrettoExampleFromLibSodium", "[PEP]") {
	// Perform a secure two-party computation of f(x) = p(x)^k.
	// x is the input sent to the second party by the first party
	// after blinding it using a random invertible scalar r,
	// and k is a secret key only known by the second party.
	// p(x) is a hash-to-group function.
	//
	// -------- First party -------- Send blinded p(x)

	// Compute px = p(x), a group element derived from x
	GroupElement px = GroupElement::Random();

	Scalar r = Scalar::Random();

	// Compute a = p(x) * g^r -> to second party
	GroupElement a = px + r * G;

	// -------- Second party -------- Send g^k and a^k
	Scalar k = Scalar::Random();

	// Compute v = g^k -> first party
	GroupElement v = k * G;

	// Compute b = a^k -> first party
	GroupElement b = k*a;

	// -------- First party -------- Unblind f(x)
	// Compute vir = v^(-r)
	Scalar ir = -r;
	GroupElement vir = ir * v;

	// Compute f(x) = b * v^(-r) = (p(x) * g^r)^k * (g^k)^(-r)
	//              = (p(x) * g)^k * g^(-k) = p(x)^k
	GroupElement fx = b + vir;
	CHECK(fx == k*px);
}

}
