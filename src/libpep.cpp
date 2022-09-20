// Author: Bernard van Gastel

#include "libpep.h"

using namespace pep;

std::tuple<GlobalPublicKey, GlobalSecretKey> pep::GenerateGlobalKeys() {
  auto secretKey = Scalar::Random();
  auto publicKey = secretKey * G;
  return {publicKey, secretKey};
}

GlobalEncryptedPseudonym pep::GeneratePseudonym(const std::string& identity, const GlobalPublicKey& pk) {
  HashSHA512 hash;
  SHA512(hash, identity);
  auto p = GroupElement::FromHash(hash);
  return Encrypt(p, pk);
}

Scalar MakeFactor(const std::string_view& type, const std::string_view& secret, const std::string_view& context) {
  HashSHA512 uhash;
  SHA512(uhash, type, "|", secret, "|", context);
  return Scalar::FromHash(uhash);
}

Scalar MakePseudonymisationFactor(const std::string_view& secret, const std::string_view& context) {
  return MakeFactor("pseudonym", secret, context);
}

Scalar MakeDecryptionFactor(const std::string_view& secret, const std::string_view& context) {
  return MakeFactor("decryption", secret, context);
}

LocalEncryptedPseudonym pep::ConvertToLocalPseudonym(const GlobalEncryptedPseudonym& p, const std::string_view& secret, const std::string_view& decryptionContext, const std::string_view& pseudonimisationContext) {
  Scalar u = MakePseudonymisationFactor(secret, pseudonimisationContext);
  Scalar t = MakeDecryptionFactor(secret, decryptionContext);
  return RKS(p, t, u);
}

LocalDecryptionKey pep::MakeLocalDecryptionKey(const GlobalSecretKey& k, const std::string_view& secret, const std::string_view& decryptionContext) {
  Scalar t = MakeDecryptionFactor(secret, decryptionContext);
  return t * k;
}

LocalPseudonym pep::DecryptLocalPseudonym(const LocalEncryptedPseudonym& p, const LocalDecryptionKey& k) {
  return Decrypt(p, k);
}

GlobalEncryptedPseudonym pep::RerandomizeGlobal(const GlobalEncryptedPseudonym& p) {
  return Rerandomize(p, Scalar::Random());
}
LocalEncryptedPseudonym pep::RerandomizeLocal(const LocalEncryptedPseudonym& p) {
  return Rerandomize(p, Scalar::Random());
}
