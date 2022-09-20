// Author: Bernard van Gastel

#include "libpep.h"

using namespace libpep;

std::tuple<GlobalPublicKey, GlobalSecretKey> libpep::GenerateGlobalKeys() {
  auto secretKey = Scalar::Random();
  auto publicKey = secretKey * G;
  return {publicKey, secretKey};
}

GlobalEncryptedPseudonym libpep::GeneratePseudonym(const std::string& identity, const GlobalPublicKey& pk) {
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

LocalEncryptedPseudonym libpep::ConvertToLocalPseudonym(const GlobalEncryptedPseudonym& p, const std::string_view& secret, const std::string_view& decryptionContext, const std::string_view& pseudonimisationContext) {
  Scalar u = MakePseudonymisationFactor(secret, pseudonimisationContext);
  Scalar t = MakeDecryptionFactor(secret, decryptionContext);
  return RKS(p, t, u);
}

LocalDecryptionKey libpep::MakeLocalDecryptionKey(const GlobalSecretKey& k, const std::string_view& secret, const std::string_view& decryptionContext) {
  Scalar t = MakeDecryptionFactor(secret, decryptionContext);
  return t * k;
}

LocalPseudonym libpep::DecryptLocalPseudonym(const LocalEncryptedPseudonym& p, const LocalDecryptionKey& k) {
  return Decrypt(p, k);
}

GlobalEncryptedPseudonym libpep::RerandomizeGlobal(const GlobalEncryptedPseudonym& p) {
  return Rerandomize(p, Scalar::Random());
}
LocalEncryptedPseudonym libpep::RerandomizeLocal(const LocalEncryptedPseudonym& p) {
  return Rerandomize(p, Scalar::Random());
}
