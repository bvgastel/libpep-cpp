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

Scalar MakeFactor(const std::string& secret, const std::string& context) {
  HashSHA512 uhash;
  SHA512(uhash, secret, "|", context);
  return Scalar::FromHash(uhash);
}

LocalEncryptedPseudonym pep::ConvertToLocalPseudonym(GlobalEncryptedPseudonym p, const std::string& secret, const std::string& decryptionContext, const std::string& pseudonimisationContext) {
  Scalar u = MakeFactor(secret, pseudonimisationContext);
  Scalar t = MakeFactor(secret, decryptionContext);
  return RKS(p, t, u);
}

LocalDecryptionKey pep::MakeLocalDecryptionKey(GlobalSecretKey k, const std::string& secret, const std::string& decryptionContext) {
  Scalar t = MakeFactor(secret, decryptionContext);
  return t * k;
}

LocalPseudonym pep::DecryptLocalPseudonym(LocalEncryptedPseudonym p, LocalDecryptionKey k) {
  return Decrypt(p, k);
}

GlobalEncryptedPseudonym pep::RerandomizeGlobal(const GlobalEncryptedPseudonym& p) {
  return Rerandomize(p, Scalar::Random());
}
LocalEncryptedPseudonym pep::RerandomizeLocal(const LocalEncryptedPseudonym& p) {
  return Rerandomize(p, Scalar::Random());
}