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

GlobalEncryptedPseudonym libpep::ConvertFromLocalPseudonym(const LocalEncryptedPseudonym& p, const std::string_view& secret, const std::string_view& decryptionContext, const std::string_view& pseudonimisationContext) {
  Scalar u = MakePseudonymisationFactor(secret, pseudonimisationContext);
  Scalar t = MakeDecryptionFactor(secret, decryptionContext);
  return RKS(p, t.invert(), u.invert());
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
