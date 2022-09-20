// Author: Bernard van Gastel

#include "zkp.h"

namespace pep {

using GlobalPublicKey = GroupElement;
using GlobalSecretKey = Scalar;
using GlobalEncryptedPseudonym = ElGamal;
using LocalEncryptedPseudonym = ElGamal;
using LocalPseudonym = GroupElement;
using LocalDecryptionKey = Scalar;

std::tuple<GlobalPublicKey, GlobalSecretKey> GenerateGlobalKeys();

GlobalEncryptedPseudonym GeneratePseudonym(const std::string& identity, const GlobalPublicKey& pk);

LocalEncryptedPseudonym ConvertToLocalPseudonym(const GlobalEncryptedPseudonym& p, const std::string_view& secret, const std::string_view& decryptionContext, const std::string_view& pseudonimisationContext);

LocalDecryptionKey MakeLocalDecryptionKey(const GlobalSecretKey& k, const std::string_view& secret, const std::string_view& decryptionContext);

LocalPseudonym DecryptLocalPseudonym(const LocalEncryptedPseudonym& p, const LocalDecryptionKey& k);

GlobalEncryptedPseudonym RerandomizeGlobal(const GlobalEncryptedPseudonym& p);
LocalEncryptedPseudonym RerandomizeLocal(const LocalEncryptedPseudonym& p);

}
