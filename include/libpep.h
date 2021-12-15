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

LocalEncryptedPseudonym ConvertToLocalPseudonym(GlobalEncryptedPseudonym p, const std::string& secret, const std::string& decryptionContext, const std::string& pseudonimisationContext);

LocalDecryptionKey MakeLocalDecryptionKey(GlobalSecretKey k, const std::string& secret, const std::string& decryptionContext);

LocalPseudonym DecryptLocalPseudonym(LocalEncryptedPseudonym p, LocalDecryptionKey k);

GlobalEncryptedPseudonym RerandomizeGlobal(const GlobalEncryptedPseudonym& p);
LocalEncryptedPseudonym RerandomizeLocal(const LocalEncryptedPseudonym& p);

}
