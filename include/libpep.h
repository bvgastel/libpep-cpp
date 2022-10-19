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

namespace libpep {

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
